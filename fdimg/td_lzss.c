/*
 * LZSS Compression - adapted from the original C code by Haruhiko Okumura (1988)
 * Modifications from https://github.com/simonowen/samdisk/blob/main/src/types/td0.cpp
 * Further refactored and improved for fdimg
 */

#include <inttypes.h>
#include <string.h>

#include "img_defs.h"
#include "img_help.h"
#include "td_lzss.h"

#define N           4096                    // ring buffer size
#define F           60                      // lookahead buffer size
#define THRESHOLD   2                       // match needs to be longer than this for position/length coding

#define N_CHAR      (256 - THRESHOLD + F)   // kinds of characters (character code = 0..N_CHAR-1)
#define T           (N_CHAR * 2 - 1)        // size of table
#define R           (T - 1)                 // tree root position
#define MAX_FREQ    0x8000                  // updates tree when root frequency reached this value


short parent[T + N_CHAR];                   // parent nodes (0..T-1) and leaf positions (rest)
short son[T];                               // pointers to child nodes (son[], son[] + 1)
uint16_t freq[T + 1];                       // frequency table

uint8_t ring_buff[N + F - 1];               // text buffer for match strings
unsigned r;                                 // Ring buffer position

unsigned uBits, uBitBuff;                   // buffered bit count and left-aligned bit buffer

int     eof_flg;                            // internal EOF flag


static const uint8_t d_len[] = { 3,3,4,4,4,5,5,5,5,6,6,6,7,7,7,8 };

static const uint8_t d_code[] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D, 0x0E, 0x0E, 0x0E, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F,
    0x10, 0x10, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11, 0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13,
    0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15, 0x16, 0x16, 0x16, 0x16, 0x17, 0x17, 0x17, 0x17,
    0x18, 0x18, 0x19, 0x19, 0x1A, 0x1A, 0x1B, 0x1B, 0x1C, 0x1C, 0x1D, 0x1D, 0x1E, 0x1E, 0x1F, 0x1F,
    0x20, 0x20, 0x21, 0x21, 0x22, 0x22, 0x23, 0x23, 0x24, 0x24, 0x25, 0x25, 0x26, 0x26, 0x27, 0x27,
    0x28, 0x28, 0x29, 0x29, 0x2A, 0x2A, 0x2B, 0x2B, 0x2C, 0x2C, 0x2D, 0x2D, 0x2E, 0x2E, 0x2F, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};


// Initialise the trees and state variables
static void Init( void )
{
    unsigned i;
    int j;

    memset( parent, 0, sizeof( parent ) );
    memset( son, 0, sizeof( son ) );
    memset( freq, 0, sizeof( freq) );
    memset( ring_buff, 0, sizeof( ring_buff ) );


    for( i = 0; i < N_CHAR; i++ ) {
        freq[i] = 1;
        son[i] = i + T;
        parent[i + T] = i;
    }

    i = 0;
    for( j = N_CHAR; j <= R; i += 2, j++ ) {
        freq[j] = freq[i] + freq[i + 1];
        son[j] = i;
        parent[i] = parent[i + 1] = j;
    }

    uBitBuff = uBits = 0;
    memset( ring_buff, ' ', sizeof( ring_buff ) );

    freq[T] = 0xffff;
    parent[R] = 0;

    r = N - F;
}

// Rebuild the tree
static void RebuildTree( void )
{
    unsigned i, j, k, f, l;

    // Collect leaf nodes in the first half of the table and replace the freq by (freq + 1) / 2
    for( i = j = 0; i < T; i++ ) {
        if( son[i] >= T ) {
            freq[j] = (freq[i] + 1) / 2;
            son[j] = son[i];
            j++;
        }
    }

    // Begin constructing tree by connecting sons
    for( i = 0, j = N_CHAR; j < T; i += 2, j++ )
    {
        k = i + 1;
        f = freq[j] = freq[i] + freq[k];
        for (k = j - 1; f < freq[k]; k--);
        k++;
        l = (j - k) * sizeof(*freq);

        memmove( &freq[k + 1], &freq[k], l );
        freq[k] = f;
        memmove( &son[k + 1], &son[k], l );
        son[k] = i;
    }

    // Connect parent
    for( i = 0; i < T; i++ )
        if( (k = son[i]) >= T )
            parent[k] = i;
        else
            parent[k] = parent[k + 1] = i;
}


// Increment frequency of given code by one, and update tree
static void UpdateTree( int c )
{
    unsigned i, j, k, l;

    if( freq[R] == MAX_FREQ )
        RebuildTree();

    c = parent[c + T];

    do {
        k = ++freq[c];

        // If the order is disturbed, exchange nodes
        if( k > freq[l = c + 1] ) {
            while (k > freq[++l]);
            l--;
            freq[c] = freq[l];
            freq[l] = k;

            i = son[c];
            parent[i] = l;
            if (i < T)
                parent[i + 1] = l;

            j = son[l];
            son[l] = i;

            parent[j] = c;
            if (j < T)
                parent[j + 1] = c;
            son[c] = j;

            c = l;
        }
    } while( (c = parent[c]) != 0 );    // Repeat up to root
}

static inline unsigned GetChar( img_fns *cb, img_file imgf )
{
    uint8_t b;
    int     rc;

    rc = cb->read( imgf, &b, sizeof( b ) );
    if( rc != sizeof( b ) )
        eof_flg = 1;

    return( !eof_flg ? b : 0 );
}

// Get one bit
static unsigned GetBit( img_fns *cb, img_file imgf )
{
    if( !uBits-- ) {
        uBitBuff |= GetChar( cb, imgf ) << 8;
        uBits = 7;
    }

    uBitBuff <<= 1;
    return( (uBitBuff >> 16) & 1 );
}

// Get one byte
static unsigned GetByte( img_fns *cb, img_file imgf )
{
    if( uBits < 8 )
        uBitBuff |= GetChar( cb, imgf ) << (8 - uBits);
    else
        uBits -= 8;

    uBitBuff <<= 8;
    return( (uBitBuff >> 16) & 0xff );
}

static unsigned DecodeChar( img_fns *cb, img_file imgf )
{
    unsigned c = son[R];

    // Travel from root to leaf, choosing the smaller child node (son[]) if the
    // read bit is 0, the bigger (son[]+1} if 1
    while( c < T )
        c = son[c + GetBit( cb, imgf )];

    c -= T;
    UpdateTree( c );
    return( c );
}

static unsigned DecodePosition( img_fns *cb, img_file imgf )
{
    unsigned i, j, c;

    // Recover upper 6 bits from table
    i = GetByte( cb, imgf );
    c = d_code[i] << 6;
    j = d_len[i >> 4];

    // Read lower 6 bits verbatim
    for( j -= 2; j--; i = (i << 1) | GetBit( cb, imgf ) )
        ;

    return( c | (i & 0x3f) );
}


// Unpack a given block into the supplied output buffer
long td_unpack_lzss( img_fns *cb, img_file imgf, uint8_t* dst, long buf_sz )
{
    unsigned i, j, k, c;
    long unp_sz = 0;

    // Store the input start/end positions and prepare to unpack
    eof_flg = 0;
    Init();

    // Loop until we've processed all the input
    while( !eof_flg ) {
        c = DecodeChar( cb, imgf );

        // Single output character?
        if( c < 256 ) {
            if( unp_sz == buf_sz )  // Avoid buffer overflow
                return( 0 );
            *dst++ = c;
            unp_sz++;

            // Update the ring buffer and position (wrapping if necessary)
            ring_buff[r++] = c;
            r &= (N - 1);
        } else {
            // Position in ring buffer and length
            i = (r - DecodePosition( cb, imgf ) - 1) & (N - 1);
            j = c - 255 + THRESHOLD;

            // Output the block
            for( k = 0; k < j; ++k ) {
                c = ring_buff[(i + k) & (N - 1)];
                if( unp_sz == buf_sz )  // Avoid buffer overflow
                    return( 0 );
                *dst++ = c;
                unp_sz++;

                ring_buff[r++] = c;
                r &= (N - 1);
            }
        }
    }

    // Return the unpacked size
    return( unp_sz );
}
