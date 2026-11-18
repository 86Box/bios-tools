/*
 * Adapted from ar002 archiver by Haruhiko Okumura (1990).
 * The algorithm is the same as the -lh5- compression method
 * in the LHA 2.x utility.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>

#include "img_defs.h"
#include "img_help.h"
#include "dxp_lh5.h"


#define DICBIT    13    /* 12(-lh4-) or 13(-lh5-) */
#define DICSIZ   (1U << DICBIT)
#define MATCHBIT   8    /* bits for MAXMATCH - THRESHOLD */
#define MAXMATCH 256    /* formerly F (not more than UCHAR_MAX + 1) */
#define THRESHOLD  3    /* choose optimal value */

#define NC (UCHAR_MAX + MAXMATCH + 2 - THRESHOLD)
                        /* alphabet = {0, 1, 2, ..., NC - 1} */
#define CBIT 9          /* $\lfloor \log_2 NC \rfloor + 1$ */
#define CODE_BIT  16    /* codeword length */

unsigned long   compsize;

/***********************************************************
        io.c -- input/output
***********************************************************/

img_fns     *cbf;
img_file    arcfile;
uint16_t    bitbuf;

#define BITBUFSIZ (CHAR_BIT * sizeof bitbuf)

static unsigned subbitbuf;
static int      bitcount;

void error( char *fmt, ... )
{
        va_list args;

        va_start(args, fmt);
        putc('\n', stderr);
        vfprintf(stderr, fmt, args);
        putc('\n', stderr);
        va_end(args);
        exit(EXIT_FAILURE);
}

/* Read the next byte from file */
static int read_byte( img_file arcfile/*lh5 *ds*/ )
{
    long        rc;
    uint8_t     byte;

//    if( ds->in_pos++ < ds->in_buf_sz ) {
        rc = cbf->read( arcfile, &byte, sizeof( byte ) );
        if( rc == sizeof( byte ) )
            return( byte );
        else
            return( -1 );
//    } else
//        return( -1 );
}

void fillbuf( int n )   /* Shift bitbuf n bits left, read n bits */
{
    bitbuf <<= n;
    while( n > bitcount ) {
        bitbuf |= subbitbuf << (n -= bitcount);
        if( compsize != 0 ) {
            compsize--;
            subbitbuf = (uint8_t)read_byte( arcfile );
        } else
            subbitbuf = 0;
        bitcount = CHAR_BIT;
    }
    bitbuf |= subbitbuf >> (bitcount -= n);
}

unsigned getbits( int n )
{
    unsigned    x;

    x = bitbuf >> (BITBUFSIZ - n);
    fillbuf( n );
    return( x );
}


void init_getbits( void )
{
    bitbuf = 0;
    subbitbuf = 0;
    bitcount = 0;
    fillbuf(BITBUFSIZ);
}

/***********************************************************
        maketbl.c -- make table for decoding
***********************************************************/

uint16_t    left[], right[];

void make_table( int nchar, uint8_t bitlen[], int tablebits, uint16_t table[] )
{
    uint16_t    count[17], weight[17], start[18], *p;
    unsigned    i, k, len, ch, jutbits, avail, nextcode, mask;

    for (i = 1; i <= 16; i++)
        count[i] = 0;
    for (i = 0; i < nchar; i++)
        count[bitlen[i]]++;

    start[1] = 0;
    for( i = 1; i <= 16; i++ )
        start[i + 1] = start[i] + (count[i] << (16 - i));
    if( start[17] != (uint16_t)(1U << 16) )
        error("Bad table");

    jutbits = 16 - tablebits;
    for( i = 1; i <= tablebits; i++ ) {
        start[i] >>= jutbits;
        weight[i] = 1U << (tablebits - i);
    }
    while( i <= 16 ) {
        weight[i] = 1U << (16 - i);
        i++;
    }

    i = start[tablebits + 1] >> jutbits;
    if( i != (uint16_t)(1U << 16) ) {
        k = 1U << tablebits;
        while( i != k )
            table[i++] = 0;
    }

    avail = nchar;
    mask = 1U << (15 - tablebits);
    for( ch = 0; ch < nchar; ch++ ) {
        if( (len = bitlen[ch]) == 0 )
            continue;
        nextcode = start[len] + weight[len];
        if( len <= tablebits ) {
            for( i = start[len]; i < nextcode; i++ )
                table[i] = ch;
        } else {
            k = start[len];
            p = &table[k >> jutbits];
            i = len - tablebits;
            while( i != 0 ) {
                if( *p == 0 ) {
                    right[avail] = left[avail] = 0;
                    *p = avail++;
                }
                if( k & mask )
                    p = &right[*p];
                else
                    p = &left[*p];
                k <<= 1;  i--;
            }
            *p = ch;
        }
        start[len] = nextcode;
    }
}

/***********************************************************
        huf.c -- static Huffman
***********************************************************/

#define NP (DICBIT + 1)
#define NT (CODE_BIT + 3)
#define PBIT 4  /* smallest integer such that (1U << PBIT) > NP */
#define TBIT 5  /* smallest integer such that (1U << TBIT) > NT */
#if NT > NP
        #define NPT NT
#else
        #define NPT NP
#endif

uint16_t        left[2 * NC - 1], right[2 * NC - 1];
static uint8_t  c_len[NC], pt_len[NPT];
static unsigned blocksize;
static uint16_t c_table[4096], pt_table[256];

/***** decoding *****/

static void read_pt_len( int nn, int nbit, int i_special )
{
    int         i, c, n;
    unsigned    mask;

    n = getbits( nbit );
    if( n == 0 ) {
        c = getbits( nbit );
        for( i = 0; i < nn; i++ )
            pt_len[i] = 0;
        for( i = 0; i < 256; i++ )
            pt_table[i] = c;
    } else {
        i = 0;
        while( i < n ) {
            c = bitbuf >> (BITBUFSIZ - 3);
            if( c == 7 ) {
                mask = 1U << (BITBUFSIZ - 1 - 3);
                while( mask & bitbuf ) {
                    mask >>= 1;
                    c++;
                }
            }
            fillbuf( (c < 7) ? 3 : c - 3 );
            pt_len[i++] = c;
            if( i == i_special ) {
                c = getbits( 2 );
                while( --c >= 0 )
                    pt_len[i++] = 0;
            }
        }
        while( i < nn )
            pt_len[i++] = 0;
        make_table( nn, pt_len, 8, pt_table );
    }
}

static void read_c_len( void )
{
    int         i, c, n;
    unsigned    mask;

    n = getbits( CBIT );
    if( n == 0 ) {
        c = getbits( CBIT );
        for( i = 0; i < NC; i++ )
            c_len[i] = 0;
        for( i = 0; i < 4096; i++ )
            c_table[i] = c;
    } else {
        i = 0;
        while( i < n ) {
            c = pt_table[bitbuf >> (BITBUFSIZ - 8)];
            if( c >= NT ) {
                mask = 1U << (BITBUFSIZ - 1 - 8);
                do {
                    if( bitbuf & mask )
                        c = right[c];
                    else
                        c = left [c];
                    mask >>= 1;
                } while( c >= NT );
            }
            fillbuf( pt_len[c] );
            if( c <= 2 ) {
                if     ( c == 0 )
                    c = 1;
                else if( c == 1 )
                    c = getbits(4) + 3;
                else
                    c = getbits( CBIT ) + 20;
                while( --c >= 0 )
                    c_len[i++] = 0;
            } else
                c_len[i++] = c - 2;
        }
        while( i < NC )
            c_len[i++] = 0;
        make_table( NC, c_len, 12, c_table );
    }
}

unsigned decode_c( void )
{
    unsigned    j, mask;

    if( blocksize == 0 ) {
        blocksize = getbits(16);
        read_pt_len( NT, TBIT, 3 );
        read_c_len();
        read_pt_len( NP, PBIT, -1 );
    }
    blocksize--;
    j = c_table[bitbuf >> (BITBUFSIZ - 12)];
    if( j >= NC ) {
        mask = 1U << (BITBUFSIZ - 1 - 12);
        do {
            if( bitbuf & mask )
                j = right[j];
            else
                j = left [j];
            mask >>= 1;
        } while( j >= NC );
    }
    fillbuf( c_len[j] );
    return( j );
}

unsigned decode_p( void )
{
    unsigned    j, mask;

    j = pt_table[bitbuf >> (BITBUFSIZ - 8)];
    if( j >= NP ) {
        mask = 1U << (BITBUFSIZ - 1 - 8);
        do {
            if( bitbuf & mask )
                j = right[j];
            else
                j = left [j];
            mask >>= 1;
        } while( j >= NP );
    }
    fillbuf( pt_len[j] );
    if( j != 0 )
        j = (1U << (j - 1)) + getbits(j - 1);
    return( j );
}

void huf_decode_start( void )
{
    init_getbits();
    blocksize = 0;
}

/***********************************************************
        decode.c
***********************************************************/

static int j;  /* remaining bytes to copy */

void decode_start( void )
{
    huf_decode_start();
    j = 0;
}

void decode( unsigned count, uint8_t buffer[] )
    /* The calling function must keep the number of
       bytes to be processed.  This function decodes
       either 'count' bytes or 'DICSIZ' bytes, whichever
       is smaller, into the array 'buffer[]' of size
       'DICSIZ' or more.
       Call decode_start() once for each new file
       before calling this function. */
{
    static unsigned i;
    unsigned    r, c;

    r = 0;
    while( --j >= 0 ) {
        buffer[r] = buffer[i];
        i = (i + 1) & (DICSIZ - 1);
        if( ++r == count )
            return;
    }
    for( ;; ) {
        c = decode_c();
        if( c <= UCHAR_MAX ) {
            buffer[r] = c;
            if( ++r == count )
                return;
        } else {
            j = c - (UCHAR_MAX + 1 - THRESHOLD);
            i = (r - decode_p() - 1) & (DICSIZ - 1);
            while( --j >= 0 ) {
                buffer[r] = buffer[i];
                i = (i + 1) & (DICSIZ - 1);
                if( ++r == count )
                    return;
            }
        }
    }
}

long dxp_unpack_lh5( img_fns *cb, img_file imgf, long comp_sz, uint8_t *dst, long buf_sz )
{
    long        origsize = buf_sz;
    unsigned    n;
    uint8_t     buffer[DICSIZ];

    cbf      = cb;
    arcfile  = imgf;
    compsize = comp_sz;

    decode_start();
    /* We cannot decompress directly to the destination. If the loop below needs
     * more than one pass (guaranteed for 3.5" HD floppy images), each subsequent
     * pass relies on the contents of the buffer from the previous pass.
     */
    while( origsize != 0 ) {
        n = (unsigned)(origsize > DICSIZ ? DICSIZ : origsize);
        decode( n, buffer );
        origsize -= n;
        memcpy( dst, buffer, n );
        dst += n;
    }

    return( buf_sz - origsize );
}
