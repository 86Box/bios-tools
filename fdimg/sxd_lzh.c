/*
 * Adapted from lzhuf.c English version 1.0. Removed compression code.
 * This algorithm is *almost* the same as the -lh1- compression method
 * in the LHarc (later LHA) utility.
 *
 *
 * English LZHUF.C was based on Japanese version 29-NOV-1988
 * LZSS coded by Haruhiko OKUMURA
 * Adaptive Huffman Coding coded by Haruyasu YOSHIZAKI
 * Edited and translated to English by Kenji RIKITAKE
 */

#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "img_defs.h"
#include "img_help.h"
#include "dxp_lh1.h"

/* LZSS Parameters */

#define N		4096	/* Size of string buffer */
#define F		60	/* Size of look-ahead buffer */
#define THRESHOLD	2
#define NIL		N	/* End of tree's node  */

/* Huffman coding parameters */

#define N_CHAR  	(256 - THRESHOLD + F)
                        /* character code (= 0..N_CHAR-1) */
#define T 		(N_CHAR * 2 - 1)	/* Size of table */
#define R 		(T - 1)			/* root position */
                        /* update when cumulative frequency */
                        /* reaches this value */
#define MAX_FREQ	0x8000

/*
* Tables for decoding upper 6 bits of sliding
* dictionary pointer
*/

/* decoder table */
static uint8_t d_code[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0E, 0x0E, 0x0E, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F,
    0x10, 0x10, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11,
    0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13,
    0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15,
    0x16, 0x16, 0x16, 0x16, 0x17, 0x17, 0x17, 0x17,
    0x18, 0x18, 0x19, 0x19, 0x1A, 0x1A, 0x1B, 0x1B,
    0x1C, 0x1C, 0x1D, 0x1D, 0x1E, 0x1E, 0x1F, 0x1F,
    0x20, 0x20, 0x21, 0x21, 0x22, 0x22, 0x23, 0x23,
    0x24, 0x24, 0x25, 0x25, 0x26, 0x26, 0x27, 0x27,
    0x28, 0x28, 0x29, 0x29, 0x2A, 0x2A, 0x2B, 0x2B,
    0x2C, 0x2C, 0x2D, 0x2D, 0x2E, 0x2E, 0x2F, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};

static uint8_t d_len[256] = {
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
};

typedef struct lh1_state {
    uint8_t     text_buf[N + F - 1];
    uint16_t    freq[T + 1];	/* cumulative freq table */
    /*
    * pointing parent nodes.
    * area [T..(T + N_CHAR - 1)] are pointers for leaves
    */
    int         prnt[T + N_CHAR];

    /* pointing children nodes (son[], son[] + 1)*/
    int16_t     son[T];

    uint16_t    getbuf;
    uint8_t     getlen;

    img_fns     *cb;            /* Image access functions */
    img_file    imgf;           /* Image file handle */

    uint8_t     *in_buf;        /* Compressed data buffer. */
    long        in_buf_sz;      /* Size of compressed data */
    long        in_pos;         /* Position in compressed stream */

    uint8_t     *out_buf;       /* Output buffer and state. */
    long        out_buf_sz;     /* Output buffer size. */
    long        out_pos;        /* Position in uncompressed buffer. */
} lh1;

/* Read the next byte from buffer */
static int read_byte( lh1 *ds )
{
    if( ds->in_pos < ds->in_buf_sz )
        return( ds->in_buf[ds->in_pos++] );
    else
        return( -1 );
}

/* Output the next decompressed byte */
static void write_byte( lh1 *ds, int c )
{
    if( ds->out_pos < ds->out_buf_sz )
        ds->out_buf[ds->out_pos++] = (uint8_t)c;
}

static int GetBit( lh1 *ds )    /* get one bit */
{
    int16_t     i;

    while( ds->getlen <= 8 ) {
        if( (i = read_byte( ds ) ) < 0 )
            i = 0;
        ds->getbuf |= i << (8 - ds->getlen);
        ds->getlen += 8;
    }
    i = ds->getbuf;
    ds->getbuf <<= 1;
    ds->getlen--;
    return( i < 0 );
}

static int GetByte( lh1 *ds )   /* get a byte */
{
    int i;

    while( ds->getlen <= 8 ) {
        if( (i = read_byte( ds )) < 0 )
            i = 0;
        ds->getbuf |= i << (8 - ds->getlen);
        ds->getlen += 8;
    }
    i = ds->getbuf;
    ds->getbuf <<= 8;
    ds->getlen -= 8;
    return( (uint16_t)i >> 8 );
}

/* initialize freq tree */
static void StartHuff( lh1 *ds )
{
    int i, j;

    for( i = 0; i < N_CHAR; i++ ) {
        ds->freq[i] = 1;
        ds->son[i] = i + T;
        ds->prnt[i + T] = i;
    }
    i = 0; j = N_CHAR;
    while( j <= R ) {
        ds->freq[j] = ds->freq[i] + ds->freq[i + 1];
        ds->son[j] = i;
        ds->prnt[i] = ds->prnt[i + 1] = j;
        i += 2; j++;
    }
    ds->freq[T] = 0xffff;
    ds->prnt[R] = 0;
}


/* reconstruct freq tree */
static void reconst( lh1 *ds )
{
    int         i, j, k;
    uint16_t    f, l;

    /* halven cumulative freq for leaf nodes */
    j = 0;
    for( i = 0; i < T; i++ ) {
        if( ds->son[i] >= T ) {
            ds->freq[j] = (ds->freq[i] + 1) / 2;
            ds->son[j] = ds->son[i];
            j++;
        }
    }
    /* make a tree : first, connect children nodes */
    for( i = 0, j = N_CHAR; j < T; i += 2, j++ ) {
        k = i + 1;
        f = ds->freq[j] = ds->freq[i] + ds->freq[k];
        for( k = j - 1; f < ds->freq[k]; k-- )
            ;
        k++;
        /* freq and son must have the same type size */
        l = (j - k) * sizeof( ds->freq[0] );

        memmove( &ds->freq[k + 1], &ds->freq[k], l );
        ds->freq[k] = f;
        memmove( &ds->son[k + 1], &ds->son[k], l );
        ds->son[k] = i;
    }
    /* connect parent nodes */
    for( i = 0; i < T; i++ ) {
        if( (k = ds->son[i]) >= T ) {
            ds->prnt[k] = i;
        } else {
            ds->prnt[k] = ds->prnt[k + 1] = i;
        }
    }
}


/* update freq tree */
static void update( lh1 *ds, int c )
{
    int i, j, k, l;

    if( ds->freq[R] == MAX_FREQ ) {
        reconst( ds );
    }
    c = ds->prnt[c + T];
    do {
        k = ++ds->freq[c];

        /* swap nodes to keep the tree freq-ordered */
        if( k > ds->freq[l = c + 1] ) {
            while( k > ds->freq[++l] )
                ;
            l--;
            ds->freq[c] = ds->freq[l];
            ds->freq[l] = k;

            i = ds->son[c];
            ds->prnt[i] = l;
            if( i < T )
                ds->prnt[i + 1] = l;

            j = ds->son[l];
            ds->son[l] = i;

            ds->prnt[j] = c;
            if( j < T )
                ds->prnt[j + 1] = c;
            ds->son[c] = j;

            c = l;
        }
    } while( (c = ds->prnt[c]) != 0 );  /* repeat until root is reached */
}

static int DecodeChar( lh1 *ds )
{
    unsigned c;

    c = ds->son[R];

    /*
     * start searching tree from the root to leaves.
     * choose node #(son[]) if input bit == 0
     * else choose #(son[]+1) (input bit == 1)
     */
    while( c < T ) {
        c += GetBit( ds );
        c = ds->son[c];
    }
    c -= T;
    update( ds, c );
    return( c );
}

static int DecodePosition( lh1 *ds )
{
    unsigned    i, j, c;

    /* decode upper 6 bits from given table */
    i = GetByte( ds );
    c = (uint16_t)d_code[i] << 6;
    j = d_len[i];

    /* input lower 6 bits directly */
    j -= 2;
    while( j-- ) {
        i = (i << 1) + GetBit( ds );
    }
    return( c | i & 0x3f );
}

static long Decode( lh1 *ds )   /* Decoding/Uncompressing */
{
    int             i, j, k, r, c;
    long            count;

    StartHuff( ds );

    /* Pre-initialize text buffer. This is where SXD differs from
     * the -lh1- decompressor; while -lh1- fills the buffer with spaces
     * (optimized for text), SXD fills it with zeros.
     */
    for( i = 0; i < N - F; i++ )
        ds->text_buf[i] = 0;

    r = N - F;
    for( count = 0; count < ds->out_buf_sz; ) {
        c = DecodeChar( ds );
        if( c < 256 ) {
            write_byte( ds, c );
            ds->text_buf[r++] = c;
            r &= (N - 1);
            count++;
        } else {
            i = (r - DecodePosition( ds ) - 1) & (N - 1);
            j = c - 255 + THRESHOLD;
            for( k = 0; k < j; k++ ) {
                c = ds->text_buf[(i + k) & (N - 1)];
                write_byte( ds, c );
                ds->text_buf[r++] = c;
                r &= (N - 1);
                count++;
            }
        }
    }
    return( count );
}

/*
 * Uncompress a block of given size into the supplied output buffer
 * NB: In the DXP format, we know both the compressed and uncompressed
 * block (track) size. If decompression is successful, the uncompressed
 * buffer should be fully filled and the compressed data fully consumed
 */
long sxd_unpack_lzhuf( img_fns *cb, img_file imgf, uint8_t *src, long comp_sz, uint8_t *dst, long buf_sz )
{
    long    unp_sz;
    lh1     decomp;

    /* Set up decompression context */
    memset( &decomp, 0, sizeof( decomp ) );
    decomp.cb         = cb;
    decomp.imgf       = imgf;

    decomp.in_buf     = src;
    decomp.in_buf_sz  = comp_sz;
    decomp.in_pos     = 0;

    decomp.out_buf    = dst;
    decomp.out_buf_sz = buf_sz;
    decomp.out_pos    = 0;

    unp_sz = Decode( &decomp );

    /* Return the unpacked size */
    return( unp_sz );
}
