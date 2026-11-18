/*
 * LZW Compression based on public domain code
 * from https://github.com/vapier/liblzw
 *
 * Further refactored and improved for fdimg, and much simplified
 * to only handle the most basic LZW algorithm used by TeleDisk.
 */

/* TeleDisk 1.05 manual states:
 *
 * "If advanced data compression was used to produce this [image] file, the
 * information appears in 6,144 byte blocks of 12 bit Lempel-Ziv code. Each
 * block is preceded by a 2 byte CRC and a 2 byte code packet count
 * (one packet = 12 bits)."
 *
 * That description is a lie, but not quite. Compressed blocks have no CRC,
 * although they arguably don't need it because the decompressed data includes
 * CRCs. The 2 byte "packet count" is for some reason stored in terms of
 * nibbles (4 bits), not 12-bit packets.
 *
 * As a consequence, all compressed blocks except for the last one start with
 * two bytes 0x00 0x30, indicating that 6,144 bytes (6K) of compressed data
 * follow. Note that we know the size of each compressed block, but we have no
 * idea what the decompressed size might be.
 *
 * TeleDisk LZW is fairly basic, closely following Welch's 1984 article.
 * Code size is fixed at 12 bits. No reset is performed when the dictionary
 * is full--the compressor simply stops outputting new codes.
 *
 * We assume that the compressed block will be no larger than 6,144 bytes.
 * With that constraint in place, the number of bits in a compressed block
 * fits into a 16-bit unsigned integer.
 */

#include <inttypes.h>
#include <string.h>

#include "img_defs.h"
#include "img_help.h"
#include "td_lzw.h"


#if 0
    #define dprintf( ... )      printf( __VA_ARGS__ )
#else
    #define dprintf( ... )
#endif


#define HBITS   17          /* 50% occupancy */
#define HSIZE   (1<<HBITS)
#define HMASK   (HSIZE-1)
#define HPRIME  9941

typedef struct {
    img_file    imgf;
    int         eof;

    uint8_t     *inbuf, *outbuf, *stackp;
    uint8_t     *unreadbuf;
    size_t      stackp_diff;
    uint16_t    inbytes;                /* Number of bytes in input block. */
    size_t      outpos;

    int maxbits;

    unsigned long int htab[HSIZE];
    unsigned short codetab[HSIZE];

    uint16_t    inbits;                 /* Number of bits in input block. */
    uint16_t    posbits;                /* Bit position in input buffer. */
    int n_bits, bitmask, finchar;
    long int maxcode, oldcode, incode, code, free_ent;
} lzwFile;

/*
 * Misc common define cruft.
 */
#define BUFSIZE      4
#define OUT_BUFSIZE  (BUFSIZE + 2048)
#define BITS         16
#define INIT_BITS    12			/* initial number of bits/code */
#define MAX_BITS     12                 /* max number of bits/code */
#define MAXCODE(n)   (1L << (n))
#define FIRST        257		/* first free entry */
#define CLEAR        256		/* table clear output code */


/*
 * Open LZW file.
 */
lzwFile *lzw_init( img_fns *cb, img_file imgf )
{
    lzwFile     *ret;
    uint8_t     buf[2];
    unsigned    nibbles;
    long        rsize;

    /* Read the compressed block size. */
    if( cb->read( imgf, buf, 2 ) != 2 )
        return( NULL );

    nibbles = buf[1] * 256 + buf[0];
    dprintf( "Compressed block contains %d nibbles (%d bytes)\n", nibbles, (nibbles + 1) / 2 );

    if( (ret = cb->m_alloc_z( sizeof( *ret ) ) ) == NULL )
        goto err_out;

    ret->imgf    = imgf;
    ret->eof     = 0;
    ret->inbytes = (nibbles + 1) / 2;
    ret->inbits  = nibbles * 4;
    ret->inbuf   = cb->m_alloc( ret->inbytes );
    ret->outbuf  = cb->m_alloc( sizeof( uint8_t ) * OUT_BUFSIZE );
    ret->stackp  = NULL;
    ret->outpos  = 0;

    /* Attempt to read the entire compressed block. */
    rsize = cb->read( ret->imgf, ret->inbuf, ret->inbytes );
    if( rsize != ret->inbytes )
        goto err_out;

    ret->maxbits = MAX_BITS;

    ret->n_bits = INIT_BITS;
    ret->maxcode = MAXCODE(INIT_BITS) - 1;
    ret->bitmask = (1 << INIT_BITS) - 1;
    ret->oldcode = -1;
    ret->finchar = 0;
    ret->posbits = 0;
    ret->free_ent = 256;

    /* initialize the first 256 entries in the table */
    for( ret->code = 255; ret->code >= 0; --ret->code )
        ret->htab[ret->code] = ret->code;

    if( ret->inbuf == NULL || ret->outbuf == NULL ) {
        goto err_out_free;
    }
    if( ret->maxbits > BITS ) {
        goto err_out_free;
    }

    return( ret );

err_out_free:
    if( ret->inbuf )
        cb->m_free( ret->inbuf );
    if( ret->outbuf )
        cb->m_free( ret->outbuf );
    cb->m_free( ret );

err_out:
    return( NULL );
}

void lzw_free( img_fns *cb, lzwFile *lzw )
{
    if( lzw->inbuf )
        cb->m_free( lzw->inbuf );
    if( lzw->outbuf )
        cb->m_free( lzw->outbuf );
    cb->m_free( lzw );
}

/*
 * Misc read-specific define cruft.
 */

#define input( b, o, c, n, m ) \
    do { \
        uint8_t *p = &(b)[(o) / 8]; \
        (c) = ((((long)(p[0]))|((long)(p[1]) << 8)| \
               ((long)(p[2]) << 16)) >> ((o) & 0x7)) & (m); \
        (o) += (n); \
    } while( 0 )

#define de_stack    ((uint8_t *)&(lzw->htab[HSIZE-1]))


/*
 * Read LZW-compressed file.
 * Returns the number of decompressed bytes, or -1 on error.
 */
long lzw_read( img_fns *cb, lzwFile *lzw, uint8_t *readbuf, size_t count )
{
    size_t  count_left = count;
    uint8_t *inbuf  = lzw->inbuf;
    uint8_t *outbuf = lzw->outbuf;

    long int maxmaxcode = MAXCODE( lzw->maxbits );

    if( !count || lzw->eof )
        return( 0 );

    while( lzw->inbits > lzw->posbits ) {

        input( inbuf, lzw->posbits, lzw->code, lzw->n_bits, lzw->bitmask );
        dprintf( "code: %d posbits: %ld inbits: %ld\n", lzw->code, lzw->posbits, lzw->inbits );

        if( lzw->oldcode == -1 ) {
            if( lzw->code >= 256 ) {
                dprintf( "Returned due to bad initial code.\n" );
                return( -1 );   /* Invalid compressed data. */
            }
            outbuf[lzw->outpos++] = lzw->finchar = lzw->oldcode = lzw->code;
            continue;
        }


        lzw->incode = lzw->code;
        lzw->stackp = de_stack;

        /* Special case for KwKwK string.*/
        if( lzw->code >= lzw->free_ent ) {
            if( lzw->code > lzw->free_ent ) {
                dprintf( "Returned due to bad KwKwK case.\n" );
                return( -1 ); /* Invalid compressed data. */
            }

            *--lzw->stackp = lzw->finchar;
            lzw->code = lzw->oldcode;
        }

        /* Generate output characters in reverse order */
        while( lzw->code >= 256 ) {
            *--lzw->stackp = lzw->htab[lzw->code];
            lzw->code = lzw->codetab[lzw->code];
        }

        *--lzw->stackp = (lzw->finchar = lzw->htab[lzw->code]);

        /* And put them out in forward order */
        {
            lzw->stackp_diff = de_stack - lzw->stackp;

            if( lzw->outpos + lzw->stackp_diff >= BUFSIZE ) {
                do {
                    if( lzw->stackp_diff > BUFSIZE - lzw->outpos )
                        lzw->stackp_diff = BUFSIZE - lzw->outpos;

                    if( lzw->stackp_diff > 0 ) {
                        memcpy( outbuf + lzw->outpos, lzw->stackp, lzw->stackp_diff );
                        lzw->outpos += lzw->stackp_diff;
                    }

                    if( lzw->outpos >= BUFSIZE ) {
                        if( lzw->outpos < count_left ) {
                            memcpy( readbuf, outbuf, lzw->outpos );
                            readbuf += lzw->outpos;
                            count_left -= lzw->outpos;
                        } else {
empty_existing_buffer:
                            lzw->outpos -= count_left;
                            memcpy( readbuf, outbuf, count_left );
                            lzw->unreadbuf = outbuf + count_left;
                            dprintf( "Returned due to full output buffer\n" );
                            return( count );
                        }
                        lzw->outpos = 0;
                    }
                    lzw->stackp += lzw->stackp_diff;
                } while( (lzw->stackp_diff = (de_stack - lzw->stackp)) > 0 );
            } else {
                memcpy( outbuf + lzw->outpos, lzw->stackp, lzw->stackp_diff );
                lzw->outpos += lzw->stackp_diff;
            }
        }

        /* Generate the new entry. */
        if( (lzw->code = lzw->free_ent) < maxmaxcode ) {
            lzw->codetab[lzw->code] = lzw->oldcode;
            lzw->htab[lzw->code] = lzw->finchar;
            lzw->free_ent = lzw->code + 1;
        }

        lzw->oldcode = lzw->incode;	/* Remember previous code. */
    }

    if( lzw->outpos < count_left ) {
        lzw->eof = 1;
        memcpy( readbuf, outbuf, lzw->outpos );
        count_left -= lzw->outpos;
        dprintf( "Decompressed %ld bytes.\n", count - count_left );
        return( count - count_left );
    } else {
        goto empty_existing_buffer;
    }
}

// Repeatedly uncompress a block into the supplied output buffer
long td_unpack_lzw( img_fns *cb, img_file imgf, uint8_t* dst, long buf_sz )
{
    long    unp_sz = 0;
    long    dst_sz = buf_sz;
    long    blk_unp_sz;
    lzwFile *lzf;

    for( ;; ) {
        lzf = lzw_init( cb, imgf );
        if( !lzf )
            break;
        blk_unp_sz = lzw_read( cb, lzf, dst, dst_sz );
        lzw_free( cb, lzf );
        if( blk_unp_sz > 0 ) {
            dst    += blk_unp_sz;
            unp_sz += blk_unp_sz;
            dst_sz -= blk_unp_sz;
        } else
            break;
    };

    // Return the unpacked size
    return( unp_sz );
}
