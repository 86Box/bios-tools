/*****************************************************************************

Copyright (c) 2013-2026  Michal Necasek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*****************************************************************************/

#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>

#include "img_defs.h"
#include "img_help.h"
#include "img_qrst.h"


/* The Quick Release Sector Transfer (QRST) format was developed by Compaq
 * in the early 1990s. There are two substantially different variants, the
 * original version and version 5 (further referred to as V5).
 *
 * QRST V5 contains a disk image compressed with the PKWARE Data Compression
 * Library. It is currently not supported.
 *
 * QRST pre-V5 contains a collection of tracks. Each track may be compressed,
 * empty, or uncompressed. Fairly simple run-length encoding is used for the
 * compressed tracks.
 *
 * Only standard DOS disk formats are supported (including 160K/180K/320K
 * disks). Any non-standard disks cannot be represented, and custom physical
 * sector ordering likewise cannot be represented.
 *
 * The image header has space for relatively long fixed-length description
 * (96 bytes) and a separate disk label (720 bytes).
 *
 * Reference:
 * http://fileformats.archiveteam.org/wiki/Quick_Release_Sector_Transfer
 *
 */

/* Maximum supported cylinders. */
#define NCYL_MAX    80

/* QRST signature. */
#define QRST_SIG    "QRST"

/* QRST image header. */
typedef struct qrst_hdr {
    char        signature[4];           /* 'QRST' signature. */
    uint32_t    version;                /* Version number. */
    uint32_t    cksum;                  /* Version < V5 only. */
    uint8_t     disk_fmt;               /* Image format specifier. */
    uint8_t     vol_set;                /* Volume in set. */
    uint8_t     set_cnt;                /* Number of volumes in set. */
    char        desc[60];               /* Disk description. */
    char        label[720];             /* Disk label. */
    uint8_t     type;                   /* Contains 2 for V5, 0 for < V5. */
} qrst_hdr;

/* QRST track header. */
typedef struct qrst_trk_hdr {
    uint8_t     cyl;                    /* Cylinder number. */
    uint8_t     head;                   /* Head number. */
    uint8_t     type;                   /* Track type. */
} qrst_trk_hdr;

/* Track types. */
#define TRK_NORMAL      0               /* Regular uncompressed track. */
#define TRK_BLANK       1               /* Blank track (with filler). */
#define TRK_CMPRSD      2               /* RLE compressed track. */
#define TRK_TYP_LAST    TRK_CMPRSD

typedef struct qrst_ctx {
    img_file    imgf;                   /* Image file handle. */
    uint8_t     trks;                   /* Number of tracks (heads * cyls). */
    uint8_t     cyls;                   /* Number of cylinders. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     spt;                    /* Sectors per track. */
    qrst_hdr    hdr;                    /* The image header. */
    long        trk_ofs[NCYL_MAX * 2];  /* Track starting offsets. */
    unsigned    track_len;              /* Length of single track in bytes. */
    int         trk_in_buf;             /* Track currently in buffer. */
    uint8_t     *track_buf;             /* Track buffer (uncompressed). */
    char        *comment;               /* Optional comment. */
} qrst_ctx;

/* Disk format descriptor. */
typedef struct qrst_dsktyp {
    uint8_t     num_cyl;                /* Number of cylinders. */
    uint8_t     num_heads;              /* Number of heads/sides. */
    uint8_t     num_spt;                /* Number of sectors per track. */
} qrst_dsktyp;

/* Disk types supported by QRST. */
static qrst_dsktyp  dsk_desc[] = {
    { 0,  0,  0 },                      /* Type 0 - unknown. */
    { 40, 2,  9 },                      /* Type 1 - 360K. */
    { 80, 2, 15 },                      /* Type 2 - 1.2M. */
    { 80, 2,  9 },                      /* Type 3 - 720K. */
    { 80, 2, 18 },                      /* Type 4 - 1.44M. */
    { 40, 1,  8 },                      /* Type 5 - 160K. */
    { 40, 1,  9 },                      /* Type 6 - 320K. */
    { 40, 2,  8 }                       /* Type 7 - 160K. */
};


/* Identify a QRST format image. Does not validate image. */
int qrst_identify( img_fns *cb, img_file img )
{
    qrst_hdr    hdr;
    int         rc;

    /* Read the header and check signature. */
    cb->seek( img, 0 );
    rc = cb->read( img, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( 0 );

    if( memcmp( hdr.signature, QRST_SIG, sizeof( hdr.signature ) ) )
        return( 0 );

    /* Signature matches, we're going to say it's a QRST image... */
    return( sizeof( qrst_ctx ) );
}

/* Open an image for access. May fail if image is damaged or unsupported. */
int qrst_open( img_fns *cb, img_file img, qrst_ctx *ctx )
{
    int             rc;
    qrst_hdr        hdr;
    qrst_trk_hdr    trk_hdr;
    uint16_t        blk_len;
    int             trk;
    int             trk_idx;
    long            cur_ofs = 0;

    /* Read the image format header. We already ensured it's ours
     * but must check if it's valid and supported.
     */
    cb->seek( img, 0 );
    rc = cb->read( img, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( IMG_ERR_READ );

    /* V5 format not supported. */
    if( hdr.type )
        return( IMG_ERR_UNK_IMG );

    /* Check the disk format kind. */
    if( !hdr.disk_fmt )
        return( IMG_ERR_BAD_IMG );

    if( hdr.disk_fmt > sizeof( dsk_desc ) / sizeof( dsk_desc[0] ) )
        return( IMG_ERR_BAD_IMG );

    /* Figure out the format. */
    ctx->heads = dsk_desc[hdr.disk_fmt].num_heads;
    ctx->cyls  = dsk_desc[hdr.disk_fmt].num_cyl;
    ctx->trks  = ctx->cyls * ctx->heads;
    ctx->spt   = dsk_desc[hdr.disk_fmt].num_spt;

    /* Allocate a buffer for uncompressed track data. */
    ctx->track_len = ctx->spt * IMG_SEC_SZ_DEF;
    ctx->track_buf = cb->m_alloc( ctx->track_len );
    if( !ctx->track_buf )
        return( IMG_ERR_MEM_ALLOC );

    cur_ofs += sizeof( hdr );

    /* Copy the header to the context structure. */
    ctx->hdr = hdr;

    /* Build a table of file offsets of each track in image. The assumption
     * is that all tracks will be accounted for in the image.
     */
    for( trk = 0; trk < ctx->trks; ++trk ) {
        /* Read and validate the track header. */
        rc = cb->read( img, &trk_hdr, sizeof( trk_hdr ) );
        if( rc != sizeof( trk_hdr ) )
            return( IMG_ERR_READ );

        if( trk_hdr.cyl > ctx->cyls )
            return( IMG_ERR_BAD_IMG );

        if( trk_hdr.head > ctx->heads )
            return( IMG_ERR_BAD_IMG );

        if( trk_hdr.type > TRK_TYP_LAST )
            return( IMG_ERR_BAD_IMG );

        /* Now that we decided the track header is valid, deal with it. */
        trk_idx = trk_hdr.cyl * ctx->heads + trk_hdr.head;

        /* Make sure the track is not a duplicate. */
        if( ctx->trk_ofs[trk_idx] )
            return( IMG_ERR_BAD_IMG );

        ctx->trk_ofs[trk_idx] = cur_ofs;
        cur_ofs += sizeof( trk_hdr );

        switch( trk_hdr.type ) {
        case TRK_NORMAL:
            cur_ofs += ctx->track_len;      /* Skip track data. */
            break;
        case TRK_BLANK:
            cur_ofs += sizeof( uint8_t );   /* Skip filler byte. */
            break;
        case TRK_CMPRSD:
            rc = cb->read( img, &blk_len, sizeof( blk_len ) );
            if( rc != sizeof( blk_len ) )
                return( IMG_ERR_READ );
            cur_ofs += sizeof( blk_len );   /* Skip length field. */
            cur_ofs += blk_len;             /* Skip track data. */
            break;
        default:
            return( IMG_ERR_BAD_IMG );  /* Can't really get here. */
        }

        cb->seek( img, cur_ofs );
    }

    /* NB: At this point, we know we read as many tracks as we expected
     * to see. The file size check makes sure there's nothing left over.
     * Except sometimes there are "laser label" images glued to other
     * disks, and we currently ignore those.
     */
    if( cb->fsize( img ) < cur_ofs )
        return( IMG_ERR_BAD_IMG );

    /* Fill out the rest of the context structure. */
    ctx->imgf       = img;
    ctx->comment    = ctx->hdr.desc;
    ctx->trk_in_buf = -1;               /* Nothing buffered. */
    return( IMG_OK );
}

/* Decompress a single track. */
int qrst_decomp_trk( img_fns *cb, qrst_ctx *ctx, uint8_t *buffer )
{
    qrst_trk_hdr    trk_hdr;
    int             rc = 0;
    int             nb;
    int             lit_run = 1;
    uint8_t         *cbuf = NULL;
    uint16_t        comp_len;
    uint8_t         *s;
    uint8_t         *d;
    uint8_t         pat;
    uint8_t         rep;

    do {
        /* Read the track header. */
        nb = cb->read( ctx->imgf, &trk_hdr, sizeof( trk_hdr ) );
        if( nb != sizeof( trk_hdr ) ) {
            rc = IMG_ERR_READ;
            break;
        }

        /* Handle the different track types. */
        if( trk_hdr.type == TRK_NORMAL ) {
            /* Read the entire track. */
            nb = cb->read( ctx->imgf, buffer, ctx->track_len );
            if( nb != ctx->track_len ) {
                rc = IMG_ERR_READ;
                break;
            }
            rc = nb;
        } else if( trk_hdr.type == TRK_BLANK ) {
            /* Read the filler byte. */
            nb = cb->read( ctx->imgf, &pat, sizeof( pat ) );
            if( nb != sizeof( pat ) ) {
                rc = IMG_ERR_READ;
                break;
            }
            memset( buffer, pat, ctx->track_len );
            rc = ctx->track_len;
        } else {
            assert( trk_hdr.type == TRK_CMPRSD );
            /* Read the compressed data size. */
            nb = cb->read( ctx->imgf, &comp_len, sizeof( comp_len ) );
            if( nb != sizeof( comp_len ) ) {
                rc = IMG_ERR_READ;
                break;
            }

            /* Allocate and read the compressed data. */
            cbuf = cb->m_alloc( comp_len );
            if( !cbuf ) {
                rc = IMG_ERR_MEM_ALLOC;
                break;
            }
            nb = cb->read( ctx->imgf, cbuf, comp_len );
            if( nb != comp_len ) {
                rc = IMG_ERR_READ;
                break;
            }

            /* And now decompress the data. */
            s = cbuf;
            d = buffer;
            while( s < cbuf + comp_len ) {
                rep = *s++;     /* Read repeat count. */
                if( lit_run ) {
                    memcpy( d, s, rep );
                    s += rep;
                } else {
                    pat = *s++;     /* Read pattern byte. */
                    memset( d, pat, rep );
                }
                d += rep;
                lit_run ^= 1;
            }
            /* Calculate the size of decompresed data. */
            rc = d - buffer;
        }
    } while( 0 );

    if( cbuf )
        cb->m_free( cbuf );
    return( rc );
}

/* Read and decompress a specified track. */
int qrst_read_track( img_fns *cb, qrst_ctx *ctx, int track_num )
{
    unsigned    rc;

    /* Read and decompress track. */
    cb->seek( ctx->imgf, ctx->trk_ofs[track_num] );
    rc = qrst_decomp_trk( cb, ctx, ctx->track_buf );
    /* If decompression succeeded but didn't return the expected
     * amount of data, the input data was probably corrupted.
     */
    if( rc > 0 && rc != ctx->track_len )
        rc = IMG_ERR_DECODE;

    ctx->trk_in_buf = track_num;
    return( rc );
}

/* Query the comment string. Returns NULL if no comment provided. */
const char *qrst_query_comment( img_fns *cb, qrst_ctx *ctx )
{
    return( ctx->comment );
}

/* Read a single sector from the image. */
int qrst_read_sect( img_fns *cb, qrst_ctx *ctx, int sect_num, void *buf )
{
    long        sec_ofs;
    int         track_num;
    int         rc;

    /* Check if we're within the image. */
    track_num = sect_num / ctx->spt;
    if( track_num >= ctx->trks )
        return( IMG_ERR_NO_SECT );

    /* Read and decompress a track unless it's already buffered.
     * Works very well for sequential access.
     */
    if( ctx->trk_in_buf != track_num ) {
        rc = qrst_read_track( cb, ctx, track_num );
        if( rc < 0 )
            return( rc );
        assert( rc == ctx->track_len );
    }

    /* Calculate the sector offset in track buffer. */
    sec_ofs = sect_num % ctx->spt * IMG_SEC_SZ_DEF;
    assert( sec_ofs + IMG_SEC_SZ_DEF <= ctx->track_len );
    memcpy( buf, ctx->track_buf + sec_ofs, IMG_SEC_SZ_DEF );

    return( IMG_SEC_SZ_DEF );
}

/* Close an image once all accesses are completed. */
void qrst_close( img_fns *cb, qrst_ctx *ctx )
{
    assert( ctx );
    assert( ctx->track_buf );
    cb->m_free( ctx->track_buf );
}
