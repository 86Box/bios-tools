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
#include "img_cqm.h"


/*
 * CopyQM format images are written by the eponymous utility created by Sydex
 * sometime in the late 1980s or early 1990s. The CopyQM format is distinctly
 * different from Sydex's other format, TeleDisk. While TeleDisk was intended
 * to preserve about as much information as one could obtain from the standard
 * PC floppy controller, CopyQM was designed for mass duplicating standard DOS
 * and Mac HFS floppies, and was later also used for distributing driver disks
 * as self-extracting CopyQM images.
 *
 * CopyQM has two basic modes of operation when creating floppy images. The
 * default mode is meant for standard FAT-formatted floppies; only cylinders
 * that contain files as indicated by the FAT are captured. The 'blind' mode
 * does not analyze the disk contents and captures the entire disk.
 *
 * For FAT-formatted disks, CopyQM has the ability to adapt the source image
 * to a different floppy format (within reason). To that end, the CopyQM
 * header includes a facsimile of the disk's BPB, which can be used to morph
 * the disk format (and decide if that's even possible).
 *
 * The CopyQM format can only represent disks with uniform sector size and
 * constant number of sectors per track. It can at least theoretically be used
 * with sector sizes other than 512 bytes.
 *
 * Cylinders not stored in the image are normally formatted and not written,
 * although CopyQM has the option to skip them entirely.
 *
 * In version 3.1, CopyQM added the ability to record interleave and skew
 * factors (globally), presumably as part of Microsoft DMF support. There is
 * also a provision for logical sector numbers not starting with 1.
 *
 * The disk data uses a simple run-length encoding (RLE) with a 16-bit length.
 * Only runs of 4 or more bytes can thus be compressed.
 *
 * Tracks are stored separately, i.e. compressed or uncompressed data never
 * crosses a track boundary. However, data blocks in image may and often do
 * cross a sector boundary.
 *
 * The CopyQM header is protected by a simple checksum. The disk data has
 * a separately calculated 32-bit CRC using a somewhat odd algorithm.
 *
 * The header is followed by optional comment; 16-bit length of the comment
 * is stored in the header. Unregistered shareware versions of CopyQM put the
 * string "Image file created by unregistered CopyQM" there.
 *
 * This implementation was initially based on a document called cqm-format.pdf
 * which itself used libdsk as its foundation.
 */


/* Somewhat arbitrary, but a regular drive shouldn't be able to do more. */
#define NTRK_MAX     84

/* Arbitrarily chosen; should never be more than 36 in practice. */
#define SPT_MAX      64


/* Format constants. */
#define CQM_SIG      "CQ\x14"    /* CopyQM header signature. */
#define CQM_SIG_LEN  3           /* Signature length. */


/* CopyQM image header. */
#pragma pack(1)
typedef struct cqm_hdr_s {
    char        signature[3];   /* 'CQ' signature. */
                                /* BPB subset starts here; only some */
                                /* of these are used in blind mode.  */
    uint16_t    sec_sz;         /* Sector size in bytes. */
    uint8_t     sec_per_clust;  /* Sectors per cluster. */
    uint16_t    resvd_sec;      /* Reserved sectors, usually 1 or more. */
    uint8_t     n_fats;         /* Number of FATs, usually 2. */
    uint16_t    root_dir_ents;  /* Number of root directory entries. */
    uint16_t    total_secs;     /* 16-bit number of sectors. */
    uint8_t     media_id;       /* Media descriptor byte. */
    uint16_t    n_fat_sec;      /* Number of sectors per FAT. */
    uint16_t    n_trk_sec;      /* Number of sectors per track. */
    uint16_t    n_heads;        /* Number of heads (1 or 2 valid). */
    uint32_t    n_hidden_secs;  /* Number of hidden sectors (should be 0). */
    uint32_t    big_total_secs; /* 32-bit number of sectors (should be 0). */
                                /* BPB subset ends here. */
    char        desc[60];       /* Disk format description, null-padded. */
    uint8_t     blind;          /* Blind mode flag. */
    uint8_t     density;        /* Density code. */
    uint8_t     n_cyl_img;      /* Number of cylinders in image. */
    uint8_t     n_cyl_dsk;      /* Number of cylinders on disk. */
    uint32_t    crc;            /* Disk data CRC. */
    char        label[11];      /* FAT volume label. */
    uint16_t    dos_time;       /* Image timestamp in DOS format. */
    uint16_t    dos_date;       /* Image date in DOS format. */
    uint16_t    comment_len;    /* Length of optional comment. */
    uint8_t     sec_base;       /* One less than starting sector number. */
    uint16_t    unknown;        /* Unknown purpose. */
    uint8_t     interleave;     /* Interleave factor. */
    uint8_t     skew;           /* Track skew. */
    uint8_t     src_drive;      /* Source drive type. */
    uint8_t     unused[13];     /* Likely not used. */
    uint8_t     hdr_csum;       /* Header checksum. */
} cqm_hdr;
#pragma pack()


/* Context structure for CopyQM format. */
typedef struct cqm_ctx {
    img_file    imgf;                   /* Image file handle. */
    uint8_t     cyls_dsk;               /* Number of cylinders on disk. */
    uint8_t     cyls_img;               /* Number of cylinders in image. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     first_id;               /* First sector ID (typically 1). */
    int         sec_sz;                 /* Sector size in bytes. */
    char        *comment;               /* Optional comment. */
    unsigned    track_len;              /* Length of single track in bytes. */
    int         trk_in_buf;             /* Track currently in buffer. */
    uint8_t     *track_buf;             /* Track buffer (uncompressed). */
    long        trk_ofs[NTRK_MAX * 2];  /* Track starting offsets. */
} cqm_ctx;


/* Identify a CopyQM format image. Does not validate image. */
int cqm_identify( img_fns *cb, img_file imgf )
{
    cqm_hdr     hdr;
    int         rc;
    int         i;
    uint8_t     sum;
    uint8_t     *hdr_bytes = (uint8_t *)&hdr;

    /* Read the image header and see if signature is there. */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* Fail if signature isn't what we expect. */
    if( memcmp( hdr.signature, CQM_SIG, CQM_SIG_LEN ) )
        return( 0 );

    /* Calculate header checksum and fail if it doesn't add up. */
    for( i = 0, sum = 0; i < sizeof( hdr ); ++i )
       sum += hdr_bytes[i];

    if( sum )
       return( 0 );

    /* This sure looks like a CopyQM image. */
    return( sizeof( cqm_ctx ) );
}


/* Read the data for a single track from image, decompress as needed. */
int cqm_decomp_trk( img_fns *cb, cqm_ctx *ctx, uint8_t *buf, long data_ofs )
{
    uint8_t     repb;
    int16_t     rep_cnt;
    int         rc;
    unsigned    bytes_read;
    unsigned    bytes_written;

    cb->seek( ctx->imgf, data_ofs );
    bytes_written = 0;
    bytes_read    = 0;

    do {
        rc = cb->read( ctx->imgf, &rep_cnt, sizeof( rep_cnt ) );
        if( rc != sizeof( rep_cnt ) )
            return( false );
        bytes_read += rc;

        /* If the repeat count is positive, it indicates the number
         * of uncompressed bytes following it. If it is negative, then
         * it represents the number of times the following byte repeats.
         * A zero count is not valid.
         */
        if( rep_cnt > 0 ) {
            /* Uncompressed object data. */
            if( rep_cnt > ctx->track_len )
                return( false );

            rc = cb->read( ctx->imgf, &buf[bytes_written], rep_cnt );
            if( rc != rep_cnt )
                return( false );
            bytes_written += rc;
            bytes_read += rc;
        } else if( rep_cnt < 0 ) {
            rep_cnt = -rep_cnt;
            rc = cb->read( ctx->imgf, &repb, sizeof( repb ) );
            if( rc != sizeof( repb ) )
                return( false );
            if( rep_cnt > ctx->track_len )
                return( 0 );
            memset( &buf[bytes_written], repb, rep_cnt );
            bytes_written += rep_cnt;
            bytes_read += rc;
        } else {
            /* If this happens, the image is corrupted. */
            assert( rep_cnt == 0 );
            return( 0 );
        }
    } while( bytes_written < ctx->track_len );


    return( bytes_read );
}


/* Sequentially scan the image, building a map of tracks/sectors. */
int cqm_build_map( img_fns *cb, cqm_ctx *ctx, long start_ofs )
{
    long        curr_ofs;
    int         trk_idx;
    int         rc;

    curr_ofs = start_ofs;

    /* Simply go over all the data in the image and see what we got. */
    for( trk_idx = 0; trk_idx < ctx->cyls_img * ctx->heads ; ++trk_idx ) {

        ctx->trk_ofs[trk_idx] = curr_ofs;
        /* Read/decompress the sector data. */
        rc = cqm_decomp_trk( cb, ctx, ctx->track_buf, curr_ofs );
        if( !rc )
            return( IMG_ERR_DECODE );

        curr_ofs += rc;
    }

    return( 0 );
}


/* Open an image for access. */
int cqm_open( img_fns *cb, img_file imgf, cqm_ctx *ctx )
{
    int         rc;
    cqm_hdr     hdr;

    ctx->imgf = imgf;

    /* Re-read the CopyQM header copy relevant data into the
     * context structure.
     */
    cb->seek( ctx->imgf, 0 );
    rc = cb->read( ctx->imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( IMG_ERR_READ );

    ///@todo: Some validation of the header contents?

    ctx->sec_sz   = hdr.sec_sz;
    ctx->spt      = hdr.n_trk_sec;
    ctx->heads    = hdr.n_heads;
    ctx->cyls_dsk = hdr.n_cyl_dsk;
    ctx->cyls_img = hdr.n_cyl_img;
    ctx->first_id = hdr.sec_base + 1;

    /* Allocate the track buffer. */
    ctx->trk_in_buf = -1;
    ctx->track_len  = ctx->spt * ctx->sec_sz;
    ctx->track_buf  = cb->m_alloc( ctx->track_len );
    if( !ctx->track_buf )
        return( IMG_ERR_MEM_ALLOC );


    /* Read the comment if there is one. The length only covers the
     * text, no null terminator, so we add one.
     */
    if( hdr.comment_len ) {
        uint16_t    cmt_size = hdr.comment_len + 1;

        ctx->comment = cb->m_alloc( cmt_size );
        if( ctx->comment ) {
            /* We'll read one extra byte. */
            rc = cb->read( ctx->imgf, ctx->comment, cmt_size );
            if( rc != cmt_size )
                return( IMG_ERR_READ );

            /* Make sure it's null terminated. */
            ctx->comment[cmt_size - 1] = '\0';
        } else {
            return( IMG_ERR_MEM_ALLOC );
        }
    }

    /* Build a map of all the tracks in the image. Also verify
     * the CRC in the process. If the entire image can be read
     * and decompressed without error and the CRC matches, it is
     * considered good.
     */
    rc = cqm_build_map( cb, ctx, sizeof( cqm_hdr ) + hdr.comment_len );
    if( rc )
        return( rc );

    assert( ctx->spt );
    return( IMG_OK );
}


/* Query the comment string. Returns NULL if no comment provided. */
const char *cqm_query_comment( img_fns *cb, cqm_ctx *ctx )
{
    return( ctx->comment );
}


/* Read and decompress a specified track. */
int cqm_read_track( img_fns *cb, cqm_ctx *ctx, int track_num )
{
    int     rc = IMG_OK;

    if( track_num < ctx->cyls_img * ctx->heads ) {
        /* Read and decompress track. */
        rc = cqm_decomp_trk( cb, ctx, ctx->track_buf, ctx->trk_ofs[track_num] );

        /* Decompression should not fail since the image was already
         * validated. However, the image may no longer be readable etc.
         */
        if( rc < 0 )
            return( rc );
    } else if( track_num < ctx->cyls_dsk * ctx->heads ) {
        /* Track is not in image but was on the disk. Freshly formatted. */
        memset( ctx->track_buf, FMT_BYTE, ctx->track_len );
    } else {
        /* Not supposed to get here. */
        assert( 0 );
        return( IMG_ERR_DECODE );
    }

    ctx->trk_in_buf = track_num;
    return( rc );
}


/* Read a single sector from the image. */
int cqm_read_sect( img_fns *cb, cqm_ctx *ctx, int sect_num, void *buf )
{
    long        sec_ofs;
    int         track_num;
    int         rc;

    /* Check if we're within the image. */
    track_num = sect_num / ctx->spt;
    if( track_num >= ctx->cyls_dsk * ctx->heads )
        return( IMG_ERR_NO_SECT );

    /* Read and decompress a track unless it's already buffered.
     * Works very well for sequential access.
     */
    if( ctx->trk_in_buf != track_num ) {
        rc = cqm_read_track( cb, ctx, track_num );
        if( rc < 0 )
            return( rc );
    }

    /* Calculate the sector offset in track buffer. */
    sec_ofs = sect_num % ctx->spt * ctx->sec_sz;
    assert( sec_ofs + ctx->sec_sz <= ctx->track_len );
    memcpy( buf, ctx->track_buf + sec_ofs, ctx->sec_sz );

    return( ctx->sec_sz );
}


/* Close an image once all accesses are completed. */
void cqm_close( img_fns *cb, cqm_ctx *ctx )
{
    assert( ctx );
    if( ctx->comment )
        cb->m_free( ctx->comment );

    if( ctx->track_buf )
        cb->m_free( ctx->track_buf );
}
