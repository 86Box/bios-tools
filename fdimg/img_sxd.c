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
#include "img_sxd.h"
#include "sxd_lzh.h"


/*
 * The SXD format is used by self-extracting images produced by the Sydex
 * CopyQM Plus utility, either directly or by running the MAKESXD tool on
 * images produced by CopyQM.
 *
 * Even though SXD images are produced by CopyQM, the SXD format is rather
 * different from the CopyQM format. While conceptually similar, the SXD
 * header structure is completely different. The SXD format is also somewhat
 * more restrictive and effectively only supports standard DOS formats with
 * 512-byte sectors. This is likely because the self-extracting stub uses
 * BIOS/OS services rather than programming the floppy controller directly.
 *
 * The SXD self-extracting stub runs on DOS but there are also variants with
 * OS/2 support, using a combined DOS and OS/2 self-extracting stub.
 *
 * The DOS stub indicates where the SXD image data starts. However, the SXD
 * image proper may be preceded by an optional block with a 'WB' signature.
 * If the WB block exists, its length is encoded the same way it is for
 * DOS executables: 'WB' is followed by two 16-bit words, the second word
 * indicating the number of 512-byte blocks and the first word recording the
 * number of bytes used in the last 512-byte block.
 *
 * The actual image starts with an 'SXD' signature which is followed by
 * a fixed format header.
 *
 * The SXD header is followed by optional comment; 16-bit length of the
 * comment is stored in the header.
 *
 * There is also an optional serial number. The serial number mechanism
 * is currently not well understood.
 *
 * It is also possible to password-protect SXD images. A password must pass
 * a CRC check (same as the CRC used to protect data), and must also match
 * a separate checksum which is calculated when generating a 16-bit key. The
 * key is used to descramble sector data as well as the optional comment.
 *
 * Password-protected images are currently not supported.
 *
 * Like CopyQM, SXD by default only stores used cylinders and if a block of
 * unused cylinders exists at the end of a disk, it is skipped.
 *
 * The SXD format works with tracks, not sectors. All tracks are stored
 * consecutively following the header and optional comment. First is
 * a 16-bit CRC of the uncompressed data. This is followed by a 16-bit
 * length of the following compressed data.
 *
 * If the length is positive, track data is stored in the same simple
 * format with RLE compression that CopyQM uses. If the length is negative,
 * its absolute value indicates the length of compressed data, and the track
 * is compressed using a slightly modified LZHUF algorithm.
 *
 * This implementation is based on reverse-engineering the SXD self-extracting
 * stub program.
 */


/* Somewhat arbitrary, but a regular drive shouldn't be able to do more. */
#define NTRK_MAX     84

/* Arbitrarily chosen; should never be more than 36 in practice. */
#define SPT_MAX      64


/* Format constants. */
#define SXD_SIG      "SXD"       /* SXD header signature. */
#define SXD_SIG_LEN  3           /* Signature length. */
#define WB_SIG       "WB"        /* WB block signature. */
#define WB_SIG_LEN   2           /* WB signature length. */

/* SXD drive types. */
typedef enum {
    SXD_DT_UNUSED,              /* 0 - value not used.  */
    SXD_DT_360K,                /* 1 - 360K 5.25"       */
    SXD_DT_12M,                 /* 2 - 1.2M 5.25"       */
    SXD_DT_720K,                /* 3 - 720K 3.5"        */
    SXD_DT_144M,                /* 4 - 1.44M 3.5"       */
    SXD_DT_8IN,                 /* 5 - 8" drive (!)     */
    SXD_DT_288M                 /* 6 - 2.88M 3.5"       */
} sxd_drv_typ;

/* SXD image header. The header is 33 bytes long, with the first 31
 * bytes protected by a checksum stored in the last two bytes.
 */
#pragma pack(1)
typedef struct sxd_hdr_s {
    char        signature[3];   /* 00: 'SXD' signature. */
    uint16_t    trk_len;        /* 03: Track length in bytes. */
    uint8_t     n_trk_sec;      /* 05: Number of sectors per track. */
    uint8_t     n_heads;        /* 06: Number of heads (1 or 2 valid). */
    uint8_t     n_cyl_dsk;      /* 07: Number of cylinders on disk. */
    uint8_t     n_cyl_img;      /* 08: Number of cylinders in image. */
    uint8_t     first_sid;      /* 09: ID of first sector - 1 (usually 0). */
    uint8_t     interleave;     /* 0A: Interleave factor (usually 1). */
    uint8_t     skew;           /* 0B: Skew factor, probably (usually 0). */
    uint8_t     sec_sz_code;    /* 0C: Sector size code (2 = 512B). */
    uint8_t     drv_typ;        /* 0D: Drive type, range 1-6. */
    uint8_t     density;        /* 0E: Density, 0/1/2 for DD/HD/ED. */
    uint16_t    pwd_crc;        /* 0F: Password CRC. */
    uint16_t    pwd_hash;       /* 11: Password hash. */
    uint16_t    comment_len;    /* 13: Length of optional comment. */
    uint16_t    crc_comment;    /* 15: CRC of the comment. */
    uint8_t     unk0[4];        /* 17: Unknown -- unused? */
    uint16_t    dos_time;       /* 1B: Image timestamp in DOS format. */
    uint16_t    dos_date;       /* 1D: Image date in DOS format. */
    uint16_t    crc_hdr;        /* 1F: CRC of the header. */
} sxd_hdr;
#pragma pack()


/* Context structure for the SXD format. */
typedef struct sxd_ctx {
    img_file    imgf;                   /* Image file handle. */
    uint8_t     cyls_dsk;               /* Number of cylinders on disk. */
    uint8_t     cyls_img;               /* Number of cylinders in image. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    int         sec_sz;                 /* Sector size in bytes. */
    char        *comment;               /* Optional comment. */
    unsigned    track_len;              /* Length of single track in bytes. */
    unsigned    cmpr_track_len;         /* Length of compressed track buffer. */
    int         trk_in_buf;             /* Track currently in buffer. */
    uint8_t     *track_buf;             /* Track buffer (uncompressed). */
    uint8_t     *cmpr_track_buf;        /* Compressed track buffer. */
    long        hdr_ofs;                /* Header offset in file. */
    long        trk_ofs[NTRK_MAX * 2];  /* Track starting offsets. */
} sxd_ctx;


/* Helpers for little-endian word/dword access. */
static uint16_t u16_le( uint8_t *wd )
{
    return( wd[0] | (wd[1] << 8) );
}

#if 0
static uint32_t u32_le( uint8_t *dw )
{
    return( dw[0] | (dw[1] << 8) | ((uint32_t)dw[2] << 16) | ((uint32_t)dw[3] << 24) );
}
#endif

/* CRC-16 calculation routines. */
#define CRC_POLY  0xA001    /* ANSI CRC-16 polynomial (reversed) */

static uint16_t crc_table[256];

static void sxd_init_crc_table( void )
{
    unsigned    i, j, val;

    for( i = 0; i < sizeof( crc_table ) / sizeof( crc_table[0] ); ++i ) {
        val = i;
        for( j = 0; j < 8; ++j ) {
            if( val & 1 )
                val = (val >> 1) ^ CRC_POLY;
            else
                val = (val >> 1);
        }
        crc_table[i] = val;
    }
}


uint16_t sxd_calc_crc( uint8_t *s, int len )
{
    uint16_t    crc = 0;

    /* Init the CRC lookup table if it's not been done yet.
     * The first entry will be zero so test the second.
     */
    if( !crc_table[1] )
        sxd_init_crc_table();

    /* Calculate the CRC-16 of a block. */
    while( --len >= 0 )
        crc = crc_table[(crc ^ (*s++)) & 0xFF] ^ (crc >> 8);

    return( crc );
}


long sxd_calc_skip( img_fns *cb, img_file imgf, long file_sz, long start_ofs )
{
    int         rc;
    uint8_t     word[2];
    uint16_t    n_blks;
    uint16_t    last_blk_sz;
    uint32_t    skip_sz;

    /* Figure out MZ style block size. */
    rc = cb->read( imgf, &word, sizeof( word ) );
    if( rc != sizeof( word ) )
        return( -1 );
    last_blk_sz = u16_le( word );

    /* Check if size of last block is sensible. */
    if( last_blk_sz > 512 )
        return( -1 );

    rc = cb->read( imgf, &word, sizeof( word ) );
    if( rc != sizeof( word ) )
        return( -1 );
    n_blks = u16_le( word );

    /* Check if number of blocks is sensible. Neither the stub
     * executable nor the WB block is going to be particularly big.
     */
    if( n_blks > 256 )
        return( -1 );

    /* Calculate and validate block size. */
    skip_sz = n_blks * 512UL - (512 - last_blk_sz);
    if( skip_sz > file_sz )
        return( -1 );

    /* Calculate the expected DXP header offset. */
    return( start_ofs + skip_sz );
}

/* Look for an SXD header. SXD images are always self-extracting, with
 * a DOS or a combined DOS-OS/2 executable stub.
 *
 * Note that the DOS executable size will in fact include the OS/2
 * executable as well, if it is present. That is very convenient because
 * SXD does not need to bother with parsing the NE header at all, and we
 * don't either.
 *
 * This function returns offset of the DXP header in file (which may be zero),
 * or a negative value if not found.
 */
long sxd_find_hdr( img_fns *cb, img_file imgf )
{
    int         rc;
    uint8_t     word[2];
    long        file_sz;
    long        hdr_ofs;

    /* Read the first two bytes to see what we're dealing with. */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &word, sizeof( word ) );
    if( rc != sizeof( word ) )
        return( -1 );

    /* If the file starts with 'SX' signature, assume it's a bare SXD
     * image. These were presumably never produced by Sydex tools, but
     * that doesn't mean we can't handle them.
     */
    if( !memcmp( word, SXD_SIG, sizeof( word ) ) )
        return( 0 );

    /* Query the file size for sanity checking. */
    file_sz = cb->fsize( imgf );
    if( file_sz <= 0 )
        return( -1 );

    /* If the file does not start with 'MZ', it can't be a SXD image.
     * Note that although 'ZM' signature is also valid for DOS executables,
     * SXD self-extracting images do not use it.
     */
    if( memcmp( word, "MZ", 2) )
        return( -1 );

    /* Skip the self-extracting stub. */
    hdr_ofs = sxd_calc_skip( cb, imgf, file_sz, 0 );
    if( hdr_ofs < 0 )
        return( -1 );

    /* See if 'SX' signature is there. */
    cb->seek( imgf, hdr_ofs );
    rc = cb->read( imgf, &word, sizeof( word ) );
    if( rc != sizeof( word ) )
        return( -1 );

    /* If it's there, we are done. */
    if( !memcmp( word, SXD_SIG, sizeof( word ) ) )
        return( hdr_ofs );

    /* There's also a possibility that a WB signature is in place
     * instead. If that is the case, we need to skip the 'WB' block.
     */
    if( !memcmp( word, WB_SIG, WB_SIG_LEN ) ) {
        /* Skip the WB block. */
        hdr_ofs = sxd_calc_skip( cb, imgf, file_sz, hdr_ofs );
        if( hdr_ofs < 0 )
            return( -1 );

        /* See if 'SX' signature is there. */
        cb->seek( imgf, hdr_ofs );
        rc = cb->read( imgf, &word, sizeof( word ) );
        if( rc != sizeof( word ) )
            return( -1 );

        /* If it's there, we are done. */
        if( !memcmp( word, SXD_SIG, sizeof( word ) ) )
            return( hdr_ofs );
    }

    return( -1 );
}


/* Identify a SXD format image. Does not validate image. */
int sxd_identify( img_fns *cb, img_file imgf )
{
    sxd_hdr     hdr;
    int         rc;
    long        hdr_ofs;

    /* Try finding the SXD header. */
    hdr_ofs = sxd_find_hdr( cb, imgf );
    if( hdr_ofs < 0 )
        return( 0 );

    /* Read the image header and see if signature is there. */
    cb->seek( imgf, hdr_ofs );
    rc = cb->read( imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* Fail if signature isn't what we expect. */
    if( memcmp( hdr.signature, SXD_SIG, SXD_SIG_LEN ) )
        return( 0 );

    /* This sure looks like an SXD image. We are going to claim it
     * because the chances of us finding the SXD signature in a file
     * of a different format are astronomically low.
     */
    return( sizeof( sxd_ctx ) );
}


/* Read copy_len bytes from the compressed buffer at cmpr_pos. */
int sxd_cmpr_read( void *dst, sxd_ctx *ctx, uint16_t *cmpr_pos, long copy_len, long cmpr_len )
{
    if( *cmpr_pos + copy_len <= cmpr_len ) {
        memcpy( dst, ctx->cmpr_track_buf + *cmpr_pos, copy_len );
        *cmpr_pos += copy_len;
        return( copy_len );
    } else {
        /* If there isn't enough data, just do nothing. */
        return( 0 );
    }
}


/* Read the data for a single track from image, decompress as needed.
 * Returns the number of bytes read from (compressed) image file.
 */
int sxd_decomp_trk( img_fns *cb, sxd_ctx *ctx, uint8_t *buf, long data_ofs )
{
    uint8_t     repb;
    int16_t     rep_cnt;
    int16_t     cmpr_len;
    uint16_t    cmpr_len_abs;
    uint16_t    crc_stored;
    uint16_t    crc_computed;
    int         rc;
    unsigned    bytes_read;
    unsigned    bytes_written;

    cb->seek( ctx->imgf, data_ofs );
    bytes_written = 0;
    bytes_read    = 0;

    /* First read the CRC-16 of uncompressed data. */
    rc = cb->read( ctx->imgf, &crc_stored, sizeof( crc_stored ) );
    if( rc != sizeof( crc_stored ) )
        return( IMG_ERR_READ );
    bytes_read += rc;

    /* Then read the length of compressed data. */
    rc = cb->read( ctx->imgf, &cmpr_len, sizeof( cmpr_len ) );
    if( rc != sizeof( cmpr_len ) )
        return( IMG_ERR_READ );
    bytes_read += rc;

    /* The length of compressed data is at most track length + 2 byes. Anything
     * larger is invalid.
     */
    cmpr_len_abs = cmpr_len > 0 ? cmpr_len : -cmpr_len;
    if( cmpr_len_abs > (ctx->track_len + 2) )
        return( IMG_ERR_READ );

    /* Read the compressed track data in one go. */
    assert( ctx->cmpr_track_len > (ctx->track_len + 2) );
    rc = cb->read( ctx->imgf, ctx->cmpr_track_buf, cmpr_len_abs );
    if( rc != cmpr_len_abs )
        return( IMG_ERR_READ );
    bytes_read += cmpr_len_abs;

    /* Now decompress the data. */
    if( cmpr_len < 0 ) {
        uint16_t    cmpr_pos = 0;
        do {
            rc = sxd_cmpr_read( &rep_cnt, ctx, &cmpr_pos, sizeof( rep_cnt ), cmpr_len_abs );
            if( rc != sizeof( rep_cnt ) )
                return( IMG_ERR_BAD_IMG );

            /* If the repeat count is positive, it indicates the number
             * of uncompressed bytes following it. If it is negative, then
             * it represents the number of times the following byte repeats.
             * A zero count is not valid.
             */
            if( rep_cnt > 0 ) {
                /* Uncompressed data. */
                if( bytes_written + rep_cnt > ctx->track_len )
                    return( IMG_ERR_BAD_IMG );

                rc = sxd_cmpr_read( &buf[bytes_written], ctx, &cmpr_pos, rep_cnt, cmpr_len_abs );
                if( rc != rep_cnt )
                    return( IMG_ERR_BAD_IMG );
                bytes_written += rc;
            } else if( rep_cnt < 0 ) {
                rep_cnt = -rep_cnt;
                rc = sxd_cmpr_read( &repb, ctx, &cmpr_pos, sizeof( repb ), cmpr_len_abs );
                if( rc != sizeof( repb ) )
                    return( IMG_ERR_BAD_IMG );
                if( bytes_written + rep_cnt > ctx->track_len )
                    return( IMG_ERR_BAD_IMG );
                memset( &buf[bytes_written], repb, rep_cnt );
                bytes_written += rep_cnt;
            } else {
                /* If this happens, the image is corrupted. */
                assert( rep_cnt == 0 );
                return( IMG_ERR_BAD_IMG );
            }
        } while( bytes_written < ctx->track_len );
    } else {
        rc = sxd_unpack_lzhuf( cb, ctx->imgf, ctx->cmpr_track_buf, cmpr_len, buf, ctx->track_len );
    }

    /* Validate the CRC of decompressed track data. */
    crc_computed = sxd_calc_crc( buf, ctx->track_len );
    if( crc_stored != crc_computed )
        return( IMG_ERR_CSUM );

    return( bytes_read );
}


/* Sequentially scan the image, building a map of tracks/sectors. */
int sxd_build_map( img_fns *cb, sxd_ctx *ctx, long start_ofs )
{
    long        curr_ofs;
    int         trk_idx;
    int         rc;

    curr_ofs = start_ofs;

    /* Simply go over all the data in the image and see what we got. */
    for( trk_idx = 0; trk_idx < ctx->cyls_img * ctx->heads ; ++trk_idx ) {

        ctx->trk_ofs[trk_idx] = curr_ofs;
        /* Read/decompress the sector data. */
        rc = sxd_decomp_trk( cb, ctx, ctx->track_buf, curr_ofs );
        if( rc < 0 )
            return( rc );

        curr_ofs += rc;
    }

    return( 0 );
}


/* Open an image for access. */
int sxd_open( img_fns *cb, img_file imgf, sxd_ctx *ctx )
{
    int         rc = IMG_OK;
    sxd_hdr     hdr;
    uint16_t    crc;

    ctx->imgf = imgf;

    /* Re-read the SXD header and copy relevant data into the
     * context structure.
     */
    ctx->hdr_ofs = sxd_find_hdr( cb, imgf );
    if( ctx->hdr_ofs < 0 )
        return( IMG_ERR_BAD_IMG );  /* Really should not happen. */

    cb->seek( ctx->imgf, ctx->hdr_ofs );
    rc = cb->read( ctx->imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( IMG_ERR_READ );

    crc = sxd_calc_crc( (void *)&hdr, offsetof( sxd_hdr, crc_hdr ) );
    if( crc != hdr.crc_hdr )
        return( IMG_ERR_CSUM );

    /* Password-protected images are not supported. */
    if( hdr.pwd_crc )
        return( IMG_ERR_PASSWD );

    ctx->sec_sz   = IMG_SEC_SZ_DEF;
    ctx->spt      = hdr.n_trk_sec;
    ctx->heads    = hdr.n_heads;
    ctx->cyls_dsk = hdr.n_cyl_dsk;
    ctx->cyls_img = hdr.n_cyl_img;

    /* Perform basic sanity checking. */
    if( hdr.trk_len != ctx->spt * ctx->sec_sz )
        return( IMG_ERR_BAD_IMG );

    ///@todo: More validation of the header contents?

    /* Allocate the buffers for compressed and uncompressed track data. */
    ctx->trk_in_buf = -1;
    ctx->track_len  = ctx->spt * ctx->sec_sz;
    ctx->track_buf  = cb->m_alloc( ctx->track_len );
    if( !ctx->track_buf )
        return( IMG_ERR_MEM_ALLOC );

    ctx->cmpr_track_len = ctx->track_len + 128;
    ctx->cmpr_track_buf = cb->m_alloc( ctx->cmpr_track_len );
    if( !ctx->cmpr_track_buf ) {
        rc = IMG_ERR_MEM_ALLOC;
        goto err_free;
    }

    /* Read the comment if there is one. The length only covers the
     * text, no null terminator, so we add one byte.
     *
     * If we really wanted to be fancy, we could generate the comments
     * SXD produces, like this one:
     *
     * This file was created on May 8, 1997  14:37:16
     */
    if( hdr.comment_len ) {
        uint16_t    cmt_size = hdr.comment_len + 1;
        uint16_t    cmt_crc;

        ctx->comment = cb->m_alloc( cmt_size );
        if( ctx->comment ) {
            /* Read the comment from file. */
            rc = cb->read( ctx->imgf, ctx->comment, hdr.comment_len );
            if( rc != hdr.comment_len ) {
                rc = IMG_ERR_READ;
                goto err_free;
            }

            /* Checksum the comment, just for the heck of it. */
            cmt_crc = sxd_calc_crc( ctx->comment, hdr.comment_len );
            if( cmt_crc == hdr.crc_comment ) {
                int     i;

                /* Replace nulls with NL characters. */
                for( i = 0; i < hdr.comment_len; ++i ) {
                    if( ctx->comment[i] == '\0' )
                        ctx->comment[i] = '\n';
                }

                /* And add null terminator (it's not in the file). */
                ctx->comment[cmt_size - 1] = '\0';
            } else {
                /* If the comment CRC is bad, throw it away but
                 * do not treat it as an error.
                 */
                cb->m_free( ctx->comment );
                ctx->comment = NULL;
            }
        } else {
            rc = IMG_ERR_MEM_ALLOC;
            goto err_free;
        }
    }

    /* Build a map of all the tracks in the image. Also verify
     * the CRC in the process. If the entire image can be read
     * and decompressed without error and the CRC matches, it is
     * considered good.
     */
    rc = sxd_build_map( cb, ctx, ctx->hdr_ofs + sizeof( sxd_hdr ) + hdr.comment_len );
    if( rc )
        goto err_free;

    assert( ctx->spt );
    return( IMG_OK );

err_free:
    if( ctx->comment )
        cb->m_free( ctx->comment );
    if( ctx->cmpr_track_buf )
        cb->m_free( ctx->cmpr_track_buf );
    if( ctx->track_buf )
        cb->m_free( ctx->track_buf );

    return( rc );
}


/* Query the comment string. Returns NULL if no comment provided. */
const char *sxd_query_comment( img_fns *cb, sxd_ctx *ctx )
{
    return( ctx->comment );
}


/* Read and decompress a specified track. */
int sxd_read_track( img_fns *cb, sxd_ctx *ctx, int track_num )
{
    int     rc = IMG_OK;

    if( track_num < ctx->cyls_img * ctx->heads ) {
        /* Read and decompress track. */
        rc = sxd_decomp_trk( cb, ctx, ctx->track_buf, ctx->trk_ofs[track_num] );

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
int sxd_read_sect( img_fns *cb, sxd_ctx *ctx, int sect_num, void *buf )
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
        rc = sxd_read_track( cb, ctx, track_num );
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
void sxd_close( img_fns *cb, sxd_ctx *ctx )
{
    assert( ctx );
    if( ctx->comment )
        cb->m_free( ctx->comment );

    if( ctx->cmpr_track_buf )
        cb->m_free( ctx->cmpr_track_buf );

    if( ctx->track_buf )
        cb->m_free( ctx->track_buf );
}
