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
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>

#include "img_defs.h"
#include "img_help.h"
#include "img_dxp.h"
#include "dxp_lh1.h"
#include "dxp_lh5.h"


/*
 * DXP format images are created by a utility called Disk eXPress by Albert
 * J. Shan. DXP was released in 1991 as DSKEXP.EXE (version 1.x) and later
 * renamed to DXP.EXE (version 2.x). The final version of DXP, version 2.34,
 * was released in 1994 and also included DXP32.EXE for OS/2 version 2.0 and
 * later.
 *
 * The DSKEXP utility could only create self-extracting floppy images and
 * was intended for transferring or distributing floppies. Several large
 * OEMs (IBM, HP, Dell) used DXP for distributing driver disks, firmware
 * updates, and similar.
 *
 * DXP always used compression by default. The DSKEXP/DXP utility only
 * contained the compressor code, and the self-extracting stub only included
 * the decompressor logic. DXP 2.0 additionally allows creation of "bare"
 * floppy images without the self-extractor, suitable for archival.
 *
 * DXP only supports standard 360K/720K/etc. format floppies and does not
 * even store the actual disk geometry, only the basic type. No provisions
 * exist for any unusual formats. For FAT formatted floppies, DXP does not
 * store tracks with zero allocated clusters. Later DXP versions are also
 * able to image disks with bad sectors. DXP is able to image non-DOS
 * floppies using standard formats.
 *
 * Note that when restoring images, DXP does not write unused tracks at all
 * and the contents of omitted tracks must be treated as indeterminate. When
 * restoring images, DXP may produce different results depending on the
 * previous contents of the target disk. In contrast, this library will
 * treat the contents of omitted tracks as freshly formatted (F6h pattern)
 * and will always produce consistent results.
 *
 * There is a provision for supplying a fixed-length comment. Newer DXP
 * versions also allow encrypting an image, although the documentation warns
 * that the method used by DXP is not very cryptographically secure.
 *
 * The header, comment, and disk data are all protected by separate
 * CRC-32 checksums. The disk data checksum is within the checksummed portion
 * of the image header. The comment checksum is standalone, since DXP allows
 * editing the comments of existing images.
 *
 * The initial DSKEXP used LZHUF compression based on Haruyasu Yoshizaki's
 * published source code. This is equivalent to the -lh1- method of LHA 1.x.
 * DXP 2.0 was upgraded to the faster and more efficient -lh5- method
 * introduced in LHA 2.x. This allowed DXP to create much smaller images
 * than many competing utilities. Each track is compressed separately,
 * ensuring that there is never more than 64K data to compress or decompress.
 * Unlike TeleDisk or DSKF formats which compress the entire image, DXP
 * compressed images are much easier to work with because there's no need
 * to uncompress the entire image or implement complex mechanisms that
 * can stop decompressing at any point and continue later.
 *
 * Tracks that cannot be compressed are stored as is. DXP also has a special
 * provision for empty tracks (typically all 00h or F6h) and uses RLE for
 * those. Images can also be stored entirely uncompressed. In that case
 * DXP creates effectively raw images, with no per-track headers, and the
 * DXP header is conveniently exactly 512 bytes long.
 *
 * DXP 1.x calculates the CRC-32 of disk data in a rather non-obvious manner.
 * For uncompressed images it's straightforward--CRC-32 is calculated over all
 * of the image data that follows the header. For compressed disks however,
 * CRC-32 is only calculated from the compressed data of each track, *not*
 * including the track headers which contain the size of each following data
 * block. Since the track headers indirectly affect CRC-32 calculation, they
 * are effectively protected by the CRC-32 as well.
 *
 * DXP 2.x always calculates the CRC-32 of uncompressed disk data, whether
 * it is stored in the image in a compressed form or not. Hence for DXP 2.x,
 * the CRC-32 of a disk image will be the same whether it is compressed
 * or not.
 *
 * Custom DXP versions may have different CRC seeds. For example an IBM
 * OEM version uses CRC seed 0x31E rather than 0x59D that regular DXP
 * versions use.
 *
 * This implementation is based on the description of the DXP format at
 * http://justsolve.archiveteam.org/wiki/Disk_Express
 *
 * The decompression algorithms were identified based on comments in the
 * DXP documentation plus some amount of qualified guesswork. The exact
 * CRC-32 logic was reverse engineered from the DXP utility.
 */


/* Standard formats only. */
#define NTRK_MAX     80


/* Format constants. */
#define DXP_SIG      "AS"        /* DXP signature, AS for Albert Shan. */
#define DXP_SIG_LEN  2           /* Signature length. */

typedef struct fmt_entry_s {
    uint8_t     cyls;           /* Number of cylinders. */
    uint8_t     heads;          /* Number of heads. */
    uint8_t     spt;            /* Sectors per track. */
} fmt_entry;

/* DXP floppy formats. */
static fmt_entry    fmt_tab[] = {
    { 40, 1, 8  },        /* 5.25" 160K  disk. */
    { 40, 1, 9  },        /* 5.25" 180K  disk. */
    { 40, 2, 8  },        /* 5.25" 320K  disk. */
    { 40, 2, 9  },        /* 5.25" 360K  disk. */
    { 80, 2, 9  },        /* 3.5"  720K  disk. */
    { 80, 2, 15 },        /* 5.25" 1.2M  disk. */
    { 80, 2, 18 },        /* 3.5"  1.44M disk. */
    { 80, 2, 36 },        /* 3.5"  2.88M disk. */
};

/* DXP image header, exactly 512 bytes in size. */
typedef struct dxp_hdr_s {
    char        signature[2];   /* 'AS' signature. */
    uint8_t     major;          /* Major DXP version needed to write image. */
    uint8_t     minor;          /* Minor DXP version needed to write image. */
    char        release;        /* DXP release used to create image. */
    uint8_t     dsk_typ;        /* Disk format (1.44M etc.). See fmt_tab. */
    uint8_t     crc_data[4];    /* CRC-32 of disk data. */
    uint8_t     compr_typ;      /* Compression type. */
    uint8_t     last_cyl;       /* Last cylinder imaged. */
    uint8_t     last_head;      /* Last head imaged. */
    uint8_t     unused_1;       /* Should be zero. */
    uint8_t     flags;          /* Image flags. */
    uint8_t     unused_2;       /* Should be zero. */
    uint8_t     pass_hash[4];   /* Password hash. */
    uint8_t     empty[284];     /* Lots of zeroes. */
    uint8_t     crc_hdr[4];     /* CRC-32 of image header. */
    char        desc[200];      /* Disk image description, space-padded. */
    uint8_t     crc_desc[4];    /* CRC-32 of image description. */
} dxp_hdr;


/* Context structure for DXP format. */
typedef struct dxp_ctx {
    img_file    imgf;                   /* Image file handle. */
    uint32_t    crc_seed;               /* Starting CRC-32 value. */
    uint32_t    crc_data;               /* Stored CRC-32 of disk data. */
    uint8_t     ver_major;              /* Major DXP version required. */
    uint8_t     ver_minor;              /* Minor DXP version required. */
    uint8_t     cyls_dsk;               /* Number of cylinders on disk. */
    uint8_t     trks_img;               /* Number of tracks in image. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    char        *comment;               /* Optional comment. */
    unsigned    track_len;              /* Length of single track in bytes. */
    int         compress;               /* Compression type from header. */
    int         trk_in_buf;             /* Track currently in buffer. */
    uint8_t     *track_buf;             /* Track buffer (uncompressed). */
    long        hdr_ofs;                /* Offset of DXP header in file. */
    long        trk_ofs[NTRK_MAX * 2];  /* Track starting offsets. */
} dxp_ctx;


/* Helpers for little-endian word/dword access. */
static uint16_t u16_le( uint8_t *wd )
{
    return( wd[0] | (wd[1] << 8) );
}

static uint32_t u32_le( uint8_t *dw )
{
    return( dw[0] | (dw[1] << 8) | ((uint32_t)dw[2] << 16) | ((uint32_t)dw[3] << 24) );
}


/* DXP uses an unusual starting value for CRC computation. */
#define DXP_CRC32_SEED      0x59D

/* Special IBM version of DXP uses a different CRC seed! */
#define DXP_CRC32_SEED_IBM  0x31E

/* Slow lookup-less CRC-32. */
uint32_t dxp_crc32_upd( uint32_t b )
{
    const uint32_t  poly = 0xEDB88320L;
    uint32_t        crc  = b;
    int             i;

    for( i = 0; i < 8; ++i )
        crc = (crc >> 1) ^ (crc & 1) * poly;
    return( crc );
}


/* The DXP CRC algorithm uses the usual polynomial but an atypical
 * seed and does not invert the final CRC value.
 */
uint32_t dxp_crc32( const void *data, size_t sz, uint32_t seed )
{
    const uint8_t *s = data;
    uint32_t       crc = seed;
    size_t         i;

    for( i = 0; i < sz; ++i ) {
        crc ^= s[i];
        crc  = dxp_crc32_upd( crc );
    }

    return( crc );  /* Not inverted! */
}


/* Look for a DXP header. Most DXP images are self-extracting, with a DOS,
 * OS/2, and most often a combined DOS-OS/2 executable stub. Note that in
 * either case, the stub executable is followed by a 32-bit checksum and
 * only then by the DXP header.
 *
 * This function returns offset of the DXP header in file (which may be zero),
 * or a negative value if not found.
 */
long dxp_find_hdr( img_fns *cb, img_file imgf )
{
    int         rc;
    uint8_t     word[2];
//    uint8_t     dword[4];
    uint16_t    n_blks;
    uint16_t    last_blk_sz;
    uint32_t    dos_sz;
    long        file_sz;
    long        hdr_ofs;

    /* Read the first two bytes to see what we're dealing with. */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &word, sizeof( word ) );
    if( rc != sizeof( word ) )
        return( -1 );

    /* If the file starts with 'AS' signature, it's a bare DXP image. */
    if( !memcmp( word, DXP_SIG, DXP_SIG_LEN ) )
        return( 0 );

    /* Query the file size for sanity checking. */
    file_sz = cb->fsize( imgf );
    if( file_sz <= 0 )
        return( -1 );

    /* If the file does not start with 'MZ', it can't be a DXP image.
     * Note that although 'ZM' signature is also valid for DOS executables,
     * DXP self-extracting images do not use it.
     */
    if( memcmp( word, "MZ", 2) )
        return( -1 );

    /* It's a DOS executable; figure out how big it is. */
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

    /* Check if number of blocks is sensible. Note that the DOS executable
     * size will in fact include the OS/2 executable as well, if it is
     * present, even if there is no DOS decompressor (only the usual tiny
     * stub). That is very convenient because DXP does not need to bother
     * with parsing the NE header at all, and we don't either.
     */
    if( n_blks > 256 )
        return( -1 );

    /* Calculate and validate DOS executable size. */
    dos_sz = n_blks * 512UL - (512 - last_blk_sz);
    if( dos_sz > file_sz )
        return( -1 );

    /* Calculate the expected DXP header offset. */
    hdr_ofs = dos_sz + 4;

    /* See if 'AS' signature is there. */
    cb->seek( imgf, hdr_ofs );
    rc = cb->read( imgf, &word, sizeof( word ) );
    if( rc != sizeof( word ) )
        return( -1 );

    /* If it's there, we are done. */
    if( !memcmp( word, DXP_SIG, DXP_SIG_LEN ) )
        return( hdr_ofs );

    return( -1 );
}


/* Check the DXP header checksum and determine the CRC-32 seed.
 * Validates the CRC-32 as a side effect. Returns zero if CRC-32
 * seed cannot be found.
 */
uint32_t dxp_find_crc_seed( dxp_hdr *hdr )
{
    uint32_t    hdr_crc_file;
    uint32_t    hdr_crc_calc;

    hdr_crc_file = u32_le( hdr->crc_hdr );

    /* Try the normal DXP CRC-32 seed value. */
    hdr_crc_calc = dxp_crc32( hdr, offsetof( dxp_hdr, crc_hdr ), DXP_CRC32_SEED );
    if( hdr_crc_file == hdr_crc_calc )
        return( DXP_CRC32_SEED );

    /* Try special IBM seed next. */
    hdr_crc_calc = dxp_crc32( hdr, offsetof( dxp_hdr, crc_hdr ), DXP_CRC32_SEED_IBM );
    if( hdr_crc_file == hdr_crc_calc )
        return( DXP_CRC32_SEED_IBM );

    /* Indicate failure -- either corrupted header or unknown seed. */
    return( 0 );
}

/* Identify a DXP format image. Does not validate image. */
int dxp_identify( img_fns *cb, img_file imgf )
{
    dxp_hdr     hdr;
    int         rc;
    long        hdr_ofs;

    /* If there's no 'AS' signature it can't be a DXP image. */
    hdr_ofs = dxp_find_hdr( cb, imgf );
    if( hdr_ofs < 0 )
        return( 0 );

    /* Read the image header. */
    cb->seek( imgf, hdr_ofs );
    rc = cb->read( imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* Check the header CRC. If it matches, the chance of this not
     * being a DXP image is vanishingly small. On the other hand,
     * if the CRC does not match, it's at best a DXP image with
     * a corrupted and hence untrustworthy header, unlikely to be
     * much good.
     */
    if( !dxp_find_crc_seed( &hdr ) )
        return( 0 );

    /* This sure looks like a DXP image. */
    return( sizeof( dxp_ctx ) );
}

/* Read the data for a single track from image, decompress as needed. */
int dxp_decomp_trk( img_fns *cb, dxp_ctx *ctx, uint8_t *buf, long data_ofs )
{
    uint8_t     repb;
    int16_t     cmpr_len;
    int         rc;
    unsigned    bytes_read;
    unsigned    bytes_written;

    cb->seek( ctx->imgf, data_ofs );
    bytes_written = 0;
    bytes_read    = 0;

    if( ctx->compress ) {
        /* Read the compressed length. */
        rc = cb->read( ctx->imgf, &cmpr_len, sizeof( cmpr_len ) );
        if( rc != sizeof( cmpr_len ) )
            return( 0 );
        bytes_read += rc;

        if( cmpr_len == 1 ) {
            /* Special case: RLE. */
            rc = cb->read( ctx->imgf, &repb, sizeof( repb ) );
            if( rc != sizeof( repb ) )
                return( 0 );
            bytes_read += rc;

            /* Fill the buffer with target byte. */
            memset( buf, repb, ctx->track_len );
        } else if( cmpr_len == ctx->track_len ) {
            /* Special case: Uncompressed track */
            rc = cb->read( ctx->imgf, buf, cmpr_len );
            if( rc != cmpr_len )
                return( 0 );
            bytes_read += rc;
        } else {
            /* Compressed track. Read it and decompress. */
            if( ctx->compress == 2 )
                rc = dxp_unpack_lh5( cb, ctx->imgf, cmpr_len, buf, ctx->track_len );
            else
                rc = dxp_unpack_lh1( cb, ctx->imgf, cmpr_len, buf, ctx->track_len );

            /* If size doesn't match, decompression failed. */
            if( rc != ctx->track_len )
                return( 0 );
            bytes_read += cmpr_len;
        }
    } else {
        /* Uncompressed image is trivial. */
        bytes_read = cb->read( ctx->imgf, buf, ctx->track_len );
        if( bytes_read != ctx->track_len )
            return( 0 );
    }

    return( bytes_read );
}


/* Test the data for a single track. This involves reading the track data and updating
 * the CRC-32 checksum.
 * Note that DXP 1.x calculates the CRC from compressed data, therefore we don't need
 * to decompress it here (and if the CRC matches, it really should decompress without
 * error). DXP 2.x calculates the CRC from original image data, which means that the
 * track must be uncompressed first.
 */
int dxp_test_trk( img_fns *cb, dxp_ctx *ctx, uint8_t *buf, long data_ofs, uint32_t *crc )
{
    uint8_t     repb;
    int16_t     cmpr_len;
    int         rc;
    unsigned    bytes_read;
    unsigned    bytes_written;

    cb->seek( ctx->imgf, data_ofs );
    bytes_written = 0;
    bytes_read    = 0;

    if( ctx->compress ) {
        /* Read the compressed length. */
        rc = cb->read( ctx->imgf, &cmpr_len, sizeof( cmpr_len ) );
        if( rc != sizeof( cmpr_len ) )
            return( 0 );
        bytes_read += rc;

        if( cmpr_len == 1 ) {
            /* Special case: RLE. */
            rc = cb->read( ctx->imgf, &repb, sizeof( repb ) );
            if( rc != sizeof( repb ) )
                return( 0 );
            bytes_read += rc;

            /* Fill the buffer with target byte. */
            memset( buf, repb, ctx->track_len );

            /* DXP 1.x calculates CRC of compressed data, DXP 2.x
             * does uncompressed.
             */
            if( ctx->compress == 1 )
                *crc = dxp_crc32( &repb, 1, *crc );
            else
                *crc = dxp_crc32( ctx->track_buf, ctx->track_len, *crc );
        } else if( cmpr_len == ctx->track_len ) {
            /* Special case: Uncompressed track */
            rc = cb->read( ctx->imgf, buf, cmpr_len );
            if( rc != cmpr_len )
                return( 0 );
            bytes_read += rc;

            *crc = dxp_crc32( ctx->track_buf, ctx->track_len, *crc );
        } else {
            if( ctx->compress == 1) {
                /* DXP 1.x compressed track. Read it and calculate CRC. */
                rc = cb->read( ctx->imgf, buf, cmpr_len );
                if( rc != cmpr_len )
                    return( 0 );

                *crc = dxp_crc32( ctx->track_buf, cmpr_len, *crc );
            } else {
                /* DXP 2.x Compressed track. Read, decompress, then calculate CRC. */
                rc = dxp_unpack_lh5( cb, ctx->imgf, cmpr_len, buf, ctx->track_len );

                /* If size doesn't match, decompression failed. */
                if( rc != ctx->track_len )
                    return( 0 );

                *crc = dxp_crc32( ctx->track_buf, ctx->track_len, *crc );
            }
            bytes_read += cmpr_len;
        }
    } else {
        /* Uncompressed image is trivial. */
        bytes_read = cb->read( ctx->imgf, buf, ctx->track_len );
        if( bytes_read != ctx->track_len )
            return( 0 );

        *crc = dxp_crc32( ctx->track_buf, ctx->track_len, *crc );
    }

    return( bytes_read );
}


/* Sequentially scan the image, building a map of tracks/sectors.
 * Also validate CRC of image data.
 */
int dxp_build_map( img_fns *cb, dxp_ctx *ctx, long start_ofs )
{
    long        curr_ofs;
    int         trk_idx;
    int         rc;
    uint32_t    crc;

    crc = ctx->crc_seed;
    curr_ofs = start_ofs;

    /* Simply go over all the data in the image and see what we got. */
    for( trk_idx = 0; trk_idx < ctx->trks_img; ++trk_idx ) {
        ctx->trk_ofs[trk_idx] = curr_ofs;

        /* Read and possibly decompress the sector data. */
        rc = dxp_test_trk( cb, ctx, ctx->track_buf, curr_ofs, &crc );
        if( !rc )
            return( IMG_ERR_DECODE );

        curr_ofs += rc;
    }

    /* Check if the CRC is what it's supposed to be. */
    if( ctx->crc_data == crc )
        return( 0 );
    else
        return( IMG_ERR_CSUM );
}


int dxp_has_comment( dxp_hdr *hdr )
{
    /* An empty comment should be all spaces. To be a little safer,
     * we just check if all the comment characters are identical.
     */
    char    c = hdr->desc[0];
    int     i;
    int     has_comment = 0;

    for( i = 1; i < sizeof( hdr->desc ); ++i ) {
        if( hdr->desc[i] != c ) {
            has_comment = 1;
            break;
        }
    }

    return( has_comment );
}


/* Open an image for access. */
int dxp_open( img_fns *cb, img_file imgf, dxp_ctx *ctx )
{
    int         rc;
    dxp_hdr     hdr;
    fmt_entry   *fmte;
    long        hdr_ofs;

    ctx->imgf = imgf;

    /* Find the DXP header again. */
    hdr_ofs = dxp_find_hdr( cb, imgf );
    if( hdr_ofs < 0 )
        return( IMG_ERR_READ );

    ctx->hdr_ofs = hdr_ofs;

    /* Re-read the DXP header. */
    cb->seek( ctx->imgf, ctx->hdr_ofs );
    rc = cb->read( ctx->imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( IMG_ERR_READ );

    /* Validate the header CRC again and remember the seed. */
    ctx->crc_seed = dxp_find_crc_seed( &hdr );
    if( !ctx->crc_seed )
        return( IMG_ERR_DECODE );

    /* If there is a password hash, the image is encrypted and
     * we won't be able to do anything with it!
     */
    if( memcmp( hdr.pass_hash, "\0\0\0\0", sizeof( hdr.pass_hash ) ) )
        return( IMG_ERR_PASSWD );

    /* Save off the CRC of image data. */
    ctx->crc_data = u32_le( hdr.crc_data );

    /* Save off the required DXP version. */
    ctx->ver_major = hdr.major;
    ctx->ver_minor = hdr.minor;

    ///@todo: How paranoid do we need to be if the CRC matches?

    /* Ensure the disk type is within range. */
    if( hdr.dsk_typ >= sizeof( fmt_tab ) / sizeof( fmt_tab[0] ) )
        return( IMG_ERR_DECODE );

    fmte = &fmt_tab[hdr.dsk_typ];

    /* Clamp the last head value. Needed for VP162FIX.EXE, created
     * with DXP 1.04 (IBM), which records the last head as 2.
     */
    if( hdr.last_head > 1 )
        hdr.last_head = 1;

    ctx->spt      = fmte->spt;
    ctx->heads    = fmte->heads;
    ctx->cyls_dsk = fmte->cyls;
    ctx->trks_img = (hdr.last_cyl + 1) * fmte->heads - (1 - hdr.last_head);
    ctx->compress = hdr.compr_typ;

    /* Allocate the track buffer. */
    ctx->trk_in_buf = -1;
    ctx->track_len  = ctx->spt * IMG_SEC_SZ_DEF;
    ctx->track_buf  = cb->m_alloc( ctx->track_len );
    if( !ctx->track_buf )
        return( IMG_ERR_MEM_ALLOC );

    /* There is always a comment, but it's often empty. Only
     * return something when it is not empty.
     */
    if( dxp_has_comment( &hdr ) ) {
        uint16_t    cmt_size = 5 * (40 + 1) + 1;

        ctx->comment = cb->m_alloc( cmt_size );
        if( ctx->comment ) {
            int     ln;

            /* The comment is formatted as 5 lines of 40 chars
             * each. There are no newlines or a terminating null
             * character, so we add those.
             */
            for( ln = 0; ln < 5; ++ln ) {
                memcpy( ctx->comment + ln * 41, &hdr.desc[ln * 40], 40 );
                ctx->comment[ln * 41 + 40] = '\n';
            }

            /* Add null terminator. */
            ctx->comment[cmt_size - 1] = '\0';
        } else {
            return( IMG_ERR_MEM_ALLOC );
        }
    }

    /* Build a map of all the tracks in the image. Also verify the CRC
     * in the process. If the entire image can be read and possibly
     * decompressed without error, and the CRC matches, it is considered
     * good.
     */
    rc = dxp_build_map( cb, ctx, ctx->hdr_ofs + sizeof( dxp_hdr ) );
    if( rc )
        return( rc );

    return( IMG_OK );
}


/* Query the comment string. Returns NULL if no comment provided. */
const char *dxp_query_comment( img_fns *cb, dxp_ctx *ctx )
{
    return( ctx->comment );
}


/* Read and decompress a specified track. */
int dxp_read_track( img_fns *cb, dxp_ctx *ctx, int track_num )
{
    int     rc = IMG_OK;

    if( track_num < ctx->trks_img ) {
        /* Read and decompress track. */
        rc = dxp_decomp_trk( cb, ctx, ctx->track_buf, ctx->trk_ofs[track_num] );

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
int dxp_read_sect( img_fns *cb, dxp_ctx *ctx, int sect_num, void *buf )
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
        rc = dxp_read_track( cb, ctx, track_num );
        if( rc < 0 )
            return( rc );
    }

    /* Calculate the sector offset in track buffer. */
    sec_ofs = sect_num % ctx->spt * IMG_SEC_SZ_DEF;
    assert( sec_ofs + IMG_SEC_SZ_DEF <= ctx->track_len );
    memcpy( buf, ctx->track_buf + sec_ofs, IMG_SEC_SZ_DEF );

    return( IMG_SEC_SZ_DEF );
}


/* Close an image once all accesses are completed. */
void dxp_close( img_fns *cb, dxp_ctx *ctx )
{
    assert( ctx );
    if( ctx->comment )
        cb->m_free( ctx->comment );

    if( ctx->track_buf )
        cb->m_free( ctx->track_buf );
}
