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
#include "img_hdcp.h"


/* The HD-Copy diskette image format was used by the eponymous DOS utility,
 * written by Oliver Fromme around 1995. The HD-Copy format is relatively
 * straightforward, supporting images with 512-byte sector size and uniform
 * sectors per track count. A basic form of run-length compression is also
 * supported, and empty/unused tracks aren't stored in the image. Images
 * with up to 82 cylinders are supported (but see below).
 *
 * No provision appears to be made for single-sided images. The disk image
 * is stored as a sequence of compressed tracks (where a track refers to only
 * one side of the disk), and individual tracks may be left out.
 *
 * The track map indicates whether a track is present in image (1), present
 * but contains data errors (2), or not present (0). Track map entries beyond
 * the last valid image track may contain garbage.
 *
 * The HD-Copy RLE compression works as follows. The image is divided into a
 * number of independent blocks, one per track. Each compressed block starts
 * with a header which contains the size of compressed data (16-bit little
 * endian) and the escape byte. Whenever the escape byte is encountered in the
 * byte stream, it is followed by a data byte and a count byte.
 *
 * Note that HD-Copy uses RLE compression for sequences of as few as three
 * bytes, even though that provides no benefit.
 *
 * It would be tempting to perform in-place decompression to save memory.
 * Unfortunately the simplistic RLE algorithm means the encoded data may be
 * larger than the decoded version, with unknown worst case behavior. Hence
 * the compressed data for a sector may not fit into a buffer the size of the
 * uncompressed sector.
 *
 * There is no signature, hence heuristics must be used to identify a HD-Copy
 * diskette image. Fortunately, the HD-Copy header is highly recognizable.
 *
 * A newer version of the HD-Copy image format includes a short fixed-size
 * header which contains a volume label. The newer format also supports up to
 * 84 cylinders, two more than the original format.
 *
 * The newer HD-Copy format appears to have a two-byte signature (FFh 18h).
 * It is unclear if either byte has any special meaning. The newer signature
 * is mutually exclusive with the older one.
 */

/* Maximum supported cylinders for old and new formats. */
#define NCYL_MXO    82
#define NCYL_MAX    84

/* HD-Copy 2.0 signature bytes. */
#define SIG1        0xFF
#define SIG2        0x18

/* HD-Copy image header. */
typedef struct hdcp_hdr {
    uint8_t     max_cyl;                /* Last cylinder (zero-based). */
    uint8_t     num_sec;                /* Sectors per track. */
    uint8_t     trk_map[NCYL_MXO * 2];  /* Track map. */
} hdcp_hdr;

/* HD-Copy 2.0 track map extension. */
typedef struct hdcp_ext {
    uint8_t     trk_map[(NCYL_MAX - NCYL_MXO) * 2];
} hdcp_ext;

/* HD-Copy 2.0 label header. */
typedef struct hdcp_lbl {
    uint8_t     sig1;                   /* Signature byte. */
    uint8_t     sig2;                   /* Signature byte. */
    uint8_t     lbl_len;                /* Length of label. */
    char        label[8 + 3];           /* Label (not null-terminated). */
} hdcp_lbl;

/* HD-Copy compressed block header. */
typedef struct cblk_hdr {
    uint8_t     length_lo;              /* Compressed block length (bytes). */
    uint8_t     length_hi;
    uint8_t     escape;                 /* Escape byte starting RLL block. */
} cblk_hdr;

typedef struct hdcp_ctx {
    img_file    imgf;                   /* Image file handle. */
    uint8_t     trks;                   /* Number of tracks. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     new_format;             /* Newer format with label. */
    hdcp_hdr    hdr;                    /* The image header. */
    hdcp_ext    ext;                    /* Extended track map. */
    long        trk_ofs[NCYL_MAX * 2];  /* Track starting offsets. */
    unsigned    track_len;              /* Length of single track in bytes. */
    int         trk_in_buf;             /* Track currently in buffer. */
    uint8_t     *track_buf;             /* Track buffer (uncompressed). */
} hdcp_ctx;


/* Identify a HD-Copy format image. Does not validate image. */
int hdcp_identify( img_fns *cb, img_file img )
{
    hdcp_hdr    hdr;
    hdcp_lbl    lbl;
    int         rc;

    /* No file magic, so we must guess. */
    cb->seek( img, 0 );
    rc = cb->read( img, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* Check for the newer format. */
    if( hdr.max_cyl == SIG1 && hdr.num_sec == SIG2 ) {
        /* If signature was found, it can't be the older format. */
        cb->seek( img, 0 );

        /* Read the label. */
        rc = cb->read( img, &lbl, sizeof( lbl ) );
        if( rc != sizeof( lbl ) )
            return( 0 );

        /* Validate label length. */
        if( lbl.lbl_len == 0 || lbl.lbl_len > sizeof( lbl.label ) )
            return( 0 );

        /* Now read the old header again and check it. */
        rc = cb->read( img, &hdr, sizeof( hdr ) );
        if( rc != sizeof( hdr ) )
            return( 0 );

        /* Range check the maximum track number. */
        if( hdr.max_cyl >= NCYL_MAX )
            return( 0 );
    } else {
        /* Range check the maximum track number. */
        if( hdr.max_cyl >= NCYL_MXO )
            return( 0 );
    }

    /* Range check the minimum track number. */
    if( hdr.max_cyl < 37 )
        return( 0 );

    /* Range check sectors per track. */
    if( hdr.num_sec < 8 || hdr.num_sec > 40 )
        return( 0 );

    /* Check if the first two tracks are indicated to be present. Note
     * that the third track might not be!
     */
    if( hdr.trk_map[0] != 1 && hdr.trk_map[0] != 2 )
        return( 0 );

    if( hdr.trk_map[1] != 1 && hdr.trk_map[1] != 2 )
        return( 0 );

    /* There's sufficient resemblance to a HD-Copy image... */
    return( sizeof( hdcp_ctx ) );
}

/* Open an image for access. May fail if image is damaged. */
int hdcp_open( img_fns *cb, img_file img, hdcp_ctx *hdcp )
{
    int         rc;
    hdcp_hdr    hdr;
    hdcp_ext    ext;
    hdcp_lbl    lbl;
    uint16_t    blk_len;
    int         trk;
    int         num_trk;
    int         new_format = 0;
    long        cur_ofs = 0;

    /* Read the image format header. We already ensured it's sensible
     * but must check for label header again.
     */
    cb->seek( img, 0 );
    rc = cb->read( img, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( IMG_ERR_READ );

    /* Check for new format (mutually exclusive with old one). */
    if( hdr.max_cyl == SIG1 && hdr.num_sec == SIG2 ) {
        new_format = 1;

        /* Read the label. */
        cb->seek( img, 0 );
        rc = cb->read( img, &lbl, sizeof( lbl ) );
        if( rc != sizeof( lbl ) )
            return( IMG_ERR_READ );

        cur_ofs += sizeof( lbl );
        rc = cb->read( img, &hdr, sizeof( hdr ) );
        if( rc != sizeof( hdr ) )
            return( IMG_ERR_READ );

        /* Read the extended track map. */
        rc = cb->read( img, &ext, sizeof( ext ) );
        if( rc != sizeof( ext ) )
            return( IMG_ERR_READ );
        cur_ofs += sizeof( ext );
    }

    cur_ofs += sizeof( hdr );

    /* Allocate a buffer for uncompressed track data. */
    hdcp->track_buf = cb->m_alloc( hdr.num_sec * IMG_SEC_SZ_DEF );
    if( !hdcp->track_buf )
        return( IMG_ERR_MEM_ALLOC );

    /* Copy the header + extension to context structure. */
    hdcp->hdr = hdr;
    if( new_format ) {
        hdcp->ext = ext;
    }

    /* Build a table of file offsets of each track in image. */
    num_trk = (hdcp->hdr.max_cyl + 1) * 2;
    for( trk = 0; trk < num_trk; ++trk ) {
        /* NB: It is unclear what difference, if any, there is between
         * sectors marked as '1' vs. '2' in the sector map. Both contain
         * RLE-compressed data.
         */
        if( hdcp->hdr.trk_map[trk] == 1 || hdcp->hdr.trk_map[trk] == 2 ) {
            rc = cb->read( img, &blk_len, sizeof( blk_len ) );
            if( rc != sizeof( blk_len ) )
                return( IMG_ERR_READ );

            /* Track offsets point to the word containing the compressed
             * block size (followed by escape byte and actual data).
             */
            hdcp->trk_ofs[trk] = cur_ofs;
            cur_ofs += blk_len + sizeof( blk_len );
            cb->seek( img, cur_ofs );
        } else {
            assert( !hdcp->hdr.trk_map[trk] );
            hdcp->trk_ofs[trk] = 0;         /* Track not in image. */
        }
    }

    /* Check the file size. If it matches, image is likely good. */
    if( cb->fsize( img ) != cur_ofs )
        return( IMG_ERR_BAD_IMG );

    /* Fill out the rest of the context structure. */
    hdcp->imgf       = img;
    hdcp->trks       = num_trk;
    hdcp->spt        = hdr.num_sec;
    hdcp->heads      = 2;
    hdcp->new_format = new_format;
    hdcp->track_len  = hdr.num_sec * IMG_SEC_SZ_DEF;
    hdcp->trk_in_buf = -1;                          /* Nothing buffered. */
    return( IMG_OK );
}

/* Decompress a single data block (track). */
int hdcp_decomp_blk( img_fns *cb, hdcp_ctx *hdcp, uint8_t *buffer )
{
    cblk_hdr    cbhdr;
    int         rc = 0;
    int         nb;
    uint8_t     *cbuf = NULL;
    unsigned    comp_len;
    uint8_t     *s;
    uint8_t     *d;
    uint8_t     pat;
    uint8_t     rep;

    do {
        /* Read the block header. */
        nb = cb->read( hdcp->imgf, &cbhdr, sizeof( cbhdr ) );
        if( nb != sizeof( cbhdr ) ) {
            rc = IMG_ERR_READ;
            break;
        }

        /* Allocate memory for compressed block. Note that the block
         * length includes the byte defining the escape.
         */
        comp_len = cbhdr.length_hi * 256 + cbhdr.length_lo - 1;
        cbuf = cb->m_alloc( comp_len );
        if( !cbuf ) {
            rc = IMG_ERR_MEM_ALLOC;
            break;
        }

        /* Read compressed data. */
        nb = cb->read( hdcp->imgf, cbuf, comp_len );
        if( nb != comp_len ) {
            rc = IMG_ERR_READ;
            break;
        }

        /* And now decompress the data. */
        s = cbuf;
        d = buffer;
        while( s < cbuf + comp_len ) {
            if( *s == cbhdr.escape ) {
                ++s;            /* Skip escape byte. */
                pat = *s++;     /* Read pattern byte. */
                rep = *s++;     /* Read repeat count. */
                memset( d, pat, rep );
                d += rep;
            } else {
                *d++ = *s++;
            }
        }
        /* Calculate the size of decompresed data. */
        rc = d - buffer;
    } while( 0 );

    if( cbuf )
        cb->m_free( cbuf );
    return( rc );
}

/* Read and decompress a specified track. */
int hdcp_read_track( img_fns *cb, hdcp_ctx *hdcp, int track_num )
{
    unsigned    rc;

    if( hdcp->hdr.trk_map[track_num] ) {
        /* Read and decompress track. */
        cb->seek( hdcp->imgf, hdcp->trk_ofs[track_num] );
        rc = hdcp_decomp_blk( cb, hdcp, hdcp->track_buf );
        /* If decompression succeeded but didn't return the expected
         * amount of data, the input data was probably corrupted.
         */
        if( rc > 0 && rc != hdcp->track_len )
            rc = IMG_ERR_DECODE;
    } else {
        /* Fill with specified format byte.*/
        memset( hdcp->track_buf, FMT_BYTE, hdcp->track_len );
        rc = hdcp->track_len;
    }
    hdcp->trk_in_buf = track_num;
    return( rc );
}

/* Read a single sector from the image. */
int hdcp_read_sect( img_fns *cb, hdcp_ctx *hdcp, int sect_num, void *buf )
{
    long        sec_ofs;
    int         track_num;
    int         rc;

    /* Check if we're within the image. */
    track_num = sect_num / hdcp->spt;
    if( track_num >= hdcp->trks )
        return( IMG_ERR_NO_SECT );

    /* Read and decompress a track unless it's already buffered.
     * Works very well for sequential access.
     */
    if( hdcp->trk_in_buf != track_num ) {
        rc = hdcp_read_track( cb, hdcp, track_num );
        if( rc < 0 )
            return( rc );
        assert( rc == hdcp->track_len );
    }

    /* Calculate the sector offset in track buffer. */
    sec_ofs = sect_num % hdcp->spt * IMG_SEC_SZ_DEF;
    assert( sec_ofs + IMG_SEC_SZ_DEF <= hdcp->track_len );
    memcpy( buf, hdcp->track_buf + sec_ofs, IMG_SEC_SZ_DEF );

    return( IMG_SEC_SZ_DEF );
}

/* Close an image once all accesses are completed. */
void hdcp_close( img_fns *cb, hdcp_ctx *hdcp )
{
    assert( hdcp );
    assert( hdcp->track_buf );
    cb->m_free( hdcp->track_buf );
}
