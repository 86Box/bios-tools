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
#include "img_dskf.h"
#include "dsk_lzmw.h"


/* The IBM DSKF format was developed by IBM in 1989 and extended in 1993. The
 * LoadDskF utility was commonly used to load .DSK images onto floppies.
 *
 * The DSKF image format is geared towards DOS-formatted floppies and unlikely
 * to handle non-FAT floppies.
 *
 * The older 'X' variant (signature AAh 58h, or AAh followed by ASCII 'X') uses
 * a fixed size 512-byte header which includes a comment (the comment typically
 * consists of a single null byte). The image header contains disk geometry
 * along with most of the BPB contents.
 *
 * The data area contains the disk sectors stored sequentially without any
 * per-sector or per-track headers. The last block of unallocated clusters is
 * not stored in the image. A simple checksum calculated over all sectors
 * stored in the image protects the image integrity.
 *
 * Note that unallocated clusters have effectively undefined contents as they
 * are not read during image creation and the LoadDskF utility does not write
 * them at all. For the purposes of this library, sectors not provided in the
 * image are considered to be freshly formatted.
 *
 * The newer 'Y' variant uses a variable-size header but is otherwise not very
 * different.
 *
 * The 'Z' variant is much like 'Y' except the data sectors are compressed. The
 * compression algorithm used is LZMW (Lempel-Ziv-Miller-Wegman), not widely
 * used but reasonably efficient algorithm. Like many other algorithms, LZMW is
 * ineffective on high-entropy input (typically compressed data). Certain IBM
 * tools which produce DSKF images appear to be unaware of this. A 1.44M floppy
 * can thus be "compressed" into a 1.8M DSKF image.
 *
 * In theory, the DSKF format could handle any floppy with a fixed geometry
 * (constant sector and track sizes), however it is not known to have been used
 * with any floppies other than standard 360K/720K/1.2M/1.44M/2.88M formats.
 * There are no provisions for storing bad sectors.
 *
 * The DSKF image format is not publicly documented. Much information about the
 * format has been gleaned from analyzing the LoadDskF utility.
 *
 */


/* The first byte of a DSKF image. */
#define DSKF_MAGIC      0xAA

/* The size of checksum validation buffer in sectors. */
#define DSKF_CKSUM_BUF_SECT     32

/* Decompression buffer is set to 3MB. A 3.5" ED disk image ought to
 * fit in that. If it doesn't, the compressed data is probably
 * garbled.
 */
#define DECOMP_BUF_SZ   (1024UL * 1024 * 2)

/* DSKF image header. */
#pragma pack(1)
typedef struct dskf_hdr {
    uint8_t     magic;          /* Must be DSKF_MAGIC. */
    uint8_t     variant;        /* 'X', 'Y', or 'Z'. */
    uint8_t     media_desc;     /* Media descriptor byte. */
    uint8_t     unused;         /* Unused/unknown. */
    uint16_t    sect_size;      /* Bytes per sector. */
    uint8_t     clust_sects_1;  /* Sectors per cluster - 1. */
    uint8_t     unknown;        /* Unclear purpose. */
    uint16_t    resvd_sects;    /* Reserved sectors. */
    uint8_t     fat_copies;     /* Number of FAT copies. */
    uint16_t    root_entries;   /* Root directory entries. */
    uint16_t    data_sects_1;   /* Number of data sectors - 1. */
    uint16_t    clusters;       /* Number of clusters. */
    uint8_t     fat_sects;      /* Sectors per FAT. */
    uint16_t    root_sects_1;   /* Root directory sectors - 1. */
    uint32_t    checksum;       /* Data area checksum. */
    uint16_t    num_cyl;        /* Number of cylinders. */
    uint16_t    num_head;       /* Number of heads. */
    uint16_t    num_sec;        /* Number of sectors per track. */
    uint32_t    spare;          /* Spare/unused. */
    uint16_t    sects_stored;   /* Number of sectors in image. */
    uint16_t    comment_ofs;    /* Offset of comment from image start. */
    uint16_t    data_ofs;       /* Offset of data from image start. */
} dskf_hdr;
#pragma pack()

/* File (regular or compressed) access context. */
typedef struct dskf_file_ctx {
    img_fns     *cb;                    /* Image helpers. */
    img_file    imgf;                   /* Uncompressed image file. */
    bool        cmprsd;                 /* Compressed file flag. */
    long        mbuf_ofs;               /* Offset in decompressed data. */
    long        mbuf_sz;                /* Size of decompressed data. */
    long        start_ofs;              /* File offset of the first sector. */
    uint8_t     *mbuf;                  /* Decompression buffer. */
} dskf_file_ctx;

/* Context structure for DSKF format. */
typedef struct dskf_ctx {
    img_file        imgf;               /* Image file handle. */
    dskf_file_ctx   fctx;               /* DSKF file context. */
    uint8_t         trks;               /* Number of tracks. */
    uint8_t         spt;                /* Sectors per track. */
    uint8_t         heads;              /* Number of heads (1 or 2). */
    dskf_hdr        hdr;                /* The image header. */
    uint16_t        img_sect;           /* Total number of sectors in image. */
    uint16_t        tot_sect;           /* Total number of sectors on disk. */
    long            start_ofs;          /* File offset of the first sector. */
    long            end_ofs;            /* File offset just past the last sector. */
    long            *sect_map;          /* Map of all sector file offsets. */
    char            *comment;           /* Optional comment. */
} dskf_ctx;


/* Read from a file or a decompressed buffer. */
size_t dskf_read( dskf_file_ctx *fctx, void *buf, size_t cnt )
{
    size_t  rc;

    if( fctx->cmprsd ) {
        size_t  max_avl;
        size_t  ncpy;

        max_avl = fctx->mbuf_sz - fctx->mbuf_ofs;
        if( max_avl < cnt )
            ncpy = max_avl;
        else
            ncpy = cnt;
        memcpy( buf, fctx->mbuf + fctx->mbuf_ofs, ncpy );
        fctx->mbuf_ofs += ncpy;
        rc = ncpy;
    } else {
        rc = fctx->cb->read( fctx->imgf, buf, cnt );
    }
    return( rc );
}

/* Seek in a file or a decompressed buffer. */
void dskf_seek( dskf_file_ctx *fctx, long pos )
{
    if( fctx->cmprsd ) {
        /* The header is not part of decompressed data. */
        fctx->mbuf_ofs = pos - fctx->start_ofs;
    } else {
        fctx->cb->seek( fctx->imgf, pos );
    }
}


/* Compute/update a checksum given a block of data. Note that the checksum
 * is 32-bit but adds 16-bit words (not 32-bit dwords!).
 */
static uint32_t dskf_calc_csum( const void *p, unsigned len, uint32_t csum )
{
    const uint16_t  *data = p;
    int             i;

    assert( !(len & 1) );
    len /= 2;
    for( i = 0; i < len; ++i) {
        csum += *data++;
    }
    return( csum );
}

/* Validate the disk contents using the stored checksum. */
static int dskf_validate_image( img_fns *cb, dskf_ctx *dskf, uint32_t img_cksum )
{
    uint32_t    cksum = 0;
    uint16_t    sects_left;
    uint16_t    sects_read;
    void        *data_buf;
    int         rc;

    assert( dskf->img_sect );

    data_buf = cb->m_alloc( DSKF_CKSUM_BUF_SECT * IMG_SEC_SZ_DEF );
    if( data_buf ) {
        dskf_seek( &dskf->fctx, dskf->start_ofs );
        sects_left = dskf->img_sect;
        /* Read all sectors in image and calculate checksum. */
        while( sects_left ) {
            if( sects_left > DSKF_CKSUM_BUF_SECT )
                sects_read = DSKF_CKSUM_BUF_SECT;
            else
                sects_read = sects_left;
            rc = dskf_read( &dskf->fctx, data_buf, sects_read * IMG_SEC_SZ_DEF );
            if( rc != sects_read * IMG_SEC_SZ_DEF ) {
                rc = IMG_ERR_READ;
                break;
            }
            /* Update the checksum. */
            cksum = dskf_calc_csum( data_buf, sects_read * IMG_SEC_SZ_DEF, cksum );
            sects_left -= sects_read;
        }

        /* Does it match? */
        if( !sects_left ) {
            if( cksum == img_cksum )
                rc = IMG_OK;
            else
                rc = IMG_ERR_CSUM;
        }
        cb->m_free( data_buf );
    } else {
        rc = IMG_ERR_MEM_ALLOC;
    }
    return( rc );
}

/* Identify a DSKF format image. Does not validate the image. */
int dskf_identify( img_fns *cb, img_file img )
{
    dskf_hdr    hdr;
    int         rc;

    assert( sizeof( hdr ) == 0x28 );

    /* Read the header and check the magic. */
    cb->seek( img, 0 );
    rc = cb->read( img, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( 0 );
    if( hdr.magic != DSKF_MAGIC )
        return( 0 );

    /* Run a few more check to ascertain whether this is a DSKF image. */
    if( hdr.variant < 'X' || hdr.variant > 'Z' )
        return( 0 );

    if( hdr.sect_size != IMG_SEC_SZ_DEF )
        return( 0 );
    else
        return( sizeof( dskf_ctx ) );
}

/* Open an image for access. May fail if image is damaged. */
int dskf_open( img_fns *cb, img_file imgf, dskf_ctx *dskf )
{
    int         nb;
    uint16_t    cmt_len;
    dskf_hdr    hdr;
    int         rc;

    /* Read the image format header. */
    cb->seek( imgf, 0 );
    nb = cb->read( imgf, &hdr, sizeof( hdr ) );
    if( nb != sizeof( hdr ) )
        return( IMG_ERR_READ );

    /* Do a basic sanity check on the header. Somewhat arbitrary. */
    if( hdr.num_cyl > 80 || hdr.num_head > 2 || hdr.num_sec > 36 )
        return( IMG_ERR_BAD_IMG );

    /* Fill in the context structure. */
    dskf->imgf  = imgf;
    dskf->trks  = hdr.num_cyl;
    dskf->spt   = hdr.num_sec;
    dskf->heads = hdr.num_head;
    dskf->hdr   = hdr;

    /* Process data area parameters. */
    dskf->start_ofs = hdr.data_ofs;
    dskf->img_sect  = hdr.sects_stored;
    dskf->tot_sect  = dskf->trks * dskf->heads * dskf->spt;

    /* Set up the file context. */
    dskf->fctx.cb        = cb;
    dskf->fctx.imgf      = imgf;
    dskf->fctx.cmprsd    = false;
    dskf->fctx.mbuf_ofs  = 0;
    dskf->fctx.mbuf_sz   = 0;
    dskf->fctx.start_ofs = hdr.data_ofs;

    /* If the image is compressed, try to decompress it. */
    if( hdr.variant == 'Z' ) {
        void    *deco_buf;

        deco_buf = cb->m_alloc( DECOMP_BUF_SZ );
        if( !deco_buf )
            return( IMG_ERR_MEM_ALLOC );

        dskf->fctx.cmprsd = true;
        dskf->fctx.mbuf   = deco_buf;

        /* Seek to the start of (compressed) sector data. */
        cb->seek( imgf, dskf->start_ofs );

        dskf->fctx.mbuf_sz = dskf_unpack_lzmw( cb, imgf, dskf->fctx.mbuf, DECOMP_BUF_SZ );
        if( !dskf->fctx.mbuf_sz )
            return( IMG_ERR_DECOMP );
    }

    /* Validate the image. */
    rc = dskf_validate_image( cb, dskf, hdr.checksum );
    if( rc != IMG_OK )
        return( rc );

    /* Read the comment if longer than 1 byte. */
    cmt_len = hdr.data_ofs - hdr.comment_ofs;
    if( cmt_len > 1 ) {
        dskf->comment = cb->m_alloc( cmt_len );
        cb->seek( imgf, hdr.comment_ofs );
        nb = cb->read( imgf, dskf->comment, cmt_len );
        if( nb != cmt_len ) {
            /* Failed to read comment, clean up. Not fatal. */
            cb->m_free( dskf->comment );
            dskf->comment = NULL;
        }
    }

    return( IMG_OK );
}

/* Query the comment string. Returns NULL if no comment provided. */
const char *dskf_query_comment( img_fns *cb, dskf_ctx *dskf )
{
    return( dskf->comment );
}

/* Read a single sector from the image. */
int dskf_read_sect( img_fns *cb, dskf_ctx *dskf, int sect_num, void *buf )
{
    long        sec_ofs;
    int         rc = IMG_SEC_SZ_DEF;

    if( sect_num >= dskf->tot_sect ) {
        /* Attempting to read just past end of image. */
        assert( sect_num == dskf->tot_sect );
        rc = IMG_ERR_NO_SECT;
    } else if( sect_num >= dskf->img_sect ) {
        memset( buf, FMT_BYTE, IMG_SEC_SZ_DEF );
    } else {
        /* Calculate the sector offset in file. */
        sec_ofs = dskf->start_ofs + sect_num * IMG_SEC_SZ_DEF;

        /* Read the sector data. */
        dskf_seek( &dskf->fctx, sec_ofs );
        rc = dskf_read( &dskf->fctx, buf, IMG_SEC_SZ_DEF );
    }
    return( rc );
}

/* Close an image once all accesses are completed. */
void dskf_close( img_fns *cb, dskf_ctx *dskf )
{
    assert( dskf );
    if( dskf->comment )
        cb->m_free( dskf->comment );

    if( dskf->fctx.cmprsd )
        cb->m_free( dskf->fctx.mbuf );
}
