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
#include "img_dim.h"

/* The DIM diskette image format was used by Disk Image Archiver, written by
 * Ray Arachelian in 1992-1993. The DIM format is relatively simple, supporting
 * images with constant sector size and uniform sectors per track count. There
 * are no provisions for compression or leaving out unused sectors.
 */

/* Size of the signature string. */
#define DIM_SIG      0x50

#define DIM_MAGIC_SZ 18
static const char dim_magic[] = "Disk IMage VER 1.0";

/* DIM image header. */
typedef struct dim_hdr {
    uint8_t     unknown;        /* Not sure what this is? */
    uint8_t     max_trk;        /* Last track (zero-based). */
    uint8_t     num_sec;        /* Sectors per track. */
    uint8_t     max_head;       /* Last head (zero-based). */
} dim_hdr;

typedef struct dim_ctx {
    img_file    imgf;           /* Image file handle. */
    uint8_t     trks;           /* Number of tracks. */
    uint8_t     spt;            /* Sectors per track. */
    uint8_t     heads;          /* Number of heads (1 or 2). */
    dim_hdr     hdr;            /* The image header. */
    long        start_ofs;      /* File offset of the first sector. */
} dim_ctx;

/* Identify a DIM format image. Does not validate image. */
int dim_identify( img_fns *cb, img_file img )
{
    char    magic[DIM_MAGIC_SZ];
    int     rc;

    /* Look for a magic string - sufficient to identify format. */
    rc = cb->read( img, &magic, sizeof( magic ) );
    if( rc != sizeof( magic ) )
        return( 0 );

    if( memcmp( magic, dim_magic, DIM_MAGIC_SZ ) )
        return( 0 );
    else
        return( sizeof( dim_ctx ) );
}

/* Open an image for access. May fail if image is damaged. */
int dim_open( img_fns *cb, img_file img, dim_ctx *dim )
{
    int         rc;
    int         img_sec;
    long        img_size;
    dim_hdr     hdr;

    /* Read the image format header. */
    cb->seek( img, DIM_SIG );
    rc = cb->read( img, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( IMG_ERR_READ );

    /* Do a basic sanity check on the header. Somewhat arbitrary. */
    if( hdr.max_trk > 100 || hdr.max_head > 1 || hdr.num_sec > 36 )
        return( IMG_ERR_BAD_IMG );

    /* Verify image size. If it matches, image is likely to be good. */
    img_sec = (hdr.max_trk + 1) * hdr.num_sec * (hdr.max_head + 1);
    img_size = DIM_SIG + sizeof( dim_hdr );
    dim->start_ofs = img_size;
    img_size += img_sec * (IMG_SEC_SZ_DEF + 1L);
    if( img_size != cb->fsize( img ) )
        return( IMG_ERR_BAD_IMG );

    dim->imgf  = img;
    dim->trks  = hdr.max_trk + 1;
    dim->spt   = hdr.num_sec;
    dim->heads = hdr.max_head + 1;
    dim->hdr   = hdr;
    return( IMG_OK );
}

/* Read a single sector from the image. */
int dim_read_sect( img_fns *cb, dim_ctx *dim, int sect_num, void *buf )
{
    long    sec_ofs;

    /* Calculate the sector offset. Note the per-sector byte data. */
    sec_ofs = dim->start_ofs + (long)sect_num * IMG_SEC_SZ_DEF;
    /* Skip 8 bytes at the end of every track. */
    sec_ofs += sect_num / dim->spt * 8; //@todo - accurate?
    /* Read the sector from image file. */
    cb->seek( dim->imgf, sec_ofs );
    return( cb->read( dim->imgf, buf, IMG_SEC_SZ_DEF ) );
}

/* Close an image once all accesses are completed. */
void dim_close( img_fns *cb, dim_ctx *dim )
{
    assert( dim );
}
