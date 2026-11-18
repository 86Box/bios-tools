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
#include "img_raw.h"


/* The raw image format assumes 512-byte sectors with a uniform number of
 * sectors per track and no gaps.
 * There is no bulletproof way to identify a raw image as the contents could
 * be anything; however, a good guess can be made based on the image file
 * size.
 */

typedef struct raw_ctx {
    img_file    imgf;           /* Image file handle. */
    uint8_t     trks;           /* Number of tracks. */
    uint8_t     spt;            /* Sectors per track. */
    uint8_t     heads;          /* Number of heads (1 or 2). */
} raw_ctx;


/* Identify a raw image. An educated guess. */
int raw_identify( img_fns *cb, img_file imgf )
{
    long    img_size;

    /* Heuristics based on the image size... */
    img_size = cb->fsize( imgf );

    /* If image isn't a multiple of sector size, can't be valid. */
    if( img_size % IMG_SEC_SZ_DEF )
        return( 0 );

    /* If image is smaller than about 15K, reject it. */
    if( img_size < 15 * 1024L )
        return( 0 );

#if 0
    /* Disabled check for working with hard disk images. */
    /* If image is bigger than about 3M, reject it. */
    if( img_size > 3200 * 1024L )
        return( 0 );
#endif

    /* Hope for the best... */
    return( sizeof( raw_ctx ) );
}

/* Open an image for access. */
int raw_open( img_fns *cb, img_file imgf, raw_ctx *raw )
{
//    int         img_sec;

    /* Not much to do here... */
    raw->imgf  = imgf;
//    raw->trks  = hdr.max_trk + 1;
//    raw->spt   = hdr.num_sec;
//    raw->heads = hdr.max_head + 1;
    return( IMG_OK );
}

/* Read a single sector from the image. */
int raw_read_sect( img_fns *cb, raw_ctx *raw, int sect_num, void *buf )
{
    long    sec_ofs;

    /* Calculate the sector offset. */
    sec_ofs = (long)sect_num * IMG_SEC_SZ_DEF;
    /* Read the sector from image file. */
    cb->seek( raw->imgf, sec_ofs );
    return( cb->read( raw->imgf, buf, IMG_SEC_SZ_DEF ) );
}

/* Close an image once all accesses are completed. */
void raw_close( img_fns *cb, raw_ctx *raw )
{
    assert( raw );
}
