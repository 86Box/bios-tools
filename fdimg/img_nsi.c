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
#include "img_nsi.h"


/* The NorthStar image format is really a raw image, but it may use 256-byte
 * sectors and cannot be easily distinguished from a raw image with 512-byte
 * sectors.
 *
 * This driver detects NorthStar images based on their unique file sizes.
 * NorthStar disks were hard-sectored, with 10 sectors per track and 35
 * tracks per side. The common formats are:
 *
 * SSSD: Single sided, 35 tracks, 256-byte sectors :  89,600 bytes
 * SSDD: Single sided, 35 tracks, 512-byte sectors : 179,200 bytes
 * DSDD: Double sided, 70 tracks, 512-byte sectors : 358,400 bytes
 *
 * Note that single-sided NorthStar images *are* equivalent to raw images,
 * with the caveat that SSSD images have 256-byte sectors.
 *
 * Double-sided: TBD!!
 */

/* NSI file sizes. */
#define NSI_FSZ_SSSD    89600
#define NSI_FSZ_SSDD    (2 * NSI_FSZ_SSSD)
#define NSI_FSZ_DSDD    (2 * NSI_FSZ_SSDD)


typedef struct nsi_ctx {
    img_file    imgf;           /* Image file handle. */
    int         sec_sz;         /* Sector size (256 or 512). */
    uint8_t     trks;           /* Number of tracks. */
    uint8_t     spt;            /* Sectors per track. */
    uint8_t     heads;          /* Number of heads (1 or 2). */
} nsi_ctx;


/* Identify an NSI image. An educated guess. */
int nsi_identify( img_fns *cb, img_file imgf )
{
    long    img_size;

    /* Need to query the image size. */
    img_size = cb->fsize( imgf );

    /* If not one of three supported sizes, can't be NSI. */
    if( img_size != NSI_FSZ_SSSD && img_size != NSI_FSZ_SSDD && img_size != NSI_FSZ_DSDD )
        return( 0 );

    /* There's very good chance it is a NorthStar image... */
    return( sizeof( nsi_ctx ) );
}

/* Open an image for access. */
int nsi_open( img_fns *cb, img_file imgf, nsi_ctx *ctx )
{
    long    img_size;

    /* Need to query the image size again. */
    img_size = cb->fsize( imgf );

    /* At this point there's little we can do to further verify
     * a NorthStar image.
     */
    ctx->imgf = imgf;

    /* There are always 35 tracks, 10 spt. */
    ctx->trks  = 35;
    ctx->spt   = 10;

    switch( img_size ) {
    case NSI_FSZ_SSSD:
        ctx->sec_sz = 256;
        ctx->heads  = 1;
        break;
    case NSI_FSZ_SSDD:
        ctx->sec_sz = 512;
        ctx->heads  = 1;
        break;
    case NSI_FSZ_DSDD:
        ctx->sec_sz = 512;
        ctx->heads  = 2;
        break;
    default:
        assert( 0 );
    }

    return( IMG_OK );
}

/* Read a single sector from the image. */
int nsi_read_sect( img_fns *cb, nsi_ctx *ctx, int sect_num, void *buf )
{
    long    sec_ofs;

    /* Calculate the sector offset. */
    sec_ofs = (long)sect_num * ctx->sec_sz;
    /* Read the sector from image file. */
    cb->seek( ctx->imgf, sec_ofs );
    return( cb->read( ctx->imgf, buf, ctx->sec_sz ) );
}

/* Close an image once all accesses are completed. */
void nsi_close( img_fns *cb, nsi_ctx *ctx )
{
    assert( ctx );
}
