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
#include "img_hdk.h"


/* The MAXI Disk image format (HDK) was developed by Herne Data Systems.
 * The company offered MAXI-71 (aka MAXI-1571) and MAXI-81 (aka MAXI-1581)
 * utilities for the Commodore 64 and 128 in the 1980s. The goal of the
 * utilities was to maximize the storage capacity of floppies.
 *
 * In the late 1980s, Herne Data Systems branched into the PC market
 * and developed MAXI Disk for DOS, and later for Windows.
 *
 * MAXI Disk can produce floppy images with .HDK file extension. The format
 * is very simple; the disk image is effectively a raw image with an 8-byte
 * header.
 *
 * It is unclear how old the HDK format is. MAXI Disk for PC versions 1.x
 * (1988-89) or 2.03 (1989) could only format floppies. The ability to copy
 * disks to/from image files may only have been introduced in MAXI Disk v4.1
 * for Windows (1997).
 *
 * The semantics of the HDK image header are pure guesswork. The format
 * appears to be fairly simple, effectively a raw image. There are no
 * provisions for compression, checksums, and the like. However, the format
 * can support custom non-DOS geometries and sector sizes other than 512.
 *
 * The disk type presumably corresponds to the table found at
 * http://www.herne.com/disks.htm :
 *
 * ID    Type 	    Kind    Size  	SPT    Cyls
 * -----------------------------------------------
 * 00  DOS 360K	    5.25"    360K	 9	40
 * 01  MAXI 420K    5.25"    420K	10	42
 * 02  DOS 720K	    3.5"     720K	 9	80
 * 03  MAXI 800K    3.5"     800K	10	80
 * 04  DOS 1.2M	    5.25"   1200K	15	80
 * 05  MAXI 1.4M    5.25"   1400K	17	82
 * 06  DOS 1.44M    3.5"    1440K	18	80
 * 07  MAXI 1.6M    3.5"    1600K	20	82
 * 08  DMF 1.7M     3.5"    1700K	21	82
 * 09  DOS 2.88M    3.5"    2880K	36	80
 * 0A  MAXI 3.2M    3.5"    3200K	39	82
 *
 * Images of single-sided disks have a type corresponding to the
 * double-sided variant, but only one head.
 *
 * The sector size code presumably corresponds to the NEC uPD765 FDC
 * definition, i.e. (128 << code).
 */


/* Image header. */
typedef struct hdk_hdr_s {
    uint8_t     unk0;           /* Version? Flags? Always 1. */
    uint8_t     dsk_type;       /* Disk type. */
    uint8_t     heads;          /* Number of heads. */
    uint8_t     n_cyls;         /* Number of cylinders (tracks) .*/
    uint8_t     sec_sz_code;    /* Sector size code. */
    uint8_t     spt;            /* Sectors per track. */
    uint8_t     unk1;           /* Unknown, always 1? */
    uint8_t     unk2;           /* Unknown, always 1? */
} hdk_hdr;


typedef struct hdk_ctx {
    img_file    imgf;           /* Image file handle. */
    unsigned    n_sect;         /* Number of sectors in image. */
    uint8_t     n_cyls;         /* Number of cylinders aka tracks. */
    uint8_t     spt;            /* Sectors per track. */
    uint16_t    sec_sz;         /* Bytes per sector. */
    uint8_t     heads;          /* Number of heads (1 or 2). */
} hdk_ctx;


/* Identify a MAXI Disk HDK format image. Does not validate image. */
int hdk_identify( img_fns *cb, img_file imgf )
{
    long        img_size;
    long        expected_size;
    long        sector_size;
    hdk_hdr     hdr;
    int         rc;

    /* First check the image size. */
    img_size = cb->fsize( imgf );

    /* If it's too big, don't even bother. */
    if( img_size > 4 * 1024L * 1024 )
        return( 0 );

    /* See if it's an integral number of 512-byte sectors + header. */
    if( img_size % IMG_SEC_SZ_DEF != sizeof( hdk_hdr ) )
        return( 0 );

    /* There is no magic string or anything; false positives are
     * guaranteed to happen. We need to validate the header so that
     * we don't erroneously claim images in a different format.
     */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* Expect all the unknown fields to be ones. If they're not,
     * we need to figure out what they really mean.
     */
    if( hdr.unk0 != 1 )
        return( 0 );
    if( hdr.unk1 != 1 )
        return( 0 );
    if( hdr.unk2 != 1 )
        return( 0 );

    /* Calculate the expected image size. If it matches the actual
     * file size, chances are extremely high that this is a HDK image.
     */
    sector_size   = 128 << hdr.sec_sz_code;
    expected_size = hdr.heads * hdr.n_cyls * hdr.spt * sector_size;
    if( expected_size != img_size - sizeof( hdr ) )
        return( 0 );

    /* The number of heads must strictly 1 or 2. */
    if( hdr.heads != 1 && hdr.heads != 2 )
        return( 0 );

    /* No known drives handle more than 85 tracks. */
    if( hdr.n_cyls > 85 )
        return( 0 );

    /* 16K is the max sector size supported by the uPD765 FDC. */
    if( sector_size > 16384 )
        return( 0 );

    return( sizeof( hdk_ctx ) );
}

/* Open an image for access. May fail if image is damaged. */
int hdk_open( img_fns *cb, img_file imgf, hdk_ctx *ctx )
{
    long        img_size;
    long        sector_size;
    hdk_hdr     hdr;
    int         rc;

    /* Read the image header. It's already partially validated. */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( IMG_ERR_READ );

    /* Bail if the sector size isn't 512. We could support sector sizes
     * other than 512 but probably won't ever see such images.
     */
    sector_size = 128 << hdr.sec_sz_code;
    if( sector_size != IMG_SEC_SZ_DEF )
        return( IMG_ERR_CANT_CONV );

    /* Calculate the number of sectors in image. */
    img_size = cb->fsize( imgf );
    ctx->n_sect = (img_size - sizeof( hdk_hdr ) ) / sector_size;

    /* Make sure the number of sectors in image matches the geometry. */
    if( ctx->n_sect != hdr.heads * hdr.n_cyls * hdr.spt )
        return( IMG_ERR_BAD_IMG );

    ctx->imgf   = imgf;
    ctx->sec_sz = sector_size;
    ctx->n_cyls = hdr.n_cyls;
    ctx->spt    = hdr.spt;
    ctx->heads  = hdr.heads;

    /* Note that if everything checked out, we treat the image as
     * a standard raw image.
     */
    return( IMG_OK );
}

/* Read a single sector from the image. */
int hdk_read_sect( img_fns *cb, hdk_ctx *ctx, int sect_num, void *buf )
{
    long    sec_ofs;

    /* Check if we're within the image. */
    if( sect_num >= ctx->n_sect )
        return( IMG_ERR_NO_SECT );

    /* Calculate the sector offset. */
    sec_ofs = (long)sect_num * ctx->sec_sz + sizeof( hdk_hdr );

    /* Read the sector from image file. */
    cb->seek( ctx->imgf, sec_ofs );
    return( cb->read( ctx->imgf, buf, ctx->sec_sz ) );
}

/* Close an image once all accesses are completed. */
void hdk_close( img_fns *cb, hdk_ctx *ctx )
{
    assert( ctx );
}
