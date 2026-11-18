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
#include "img_drdi.h"


/* The DiskImage diskette image format was developed by Digital Research
 * circa 1990. The images were produced by the DISKCOPY utility shipped
 * with DR DOS 6.0/7.0 and the format was also used by Novell and Caldera.
 * No official documentation of this format is known to exist.
 *
 * DiskImage files appear to be effectively raw floppy images with added
 * fixed-length trailer at the end. There is standard file extension;
 * .img and .144 extensions have been used for 1.44M floppy images, while .720
 * and .120 extensions have been used for 720K and 1.2M images, respectively.
 *
 * DISKCOPY is only capable of copying disks for which DOS is able to build
 * a BPB. That is, DISKCOPY can image DOS disks without a BPB (such as DOS
 * 1.x disks) but not non-DOS disks (e.g. various UNIX disks).
 *
 * Note that the trailer is not sector-sized, which means that a quick check
 * can be done on the image size; file size modulo sector size (512) must
 * equal trailer size (419).
 *
 * The trailer consists of three sections:
 *  - signature string (ASCIIZ), 51 bytes
 *  - data section, 184 bytes
 *  - another data section, 184 bytes
 *  (419 bytes total)
 *
 *  The following is guesswork:
 *
 *  The first data section is the source disk "descriptor", whereas the
 *  second is the destination disk descriptor. Since the image file must
 *  have been created from a disk, the first descriptor corresponds to the
 *  source disk and the second to the destination (actual) image file.
 *
 *  In almost all cases, both descriptors are identical. However, they can
 *  differ, notably when the DISKCOPY /1 switch is used on a double-sided
 *  source disk.
 *
 *  The image descriptor is designed to directly plug into the DOS
 *  Get/Set Device Parameters generic IOCTL. For details, see the IBM
 *  PC DOS 7 Technical Update, Document Number GG24-4459-00, pages 288-292.
 *
 *  The second byte contains the IOCTL device type defined as follows (table
 *  courtesy of IBM):
 *
 *   0 = 320/360 KB 5.25 inch
 *   1 = 5.25 inch, 1.2 MB
 *   2 = 3.5 inch, 720 KB
 *   3 = 8-inch single-density
 *   4 = 8-inch double-density
 *   5 = Hard disk
 *   6 = Tape drive
 *   7 = 3.5 inch, 1.44 MB
 *   8 = Read/Write Optical devices
 *   9 = 3.5 inch, 2.88 MB
 *
 *  Only types 0, 1, 2, 7, and possibly 9 will occur in practice.
 *
 *  The entire trailer is largely irrelevant. Since the image format only
 *  works with standard DOS floppies, generic raw image detection logic is
 *  sufficient in almost all cases. However, the image descriptor does
 *  provide unambiguous geometry information should it be needed.
 */


/* Known signature strings. */
static const char drdi_magic[] = "DiskImage 2.01 (C) 1990,1991 Digital Research Inc.";
#define DRDI_MAGIC_SZ       sizeof( drdi_magic )

#define DRDI_TRAILER_SZ     419     /* Size of the image trailer. */

#pragma pack(1)

/* Disk/image descriptor in the trailer. */
typedef struct drdi_desc_s {
    uint8_t     spec_fn;        /* IOCTL special function. */
    uint8_t     dev_type;       /* IOCTL device type. */
    uint16_t    dev_attr;       /* IOCTL device attributes. */
    uint16_t    num_cyls;       /* IOCTL number of cylinders. */
    uint8_t     media_type;     /* IOCTL media type (zero). */
    uint16_t    bpb_bps;        /* BPB bytes per sector. */
    uint8_t     bpb_spc;        /* BPB sectors per cluster. */
    uint16_t    bpb_resv;       /* BPB reserved sectors. */
    uint8_t     bpb_fats;       /* BPB number of FATs. */
    uint16_t    bpb_root_e;     /* BPB root dir entries. */
    uint16_t    bpb_total;      /* BPB total sectors. */
    uint8_t     bpb_mdesc;      /* BPB media descriptor. */
    uint16_t    bpb_spf;        /* BPB sectors per FAT. */
    uint16_t    bpb_spt;        /* BPB sectors per track. */
    uint16_t    bpb_heads;      /* BPB number of heads. */
    uint32_t    bpb_hidden;     /* BPB hidden sectors. */
    uint32_t    bpb_etotal;     /* BPB extended total sectors. */
    uint8_t     bpb_resvd[6];   /* BPB reserved bytes.*/
    uint16_t    trk_sect;       /* Sectors per track. */
    uint8_t     trk_layout[144];/* Zeros, room for 36 sectors (4b each). */
} drdi_desc;

#pragma pack()

typedef struct drdi_ctx {
    img_file    imgf;           /* Image file handle. */
    unsigned    n_sect;         /* Number of sectors in image. */
    uint8_t     n_cyls;         /* Number of cylinders ("tracks"). */
    uint8_t     spt;            /* Sectors per track. */
    uint16_t    sec_sz;         /* Bytes per sector. */
    uint8_t     heads;          /* Number of heads (1 or 2). */
    bool        one_side;       /* Two-sided floppy imaged with /1 switch. */
} drdi_ctx;


/* Identify a DR DiskImage format image. Does not validate image. */
int drdi_identify( img_fns *cb, img_file imgf )
{
    long        img_size;
    char        magic[DRDI_MAGIC_SZ];
    int         rc;

    /* First check the image size. */
    img_size = cb->fsize( imgf );

    /* If it's too big, don't even bother. */
    if( img_size > 4 * 1024L * 1024 )
        return( 0 );

    /* See if it's an integral number of 512-byte sectors + trailer. */
    if( img_size % IMG_SEC_SZ_DEF != DRDI_TRAILER_SZ )
        return( 0 );

    /* Look for the magic strings - if found, The likelihood of a
     * false positive is vanishingly small.
     */
    cb->seek( imgf, img_size - DRDI_TRAILER_SZ );
    rc = cb->read( imgf, &magic, sizeof( magic ) );
    if( rc != sizeof( magic ) )
        return( 0 );

    if( memcmp( magic, drdi_magic, DRDI_MAGIC_SZ ) )
        return( 0 );
    else
        return( sizeof( drdi_ctx ) );
}

/* Open an image for access. May fail if image is damaged. */
int drdi_open( img_fns *cb, img_file imgf, drdi_ctx *ctx )
{
    long        img_size;
    drdi_desc   dsk_desc;
    drdi_desc   img_desc;
    int         rc;
    int         i;

    /* Check if the data copies match. */
    img_size = cb->fsize( imgf );
    cb->seek( imgf, img_size - DRDI_TRAILER_SZ + DRDI_MAGIC_SZ );
    rc = cb->read( imgf, &dsk_desc, sizeof( dsk_desc ) );
    if( rc != sizeof( dsk_desc ) )
        return( IMG_ERR_READ );

    rc = cb->read( imgf, &img_desc, sizeof( img_desc ) );
    if( rc != sizeof( img_desc ) )
        return( IMG_ERR_READ );

    /* If the data isn't identical, the image is corrupted... */
    if( memcmp( &dsk_desc, &img_desc, sizeof( drdi_desc ) ) ) {
        /* ... except one side of the disk could be omitted. */
        dsk_desc.bpb_heads = img_desc.bpb_heads;
        /* If it's still different, bail. */
        if( memcmp( &dsk_desc, &img_desc, sizeof( drdi_desc ) ) )
            return( IMG_ERR_BAD_IMG );
        ctx->one_side = true;
    }

    /* The trk_layout area should be all zeros. */
    for( i = 0; i < sizeof( img_desc.trk_layout ); ++i ) {
        if( img_desc.trk_layout[i] )
            return( IMG_ERR_BAD_IMG );
    }

    /* Bail if image dropped one side. This could be supported but the
     * likelihood that the image is actually any good is slim. Note that
     * images of actual one-sided floppies will work fine.
     */
    if( ctx->one_side )
        return( IMG_ERR_CANT_CONV );

    /* Bail if the sector size isn't 512. */
    if( img_desc.bpb_bps != IMG_SEC_SZ_DEF )
        return( IMG_ERR_CANT_CONV );

    /* Calculate the number of sectors in image. */
    ctx->n_sect = (img_size - DRDI_TRAILER_SZ) / img_desc.bpb_bps;

    /* Make sure the number of sectors in image matches the BPB. */
    if( ctx->n_sect != img_desc.bpb_total )
        return( IMG_ERR_BAD_IMG );

    ctx->imgf   = imgf;
    ctx->sec_sz = img_desc.bpb_bps;
    ctx->n_cyls = img_desc.num_cyls;
    ctx->spt    = img_desc.bpb_spt;
    ctx->heads  = img_desc.bpb_heads;

    /* Note that if everything checked out, we treat the image as
     * a standard raw image. If we decided to support images with
     * one side missing, that would have to change.
     */
    return( IMG_OK );
}

/* Read a single sector from the image. */
int drdi_read_sect( img_fns *cb, drdi_ctx *ctx, int sect_num, void *buf )
{
    long    sec_ofs;

    /* Check if we're within the image. */
    if( sect_num >= ctx->n_sect )
        return( IMG_ERR_NO_SECT );

    /* Calculate the sector offset. */
    sec_ofs = (long)sect_num * ctx->sec_sz;

    /* Read the sector from image file. */
    cb->seek( ctx->imgf, sec_ofs );
    return( cb->read( ctx->imgf, buf, ctx->sec_sz ) );
}

/* Close an image once all accesses are completed. */
void drdi_close( img_fns *cb, drdi_ctx *ctx )
{
    assert( ctx );
}
