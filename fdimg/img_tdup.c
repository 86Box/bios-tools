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
#include "img_tdup.h"


/* The Duplicator diskette image format was used by the eponymous DOS tool
 * used for duplicating floppies on a PC. The tool was developed by The Finot
 * Group of Mountain View, CA in the 1980s.
 *
 * All information about this format was obtained by analyzing available image
 * files and may not be entirely accurate.
 *
 * The format assumes uniform geometry with 512-byte sectors. The geometry
 * (heads/sectors per track/cylinders) is stored in the image.
 *
 * The image header is followed by a cylinder map. Provisions are made for
 * leaving empty cylinders out of the image.
 *
 * The format appears to store checksums for each cylinder and possibly the
 * header itself, but the algorithm is not known.
 *
 * An ASCII signature uniquely identifies this format.
 */

/* The signature string. */
static const char tdup_magic[] = "Image file of a diskette by THE DUPLICATOR\0\0\0\0\0";
#define TDUP_MAGIC_SZ       sizeof( tdup_magic )    /* 48 */

#define TDUP_OFS_HDR        0x40        /* Offset of the image header. */
#define TDUP_OFS_CYLMAP     0x60        /* Offset of the cylinder map. */

/* The Duplicator image header (at offset 40h). */
typedef struct tdup_hdr {
    uint16_t    version;                /* Maybe it's version? */
    uint16_t    num_heads;              /* Number of heads/sides. */
    uint16_t    num_sec;                /* Number of sectors per track. */
    uint16_t    num_cyls;               /* Number of cylinders. */
    uint16_t    unknown;                /* What could this be? */
    uint16_t    media;                  /* Maybe media type? */
} tdup_hdr;

/* Likely media type values; other types probably unsupported:
 * 1 = 360K, 2=720K, 3 = 1.2M, 4=1.44M
 */

/* The Duplicator cylinder information (at offset 60h). */
typedef struct tdup_cylnfo {
    uint16_t    cksum;                  /* Maybe cylinder checksum? */
    uint16_t    flags;                  /* Cylinder flags. */
    uint16_t    start;                  /* File offset in 512-byte units. */
    uint8_t     filler;                 /* Filler byte for left-out cyls. */
    uint8_t     junk;                   /* Maybe unused junk? */
} tdup_cylnfo;

/* Values for the 'flags' field of tdup_cylnfo. */
#define CYLFLG_IMGDATA      0x00        /* Cylinder stored in image file. */
#define CYLFLG_FILLER       0x02        /* Cylinder not stored, use filler. */

typedef struct tdup_ctx {
    img_file    imgf;                   /* Image file handle. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     spc;                    /* Sectors per cylinder. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    tdup_hdr    hdr;                    /* The image header. */
    tdup_cylnfo *cyl_map;               /* Per-cylinder information. */
    unsigned    cyl_len;                /* Length of single cylinder in bytes. */
    int         cyl_in_buf;             /* Cylinder currently in buffer. */
    uint8_t     *cyl_buf;               /* Cylinder buffer. */
} tdup_ctx;


/* Identify an image created by The Duplicator. Does not validate image. */
int tdup_identify( img_fns *cb, img_file img )
{
    char    magic[TDUP_MAGIC_SZ];
    int     rc;

    /* Look for a magic string - sufficient to identify format.
     * The likelihood of a false positive is vanishingly small.
     */
    cb->seek( img, 0 );
    rc = cb->read( img, &magic, sizeof( magic ) );
    if( rc != sizeof( magic ) )
        return( 0 );

    if( memcmp( magic, tdup_magic, TDUP_MAGIC_SZ ) )
        return( 0 );
    else
        return( sizeof( tdup_ctx ) );
}

/* Open an image for access. May fail if image is damaged. */
int tdup_open( img_fns *cb, img_file img, tdup_ctx *tdup )
{
    int         rc;
    tdup_hdr    hdr;
    uint16_t    cmap_len;

    /* Read the image format header. We already ensured it's sensible. */
    cb->seek( img, TDUP_OFS_HDR );
    rc = cb->read( img, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( IMG_ERR_READ );

    /* Allocate a buffer for cylinder data. */
    tdup->cyl_buf = cb->m_alloc( hdr.num_sec * hdr.num_heads * IMG_SEC_SZ_DEF );
    if( !tdup->cyl_buf )
        return( IMG_ERR_MEM_ALLOC );

    /* Allocate memory for the cylinder map. */
    cmap_len      = hdr.num_cyls * sizeof( tdup_cylnfo );
    tdup->cyl_map = cb->m_alloc( cmap_len );
    if( !tdup->cyl_map ) {
        cb->m_free( tdup->cyl_buf );
        return( IMG_ERR_MEM_ALLOC );
    }

    /* Read the cylinder map from the image. */
    cb->seek( img, TDUP_OFS_CYLMAP );
    rc = cb->read( img, tdup->cyl_map, cmap_len );
    if( rc != cmap_len ) {
        cb->m_free( tdup->cyl_buf );
        cb->m_free( tdup->cyl_map );
        return( IMG_ERR_READ );
    }

    /* Fill out the rest of the context structure. */
    tdup->imgf       = img;
    tdup->spt        = hdr.num_sec;
    tdup->spc        = hdr.num_sec * hdr.num_heads;
    tdup->heads      = hdr.num_heads;
    tdup->hdr        = hdr;
    tdup->cyl_len    = hdr.num_sec * IMG_SEC_SZ_DEF * hdr.num_heads;
    tdup->cyl_in_buf = -1;                          /* Nothing buffered. */
    return( IMG_OK );
}

/* Read a specified cylinder. */
int tdup_read_cylinder( img_fns *cb, tdup_ctx *tdup, int cyl_num )
{
    unsigned    rc;

    if( tdup->cyl_map[cyl_num].flags == CYLFLG_IMGDATA ) {
        uint32_t    cyl_ofs;

        /* Read cylinder data from file. */
        cyl_ofs = tdup->cyl_map[cyl_num].start * IMG_SEC_SZ_DEF;
        cb->seek( tdup->imgf, cyl_ofs );
        rc = cb->read( tdup->imgf, tdup->cyl_buf, tdup->cyl_len );
        if( rc != tdup->cyl_len )
            rc = IMG_ERR_READ;
    } else if( tdup->cyl_map[cyl_num].flags == CYLFLG_FILLER ) {
        uint8_t     filler;

        /* Fill with specified byte.*/
        filler = tdup->cyl_map[cyl_num].filler;
        memset( tdup->cyl_buf, filler, tdup->cyl_len );
        rc = tdup->cyl_len;
    } else
        rc = IMG_ERR_BAD_IMG;

    tdup->cyl_in_buf = cyl_num;
    return( rc );
}

/* Read a single sector from the image. */
int tdup_read_sect( img_fns *cb, tdup_ctx *tdup, int sect_num, void *buf )
{
    long        sec_ofs;
    int         cyl_num;
    int         rc;

    /* Check if we're within the image. */
    cyl_num = sect_num / tdup->spc;
    if( cyl_num >= tdup->hdr.num_cyls )
        return( IMG_ERR_NO_SECT );

    /* Read cylinder data unless it's already buffered.
     * Works very well for sequential access.
     */
    if( tdup->cyl_in_buf != cyl_num ) {
        rc = tdup_read_cylinder( cb, tdup, cyl_num );
        if( rc < 0 )
            return( rc );
        assert( rc == tdup->cyl_len );
    }

    /* Calculate the sector offset in cylinder buffer. */
    sec_ofs = sect_num % tdup->spc * IMG_SEC_SZ_DEF;
    assert( sec_ofs + IMG_SEC_SZ_DEF <= tdup->cyl_len );
    memcpy( buf, tdup->cyl_buf + sec_ofs, IMG_SEC_SZ_DEF );

    return( IMG_SEC_SZ_DEF );
}

/* Close an image once all accesses are completed. */
void tdup_close( img_fns *cb, tdup_ctx *tdup )
{
    assert( tdup );
    assert( tdup->cyl_buf );
    assert( tdup->cyl_map );
    cb->m_free( tdup->cyl_buf );
    cb->m_free( tdup->cyl_map );
}
