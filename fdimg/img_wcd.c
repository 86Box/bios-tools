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
#include "img_wcd.h"


/* The WC Disk Image diskette image format was used by the D2F/F2D utilities,
 * written by William Couture in the late 1990s(?).
 *
 * The format is relatively simple, supporting up to 80 cylinders, with up to
 * 18 sectors per track. Every track must contain the same number of 512-byte
 * sectors. The format was apparently extended to handle up to 82 cylinders,
 * as well as image comments.
 *
 * Sector data is protected by CRCs. There are provisions for skipping sectors
 * with bad CRC. Trivial compression is used for sectors which only contain
 * repeated instances of the same byte value.
 *
 * The WC Disk Image format also supports optional directory listings as
 * a special form of comments. These are ignored.
 *
 * The WC Disk Image support is based on diskfile.h provided in an archive
 * available at http://www.datapackrat.com/utilities/extr_src.zip
 *
 * NB: It appears that all sectors in image must be stored strictly in C/H/S
 * order, with no gaps.
 */

/* The signature string. */
static const char wcd_magic[] = "WC DISK IMAGE\032\032";
#define WCD_MAGIC_SZ    sizeof( wcd_magic )   /* 16 */

/* WCD image header. */
typedef struct wcd_hdr {
    uint8_t     version;        /* Version 0 or 1. */
    uint8_t     num_head;       /* Number of sides (1 or 2). */
    uint8_t     num_sec;        /* Sectors per track. */
    uint8_t     num_cyl;        /* Number of cylinders (up to 80). */
    uint8_t     c81s1;          /* 81st cylinder, side 0 present. */
    uint8_t     c81s2;          /* 81st cylinder, side 1 present. */
    uint8_t     c82s1;          /* 82nd cylinder, side 0 present. */
    uint8_t     c82s2;          /* 82nd cylinder, side 1 present. */
    uint8_t     exflags;        /* Extra flags (comments, dirs). */
    uint8_t     resvd[7];       /* Unused. */
} wcd_hdr;

/* Bit flags for 'exflags' member above. */
#define EXFLAG_COMMENT      1   /* Comment present in image. */
#define EXFLAG_DIR          2   /* Directory field present. */


/* WCD sector header. */
typedef struct wcd_shead {
    uint8_t     flags;          /* Sector flags/type. */
    uint8_t     head_no;        /* Head/side number (0-based). */
    uint8_t     sect_no;        /* Sector number (0-based). */
    uint8_t     cyl_no;         /* Cylinder number (1-based). */
    uint16_t    crc;            /* Sector data CRC. */
} wcd_shead;

/* Possible values of 'flags' member above. */
#define SFLAG_DATA          0   /* Regular raw 512-byte sector. */
#define SFLAG_BAD_SEC       1   /* Bad sector, no data. */
#define SFLAG_PATTERN       2   /* Repeating byte pattern in CRC low byte. */
#define SFLAG_COMMENT       3   /* 'Sector' is a comment (length in CRC). */
#define SFLAG_DIR           4   /* A directory entry (length in CRC). */


typedef struct wcd_ctx {
    img_file    imgf;           /* Image file handle. */
    uint8_t     trks;           /* Number of tracks. */
    uint8_t     spt;            /* Sectors per track. */
    uint8_t     heads;          /* Number of heads (1 or 2). */
    wcd_hdr     hdr;            /* The image header. */
    uint16_t    tot_sect;       /* Total number of sectors in image. */
    long        start_ofs;      /* File offset of the first sector. */
    long        end_ofs;        /* File offset just past the last sector. */
    long        *sect_map;      /* Map of all sector file offsets. */
    char        *comment;       /* Optional comment. */
} wcd_ctx;


/*  A table of 16-bit CRC values based on x^16+x^15+x^2+1 polynomial
 *  or (0xA001). Bits are inserted from LSB to MSB.
 */
static uint16_t wcd_crc16[256] =
{
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

/* Compute/update a CRC given a block of data. */
uint16_t wcd_calc_crc( const void *p, unsigned len, uint16_t crc )
{
    const uint8_t   *data = p;
    uint16_t        tmp;
    int             i;

    for( i = 0; i < len; ++i) {
        tmp = crc ^ *data++;
        crc = (crc >> 8) ^ wcd_crc16[tmp & 0xFF];
    }
    return( crc );
}

/* Identify a WCD format image. Does not validate image. */
int wcd_identify( img_fns *cb, img_file img )
{
    char    magic[WCD_MAGIC_SZ];
    int     rc;

    /* Look for a magic string - sufficient to identify format.
     * A false positive is extremely unlikely.
     */
    cb->seek( img, 0 );
    rc = cb->read( img, &magic, sizeof( magic ) );
    if( rc != sizeof( magic ) )
        return( 0 );

    if( memcmp( magic, wcd_magic, WCD_MAGIC_SZ ) )
        return( 0 );
    else
        return( sizeof( wcd_ctx ) );
}

/* Build a map of sector offsets. Since sectors in image may not all
 * have the same size, sector offsets must be determined by sequentially
 * scanning the image. While at it, CRCs of data sectors are checked.
 */
int wcd_build_sector_map( img_fns *cb, wcd_ctx *wcd )
{
    uint8_t     buf[IMG_SEC_SZ_DEF];
    wcd_shead   sec_hdr;
    int         cyl;
    int         head;
    int         sect;
    int         sect_no;
    int         nb;
    uint16_t    crc;
    long        sec_off;

    /* Make sure we start at the first sector. */
    sec_off = wcd->start_ofs;
    cb->seek( wcd->imgf, sec_off );
    sect_no = 0;

    /* Loop over all sectors in the image. */
    for( cyl = 0; cyl < wcd->trks; ++cyl ) {
        for( head = 0; head < wcd->heads; ++head ) {
            for( sect = 0; sect < wcd->spt; ++sect ) {
                /* Store the sector offset. */
                wcd->sect_map[sect_no++] = sec_off;
                /* Read sector header. */
                nb = cb->read( wcd->imgf, &sec_hdr, sizeof( sec_hdr ) );
                if( nb != sizeof( sec_hdr ) )
                    return( false );
                sec_off += sizeof( sec_hdr );
                /* Validate C/H/S. */
                if(  sec_hdr.cyl_no  != cyl
                  || sec_hdr.head_no != head
                  || sec_hdr.sect_no != sect + 1 )
                    return( false);
                /* Now process the sector data, if any. */
                switch( sec_hdr.flags ) {
                case SFLAG_DATA:
                    /* Read raw data, validate CRC. */
                    nb = cb->read( wcd->imgf, buf, IMG_SEC_SZ_DEF );
                    if( nb != IMG_SEC_SZ_DEF )
                        return( false );
                    sec_off += IMG_SEC_SZ_DEF;
                    crc = wcd_calc_crc( buf, IMG_SEC_SZ_DEF, 0 );
                    if( crc != sec_hdr.crc )
                        return( false );
                    break;
                case SFLAG_BAD_SEC:
                case SFLAG_PATTERN:
                    /* Bad sectors or repeated patterns have no more data. */
                    break;
                default:
                    /* Any non-data or corrupted sector is considered fatal. */
                    return( false );
                }
            }
        }
    }
    wcd->end_ofs = sec_off;
    return( true );
}

/* Open an image for access. May fail if image is damaged. */
int wcd_open( img_fns *cb, img_file imgf, wcd_ctx *wcd )
{
    int         nb;
    wcd_shead   shdr;
    wcd_hdr     hdr;

    /* Read the image format header. */
    cb->seek( imgf, WCD_MAGIC_SZ );
    nb = cb->read( imgf, &hdr, sizeof( hdr ) );
    if( nb != sizeof( hdr ) )
        return( IMG_ERR_READ );

    /* Version must be 0 or 1. */
    if( hdr.version > 1 )
        return( IMG_ERR_BAD_IMG );

    /* Do a basic sanity check on the header. Somewhat arbitrary. */
    if( hdr.num_cyl > 80 || hdr.num_head > 2 || hdr.num_sec > 18 )
        return( IMG_ERR_BAD_IMG );

    wcd->imgf  = imgf;
    wcd->trks  = hdr.num_cyl;
    wcd->spt   = hdr.num_sec;
    wcd->heads = hdr.num_head;
    wcd->hdr   = hdr;

    /* Account for potential extra tracks. */
    if( hdr.c81s1 )
        ++hdr.num_cyl;
    if( hdr.c82s1 )
        ++hdr.num_cyl;

    /* Allocate the sector map. */
    wcd->start_ofs = WCD_MAGIC_SZ + sizeof( wcd_hdr );
    wcd->tot_sect  = wcd->trks * wcd->heads * wcd->spt;
    wcd->sect_map  = cb->m_alloc( sizeof( long ) * wcd->tot_sect );
    if( !wcd->sect_map ) {
        return( IMG_ERR_MEM_ALLOC );
    }

    /* Build the sector map, validating the image in the process. */
    if( !wcd_build_sector_map( cb, wcd ) ) {
        cb->m_free( wcd->sect_map );
        return( IMG_ERR_DECODE );
    }

    /* If a comment is supposed to be present, look for it.
     * Any errors are treated as non-fatal.
     */
    if( hdr.exflags & EXFLAG_COMMENT ) {
        nb = cb->read( imgf, &shdr, sizeof( shdr ) );
        if( nb == sizeof( shdr ) ) {
            wcd->comment = cb->m_alloc( shdr.crc + 1 );
            nb = cb->read( imgf, wcd->comment, shdr.crc );
            if( nb == shdr.crc ) {
                /* Success; null-terminate comment. */
                wcd->comment[shdr.crc] = '\0';
            } else {
                /* Failed to read comment, clean up. */
                cb->m_free( wcd->comment );
                wcd->comment = NULL;
            }
        }
    }

    return( IMG_OK );
}

/* Query the comment string. Returns NULL if no comment provided. */
const char *wcd_query_comment( img_fns *cb, wcd_ctx *wcd )
{
    return( wcd->comment );
}

/* Read a single sector from the image. */
int wcd_read_sect( img_fns *cb, wcd_ctx *wcd, int sect_num, void *buf )
{
    wcd_shead   sec_hdr;
    long        sec_ofs;
    int         rc = IMG_SEC_SZ_DEF;

    /* Look up the sector offset. */
    sec_ofs = wcd->sect_map[sect_num];
    /* Read the sector header. */
    cb->seek( wcd->imgf, sec_ofs );
    cb->read( wcd->imgf, &sec_hdr, sizeof( sec_hdr ) );
    /* Read/rebuild sector data based on sector type flag. */
    switch( sec_hdr.flags ) {
    case SFLAG_DATA:    /* Raw sector data. */
        rc = cb->read( wcd->imgf, buf, IMG_SEC_SZ_DEF );
        break;
    case SFLAG_BAD_SEC: /* Bad sector - not in image. */
        memset( buf, 0, IMG_SEC_SZ_DEF );
        strcpy( buf, "WCD bad sector!" );
        break;
    case SFLAG_PATTERN: /* Repeating byte pattern. */
        memset( buf, sec_hdr.crc, IMG_SEC_SZ_DEF );
        break;
    default:            /* Attempting to read just past end of image. */
        assert( sect_num == wcd->tot_sect );
        rc = IMG_ERR_NO_SECT;
    }
    return( rc );
}

/* Close an image once all accesses are completed. */
void wcd_close( img_fns *cb, wcd_ctx *wcd )
{
    assert( wcd );
    assert( wcd->sect_map );
    if( wcd->comment )
        cb->m_free( wcd->comment );
    cb->m_free( wcd->sect_map );
}
