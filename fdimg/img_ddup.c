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
#include "img_ddup.h"


/* The DDI diskette image format was used by the DiskDupe DOS utility,
 * developed by Micro System Designs, Inc. of Cupertino, California in the
 * early 1990. DiskDupe was used to drive floppy autoloaders/duplicators
 * and disk image functionality was a fringe feature.
 *
 * All information about this format was obtained by analyzing available image
 * files and may not be entirely accurate.
 *
 * The DDI (DiskDupe Image) format is very simplistic, only supporting
 * standard PC floppy formats. It was not intended as a generic floppy disk
 * archival format.
 *
 * There is no compression and no checksums, but provisions are made to leave
 * out unused tracks. There is a track map at the beginning of the image.
 * The image header is the same size as a single track; the track map uses
 * this fact and gives the starting offset of each track in units of one
 * track's worth of data (e.g. 7.5KB for 1.2M images).
 *
 * Newer DDI versions have the capability of leaving out any track filled
 * with the same byte. The filler byte is recorded in the track map.
 *
 * There is a unique signature ('IM' followed by at least one zero), which
 * means that DDI files are easy to recognize.
 */

/* Possible signature strings. */
static const char ddup_magic1[] = "IM\0\0\0";
static const char ddup_magic2[] = "IM\0\3\0";
#define DDUP_MAGIC_SZ       sizeof( ddup_magic1 )

#define DDUP_OFS_DSKTYPE    10          /* File offset of the disk type. */
#define DDUP_OFS_TRKMAP     100         /* File offset of track map. */

/* Maximum supported cylinders. Guesswork. */
#define NCYL_MAX            80

/* Disk format descriptor. */
typedef struct ddup_dsktyp {
    uint8_t     num_cyl;                /* Number of cylinders. */
    uint8_t     num_heads;              /* Number of heads/sides. */
    uint8_t     num_spt;                /* Number of sectors per track. */
} ddup_dsktyp;

/* Disk types supported by DiskDupe. */
static ddup_dsktyp  dsk_desc[] = {
    { 0,  0,  0 },                      /* Type 0 - unknown. */
    { 40, 2,  9 },                      /* Type 1 - 360K. */
    { 80, 2, 15 },                      /* Type 2 - 1.2M. */
    { 80, 2,  9 },                      /* Type 3 - 720K. */
    { 80, 2, 18 }                       /* Type 4 - 1.44M. */
};

/* Information record for each track in the image. */
typedef struct ddup_trknfo {
    uint8_t     type;                   /* Track type (file/left out). */
    uint8_t     track_loc;              /* Track location in image or filler. */
    uint8_t     zeros[3];               /* Unknown, always zeroed. */
    uint8_t     unknown;                /* Unknown, always set to 1? */
} ddup_trknfo;

/* Possible track types. */
#define TRK_NOT_PRES    0               /* Track not present. */
#define TRK_IMAGE       1               /* Track stored in image. */
#define TRK_FILLER      2               /* Not in image, use given filler. */


typedef struct ddup_ctx {
    img_file    imgf;                   /* Image file handle. */
    uint8_t     trks;                   /* Number of tracks. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    long        trk_ofs[NCYL_MAX * 2];  /* Track starting offsets. */
    unsigned    track_len;              /* Length of single track in bytes. */
    int         trk_in_buf;             /* Track currently in buffer. */
    uint8_t     *track_buf;             /* Track buffer. */
} ddup_ctx;


/* Identify a DiskDupe format image. Does not validate image. */
int ddup_identify( img_fns *cb, img_file img )
{
    char    magic[DDUP_MAGIC_SZ];
    int     rc;

    /* Look for one of recognized magic strings - sufficient to identify
     * format. The likelihood of a false positive is vanishingly small.
     */
    cb->seek( img, 0 );
    rc = cb->read( img, &magic, sizeof( magic ) );
    if( rc != sizeof( magic ) )
        return( 0 );

    if(  memcmp( magic, ddup_magic1, DDUP_MAGIC_SZ )
      && memcmp( magic, ddup_magic2, DDUP_MAGIC_SZ ) )
        return( 0 );
    else
        return( sizeof( ddup_ctx ) );
}

/* Open an image for access. May fail if image is damaged. */
int ddup_open( img_fns *cb, img_file img, ddup_ctx *ddup )
{
    int         rc;
    uint16_t    dsk_id;
    ddup_dsktyp *dsk_typ;
    ddup_trknfo trk_nfo;
    int         trk;
    int         num_trk;
    long        cur_ofs;

    /* Read the image type. Unclear if byte or larger. */
    cb->seek( img, DDUP_OFS_DSKTYPE );
    rc = cb->read( img, &dsk_id, sizeof( dsk_id ) );
    if( rc != sizeof( dsk_id ) )
        return( IMG_ERR_READ );

    if( dsk_id > sizeof( dsk_desc ) / sizeof( dsk_desc[0] ) )
        return( IMG_ERR_BAD_IMG );

    /* Find the hardcoded disk geometry. */
    dsk_typ = &dsk_desc[dsk_id];
    assert( dsk_typ->num_cyl );

    ddup->track_len = dsk_typ->num_spt * IMG_SEC_SZ_DEF;
    cur_ofs = ddup->track_len;

    /* Build a table of file offsets of each track in image. */
    cb->seek( img, DDUP_OFS_TRKMAP );
    num_trk = dsk_typ->num_cyl * dsk_typ->num_heads;
    for( trk = 0; trk < num_trk; ++trk ) {
        rc = cb->read( img, &trk_nfo, sizeof( trk_nfo ) );
        if( rc != sizeof( trk_nfo ) )
            return( IMG_ERR_READ );

        /* See what kind of track this is... */
        switch( trk_nfo.type ) {
        case TRK_IMAGE:
            /* Track data present in file. Calculate offset. */
            assert( trk_nfo.unknown == 1 );
            /* In some images, track location is zero. Guessing that in
             * that case, the currently calculated offset should be used.
             */
            if( trk_nfo.track_loc )
                ddup->trk_ofs[trk] = trk_nfo.track_loc * ddup->track_len;
            else
                ddup->trk_ofs[trk] = cur_ofs;
            cur_ofs += ddup->track_len;
            break;
        case TRK_FILLER:
            /* Track not in image, use a specified filler. We abuse the fact
             * that tracks can't possibly start at a file offset < 256.
             */
            assert( !trk_nfo.unknown );
            ddup->trk_ofs[trk] = trk_nfo.track_loc;
            break;
        case TRK_NOT_PRES:
            /* Track not in image. Default filler will be used. */
            assert( !trk_nfo.unknown && !trk_nfo.track_loc );
            ddup->trk_ofs[trk] = FMT_BYTE;
            break;
        default:
            /* Bad or unknown image. */
            assert( 0 );
            return( IMG_ERR_BAD_IMG );
        }
    }

    /* Check the file size. If it matches, image is likely good. */
    if( cb->fsize( img ) != cur_ofs )
        return( IMG_ERR_BAD_IMG );

    /* Allocate a buffer for track data. */
    ddup->track_buf = cb->m_alloc( ddup->track_len );
    if( !ddup->track_buf )
        return( IMG_ERR_MEM_ALLOC );

    /* Fill out the rest of the context structure. */
    ddup->imgf       = img;
    ddup->trks       = num_trk;
    ddup->spt        = dsk_typ->num_spt;
    ddup->heads      = dsk_typ->num_heads;
    ddup->trk_in_buf = -1;                          /* Nothing buffered. */
    assert( ddup->spt );
    return( IMG_OK );
}

/* Read a specified track. */
int ddup_read_track( img_fns *cb, ddup_ctx *ddup, int track_num )
{
    long        ofs;
    unsigned    rc;

    ofs = ddup->trk_ofs[track_num];
    if( ofs > 255) {
        /* Read track from file. */
        assert( ofs >= ddup->track_len );
        cb->seek( ddup->imgf, ofs );
        rc = cb->read( ddup->imgf, ddup->track_buf, ddup->track_len );
        if( rc > 0 && rc != ddup->track_len )
            rc = IMG_ERR_READ;
    } else {
        /* Fill with specified format byte.*/
        assert( ofs < ddup->track_len );
        memset( ddup->track_buf, (uint8_t)ofs, ddup->track_len );
        rc = ddup->track_len;
    }
    ddup->trk_in_buf = track_num;
    return( rc );
}

/* Read a single sector from the image. */
int ddup_read_sect( img_fns *cb, ddup_ctx *ddup, int sect_num, void *buf )
{
    long        sec_ofs;
    int         track_num;
    int         rc;

    /* Check if we're within the image. */
    track_num = sect_num / ddup->spt;
    if( track_num >= ddup->trks )
        return( IMG_ERR_NO_SECT );

    /* Read and a track unless it's already buffered.
     * Works very well for sequential access.
     */
    if( ddup->trk_in_buf != track_num ) {
        rc = ddup_read_track( cb, ddup, track_num );
        if( rc < 0 )
            return( rc );
        assert( rc == ddup->track_len );
    }

    /* Calculate the sector offset in track buffer. */
    sec_ofs = sect_num % ddup->spt * IMG_SEC_SZ_DEF;
    assert( sec_ofs + IMG_SEC_SZ_DEF <= ddup->track_len );
    memcpy( buf, ddup->track_buf + sec_ofs, IMG_SEC_SZ_DEF );

    return( IMG_SEC_SZ_DEF );
}

/* Close an image once all accesses are completed. */
void ddup_close( img_fns *cb, ddup_ctx *ddup )
{
    assert( ddup );
    assert( ddup->track_buf );
    cb->m_free( ddup->track_buf );
}
