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
#include "img_imd.h"


/* The ImageDisk diskette image format (.IMD) was developed by Dave Dunfield
 * in 2005 with the aim of reading (and when possible, writing) various non-PC
 * floppies on PCs.
 *
 * The ImageDisk format is simpler than the TeleDisk format and slightly less
 * capable. It cannot represent different sector sizes on a single track, but
 * supports different sector sizes on different tracks.
 *
 * ImageDisk can represent any interleave scheme because it preserves the
 * physical order of sectors and their logical IDs. Optionally, a track can
 * have a custom cylinder and/or head map in case the logical cylinder/head
 * IDs do not correspond to physical ones.
 *
 * Only a trivial pattern compression is supported. There are no CRCs or other
 * integrity checks.
 *
 * There is no length limit whatsoever on the comment field in IMD images. The
 * only requirement is that the comment is terminated with an ASCII EOF (0x1A)
 * character. This is inconvenient.
 *
 * Due to the complexity of the ImageDisk format, it may not be possible to
 * convert an arbitrary image into a straightforward 'raw' format. Therefore
 * opening an image builds a sector map, in the process checking that:
 *  - All sectors have the same size
 *  - All tracks contain the same number of sectors
 *  - No tracks are skipped
 *  - Logical track/head IDs match physical ones
 *  - Each track contains exactly 1-n sectors with no gaps or duplicates
 *
 * In special cases we may to attempt to "normalize" strange disk images with
 * extra tracks/sectors which are not part of the logical image.
 */


/* Somewhat arbitrary, but a regular drive shouldn't be able to do more. */
#define NTRK_MAX    84

/* ImageDisk image header. */
typedef struct imd_hdr_s {
    char        signature[6];           /* 'IMD ', 'IMDU', etc. signature. */
} imd_hdr;

/* ImageDisk track header. */
typedef struct track_hdr_s {
    uint8_t     mode;                   /* Data rate and encoding. */
    uint8_t     cylinder;               /* Physical cylinder (zero-based). */
    uint8_t     head;                   /* Head/side (0 or 1). */
    uint8_t     num_sect;               /* Number of sectors on this track. */
    uint8_t     sect_sz;                /* Sector size code. */
} track_hdr;

/* Head bits actually used for the head number. The rest is flags. */
#define TRK_HEAD_MASK   0x0F

#define TRK_CYLN_MAP    0x80    /* Track has a custom cylinder map. */
#define TRK_HEAD_MAP    0x40    /* Track has a custom head map. */

/* Maximum SPT supported by ImageDisk. */
#define IMD_MAX_SPT     256

/* Sector data types: */
#define SECT_NO_DATA    0x00            /* No data for sector. */
#define SECT_NORM       0x01            /* Normal data sector. */
#define SECT_CMPR       0x02            /* Compressed, all bytes identical. */
#define SECT_DDAM_NORM  0x03            /* Normal with Deleted Data AM. */
#define SECT_DDAM_CMPR  0x04            /* Compressed with DDAM. */
#define SECT_ERR_NORM   0x05            /* Data read with error. */
#define SECT_ERR_CMPR   0x06            /* Compressed with error. */
#define SECT_DERR_NORM  0x07            /* Deleted, with error. */
#define SECT_DERR_CMPR  0x08            /* Deleted, with error, compressed. */

/* Macro to convert encoded sector size to bytes. */
#define SEC_SZ_BYTES(sz)    (128 << (sz))


/* Sector offset descriptor. Points to the sector header in image file. Note
 * that logical sector IDs may occur in any order, may have gaps, and may
 * not be unique. Logical cylinder and head IDs normally match physical ones,
 * but in some images have custom mappings.
 */
typedef struct sect_desc_s {
    long        file_ofs;               /* Offset of data header in file. */
    unsigned    sect_size;              /* Sector size in bytes. */
    uint8_t     sect_id;                /* Logical sector ID. */
    uint8_t     cyln_id;                /* Logical cylinder ID. */
    uint8_t     head_id;                /* Logical head ID. */
} sect_desc;


/* Track descriptor. Contains a pointer to a list of sector offset descriptors
 * plus the count of items, as sectors per track may not be uniform.
 */
typedef struct trk_desc_s {
    sect_desc   *sdesc;                 /* Sector descriptor list. */
    int         num_desc;               /* Number of list items. */
} trk_desc;


/* Context structure for ImageDisk format. */
typedef struct imd_ctx {
    img_file    imgf;                   /* Image file handle. */
    uint8_t     trks;                   /* Number of tracks. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     first_id;               /* First sector ID (typically 1). */
    imd_hdr     hdr;                    /* The image header. */
    char        *comment;               /* Optional comment. */
    trk_desc    trk_ofs[NTRK_MAX * 2];  /* Per-track sector descriptors. */
} imd_ctx;


/* Identify a ImageDisk format image. Does not validate image. */
int imd_identify( img_fns *cb, img_file imgf )
{
    imd_hdr     hdr;
    int         rc;

    /* Just read the image header and see if it makes sense. */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* Fail if signature isn't 'IMD'. */
    if( memcmp( hdr.signature, "IMD", 3 ) )
        return( 0 );

    /* The signature may include lots more, including a timestamp, but
     * it need not be more than 'IMD'. Don't bother checking further,
     * all we need here is a quick check whether the file looks like
     * an IMD image or not.
     */

    /* The image looks sensible enough... */
    return( sizeof( imd_ctx ) );
}

/* Read sector data from image, decompress as needed; sdata_ofs is the image
 * offset of the sector data headerThe img_read argument points to a location
 * where the number of bytes read from image is returned (or NULL if that is
 * not relevant).
 */
int imd_decomp_sect( img_fns *cb, imd_ctx *imd, long sdata_ofs, void *buf, unsigned sec_sz, unsigned *img_read )
{
    uint8_t     drec;
    uint8_t     repb;
    int         rc;
    unsigned    bytes_read;

    /* Read sector data record, followed by raw or compressed data. */
    cb->seek( imd->imgf, sdata_ofs );
    rc = cb->read( imd->imgf, &drec, sizeof( drec ) );
    if( rc != sizeof( drec ) )
        return( false );

    bytes_read = 1;

    switch( drec ) {
    case SECT_NO_DATA:
        memset( buf, 0, sec_sz );
        strcpy( buf, "IMD sector ID only!" );
        break;
    case SECT_NORM:
    case SECT_DDAM_NORM:
        /* Uncompressed sector data. */
        rc = cb->read( imd->imgf, buf, sec_sz );
        if( rc != sec_sz )
            return( false );
        bytes_read += sec_sz;
        break;
    case SECT_CMPR:
    case SECT_DDAM_CMPR:
        rc = cb->read( imd->imgf, &repb, sizeof( repb ) );
        if( rc != sizeof( repb ) )
            return( false );
        memset( buf, repb, sec_sz );
        ++bytes_read;
        break;
    default:
        /* If this happens, the image is corrupted. */
        assert( 0 );
        return( false );
    }

    /* Return the number of bytes read from image if requested. */
    if( img_read )
        *img_read = bytes_read;

    return( true );
}

/* Sequentially scan the image, building a map of tracks/sectors. */
int imd_build_track_map( img_fns *cb, imd_ctx *imd, long start_ofs )
{
    track_hdr   thdr;
    long        curr_ofs;
    long        shdr_ofs;
    int         trk_idx;
    int         trk_last;
    int         phys_sect;
    int         rc;
    sect_desc   *sdesc;
    unsigned    img_read;
    unsigned    sec_size;
    uint8_t     smap[IMD_MAX_SPT];
    uint8_t     cmap[IMD_MAX_SPT];
    uint8_t     hmap[IMD_MAX_SPT];
    uint8_t     sec_buf[IMG_SEC_SZ_MAX];
    bool        seen_2nd_side;

    curr_ofs      = start_ofs;
    trk_last      = 0;
    seen_2nd_side = false;

    for( ;; ) {
        /* Read track header; even the EOF marker includes a full header,
         * despite the fact that only the first byte is meaningful.
         */
        rc = cb->read( imd->imgf, &thdr, sizeof( thdr ) );

        /* Exit if at end end of image. */
        if( !rc ) {
            //@todo: Should the number of tracks really be what it says, i.e.
            // the # of tracks and not cylinders?
            imd->trks = trk_last / 2 + 1;
            break;
        }

        if( rc != sizeof( thdr ) )
            return( IMG_ERR_READ );
        curr_ofs += rc;

        /* Read the sector numbering map. */
        rc = cb->read( imd->imgf, &smap, thdr.num_sect );
        if( rc != thdr.num_sect )
            return( IMG_ERR_READ );
        curr_ofs += rc;

        /* If we heave it, read the custom cylinder numbering map. */
        if( thdr.head & TRK_CYLN_MAP ) {
            rc = cb->read( imd->imgf, &cmap, thdr.num_sect );
            if( rc != thdr.num_sect )
                return( IMG_ERR_READ );
            curr_ofs += rc;
        } else{
            memset( cmap, thdr.cylinder, thdr.num_sect );
        }

        /* If we heave it, read the custom head numbering map. */
        if( thdr.head & TRK_HEAD_MAP ) {
            rc = cb->read( imd->imgf, &hmap, thdr.num_sect );
            if( rc != thdr.num_sect )
                return( IMG_ERR_READ );
            curr_ofs += rc;
        } else {
            memset( hmap, thdr.head & TRK_HEAD_MASK, thdr.num_sect );
        }

        /* Calculate and validate track number. */
        trk_idx = thdr.cylinder * 2 + (thdr.head & TRK_HEAD_MASK);
        if( trk_idx > sizeof( imd->trk_ofs ) / sizeof( imd->trk_ofs[0] ) )
            return( IMG_ERR_BAD_IMG );  /* Track out of bounds. */

        /* Update 'last valid track' counter. */
        trk_last = trk_idx;
        /* Check if it's a two-sided disk. */
        if( thdr.head & 1 )
            seen_2nd_side = true;

        /* Allocate and link sector descriptors for this track. */
        sdesc = cb->m_alloc( thdr.num_sect * sizeof( sdesc[0] ) );
        if( !sdesc )
            return( IMG_ERR_MEM_ALLOC );    //@todo: free previously allocated bits
        imd->trk_ofs[trk_idx].sdesc    = sdesc;
        imd->trk_ofs[trk_idx].num_desc = thdr.num_sect;
        sec_size = SEC_SZ_BYTES( thdr.sect_sz );

        /* Loop over all sectors on this track... */
        for( phys_sect = 0; phys_sect < thdr.num_sect; ++phys_sect ) {
            /* Read sector header to see what to do next. */
            shdr_ofs = curr_ofs;

            /* If present, read the sector data header and actual data. */
            rc = imd_decomp_sect( cb, imd, curr_ofs, sec_buf, sec_size, &img_read );
            if( !rc )
                return( IMG_ERR_DECODE );
            curr_ofs += img_read;

            /* Sector looks good; store vital data in descriptor. */
            sdesc[phys_sect].file_ofs  = shdr_ofs;
            sdesc[phys_sect].sect_size = sec_size;
            sdesc[phys_sect].sect_id   = smap[phys_sect];
            sdesc[phys_sect].cyln_id   = cmap[phys_sect];
            sdesc[phys_sect].head_id   = hmap[phys_sect];
        }
    }

    imd->heads = seen_2nd_side ? 2 : 1;
    return( IMG_OK );
}

/* Find the lowest sector ID on the first track. */
uint8_t imd_find_first_id( imd_ctx *imd )
{
    int         phys_sect;
    uint8_t     low_id;
    trk_desc    *tdesc;
    sect_desc   *sdesc;

    /* Get the sector descriptors for the first track. */
    tdesc = &imd->trk_ofs[0];
    sdesc = tdesc->sdesc;
    assert( sdesc );
    low_id = 255;

    /* Look for the lowest sector ID. */
    for( phys_sect = 0; phys_sect < tdesc->num_desc; ++phys_sect ) {
        if( sdesc[phys_sect].sect_id < low_id )
            low_id = sdesc[phys_sect].sect_id;
    }
    return( low_id );
}

/* Check if it might be useful to adjust the SPT value. Images have been
 * seen with junk/dummy/spare sectors that have logical sector and track
 * IDs of zero.
 */
void imd_adjust_spt( imd_ctx *imd )
{
    int         phys_sect;
    uint8_t     low_id;
    uint8_t     lo_idx;
    trk_desc    *tdesc;
    sect_desc   *sdesc;

    do {
        /* The lowest sector ID must be zero. */
        if( imd->first_id != 0 )
            break;

        /* Must have at least a few tracks. */
        if( imd->trks < 4 )
            break;

        /* Get the sector descriptors for the second cylinder. */
        tdesc = &imd->trk_ofs[2];
        sdesc = tdesc->sdesc;

        /* Look for the lowest sector ID. */
        low_id = 255;
        for( phys_sect = 0; phys_sect < tdesc->num_desc; ++phys_sect ) {
            if( sdesc[phys_sect].sect_id < low_id )
                low_id = sdesc[phys_sect].sect_id;
                lo_idx = phys_sect;
        }

        /* See if the lowest sector and cylinder IDs are both zero. */
        if( sdesc[lo_idx].sect_id || sdesc[lo_idx].cyln_id)
            break;

        /* Have a funny image. Adjust lowest sector ID and SPT. */
        imd->first_id = 1;
        imd->spt      = imd->spt - 1;
    } while( 0 );
}

/* Open an image for access. May fail if image is damaged or cannot be
 * represented as a raw format image.
 */
int imd_open( img_fns *cb, img_file imgf, imd_ctx *imd )
{
    int         rc = IMG_ERR_BAD_IMG;
    int         nb;
    imd_hdr     img_hdr;
    char        chr;
    char        *comment;
    uint16_t    cmt_len;
    long        curr_ofs;

    /* Read the image format header. We already ensured it's sensible. */
    cb->seek( imgf, 0 );
    nb = cb->read( imgf, &img_hdr, sizeof( img_hdr ) );
    if( nb != sizeof( img_hdr ) )
        return( IMG_ERR_READ );

    curr_ofs = sizeof( img_hdr );

    /* Read in comment, looking for EOF. */
    comment = NULL;
    cmt_len = 0;
    do {
        nb = cb->read( imgf, &chr, sizeof( chr ) );
        ++cmt_len;
    } while( nb == sizeof( chr ) && chr != 0x1A );

    /* If we didn't find the EOF, image is bad. */
    if( nb != sizeof( chr ) )
        return( IMG_ERR_READ );

    /* Now read the entire comment. */
    if( cmt_len ) {
        comment = cb->m_alloc( cmt_len );
        if( !comment )
            return( IMG_ERR_MEM_ALLOC );

        cb->seek( imgf, curr_ofs );
        nb = cb->read( imgf, comment, cmt_len );
        if( nb != cmt_len )
            goto error_cleanup;
    }
    curr_ofs += cmt_len;

    /* Store the comment and image pointers. */
    imd->comment = comment;
    imd->imgf    = imgf;

    /* Build a map of all the tracks in the image. If the track map
     * can be built, the image is assumed to be OK.
     */
    rc = imd_build_track_map( cb, imd, curr_ofs );
    if( rc )
        goto error_cleanup;

    /* Figure out the starting sector ID. */
    imd->first_id    = imd_find_first_id( imd );

    /* Fill out the rest of the context structure. */
    imd->spt         = imd->trk_ofs[0].num_desc;
    imd->hdr         = img_hdr;
    assert( imd->spt );

    imd_adjust_spt( imd );

    return( IMG_OK );

error_cleanup:
    if( comment )
        cb->m_free( comment );

    return( rc );
}

/* Query the comment string. Returns NULL if no comment provided. */
const char *imd_query_comment( img_fns *cb, imd_ctx *imd )
{
    return( imd->comment );
}

//@todo: split out a worker with CHS addressing!
/* Read a single sector from the image. */
int imd_read_sect( img_fns *cb, imd_ctx *imd, int sect_num, void *buf )
{
    trk_desc    *tdesc;
    sect_desc   *sdesc;
    long        sec_ofs;
    unsigned    sec_size;
    int         track_num;
    int         sect_id;
    int         phys_sect;
    int         rc;

    /* Check if we're within image. */
    track_num = sect_num / imd->spt;
    if( imd->heads == 1 )
        track_num *= 2;
    sect_id   = sect_num % imd->spt;
    if( track_num >= imd->trks * 2 )
        return( IMG_ERR_NO_SECT );

    /* Logical sector IDs are typically 1-based. */
    sect_id += imd->first_id;

    /* Get the sector descriptors for this track. */
    tdesc = &imd->trk_ofs[track_num];
    sdesc = tdesc->sdesc;
    assert( sdesc );

    /* Look for the sector ID. */
    for( phys_sect = 0; phys_sect < tdesc->num_desc; ++phys_sect ) {
        if( sdesc[phys_sect].sect_id == sect_id )
            break;
    }
    /* If the sector is missing entirely, make something up. */
    if( phys_sect >= tdesc->num_desc ) {
        memset( buf, 0, sdesc[phys_sect].sect_size );
        strcpy( buf, "IMD sector missing!" );
        return( sdesc[0].sect_size );
    }

    sec_size = sdesc[phys_sect].sect_size;
    sec_ofs  = sdesc[phys_sect].file_ofs;
//@todo: assert sec_ofs within image?

    /* If sector size is bigger than what caller expects, bail. */
    if( sec_size > IMG_SEC_SZ_MAX )
        return( IMG_ERR_CANT_CONV );

    /* Read/decompress sector data. */
    rc = imd_decomp_sect( cb, imd, sec_ofs, buf, sec_size, NULL );
    if( !rc )
        return( IMG_ERR_DECODE );

    return( sec_size );
}

/* Close an image once all accesses are completed. */
void imd_close( img_fns *cb, imd_ctx *imd )
{
    int     trk_idx;
    int     max_trk;

    assert( imd );
    if( imd->comment )
        cb->m_free( imd->comment );

    max_trk = sizeof( imd->trk_ofs ) / sizeof( imd->trk_ofs[0] );
    for( trk_idx = 0; trk_idx < max_trk; ++trk_idx ) {
        if( imd->trk_ofs[trk_idx].sdesc )
            cb->m_free( imd->trk_ofs[trk_idx].sdesc );
    }
}
