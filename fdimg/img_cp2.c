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
#include "img_cp2.h"


/* The CP2 format has a rather curious history. Sometime circa 1983,
 * Central Point Software started selling a program called COPY II - PC
 * which could copy many non-DOS disks, as well as some copy protected
 * disks, using the standard PC floppy drive and controller.
 *
 * However, COPY II - PC could only copy and did not have the ability
 * to store floppy images. Circa 1986, Software Pirates, Inc., released
 * the SNATCH-IT utility which remedied this problem. SNATCH-IT was
 * a wrapper around COPY II - PC and allowed users to store and transfer
 * images of floppy disks, and later restore them.
 *
 * SNATCH-IT/COPY II - PC is similar to TeleDisk in terms of capabilities
 * It can read and write whatever the standard PC floppy controller and
 * driver can read and write.
 *
 * Before TeleDisk and other floppy imaging utilities became common,
 * SNATCH-IT was used to archive not just copy protected but also standard
 * disks, such as bootable disks or disks with a complex directory
 * structure (which file archiving utilities at the time could not handle!).
 *
 * A CP2 image starts with a fixed signature. The sector data is split
 * into one or more "segments" with less than 64K size. Each segment
 * starts with headers for some number of track. Each track contains
 * 24 sector headers with 16 bytes each. 24 appears to be an arbitrary
 * limitation.
 *
 * The sector headers include result bytes from the execution of uPD765
 * FDC read commands.
 *
 * The sector header block is terminated by a "trailer byte". In newer
 * SNATCH-IT versions (perhaps 4.0 and later), the trailer byte is EEh
 * except for the last block, where it is FFh. In older SNATCH-IT versions,
 * the last trailer byte is also FFh but the others have no apparent
 * system, except the low bit is not set.
 *
 * SNATCH-IT 5.5 produces an empty terminating segment. Earlier versions
 * generate no explicit terminator and the image file simply ends,
 * although the trailer byte described above can still be used to detect
 * when the end of image is expected.
 *
 * The track header is followed by sector data. Sector headers include
 * offsets (within the segment) to the start of each sector's data.
 *
 * The CP2 image format does not use compression and is somewhat wasteful
 * due to fairly large track headers. An image of a 360K disk is typically
 * 400,439 bytes big. It is likely that the SNATCH-IT essentially dumps
 * COPY II - PC internal structures on disk, which results in a somewhat
 * idiosyncratic format.
 *
 * In some cases, SNATCH-IT records "phantom-six" tracks. These have
 * one sector with cylinder/head/sector ID of 6, and sector size code 6.
 * These typically occur on the 41st cylinder of 40-cylinder disks or
 * on the unused side of a single-sided floppy. We treat such tracks
 * as not present.
 *
 * SNATCH-IT is capable of splitting floppy images into multiple files.
 * The last two bytes of the header contain the character '$' followed
 * by an ASCII digit. This is normally '0', but can be '1', '2', etc.
 * for second, third, etc. file of a multi-file image. The images appear
 * to be split at an arbitrary byte offset, meaning that all but the last
 * file of a multi-volume image have identical size. Such split images
 * are fortunately not common.
 *
 * The SNATCH-IT format does not use any checksums or CRCs, hence there
 * is no way to ensure data integrity. Most SNATCH-IT images are
 * fortunately found inside ARC or ZIP archives which should make it
 * easy to check whether an image is damaged.
 */


/* Somewhat arbitrary, but a regular drive shouldn't be able to do more. */
#define NCYL_MAX    84

/* Maximum SPT supported by CP2 format. */
#define CP2_MAX_SPT     24

/* A magic value that is not understood. The data offset of the first sector
 * in each segment is always 16ADh, which corresponds to the beginning of the
 * segment's data block. Perhaps this value has something to do with
 * COPY II - PC internals.
 */
#define CP2_SEC_OFS_MAGIC   0x16AD

/* The trailer byte value indicating the last segment in image. */
#define CP2_TRAILER_LAST    0xFF

/* SNATCH-IT image header. */
typedef struct cp2_hdr_s {
    char        pirates[16];            /* 'SOFTWARE PIRATES' sig. */
    char        version[12];            /* Release number string. */
    char        dollar;                 /* '$' */
    char        vol_no;                 /* ASCII 0-n, volume number. */
} cp2_hdr;

/* SNATCH-IT sector header. */
typedef struct cp2_shdr_s {
    uint8_t     result;                 /* FDC read result (normally 0). */
    uint8_t     st0;                    /* Status ST0 (normally 0). */
    uint8_t     st1;                    /* Status ST1 (normally 0). */
    uint8_t     st2;                    /* Status ST2 (normally 0). */
    uint8_t     hdr_cyl;                /* Cylinder number from ID. */
    uint8_t     hdr_head;               /* Head number from ID. */
    uint8_t     hdr_sec;                /* Sector number from ID. */
    uint8_t     size_code;              /* Sector size code. */
    uint8_t     sofs_lo;                /* Sector offset low. */
    uint8_t     sofs_hi;                /* Sector offset high. */
    uint8_t     unk[6];
} cp2_shdr;

/* SNATCH-IT track header. */
typedef struct cp2_thdr_s {
    uint8_t     cyl;                    /* Physical cylinder (zero-based). */
    uint8_t     head;                   /* Physical head number. */
    uint8_t     num_sect;               /* Number of sectors on this track. */
    cp2_shdr    sct_hdr[CP2_MAX_SPT];   /* 24 sector headers. */
} cp2_thdr;


/* Macro to convert encoded sector size to bytes. */
#define SEC_SZ_BYTES(sz)    (128 << (sz))


/* Sector offset descriptor. Points to the sector header in image file. Note
 * that logical sector IDs may occur in any order, may have gaps, and may
 * not be unique.
 */
typedef struct sect_desc {
    long        file_ofs;               /* Offset of sector data in file. */
    unsigned    sect_size;              /* Sector size in bytes. */
    uint8_t     sect_id;                /* Logical sector ID. */
} sect_desc;


/* Track descriptor. Contains a pointer to a list of sector offset descriptors
 * plus the count of items, as sectors per track may not be uniform.
 */
typedef struct trk_desc_s {
    sect_desc   *sdesc;                 /* Sector descriptor list. */
    int         num_desc;               /* Number of list items. */
} trk_desc;

/* Context structure for SNATCH-IT format. */
typedef struct cp2_ctx {
    img_file    *imgf;                  /* Image file handle. */
    long        img_size;               /* Image file size. */
    uint8_t     cyls;                   /* Number of cylinders. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     first_id;               /* First sector ID (typically 1). */
    trk_desc    trk_ofs[NCYL_MAX * 2];  /* Per-track sector descriptors. */
} cp2_ctx;


/* Identify a CP2 format image. Does not validate image. */
int cp2_identify( img_fns *cb, img_file imgf )
{
    cp2_hdr     hdr;
    int         rc;

    /* Just read the image header and see if it makes sense. */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* Fail if signature isn't what we expect. */
    if( memcmp( hdr.pirates, "SOFTWARE PIRATES", 16 ) )
        return( 0 );

    if( memcmp( hdr.version, "Release", 7) ) {
        return( 0 );
    }

    /* The image looks sensible enough... */
    return( sizeof( cp2_ctx ) );
}

/* Process one track in the image. */
int cp2_map_track( img_fns *cb, cp2_ctx *cp2, cp2_thdr *thdr, long trkdata_ofs, int first_in_seg )
{
    cp2_shdr    *shdr;
    sect_desc   *sdesc;
    long        sdata_ofs;
    unsigned    sec_size;
    int         trk_idx;
    int         phys_sect;
    int         first_sect = 1;
    uint16_t    sec_ofs;

    /* Validate cylinder and head. */
    if( thdr->cyl >= NCYL_MAX )
        return( IMG_ERR_BAD_IMG );
    if( thdr->head > 1 )
        return( IMG_ERR_BAD_IMG );

    /* Calculate and validate track number. */
    trk_idx = thdr->cyl * 2 + thdr->head;
    if( trk_idx > sizeof( cp2->trk_ofs ) / sizeof( cp2->trk_ofs[0] ) )
        return( IMG_ERR_BAD_IMG );  /* Track out of bounds. */

    /* If we've seen this track before, we have a problem. */
    if( cp2->trk_ofs[trk_idx].sdesc )
        return( IMG_ERR_BAD_IMG );

    /* Allocate and link sector descriptors for this track. */
    sdesc = cb->m_alloc_z( thdr->num_sect * sizeof( sdesc[0] ) );
    if( !sdesc )
        return( IMG_ERR_MEM_ALLOC );

    cp2->trk_ofs[trk_idx].sdesc    = sdesc;
    cp2->trk_ofs[trk_idx].num_desc = thdr->num_sect;


    /* Scan sector headers one by one. */
    for( phys_sect = 0; phys_sect < thdr->num_sect; ++phys_sect ) {
        shdr = &thdr->sct_hdr[phys_sect];
        sec_size = SEC_SZ_BYTES( shdr->size_code );
        sec_ofs = (shdr->sofs_hi << 8) + shdr->sofs_lo;

        /* Check the data offset of the first sector in the segment; should be
         * a magic value.
         */
        if( first_sect ) {
            if( first_in_seg && (sec_ofs != CP2_SEC_OFS_MAGIC) )
                return( IMG_ERR_BAD_IMG );

            first_sect = 0;
        }

        /* Ensure sector offset is not less than magic value. */
        if( sec_ofs < CP2_SEC_OFS_MAGIC )
            return( IMG_ERR_BAD_IMG );

        /* ST0-3 bits mostly indicate errors, but only mostly. Notably ST0
         * bits 1:0 indicate the drive selected, and bit 2 indicates the
         * head number.
         */
        if( (shdr->st0 & 0xF8) || shdr->st1 || shdr->st2 )
            return( IMG_ERR_BAD_IMG );

        /* Ensure that the sector ID matches physical track. */
        if( thdr->cyl != shdr->hdr_cyl )
            return( IMG_ERR_BAD_IMG );

        if( thdr->head != shdr->hdr_head )
            return( IMG_ERR_BAD_IMG );

        sdata_ofs = trkdata_ofs + sec_ofs - CP2_SEC_OFS_MAGIC;

        /* Sector looks good; store vital data in descriptor. */
        sdesc[phys_sect].file_ofs  = sdata_ofs;
        sdesc[phys_sect].sect_id   = shdr->hdr_sec;
        sdesc[phys_sect].sect_size = sec_size;

    }

    return( IMG_OK );
}

/* Sequentially scan the image, building a map of tracks/sectors. */
int cp2_build_track_map( img_fns *cb, cp2_ctx *ctx, long start_ofs )
{
    cp2_shdr    *shdr;
    cp2_thdr    thdr;
    long        curr_ofs;
    int         rc;
    uint8_t     trailer;
    uint16_t    blk_sz;
    int         segment = 0;
    int         first_in_seg;
    int         n_thdrs;
    int         i;
    int         cyl_last = 0;
    bool        seen_2nd_side = false;
    int         is_phantom;
    long        trkdata_ofs;

    curr_ofs = start_ofs;

    for( ;; ) {
        segment++;
        first_in_seg = 1;

        /* Read the size of the track header block. */
        rc = cb->read( ctx->imgf, &blk_sz, sizeof( blk_sz ) );
        if( rc != sizeof( blk_sz ) )
            break;

        /* Sanity check the block size. */
        if( (blk_sz == 0) || (blk_sz >= 0x8000) )
            return( IMG_ERR_BAD_IMG );

        if( (blk_sz - 1) % sizeof( cp2_thdr ) )
            return( IMG_ERR_BAD_IMG );

        curr_ofs += sizeof( blk_sz );

        /* Calculate the offset of sector data in the image. */
        trkdata_ofs = curr_ofs + blk_sz + sizeof( blk_sz );

        /* Calculate the number of track headers in this block. */
        n_thdrs = (blk_sz - 1) / sizeof( cp2_thdr );

        /* Process all track headers in this block. */
        for( i = 0; i < n_thdrs; ++i ) {
            /* Read track header */
            rc = cb->read( ctx->imgf, &thdr, sizeof( cp2_thdr ) );
            if( rc != sizeof( cp2_thdr ) )
                return( IMG_ERR_READ );

            curr_ofs += sizeof( cp2_thdr );

            /* Check for a phantom track and ignore if so. */
            is_phantom = 0;
            if( thdr.num_sect == 1 ) {
                shdr = &thdr.sct_hdr[0];
                if( (shdr->hdr_cyl == 6) && (shdr->hdr_sec == 6) && (shdr->size_code == 6) )
                    is_phantom = 1;
            }

            if( !is_phantom ) {
                /* Process all sectors in this track. */
                rc = cp2_map_track( cb, ctx, &thdr, trkdata_ofs, first_in_seg );
                if( rc != 0 )
                    return( rc );

                /* Update 'last valid track' counter. */
                if( cyl_last < thdr.cyl )
                    cyl_last = thdr.cyl;

                /* Check if it's a two-sided disk. */
                if( thdr.head )
                    seen_2nd_side = true;
            }

            first_in_seg = 0;
        }

        /* Read the trailer byte. */
        rc = cb->read( ctx->imgf, &trailer, sizeof( trailer ) );
        if( rc != sizeof( trailer ) )
            return( IMG_ERR_READ );

        curr_ofs += sizeof( trailer );

        /* Read the size of the track data block. */
        rc = cb->read( ctx->imgf, &blk_sz, sizeof( blk_sz ) );
        if( rc != sizeof( blk_sz ) )
            return( IMG_ERR_READ );

        curr_ofs += sizeof( blk_sz );

        /* Skip the data block. */
        cb->seek( ctx->imgf, curr_ofs + blk_sz );

        curr_ofs += blk_sz;

        /* If the trailer byte indicates end of image, we're done. */
        if( trailer == CP2_TRAILER_LAST )
            break;
    }

    /* Figure out the number of heads and cylinders. */
    ctx->heads = seen_2nd_side ? 2 : 1;
    ctx->cyls  = cyl_last + 1;

    return( IMG_OK );
}

/* Find the lowest sector ID on the first track. */
uint8_t cp2_find_first_id( cp2_ctx *ctx )
{
    int         phys_sect;
    uint8_t     low_id;
    trk_desc    *tdesc;
    sect_desc   *sdesc;

    /* Get the sector descriptors for the first track. */
    tdesc = &ctx->trk_ofs[0];
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

/* Open an image for access. May fail if image is damaged or cannot be
 * represented as a raw format image.
 */
int cp2_open( img_fns *cb, img_file imgf, cp2_ctx *ctx )
{
    int         rc = IMG_ERR_BAD_IMG;
    int         nb;
    cp2_hdr     img_hdr;
    long        curr_ofs;

    /* Read the image format header. We already ensured it's sensible. */
    cb->seek( imgf, 0 );
    nb = cb->read( imgf, &img_hdr, sizeof( img_hdr ) );
    if( nb != sizeof( img_hdr ) )
        return( IMG_ERR_READ );

    curr_ofs = sizeof( img_hdr );

    /* Store the image pointer and image size. */
    ctx->imgf     = imgf;
    ctx->img_size = cb->fsize( imgf );

    /* Build a map of all the tracks in the image. If the track map
     * can be built, the image is assumed to be OK.
     */
    rc = cp2_build_track_map( cb, ctx, curr_ofs );
    if( rc )
        goto error_cleanup;

    /* Figure out the starting sector ID. */
    ctx->first_id = cp2_find_first_id( ctx );

    /* Fill out the rest of the context structure. */
    ctx->spt      = ctx->trk_ofs[0].num_desc;
    assert( ctx->spt );

    return( IMG_OK );

error_cleanup:

    return( rc );
}

/* Query the comment string. Unsupported. */
const char *cp2_query_comment( img_fns *cb, cp2_ctx *td )
{
    return( NULL );
}

/* Read a single sector from the image. */
int cp2_read_sect( img_fns *cb, cp2_ctx *ctx, int sect_num, void *buf )
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
    track_num = sect_num / ctx->spt;
    if( ctx->heads == 1 )
        track_num *= 2;
    sect_id   = sect_num % ctx->spt;
    if( track_num >= ctx->cyls * 2 )
        return( IMG_ERR_NO_SECT );

    /* Logical sector IDs are typically 1-based. */
    sect_id += ctx->first_id;

    /* Get the sector descriptors for this track. */
    tdesc = &ctx->trk_ofs[track_num];

    /* If a track in the middle has not been recorded, make something up. */
    if( !tdesc->num_desc ) {
        memset( buf, 0, IMG_SEC_SZ_DEF );
        strcpy( buf, "CP2 track missing!" );
        return( IMG_SEC_SZ_DEF );
    }

    sdesc = tdesc->sdesc;
    assert( sdesc );

    /* Look for the sector ID. */
    for( phys_sect = 0; phys_sect < tdesc->num_desc; ++phys_sect ) {
        if( sdesc[phys_sect].sect_id == sect_id )
            break;
    }
    /* If the sector is missing entirely, make something up. */
    if( phys_sect >= tdesc->num_desc ) {
        memset( buf, 0, IMG_SEC_SZ_DEF );
        strcpy( buf, "CP2 sector missing!" );
        return( IMG_SEC_SZ_DEF );
    }

    sec_size = sdesc[phys_sect].sect_size;
    sec_ofs  = sdesc[phys_sect].file_ofs;

    /* If sector size is bigger than what caller expects, bail. */
    if( sec_size > IMG_SEC_SZ_MAX )
        return( IMG_ERR_CANT_CONV );

    assert( sdesc[phys_sect].sect_id == sect_id );

    /* Read sector data. */
    cb->seek( ctx->imgf, sec_ofs );
    rc = cb->read( ctx->imgf, buf, sec_size );
    if( rc != sec_size )
        return( IMG_ERR_READ );

    return( sec_size );
}

/* Close an image once all accesses are completed. */
void cp2_close( img_fns *cb, cp2_ctx *ctx )
{
    int     trk_idx;
    int     max_trk;

    assert( ctx );

    max_trk = sizeof( ctx->trk_ofs ) / sizeof( ctx->trk_ofs[0] );
    for( trk_idx = 0; trk_idx < max_trk; ++trk_idx ) {
        if( ctx->trk_ofs[trk_idx].sdesc )
            cb->m_free( ctx->trk_ofs[trk_idx].sdesc );
    }
}
