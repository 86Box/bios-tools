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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>

/* See img_cp2.c for SNATCH-IT format description. */

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
    FILE        *imgf;                  /* Image file handle. */
    uint8_t     trks;                   /* Number of tracks. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     first_id;               /* First sector ID (typically 1). */
    trk_desc    trk_ofs[NCYL_MAX * 2];  /* Per-track sector descriptors. */
} cp2_ctx;


/* Identify a CP2 format image. Does not validate image. */
int cp2_identify( FILE *imgf )
{
    cp2_hdr     hdr;
    int         rc;

    /* Just read the image header and see if it makes sense. */
    fseek( imgf, 0, SEEK_SET );
    rc = fread( &hdr, 1, sizeof( hdr ), imgf );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* Fail if signature isn't what we expect. */
    if( memcmp( hdr.pirates, "SOFTWARE PIRATES", 16 ) )
        return( 0 );

    /* The image looks sensible enough... */
    return( sizeof( cp2_ctx ) );
}

/* Process one track in the image. */
int cp2_explore_track( cp2_ctx *cp2, cp2_thdr *thdr, long trkdata_ofs, int first_in_seg )
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
    if( thdr->cyl >= NCYL_MAX ) {
        printf( "Cylinder number (%d) out of range!\n", thdr->cyl );
        return( 1 );
    }
    if( thdr->head > 1 ) {
        printf( "Head number (%d) out of range!\n", thdr->head );
        return( 1 );
    }

    /* Special case for phantom tracks. */
    if( thdr->num_sect == 1 ) {
        shdr = &thdr->sct_hdr[0];
        if( (shdr->hdr_cyl == 6) && (shdr->hdr_sec == 6) && (shdr->size_code == 6) ) {
            sec_ofs = (shdr->sofs_hi << 8) + shdr->sofs_lo;
            sec_size = SEC_SZ_BYTES( shdr->size_code );
            printf( "  Ignoring phantom-six track (sec %d %dB@%X)\n", shdr->hdr_sec, sec_size, sec_ofs );
            return( 0 );
        }
    }

    /* Calculate and validate track number. */
    trk_idx = thdr->cyl * 2 + thdr->head;
    if( trk_idx > sizeof( cp2->trk_ofs ) / sizeof( cp2->trk_ofs[0] ) )
        return( 2 );  /* Track out of bounds. */

    /* If we've seen this track before, we have a problem. */
    if( cp2->trk_ofs[trk_idx].sdesc ) {
        printf( "Track %d%/%d already seen!\n", trk_idx / 2, trk_idx % 2 );
        return( 1 );
    }

    /* Allocate and link sector descriptors for this track. */
    sdesc = malloc( thdr->num_sect * sizeof( sdesc[0] ) );
    if( !sdesc )
        return( 3 );    //@todo: free previously allocated bits
    cp2->trk_ofs[trk_idx].sdesc    = sdesc;
    cp2->trk_ofs[trk_idx].num_desc = thdr->num_sect;


    printf( "  " );
    /* Scan sector headers one by one. */
    for( phys_sect = 0; phys_sect < thdr->num_sect; ++phys_sect ) {
        shdr = &thdr->sct_hdr[phys_sect];
        sec_size = SEC_SZ_BYTES( shdr->size_code );
        sec_ofs = (shdr->sofs_hi << 8) + shdr->sofs_lo;

        /* Check the data offset of the first sector in the segment; should be
         * a magic value.
         */
        if( first_sect ) {
            if( first_in_seg && (sec_ofs != CP2_SEC_OFS_MAGIC) ) {
                printf( "  Data offset of first sector not %04X!\n", CP2_SEC_OFS_MAGIC );
                return( 1 );
            }
            first_sect = 0;
        }

        /* Ensure sector offset is not less than magic value. */
        if( sec_ofs < CP2_SEC_OFS_MAGIC ) {
            printf( "  Data offset of first sector too small (%04X < %04X)!\n", sec_ofs, CP2_SEC_OFS_MAGIC );
            return( 1 );
        }

        /* Subtract the weird magic. */
        printf( "%d %dB@%X;", shdr->hdr_sec, sec_size, sec_ofs - CP2_SEC_OFS_MAGIC );

        /* ST0-3 bits mostly indicate errors, but only mostly. Notably ST0
         * bits 1:0 indicate the drive selected, and bit 2 indicates the
         * head number.
         */
        if( (shdr->st0 & 0xF8) || shdr->st1 || shdr->st2 ) {
            printf( "ST0-3:%02X %02X %02X", shdr->st0, shdr->st1, shdr->st2 );
        }

        /* Ensure that the sector ID matches physical track. */
        if( thdr->cyl != shdr->hdr_cyl ) {
            printf( "Cylinder mismatch, %d phys vs %d in ID!\n", thdr->cyl, shdr->hdr_cyl );
            return( 1 );
        }
        if( thdr->head != shdr->hdr_head ) {
            printf( "Head mismatch, %d phys vs %d in ID!\n", thdr->head, shdr->hdr_head );
            return( 1 );
        }

        sdata_ofs = trkdata_ofs + sec_ofs - CP2_SEC_OFS_MAGIC;

        /* Sector looks good; store vital data in descriptor. */
        sdesc[phys_sect].file_ofs  = sdata_ofs;
        sdesc[phys_sect].sect_id   = shdr->hdr_sec;
        sdesc[phys_sect].sect_size = sec_size;

    }
    printf( "\n" );

    return( 0 );
}

/* Sequentially scan the image, building a map of tracks/sectors. */
int cp2_explore_image( cp2_ctx *cp2, long start_ofs )
{
    cp2_thdr    thdr;
    long        curr_ofs;
    int         rc;
    uint8_t     trailer;
    uint16_t    blk_sz;
    int         segment = 0;
    int         first_in_seg;
    int         n_thdrs;
    int         i;
    long        trkdata_ofs;

    curr_ofs = start_ofs;

    for( ;; ) {
        segment++;
        first_in_seg = 1;

        /* Read the size of the track header block. */
        rc = fread( &blk_sz, 1, sizeof( blk_sz ), cp2->imgf );
        if( rc != sizeof( blk_sz ) )
            break;

        printf( "Seg %02d track headr blk size: %04X at ofs %08lX\n", segment, blk_sz, curr_ofs );

        /* Sanity check the block size. */
        if( (blk_sz == 0) || (blk_sz >= 0x8000) ) {
            printf( "Invalid track header block size!\n" );
            break;
        }

        if( (blk_sz - 1) % sizeof( cp2_thdr ) ) {
            printf( "Track header block size not a multiple of track entry size (%d)!\n", sizeof( cp2_thdr ) );
            break;
        }

        curr_ofs += sizeof( blk_sz );

        /* Calculate the offset of sector data in the image. */
        trkdata_ofs = curr_ofs + blk_sz + sizeof( blk_sz );

        /* Calculate the number of track headers in this block. */
        n_thdrs = (blk_sz - 1) / sizeof( cp2_thdr );

        /* Process all track headers in this block. */
        for( i = 0; i < n_thdrs; ++i ) {
            /* Read track header */
            rc = fread( &thdr, 1, sizeof( cp2_thdr ), cp2->imgf );
            if( rc != sizeof( cp2_thdr ) ) {
                printf( "Could not read track header at offset %08lX!\n", curr_ofs );
                return( 1 );
            }

            printf( " cyl %02d/hd %d, %d sectors @ %08lX\n", thdr.cyl, thdr.head, thdr.num_sect, curr_ofs );
            curr_ofs += sizeof( cp2_thdr );

            /* Now process all sectors in this track. */
            rc = cp2_explore_track( cp2, &thdr, trkdata_ofs, first_in_seg );
            if( rc != 0 )
                return( 1 );
            first_in_seg = 0;
        }

        /* Read the trailer byte. */
        rc = fread( &trailer, 1, sizeof( trailer ), cp2->imgf );
        if( rc != sizeof( trailer ) ) {
            printf( "Could not read trailer byte at offset %08lX!\n", curr_ofs );
            return( 1 );
        }
        printf( " trailer: %02X @ %08lX\n", trailer, curr_ofs );
        curr_ofs += sizeof( trailer );

        /* Read the size of the track data block. */
        rc = fread( &blk_sz, 1, sizeof( blk_sz ), cp2->imgf );
        if( rc != sizeof( blk_sz ) )
        {
            printf( "Cold not read data block size!\n" );
            return( 1 );
        }

        printf( "Seg %02d sector data blk size: %04X at ofs %08lX (sector data at %08lX)\n",
                segment, blk_sz, curr_ofs, curr_ofs + sizeof( uint16_t ) );

        curr_ofs += sizeof( blk_sz );

        /* Skip the data block. */
        fseek( cp2->imgf, curr_ofs + blk_sz, SEEK_SET );

        curr_ofs += blk_sz;

        /* If the trailer byte indicates end of image, we're done. */
        if( trailer == CP2_TRAILER_LAST )
            break;
    }
    return( 0 );
}

int main( int argc, char **argv )
{
    int             rc;
    int             nb;
    cp2_hdr         img_hdr;
    long            curr_ofs;
    cp2_ctx         cp2;
    FILE            *imgf;

    if( argc != 2 ) {
        printf( "usage: %s <cp2_file>\n", argv[0] );
        return( 127 );
    }

    memset( &cp2, 0, sizeof( cp2 ) );

    imgf = fopen( argv[1], "rb" );
    if( !imgf ) {
        printf( "error: failed to open `%s'\n", argv[1] );
        return( 126 );
    }

    if( !cp2_identify( imgf ) ) {
        printf( "error: `%s' is not a SNATCH-IT image.", argv[1] );
        return( 125 );
    }

    /* Read the bare image format header. */
    fseek( imgf, 0, SEEK_SET );
    curr_ofs = sizeof( img_hdr );
    nb = fread( &img_hdr, 1, curr_ofs, imgf );
    if( nb != curr_ofs ) {
        printf( "error: could not read SNATCH-IT image header!" );
        return( 124 );
    }

    printf( "SNATCH-IT: %.12s vol %c\n", img_hdr.version, img_hdr.vol_no );

    if( img_hdr.vol_no != '0' ) {
        printf( "Not the first volume of a multi-volume image!\n" );
        return( 1 );
    }

    /* Store the image file pointer. */
    cp2.imgf = imgf;

    /* Build a map of all the tracks in the image. If the track map
     * can be built, the image is assumed to be OK.
     */
    rc = cp2_explore_image( &cp2, curr_ofs );
    fclose( imgf );
    if( rc ) {
        printf( "error: SNATCH-IT image not understood or corrupted!" );
        goto error_cleanup;
    }

    return( 0 );

error_cleanup:

    return( rc );
}
