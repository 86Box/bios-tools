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

/* See img_imd.c for ImageDisk format description. */

/* Somewhat arbitrary, but a regular drive shouldn't be able to do more. */
#define NTRK_MAX    84

/* ImageDisk image header. */
typedef struct imd_hdr_s {
    char        signature[32];          /* 'IMD' timestamp signature. */
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
 * not be unique.
 */
typedef struct sect_desc {
    long        file_ofs;               /* Offset of sector header in file. */
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


/* Context structure for ImageDisk format. */
typedef struct imd_ctx {
    FILE        *imgf;                  /* Image file handle. */
    uint8_t     trks;                   /* Number of tracks. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     first_id;               /* First sector ID (typically 1). */
    imd_hdr     hdr;                    /* The image header. */
    char        *comment;               /* Optional comment. */
    trk_desc    trk_ofs[NTRK_MAX * 2];  /* Per-track sector descriptors. */
} imd_ctx;


/* Identify a ImageDisk format image. Does not validate image. */
int imd_identify( FILE *imgf )
{
    imd_hdr     hdr;
    int         rc;

    /* Just read the image header and see if it makes sense. */
    fseek( imgf, 0, SEEK_SET );
    rc = fread( &hdr, 1, sizeof( hdr ), imgf );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* Fail if signature isn't 'IMD'. */
    if( memcmp( hdr.signature, "IMD", 3 ) )
        return( 0 );

    /* The signature may include lots more, including a timestamp, but
     * it need not be more than 'IMD'. Don't bother checking further.
     */

    /* The image looks sensible enough... */
    return( sizeof( imd_ctx ) );

}

/* Read sector data from image, decompress as needed; sdata_ofs is the image
 * offset of the sector data header. The img_read argument points to a location
 * where the number of bytes read from image is returned (or NULL if that is
 * not relevant).
 */
int imd_decomp_sect( imd_ctx *imd, long sdata_ofs, void *buf, unsigned sec_sz, unsigned *img_read )
{
    uint8_t     drec;
    uint8_t     repb;
    int         rc;
    unsigned    bytes_read;

    /* Read sector data record, followed by raw or compressed data. */
    fseek( imd->imgf, sdata_ofs, SEEK_SET );
    rc = fread( &drec, 1, sizeof( drec ), imd->imgf );
    if( rc != sizeof( drec ) )
        return( false );

    printf( " %02d", drec );
    bytes_read = 1;

    switch( drec ) {
    case SECT_NO_DATA:
        memset( buf, 0, sec_sz );
        strcpy( buf, "IMD sector ID only!" );
        break;
    case SECT_NORM:
    case SECT_DDAM_NORM:
    case SECT_ERR_NORM:
    case SECT_DERR_NORM:
        /* Uncompressed sector data. */
        rc = fread( buf, 1, sec_sz, imd->imgf );
        if( rc != sec_sz )
            return( false );
        bytes_read += sec_sz;
        break;
    case SECT_CMPR:
    case SECT_DDAM_CMPR:
    case SECT_ERR_CMPR:
    case SECT_DERR_CMPR:
        rc = fread( &repb, 1, sizeof( repb ), imd->imgf );
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

const char *imd_rate[] = { "500 kbps FM",  "300 kbps FM",  "250 kbps FM",
                           "500 kbps MFM", "300 kbps MFM", "250 kbps MFM" };

/* Sequentially scan the image, building a map of tracks/sectors.
   Also validates CRCs to get that out of the way. */
int imd_explore( imd_ctx *imd, long start_ofs )
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
    uint8_t     sec_buf[4096];

    curr_ofs = start_ofs;
    trk_last = 0;

    for( ;; ) {
        /* Read track header; even the EOF marker includes a full header,
         * despite the fact that only the first byte is meaningful.
         */
        rc = fread( &thdr, 1, sizeof( thdr ), imd->imgf );

        /* Exit if at end end of image. */
        if( !rc ) {
            //@todo: Should the number of tracks really be what it says, i.e.
            // the # of tracks and not cylinders?
            imd->trks = trk_last / 2 + 1;
            break;
        }

        if( rc != sizeof( thdr ) )
            return( 1 );
        sec_size = SEC_SZ_BYTES( thdr.sect_sz );

        printf( " %02d/%d (%02d %d-byte sectors, %s, flags %02X) at %08lX\n",
                 thdr.cylinder, thdr.head & TRK_HEAD_MASK, thdr.num_sect,
                 sec_size, imd_rate[thdr.mode], thdr.head & ~TRK_HEAD_MASK,
                 curr_ofs );

        curr_ofs += rc;

        /* Calculate and validate track number. */
        trk_idx = thdr.cylinder * 2 + (thdr.head & TRK_HEAD_MASK);
        if( trk_idx > sizeof( imd->trk_ofs ) / sizeof( imd->trk_ofs[0] ) )
            return( 2 );  /* Track out of bounds. */

        /* Read the sector numbering map. */
        rc = fread( &smap, 1, thdr.num_sect, imd->imgf );
        if( rc != thdr.num_sect )
            return( 1 );
        curr_ofs += rc;

        /* Print the sector map. */
        printf( "  smap:" );
        for( phys_sect = 0; phys_sect < thdr.num_sect; ++phys_sect )
            printf( " %02d", smap[phys_sect] );
        printf( "\n" );

        /* Read the cylinder numbering map if present. */
        if( thdr.head & TRK_CYLN_MAP ) {
            rc = fread( &cmap, 1, thdr.num_sect, imd->imgf );
            if( rc != thdr.num_sect )
                return( 1 );
            curr_ofs += rc;

            /* Print the cylinder map. */
            printf( "  cmap:" );
            for( phys_sect = 0; phys_sect < thdr.num_sect; ++phys_sect )
                printf( " %02d", cmap[phys_sect] );
            printf( "\n" );
        }

        /* Read the head numbering map if present. */
        if( thdr.head & TRK_HEAD_MAP ) {
            rc = fread( &hmap, 1, thdr.num_sect, imd->imgf );
            if( rc != thdr.num_sect )
                return( 1 );
            curr_ofs += rc;

            /* Print the cylinder map. */
            printf( "  hmap:" );
            for( phys_sect = 0; phys_sect < thdr.num_sect; ++phys_sect )
                printf( " %02d", hmap[phys_sect] );
            printf( "\n" );
        }

        /* Update 'last valid track' counter. */
        trk_last = trk_idx;

        /* Allocate and link sector descriptors for this track. */
        sdesc = malloc( thdr.num_sect * sizeof( sdesc[0] ) );
        if( !sdesc )
            return( 3 );    //@todo: free previously allocated bits
        imd->trk_ofs[trk_idx].sdesc    = sdesc;
        imd->trk_ofs[trk_idx].num_desc = thdr.num_sect;

        /* Loop over all sectors on this track... */
        printf( "  sdta:" );
        for( phys_sect = 0; phys_sect < thdr.num_sect; ++phys_sect ) {
            /* Read sector header to see what to do next. */
            shdr_ofs = curr_ofs;

            /* If present, read the sector data header and actual data. */
            rc = imd_decomp_sect( imd, curr_ofs, sec_buf, sec_size, &img_read );
            if( !rc )
                return( 4 );
            curr_ofs += img_read;

            /* Sector looks good; store vital data in descriptor. */
            sdesc[phys_sect].file_ofs  = shdr_ofs;
            sdesc[phys_sect].sect_id   = smap[phys_sect];
            sdesc[phys_sect].sect_size = sec_size;
        }
        printf( "\n\n" );
    }
    return( 0 );
}

int main( int argc, char **argv )
{
    int             rc;
    int             nb;
    char            chr;
    imd_hdr         img_hdr;
    char            *comment;
    long            curr_ofs;
    imd_ctx         imd;
    FILE            *imgf;
    int             cmnt_len;

    if( argc != 2 ) {
        printf( "usage: %s <imd_file>\n", argv[0] );
        return( 127 );
    }

    imgf = fopen( argv[1], "rb" );
    if( !imgf ) {
        printf( "error: failed to open `%s'\n", argv[1] );
        return( 126 );
    }

    if( !imd_identify( imgf ) ) {
        printf( "error: `%s' is not a ImageDisk image.", argv[1] );
        return( 125 );
    }

    /* Read the bare image format header, "IMD " or "IMDU". */
    fseek( imgf, 0, SEEK_SET );
    curr_ofs = 4;
    nb = fread( &img_hdr, 1, curr_ofs, imgf );
    if( nb != curr_ofs ) {
        printf( "error: could not read ImageDisk image header!" );
        return( 1 );
    }


    printf( "ImageDisk: %.4s\n", img_hdr.signature );

    /* Read in comment, if present. */
    comment = NULL;

    cmnt_len = 0;
    do {
        nb = fread( &chr, 1, sizeof( chr ), imgf );
        ++cmnt_len;
    } while( nb == 1 && chr != 0x1A );

    if( nb != 1 ) {
        fclose( imgf );
        printf( "error: ImageDisk comment not understood or corrupted!" );
        goto error_cleanup;
    }

    /* Read in the comment. */
    fseek( imgf, curr_ofs, SEEK_SET );
    comment = malloc( cmnt_len );
    if( !comment ) {
        fclose( imgf );
        printf( "error: Comment memory allocation failed!" );
        goto error_cleanup;
    }
    nb = fread( comment, 1, cmnt_len, imgf );
    comment[cmnt_len - 1] = '\0';   /* Replace EOF with NUL. */
    printf( "Comment: %s\n", comment );

    curr_ofs += cmnt_len;

    /* Store the comment and image pointers. */
    imd.comment = comment;
    imd.imgf    = imgf;

    /* Build a map of all the tracks in the image. Also validates CRCs and
     * suchlike. If the track map can be built, the image is assumed to be OK.
     */
    rc = imd_explore( &imd, curr_ofs );
    fclose( imgf );
    if( rc ) {
        printf( "error: ImageDisk image not understood or corrupted!" );
        goto error_cleanup;
    }

    return( 0 );

error_cleanup:
    if( comment )
        free( comment );

    return( rc );
}
