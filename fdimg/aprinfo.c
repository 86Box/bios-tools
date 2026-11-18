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

/* See img_apr.c for ACT Apricot format description. */

/* Somewhat arbitrary, but a regular drive shouldn't be able to do more. */
#define NTRK_MAX    84

/* Arbitrarily chosen; should never be more than 36 in practice. */
#define SPT_MAX     64


/* Format constants. */
#define OBJ_SIG     0xE31D          /* Object header signature. */
#define OBJT_SECT   0x0001          /* Object is a sector. */
#define OBJT_CMNT   0x0002          /* Object is a comment. */
#define CMPR_NONE   0x9E90          /* Compression - uncompressed. */
#define CMPR_REPE   0x3E5A          /* Compression - Repeated byte */


/* ACT Apricot image header. */
typedef struct apr_hdr_s {
    char        signature[24];      /* 'ACT Apricot' signature. */
    char        padding[128 - 24];  /* Zeros. */
} apr_hdr;

/* ACT Apricot object header. */
typedef struct obj_hdr_s {
    uint16_t    obj_typ;            /* Object type. */
    uint16_t    magic;              /* Signature. */
    uint16_t    compres;            /* Compression indicator. */
    uint16_t    hdr_len;            /* Length of header in bytes. */
    uint16_t    obj_len;            /* Length of following object in bytes. */
    uint16_t    stuf1;              /* Unused? */
    uint8_t     head;               /* Head/side (0 or 1). */
    uint8_t     sect_id;            /* Sector ID (1-based). */
    uint16_t    cylinder;           /* Physical cylinder (zero-based). */
    uint16_t    stuf2;              /* Unused? */
} obj_hdr;

/* Sector offset descriptor. Points to the sector header in image file. Note
 * that logical sector IDs may occur in any order, may have gaps, and may
 * not be unique.
 */
typedef struct sect_desc {
    long        file_ofs;           /* Offset of object header in file. */
    int         sect_size;          /* Sector size in bytes. */
    uint8_t     sect_id;            /* Logical sector ID. */
} sect_desc;


/* Track descriptor. Contains a pointer to a list of sector offset descriptors
 * plus the count of items, as sectors per track may not be uniform.
 */
typedef struct trk_desc_s {
    sect_desc   *sdesc;             /* Sector descriptor list. */
    int         num_desc;           /* Number of list items. */
} trk_desc;


/* Context structure for ACT Apricot format. */
typedef struct apr_ctx {
    FILE        *imgf;                  /* Image file handle. */
    uint8_t     trks;                   /* Number of tracks. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     first_id;               /* First sector ID (typically 1). */
    char        *comment;               /* Optional comment. */
    trk_desc    trk_ofs[NTRK_MAX * 2];  /* Per-track sector descriptors. */
} apr_ctx;


/* Identify an ACT Apricot format image. Does not validate image. */
int apr_identify( FILE *imgf )
{
    apr_hdr     hdr;
    int         rc;

    /* Just read the image header and see if signature is there. */
    fseek( imgf, 0, SEEK_SET );
    rc = fread( &hdr, 1, sizeof( hdr ), imgf );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* Fail if signature isn't 'ACT Apricot'. */
    if( memcmp( hdr.signature, "ACT Apricot disk image\x1a\x4", sizeof( hdr.signature ) ) )
        return( 0 );

    /* Yep, must be an Apricot image. */
    return( sizeof( apr_ctx ) );

}


/* Read sector data from image, decompress as needed; sdata_ofs is the image
 * offset of the object header. The img_read argument points to a location
 * where the number of bytes read from image is returned (or not if img_read
 * is NULL).
 */
int apr_decomp_obj( apr_ctx *apr, long sdata_ofs, void *buf, unsigned buf_sz, unsigned *img_read )
{
    obj_hdr     ohdr;
    uint8_t     repb;
    uint16_t    rep_cnt;
    int         rc;
    unsigned    bytes_read;

    /* Read sector data record, followed by raw or compressed data. */
    fseek( apr->imgf, sdata_ofs, SEEK_SET );
    rc = fread( &ohdr, 1, sizeof( ohdr ), apr->imgf );
    if( rc != sizeof( ohdr ) )
        return( false );

    bytes_read = rc;

    switch( ohdr.compres ) {
    case CMPR_NONE:
        /* Uncompressed object data. */
        if( ohdr.obj_len > buf_sz ) {
            printf( "Object buffer too small for reading! (need %d, got %d bytes)\n",
                    ohdr.obj_len, buf_sz );
            return( false );
        }
        rc = fread( buf, 1, ohdr.obj_len, apr->imgf );
        if( rc != ohdr.obj_len )
            return( false );
        bytes_read += ohdr.obj_len;
        break;
    case CMPR_REPE:
        /* Repeated object data. */
        rc = fread( &rep_cnt, 1, sizeof( rep_cnt ), apr->imgf );
        if( rc != sizeof( rep_cnt ) )
            return( false );
        bytes_read += rc;
        rc = fread( &repb, 1, sizeof( repb ), apr->imgf );
        if( rc != sizeof( repb ) )
            return( false );
        bytes_read += rc;
        if( rep_cnt > buf_sz ) {
            printf( "Object buffer too small for decompression! (need %d, got %d bytes)\n",
                    rep_cnt, buf_sz );
            return( false );
        }
        memset( buf, repb, rep_cnt );
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
int apr_explore( apr_ctx *apr, long start_ofs )
{
    obj_hdr     ohdr;
    long        curr_ofs;
    int         trk_idx;
    int         trk_last;
    int         sec_idx;
    int         sect_max;
    int         cyln_max;
    int         head_max;
    int         num_sect;
    int         rc;
    int         i;
    sect_desc   *sdesc;
    unsigned    img_read;
    unsigned    obj_size;
    uint8_t     sec_buf[4096];  /* Size is a guesstimate. */

    curr_ofs = start_ofs;
    trk_last = 0;
    sect_max = 0;
    cyln_max = 0;
    head_max = 0;
    num_sect = 0;

    /* Simply go over all the 'objects' in the image and see what we got. */
    for( ;; ) {
        /* Read object header */
        rc = fread( &ohdr, 1, sizeof( ohdr ), apr->imgf );

        /* Exit if at end end of image. */
        if( !rc ) {
            //@todo: Should the number of tracks really be what it says, i.e.
            // the # of tracks and not cylinders?
            apr->trks = trk_last / 2 + 1;
            break;
        }

        if( rc != sizeof( ohdr ) )
            return( 1 );

        if( ohdr.magic != OBJ_SIG ) {
            printf( "Bad magic! (need %X, got %X)\n", OBJ_SIG, ohdr.magic );
            return( 1 );
        }

        if( ohdr.hdr_len != sizeof( ohdr ) ) {
            printf( "Bad objhdr size! (need %X, got %X)\n", sizeof( ohdr ), ohdr.hdr_len );
            return( 1 );
        }

        obj_size = ohdr.obj_len;

        printf( "Magic:%X Type:%X Compr:%X Objsize:%.3d ",
                 ohdr.magic, ohdr.obj_typ, ohdr.compres, ohdr.obj_len );
        printf( "C/H/S: %02d/%02d/%02d at %08lX\n",
                ohdr.cylinder, ohdr.head, ohdr.sect_id, curr_ofs );

        if( ohdr.stuf1 ) {
            printf( "Non-zero stuf1 (%04X)!\n", sizeof( ohdr ), ohdr.stuf1 );
            return( 1 );
        }
        if( ohdr.stuf2 ) {
            printf( "Non-zero stuf2 (%04X)!\n", sizeof( ohdr ), ohdr.stuf2 );
            return( 1 );
        }

        if( ohdr.obj_typ == OBJT_SECT ) {
            /* Calculate and validate track number. */
            trk_idx = ohdr.cylinder * 2 + ohdr.head;
            if( trk_idx > sizeof( apr->trk_ofs ) / sizeof( apr->trk_ofs[0] ) )
                return( 2 );  /* Track out of bounds. */

            trk_last = trk_idx;
            ++num_sect;

            /* We have no idea what the geometry is. Keep track here. */
            if( ohdr.sect_id > sect_max )
                sect_max = ohdr.sect_id;
            if( ohdr.cylinder > cyln_max )
                cyln_max = ohdr.cylinder;
            if( ohdr.head > head_max )
                head_max = ohdr.head;

            /* Allocate and link sector descriptors for this track if needed. */
            if( !apr->trk_ofs[trk_idx].sdesc ) {
                sdesc = calloc( 1, SPT_MAX * sizeof( sdesc[0] ) );
                if( !sdesc )
                    return( 3 );    //@todo: free previously allocated bits
                apr->trk_ofs[trk_idx].sdesc    = sdesc;
                apr->trk_ofs[trk_idx].num_desc = 0;
            } else {
                sdesc = apr->trk_ofs[trk_idx].sdesc;
            }
            sec_idx = apr->trk_ofs[trk_idx].num_desc;

            /* Read/decompress the sector data. */
            rc = apr_decomp_obj( apr, curr_ofs, sec_buf, sizeof( sec_buf ), &img_read );
            if( !rc )
                return( 4 );

            /* Sector looks good; store vital data in descriptor. */
            sdesc[sec_idx].file_ofs  = curr_ofs;
            sdesc[sec_idx].sect_id   = ohdr.sect_id;
            sdesc[sec_idx].sect_size = obj_size;

            curr_ofs += img_read;
            //@todo: check for overflow!
            apr->trk_ofs[trk_idx].num_desc++;
        } else if( ohdr.obj_typ == OBJT_CMNT ) {
            /* Allocate space for comment (must be uncompressed). */
            apr->comment = malloc( ohdr.obj_len );
            if( !apr->comment )
                return( 3 );

            /* Read comment. */
            rc = apr_decomp_obj( apr, curr_ofs, apr->comment, ohdr.obj_len, &img_read );
            if( !rc )
                return( 4 );

            apr->comment[ohdr.obj_len] = '\0';  /* Just to be safe. */

            /* Massage comment string. */
            i = 0;
            while( apr->comment[i] ) {
                if( apr->comment[i] == '\r' )
                    apr->comment[i] = '\n';
                ++i;
            }

        } else {
            printf( "Unknown object type (%04X)!\n", ohdr.obj_typ );
            return( 5 );
        }
    }
    printf( "max track:%d  max sector: %d  max head: %d\n",
            cyln_max, sect_max, head_max );
    printf( "Have %d sectors, should have %d\n",
            num_sect, (cyln_max + 1) * (head_max + 1) * sect_max );

    return( 0 );
}

int main( int argc, char **argv )
{
    int             rc;
    long            curr_ofs;
    apr_ctx         apr;
    FILE            *imgf;

    if( argc != 2 ) {
        printf( "usage: %s <apr_file>\n", argv[0] );
        return( 127 );
    }

    imgf = fopen( argv[1], "rb" );
    if( !imgf ) {
        printf( "error: failed to open `%s'\n", argv[1] );
        return( 126 );
    }

    if( !apr_identify( imgf ) ) {
        printf( "error: `%s' is not an ACT Apricot image.", argv[1] );
        return( 125 );
    }

    /* Seek past the image file signature. */
    fseek( imgf, sizeof( apr_hdr ), SEEK_SET );
    curr_ofs = sizeof( apr_hdr );

    /* Set up the image context. */
    apr.imgf    = imgf;
    apr.comment = NULL;
    memset( apr.trk_ofs, 0, sizeof( apr.trk_ofs ) );

    /* Build a map of all the tracks and sectors in the image. If the
     * track map can be built, the image is assumed to be OK.
     */
    rc = apr_explore( &apr, curr_ofs );
    fclose( imgf );
    if( rc ) {
        printf( "error: ACT Apricot image not understood or corrupted!" );
        goto error_cleanup;
    }

    if( apr.comment )
        printf( "%s", apr.comment );

    return( 0 );

error_cleanup:
    if( apr.comment )
        free( apr.comment );

    return( rc );
}
