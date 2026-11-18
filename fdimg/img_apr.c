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
#include "img_apr.h"


/* The ACT Apricot format is used by the APRIDISK utility created by
 * Jonathan Marsters around 2000, available from actapricot.org. This code
 * was written purely based on the available Apricot .DSK images and the
 * debug output of APRIDISK.
 *
 * The Apricot format is unusual in that it provides absolutely no hint about
 * the kind of disk it represents. The image file has a 80-byte unique header
 * starting with an "ACT Apricot disk image" string. The rest of the image
 * consists from a stream of "objects"; the only two currently known object
 * types are sectors data and comments.
 *
 * Each object has a 18-byte header which includes the object type,
 * signature, header size, data size (how much data follows the header),
 * compression type, and track/side/sector indicator.
 *
 * The format can in theory handle almost any geometry and any sector size
 * which fits within 16 bits. It was likely only intended to be used with
 * 512-byte sectors. Bad sectors are simply not stored in the image at all.
 * The format might theoretically preserve logical sector ordering by
 * ordering sectors in the image the same way they were ordered on the disk.
 *
 * Sector (and comment) data is either stored as is, or using a simple method
 * of compression with a data byte and 16-bit repeat count.
 *
 * Existing images always store sectors in ascending track/side/sector order
 * but there is nothing inherent in the format which would enforce this. The
 * existing images also always have a comment at the end, but in theory it
 * could be anywhere in the image.
 *
 * Newer Apricot disks used standard IBM 3.5" 720K and 1.44M formats. Older
 * disks used a unique single-sided format with 9 sectors and 70 tracks (for
 * a total of 315K).
 *
 * An Apricot disk image need not represent any kind of remotely sensible
 * disk format. But existing images were created from real Apricot floppies
 * and are in one of the above formats. We simply go through the entire image
 * and build a map of tracks/sectors, and at the end we know the highest
 * track, side, and sector number we've seen.
 *
 * Missing sectors are assumed to have been bad/unreadable. The image format
 * provides absolutely no information about bad sectors; we have to guess
 * how big they might have been, and for that we simply use the size of the
 * first data sector (which with a great degree of probability is also the
 * size of all other data sectors).
 */


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
typedef struct sect_desc_s {
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
    img_file    imgf;                   /* Image file handle. */
    uint8_t     trks;                   /* Number of tracks. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     first_id;               /* First sector ID (typically 1). */
    int         def_sec_sz;             /* Default sector size. */
    char        *comment;               /* Optional comment. */
    trk_desc    trk_ofs[NTRK_MAX * 2];  /* Per-track sector descriptors. */
} apr_ctx;


/* Identify an ACT Apricot format image. Does not validate image. */
int apr_identify( img_fns *cb, img_file imgf )
{
    apr_hdr     hdr;
    int         rc;

    /* Just read the image header and see if signature is there. */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &hdr, sizeof( hdr ) );
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
 * is NULL). The data_read argument points to a location where the number of
 * bytes read or decompressed is returned (or not if data_read is NULL).
 * This is needed because the object header does not specify the size of
 * decompressed data.
 */
int apr_decomp_obj( img_fns *cb, apr_ctx *apr, long sdata_ofs, void *buf,
                    unsigned buf_sz, unsigned *img_read, unsigned *data_read )
{
    obj_hdr     ohdr;
    uint8_t     repb;
    uint16_t    rep_cnt;
    int         rc;
    unsigned    bytes_read;
    unsigned    bytes_provided;

    /* Read sector data record, followed by raw or compressed data. */
    cb->seek( apr->imgf, sdata_ofs );
    rc = cb->read( apr->imgf, &ohdr, sizeof( ohdr ) );
    if( rc != sizeof( ohdr ) )
        return( false );

    bytes_read     = rc;
    bytes_provided = 0;

    switch( ohdr.compres ) {
    case CMPR_NONE:
        /* Uncompressed object data. */
        if( ohdr.obj_len > buf_sz )
            return( false );
        rc = cb->read( apr->imgf, buf, ohdr.obj_len );
        if( rc != ohdr.obj_len )
            return( false );
        bytes_provided = rc;
        bytes_read += ohdr.obj_len;
        break;
    case CMPR_REPE:
        /* Repeated object data. */
        rc = cb->read( apr->imgf, &rep_cnt, sizeof( rep_cnt ) );
        if( rc != sizeof( rep_cnt ) )
            return( false );
        bytes_read += rc;
        rc = cb->read( apr->imgf, &repb, sizeof( repb ) );
        if( rc != sizeof( repb ) )
            return( false );
        bytes_read += rc;
        if( rep_cnt > buf_sz )
            return( false );
        bytes_provided = rep_cnt;
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

    /* Return the number of bytes placed in the buffer if requested. */
    if( data_read )
        *data_read = bytes_provided;

    return( true );
}


/* Sequentially scan the image, building a map of tracks/sectors. */
int apr_build_map( img_fns *cb, apr_ctx *apr, long start_ofs )
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
    unsigned    data_read;
    unsigned    obj_size;
    uint8_t     sec_buf[IMG_SEC_SZ_MAX];

    curr_ofs = start_ofs;
    trk_last = 0;
    sect_max = 0;
    cyln_max = 0;
    head_max = 0;
    num_sect = 0;

    /* Simply go over all the 'objects' in the image and see what we got. */
    for( ;; ) {
        /* Read object header */
        rc = cb->read( apr->imgf, &ohdr, sizeof( ohdr ) );

        /* Exit if at end end of image. */
        if( !rc ) {
            //@todo: Should the number of tracks really be what it says, i.e.
            // the # of tracks and not cylinders?
            apr->trks = trk_last / 2 + 1;
            break;
        }

        if( rc != sizeof( ohdr ) )
            return( IMG_ERR_READ );

        if( (ohdr.magic != OBJ_SIG) || (ohdr.hdr_len != sizeof( ohdr )) )
            return( IMG_ERR_BAD_IMG );

        obj_size = ohdr.obj_len;

        if( ohdr.stuf1 || ohdr.stuf2 )
            return( IMG_ERR_BAD_IMG );

        if( ohdr.obj_typ == OBJT_SECT ) {
            /* Calculate and validate track number. */
            trk_idx = ohdr.cylinder * 2 + ohdr.head;
            if( trk_idx > sizeof( apr->trk_ofs ) / sizeof( apr->trk_ofs[0] ) )
                return( IMG_ERR_BAD_IMG );  /* Track out of bounds. */

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
                sdesc = cb->m_alloc_z( SPT_MAX * sizeof( sdesc[0] ) );
                if( !sdesc )
                    return( IMG_ERR_MEM_ALLOC );    //@todo: free any previously allocated bits
                apr->trk_ofs[trk_idx].sdesc    = sdesc;
                apr->trk_ofs[trk_idx].num_desc = 0;
            } else {
                sdesc = apr->trk_ofs[trk_idx].sdesc;
            }
            sec_idx = apr->trk_ofs[trk_idx].num_desc;

            /* Read/decompress the sector data. */
            rc = apr_decomp_obj( cb, apr, curr_ofs, sec_buf, sizeof( sec_buf ), &img_read, &data_read );
            if( !rc )
                return( IMG_ERR_DECODE );

            /* Sector looks good; store vital data in descriptor. */
            sdesc[sec_idx].file_ofs  = curr_ofs;
            sdesc[sec_idx].sect_id   = ohdr.sect_id;
            sdesc[sec_idx].sect_size = data_read;

            /* We have no idea how big missing sectors were. But we can
             * make a pretty good guess.
             */
            if( apr->def_sec_sz == 0 )
                apr->def_sec_sz = data_read;

            curr_ofs += img_read;
            //@todo: check for overflow!
            apr->trk_ofs[trk_idx].num_desc++;
        } else if( ohdr.obj_typ == OBJT_CMNT ) {
            /* Allocate space for comment (must not be compressed). */
            apr->comment = cb->m_alloc( ohdr.obj_len );
            if( !apr->comment )
                return( IMG_ERR_MEM_ALLOC );

            /* Read comment. */
            rc = apr_decomp_obj( cb, apr, curr_ofs, apr->comment, ohdr.obj_len, &img_read, &data_read );
            if( !rc )
                return( IMG_ERR_DECODE );

            apr->comment[ohdr.obj_len] = '\0';  /* Just to be safe. */

            /* Massage comment string. */
            i = 0;
            while( apr->comment[i] ) {
                if( apr->comment[i] == '\r' )
                    apr->comment[i] = '\n';
                ++i;
            }

        } else
            return( IMG_ERR_BAD_IMG );
    }
    apr->spt   = sect_max;
    apr->heads = head_max + 1;

    return( 0 );
}


/* Open an image for access. */
int apr_open( img_fns *cb, img_file imgf, apr_ctx *apr )
{
    int         rc;

    apr->imgf  = imgf;

    /* Build a map of all the tracks in the image. If the track map
     * can be built, the image is assumed to be OK. Don't even bother
     * reading the signature again since there's nothing very useful
     * in there.
     */
    rc = apr_build_map( cb, apr, sizeof( apr_hdr ) );
    if( rc )
        return( rc );

    apr->first_id = 1;  /* Reasonable assumption. */

    assert( apr->spt );
    return( IMG_OK );
}


/* Query the comment string. Returns NULL if no comment provided. */
const char *apr_query_comment( img_fns *cb, apr_ctx *apr )
{
    return( apr->comment );
}


/* Read a single sector from the image. */
int apr_read_sect( img_fns *cb, apr_ctx *apr, int sect_num, void *buf )
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
    track_num = sect_num / apr->spt;
    if( apr->heads == 1 )
        track_num *= 2;
    sect_id = sect_num % apr->spt;
    if( track_num >= apr->trks * 2 )
        return( IMG_ERR_NO_SECT );

    /* Logical sector IDs are typically 1-based. */
    sect_id += apr->first_id;

    /* Get the sector descriptors for this track. */
    tdesc = &apr->trk_ofs[track_num];
    sdesc = tdesc->sdesc;
    assert( sdesc );

    /* Look for the sector ID. */
    for( phys_sect = 0; phys_sect < tdesc->num_desc; ++phys_sect ) {
        if( sdesc[phys_sect].sect_id == sect_id )
            break;
    }

    /* If the sector is missing entirely, make something up. */
    if( phys_sect >= tdesc->num_desc ) {
        memset( buf, 0, apr->def_sec_sz );
        strcpy( buf, "ACT Apricot sector bad/missing!" );
        return( sdesc[0].sect_size );
    }

    sec_size = sdesc[phys_sect].sect_size;
    sec_ofs  = sdesc[phys_sect].file_ofs;

    /* Read/decompress sector data. */
    rc = apr_decomp_obj( cb, apr, sec_ofs, buf, sec_size, NULL, NULL );
    if( !rc )
        return( IMG_ERR_DECODE );

    return( sec_size );
}


/* Close an image once all accesses are completed. */
void apr_close( img_fns *cb, apr_ctx *apr )
{
    int     trk_idx;
    int     max_trk;

    assert( apr );
    if( apr->comment )
        cb->m_free( apr->comment );

    max_trk = sizeof( apr->trk_ofs ) / sizeof( apr->trk_ofs[0] );
    for( trk_idx = 0; trk_idx < max_trk; ++trk_idx ) {
        if( apr->trk_ofs[trk_idx].sdesc )
            cb->m_free( apr->trk_ofs[trk_idx].sdesc );
    }
}
