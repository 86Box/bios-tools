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
#include "img_v9k.h"


/* The Victor 9000 (also known as Sirius S1) had quite unusual disk subsystem,
 * possibly the most complex of all MS-DOS compatible machines.
 *
 * To maximize storage capacity, the drive could spin at different RPMs, with
 * 9 different "zones" each with a different number of sectors per track,
 * ranging from 19 down to 11 SPT.
 *
 * Each floppy has its own map of these zones recorded in the first sector,
 * although in practice the map is likely to be always the same. For each zone,
 * the zone map includes:
 *  - The number of sectors per track
 *  - The highest track of the zone
 *  - Motor controller programming information
 *
 * Early Victor 9000 machines had single-sided drives with 1,224 sectors total
 * and the zoning could be ignored when producing raw floppy images. Things got
 * quite complicated when Victor introduced double-sided drives.
 *
 * The trouble is that on double-sided drives, head 1 is physically offset from
 * head 0 and moved closer to the center of the disk. As a consequence, the
 * zones on side 1 must be different from side 0. This inevitably results in some
 * tracks falling into different zones on side 0 vs. side 1. And as a side effect,
 * the capacity of side 1 is slightly smaller and double-sided disks don't hold
 * quite the double the data of single-sided disks.
 *
 * Victor did not want to or couldn't change the rotational speed when "only"
 * switching heads. For that reason, logical sector numbers on double-sided disks
 * are mapped such that first all of side 0 is read, and then all of side 1.
 *
 * When raw images are produced, it is natural to write track 0 side 0, track 0
 * side 1, then track 1 side 0, track 1 side 1, etc. For tools that expect to
 * read sectors in logical number order, a bit of swizzling is required, such
 * that (again) the entire side 0 is read first, and side 1 next. That is what
 * this driver tries to do.
 *
 * Typical image formats need a trivial track map to quickly find the location
 * of any sector within the image. With Victor 9000, the sector per track value
 * is variable, so finding the track given a logical sector number (LSN) needs
 * a little work.
 *
 * An additional issue is that typical Victor 9000 CP/M-86 disks use software
 * visible interleaving. This complicates handling single-sided disks as well,
 * since the interleaving is per track and the tracks don't have a constant
 * number of sectors per track.
 *
 * To untangle interleaved images, we must build an interleave map which uses
 * the interleave factor recorded in sector 0 but is by necessity different
 * for each zone.
 *
 *
 * References:
 *
 * http://bitsavers.org/pdf/victor/victor9000/Victor9000TechRef_Jun82.pdf (Chapter 7)
 */

/* Maximum (and only) supported cylinder count. */
#define NCYL_MAX    80

#define V9K_SCNT_S0 1224    /* Number of sectors on side 0. */

#define V9K_MAX_SPT 32      /* Maximum supported sectors per track (generous). */

#define V9K_SZ_SS   (V9K_SCNT_S0 * IMG_SEC_SZ_DEF)  /* Single-sided image size. */
#define V9K_SZ_DS   (2391 * IMG_SEC_SZ_DEF) /* Double-sided image size. */

/* Victor 9000 sector 0 structure. */
typedef struct v9k_sect0 {
    uint16_t    sys_id;     /* FF,00 for system (boot) disk; 00,00 otherwise. */
    uint16_t    load_adr;   /* Boot program load address (in paragraphs). */
    uint16_t    load_sz;    /* Load size in paragraphs. */
    uint16_t    entry_ip;   /* Initial IP. */
    uint16_t    entry_cs;   /* Initial CS. */
    uint8_t     dsk_id[8];  /* Disk identifier. */
    uint8_t     prt_no[8];  /* Part number. */
    uint16_t    sec_sz;     /* Sector size in bytes. */
    uint16_t    data_sec;   /* First data sector on disk. */
    uint16_t    boot_sec;   /* First sector of boot program. */
    uint16_t    dbl_sd:1;   /* Double-sided disk flag. */
    uint16_t    rsvd0:11;   /* Unused. */
    uint16_t    intrlv:4;   /* Interleave factor. */
    uint8_t     dsk_typ;    /* 0 for CP/M, 1 for DOS. */
    uint8_t     rsvd1[3];   /* Unused. */
    uint8_t     spd_t[18];  /* Speed table. */
    uint8_t     zon_t[15];  /* Zone table (high track of each zone). */
    uint8_t     spt_t[15];  /* Sectors per track for each zone. */
} v9k_sect0;

/* Victor 9000 track map. */
typedef struct v9k_tmap {
    long        trk_ofs;    /* Offset of track in file. */
    uint16_t    lsn;        /* Starting logical sector number. */
    uint8_t     spt;        /* Number of sectors on this track. */
} v9k_tmap;

typedef struct v9k_ctx {
    img_file    imgf;                   /* Image file handle. */
    uint8_t     trks;                   /* Number of tracks (heads * cyls). */
    uint8_t     cyls;                   /* Number of cylinders. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     cur_zone_spt;           /* SPT of currently accessed zone. */
    uint8_t     i_map[V9K_MAX_SPT];     /* Interleave map of current zone. */
    uint16_t    num_sect;               /* Number of sectors in image. */
    v9k_tmap    trk_map[NCYL_MAX * 2];  /* Image track map. */
    v9k_sect0   hdr;                    /* The disk descriptor in sector 0. */
} v9k_ctx;



/* Identify a Victor 9000 raw image. Does not validate image. */
int v9k_identify( img_fns *cb, img_file img )
{
    v9k_sect0   hdr;
    int         rc;
    long        f_size;

    /* Read the disk descriptor. */
    cb->seek( img, 0 );
    rc = cb->read( img, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( 0 );

    /* The sector size must be 512 */
    if( hdr.sec_sz != 512 )
        return( 0 );

    /* Check if the file size corresponds to single-sided or
     * double-sided image. The sizes are fairly unique.
     * NB: It might be possible to calculate the expected size
     * from the zone map.
     */
    f_size = cb->fsize( img );
    if( (f_size != V9K_SZ_SS) && (f_size != V9K_SZ_DS) )
        return( 0 );

    /* We're sure enough it's a Victor 9000 image. */
    return( sizeof( v9k_ctx ) );
}

/* Open an image for access. May fail if image is damaged or unsupported. */
int v9k_open( img_fns *cb, img_file img, v9k_ctx *ctx )
{
    int             rc;
    v9k_sect0       hdr;
    int             cyl;
    int             trk;
    long            cur_ofs;
    uint16_t        cur_lsn_s0, cur_lsn_s1;
    uint8_t         zone_spt;
    int             zone_idx_s0, zone_idx_s1;
    int             zone_last_s0, zone_last_s1;

    /* Read the disk descriptor again. We already decided it's ours but
     * it still needs to be validated.
     */
    cb->seek( img, 0 );
    rc = cb->read( img, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( IMG_ERR_READ );

    /* Identify double vs. single-sided image based on the file size,
     * *not* on the flag in sector 0. There are double-sided images of
     * single-sided disks and vice versa.
     */
    ctx->heads = cb->fsize( img ) == V9K_SZ_DS ? 2 : 1;
    ctx->num_sect = ctx->heads == 2 ? 2391 : 1224;

    /* Set up the format. */
    ctx->cyls  = NCYL_MAX;
    ctx->trks  = ctx->cyls * ctx->heads;

    /* Copy the descriptor to the context structure. */
    ctx->hdr = hdr;

    /* For single-sided non-interleaved images, don't even bother, but for
     * double-sided or interleaved ones, we have to build a map of track
     * starting offsets.
     */
    cur_ofs    = 0;
    cur_lsn_s0 = 0;
    cur_lsn_s1 = V9K_SCNT_S0;

    if( (ctx->heads == 2) || ctx->hdr.intrlv ) {
        /* Initial zone setup. */
        zone_idx_s0  = -1;
        zone_idx_s1  = 0;   /* Side 1 starts in zone 1. */
        zone_last_s0 = zone_last_s1 = -1;

        /* Now run through all the cylinders/tracks. */
        for( cyl = 0; cyl < ctx->cyls; ++cyl ) {
            /* Side 0 first. */

            /* Check if we're stepping into the next zone. */
            if( cyl > zone_last_s0 ) {
                ++zone_idx_s0;
                zone_last_s0 = ctx->hdr.zon_t[zone_idx_s0];
            }
            zone_spt = ctx->hdr.spt_t[zone_idx_s0];
            trk = cyl;

            /* Fill out the track map entry for side 0. */
            ctx->trk_map[trk].lsn     = cur_lsn_s0;
            ctx->trk_map[trk].spt     = zone_spt;
            ctx->trk_map[trk].trk_ofs = cur_ofs;

            /* Advance counters. */
            cur_lsn_s0 += zone_spt;
            cur_ofs    += zone_spt * IMG_SEC_SZ_DEF;

            /* Side 1 next. */
            if( ctx->heads > 1 ) {
                /* Check if we're stepping into the next zone. */
                if( (cyl + 8) > zone_last_s1 ) {
                    ++zone_idx_s1;
                    zone_last_s1 = ctx->hdr.zon_t[zone_idx_s1];
                }
                zone_spt = ctx->hdr.spt_t[zone_idx_s1];
                trk = cyl + NCYL_MAX;

                /* Fill out the track map entry for side 0. */
                ctx->trk_map[trk].lsn     = cur_lsn_s1;
                ctx->trk_map[trk].spt     = zone_spt;
                ctx->trk_map[trk].trk_ofs = cur_ofs;

                /* Advance counters. */
                cur_lsn_s1 += zone_spt;
                cur_ofs    += zone_spt * IMG_SEC_SZ_DEF;
            }
        }
//        printf( "Sector count: %d (%d/%d)\n", cur_lsn_s1, cur_lsn_s0, cur_lsn_s1 - cur_lsn_s0 );
    }

    /* Fill out the rest of the context structure. */
    ctx->imgf         = img;
    ctx->cur_zone_spt = UINT8_MAX;
    memset( ctx->i_map, UINT8_MAX, sizeof( ctx->i_map ) );

    return( IMG_OK );
}

void v9k_build_interleave_map( v9k_ctx *ctx, uint8_t *i_map, uint8_t spt )
{
    int     sect_no;
    int     i;
    uint8_t tmp_map[V9K_MAX_SPT];

    /* Pre-fill interleave map with invalid values. */
    for( i = 0; i < spt; ++i )
        tmp_map[i] = UINT8_MAX;

    sect_no = i = 0;

    /* Build physical-to-logical sector number map. */
    do {
        /* Find the first empty physical sector. */
        while( tmp_map[i] != UINT8_MAX )
            i = (i + 1) % spt;
        tmp_map[i] = sect_no;

        /* Move to the next desired physical sector. */
        i = (i + ctx->hdr.intrlv) % spt;
        ++sect_no;
    } while( sect_no < spt );

    /* Now turn it into logical-to-physical map. */
    for( i = 0; i < spt; ++i )
        i_map[tmp_map[i]] = i;
}

/* Read a single sector from the image. */
int v9k_read_sect( img_fns *cb, v9k_ctx *ctx, int sect_num, void *buf )
{
    long        sec_ofs = -1;
    int         trk;
    int         sector;
    v9k_tmap    *tmap;

    /* Check if we're within the image. */
    if( sect_num >= ctx->num_sect )
        return( IMG_ERR_NO_SECT );

    /* For double-sided or interleaved disks, we have to do a bit of work. */
    if( (ctx->heads == 2) || ctx->hdr.intrlv ) {
        for ( trk = 0; trk < ctx->heads * ctx->cyls; ++trk ) {
            tmap = &ctx->trk_map[trk];
            if ( (sect_num >= tmap->lsn) && (sect_num < tmap->lsn + tmap->spt) ) {
                sec_ofs  = tmap->trk_ofs;
                sector   = sect_num - tmap->lsn;    /* Sector index within track. */
                /* Adjust for interleave if necessary (common on CP/M disks). */
                if( ctx->hdr.intrlv ) {
                    /* Rebuild interleave map if SPT changed. */
                    if ( ctx->cur_zone_spt != tmap->spt )
                        v9k_build_interleave_map( ctx, ctx->i_map, tmap->spt );

                    sector = ctx->i_map[sector];
                    assert( sector < tmap->spt );   /* Must be in range. */
                }
                sec_ofs += sector * IMG_SEC_SZ_DEF;
                break;
            }
        }
        /* This really shouldn't happen... */
        if ( sec_ofs == -1 )
            return( IMG_ERR_NO_SECT );
    } else {
        /* Calculate the sector offset. */
        sec_ofs = (long)sect_num * IMG_SEC_SZ_DEF;
    }

    /* Read the sector from image file. */
    cb->seek( ctx->imgf, sec_ofs );
    return( cb->read( ctx->imgf, buf, IMG_SEC_SZ_DEF ) );
}

/* Close an image once all accesses are completed. */
void v9k_close( img_fns *cb, v9k_ctx *ctx )
{
    assert( ctx );
}
