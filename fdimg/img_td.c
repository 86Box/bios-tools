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
#include "img_td.h"
#include "td_lzss.h"
#include "td_lzw.h"


/* The TeleDisk diskette image format (.TD0) was used by the eponymous DOS
 * utility, developed by Sydex in 1988. The TeleDisk format is quite complex,
 * capable of representing many non-standard formats. TeleDisk allows
 * variable numbers of sectors per track, variable sector sizes even on a
 * single track, and logical track/sector IDs which need not match physical
 * ones. Physical sector ordering (e.g. interleave) is also preserved.
 *
 * Simple pattern compression and RLE compression is supported on a
 * sector-by-sector basis. For DOS-formatted disks, unallocated sectors
 * (clusters) may be left out. Data structures are protected by CRC.
 *
 * TeleDisk supports "advanced" compression (version specific) where the
 * entire image contents (minus header) is compressed as a single block.
 * The compressed TeleDisk data is not protected by any CRC or similar,
 * however all data within the decompressed image is CRC protected, hence
 * any decompression errors should be detected.
 *
 * Regular TeleDisk images start with a 'TD' signature. Compressed images use
 * a 'td' signature instead.
 *
 * Old (1.x) TeleDisk versions used LZW compression, while newer TeleDisk
 * versions (2.x) used LZSS compression. The LZSS compression tends to be
 * significantly more efficient.
 *
 * Sydex also produced a utility called TeleGet. This was a stripped down
 * TeleDisk, only capable of writing images to floppies. TeleDisk was meant
 * for OEMs. The only known TeleGet OEM so far is IBM. The only difference
 * in IBM TeleGet images is that the header is 10 bytes longer than usual
 * and contains the string 'IBM NSC' (National Support Center) right after
 * the TD signature.
 *
 * Due to the complexity of the TeleDisk format, it may not be possible to
 * convert an arbitrary image into a straightforward 'raw' format. Therefore
 * opening an image builds a sector map, in the process checking that:
 *  - All sectors have the same size (512 bytes)
 *  - All tracks contain the same number of sectors
 *  - No tracks are skipped
 *  - Logical track/head IDs match physical ones
 *  - Each track contains exactly 1-n sectors with no gaps or duplicates
 */


/* Decompression buffer is set to 2MB. A 3.5" HD disk image ought to
 * fit in that. So far the only known case where the decompression buffer
 * was too small is a corrupted TeleDisk image.
 */
#define DECOMP_BUF_SZ   (1024UL * 1024 * 2)

/* Somewhat arbitrary, but a regular drive shouldn't be able to do more. */
#define NTRK_MAX    84

/* TeleDisk image header. */
typedef struct td_hdr {
    char        signature[2];           /* 'TD' or 'td' signature. */
    uint8_t     seq_no;                 /* Sequence number (zero). */
    uint8_t     seq_chk;                /* Sequence check. */
    uint8_t     td_ver;                 /* TeleDisk version (x.y decimal). */
    uint8_t     drate;                  /* Data rate. */
    uint8_t     drv_typ;                /* Drive type. */
    uint8_t     step_hdr;               /* Stepping and comment flags. */
    uint8_t     dos_flag;               /* DOS cluster allocation flag. */
    uint8_t     sides;                  /* Number of sides. */
    uint16_t    crc;                    /* CRC of the preceding 10 bytes. */
} td_hdr;

/* Alternative TeleGet image header. */
typedef struct tg_hdr_s {
    char        signature[2];           /* 'TD' or 'td' signature. */
    char        oem_name[10];           /* OEM name (ASCIIZ?). */
    uint8_t     seq_no;                 /* Sequence number (zero). */
    uint8_t     seq_chk;                /* Sequence check. */
    uint8_t     td_ver;                 /* TeleDisk version (x.y decimal). */
    uint8_t     drate;                  /* Data rate. */
    uint8_t     drv_typ;                /* Drive type. */
    uint8_t     step_hdr;               /* Stepping and comment flags. */
    uint8_t     dos_flag;               /* DOS cluster allocation flag. */
    uint8_t     sides;                  /* Number of sides. */
    uint16_t    crc;                    /* CRC of the preceding 10 bytes. */
} tg_hdr;

/* Comment presence bit in step_hdr field. */
#define IMGHDR_HAVE_COMMENT     0x80


/* TeleDisk comment header. */
typedef struct comment_hdr {
    uint16_t    crc;                    /* CRC of the entire header + data. */
    uint16_t    data_len;               /* Length of following data block. */
    uint8_t     year;                   /* Years since 1900. */
    uint8_t     month;                  /* January = 0. */
    uint8_t     day;                    /* Day of the month. */
    uint8_t     hour;                   /* In 24-hr format. */
    uint8_t     minute;
    uint8_t     second;
} comment_hdr;


/* TeleDisk track header. */
typedef struct track_hdr {
    uint8_t     num_sect;               /* Number of sectors in this track. */
    uint8_t     cylinder;               /* Physical cylinder (zero-based). */
    uint8_t     head;                   /* Head/side (0 or 1). */
    uint8_t     crc;                    /* Low byte of header's CRC. */
} track_hdr;

/* Flag in the 'head' byte of track header: */
#define TRK_HFLG_FM         0x80        /* Track recorded as FM, not MFM. */
#define TRK_HEAD_MASK       (~TRK_HFLG_FM)

/* EOF marker in the first byte of track header. */
#define TRK_EOF_MARK        0xFF


/* TeleDisk sector header. */
typedef struct sect_hdr {
    uint8_t     cyl_id;                 /* Logical cylinder ID. */
    uint8_t     head_id;                /* Logical head/side ID. */
    uint8_t     sect_id;                /* Logical sector ID. */
    uint8_t     sect_sz;                /* Sector size code. */
    uint8_t     flags;                  /* Per-sector flags. */
    uint8_t     crc;                    /* Low byte of header's CRC. */
} sect_hdr;

/* Sector header flag bits: */
#define SECT_DUPLICATED 0x01            /* Sector duplicated within track. */
#define SECT_CRC_BAD    0x02            /* Sector was read with bad CRC. */
#define SECT_DDAM       0x04            /* Deleted-Data Address Mark. */
#define SECT_SKIPPED    0x10            /* Skipped unallocated cluster. */
#define SECT_ID_ONLY    0x20            /* Sector ID only, no data. */
#define SECT_DATA_ONLY  0x40            /* Data but no sector ID (bad). */

/* Bit mask to check whether sector data follows. */
#define SECTOR_NO_DATA  (SECT_SKIPPED | SECT_ID_ONLY)

/* Macro to convert encoded sector size to bytes. */
#define SEC_SZ_BYTES(sz)    (128 << (sz))


/* TeleDisk sector data header. */
#pragma pack(1)     /* This is the only struct where aligned size is off! */
typedef struct sdata_hdr {
    uint16_t    blk_sz;                 /* Bytes following this word. */
    uint8_t     encoding;               /* Encoding method (0-2). */
} sdata_hdr;
#pragma pack()

/* Sector encoding types. */
#define SDATA_ENC_RAW   0               /* Raw data. */
#define SDATA_ENC_REP   1               /* Repeated 2-byte pattern. */
#define SDATA_ENC_RLE   2               /* Run-Length Encoding. */


/* TeleDisk repeated pattern entry. */
typedef struct td_rep_pat {
    uint16_t    num_reps;               /* Number of repetitions. */
    uint16_t    pattern;                /* 16-bit pattern. */
} td_rep_pat;


/* TeleDisk RLE control structure. */
typedef struct td_rle_ctl {
    uint8_t     method;                 /* Block length (0 if raw data). */
    uint8_t     rcnt;                   /* Raw data length or repeat count. */
} td_rle_ctl;



/* Sector offset descriptor. Points to the sector header in image file. Note
 * that logical sector IDs may occur in any order, may have gaps, and may
 * not be unique.
 */
typedef struct sect_desc {
    long        file_ofs;               /* Offset of sector header in file. */
    unsigned    sect_size;              /* Sector size in bytes. */
    uint8_t     sect_id;                /* Logical sector ID. */
    uint16_t    sect_crc;               /* 16-bit CRC of sector data. */
} sect_desc;


/* Track descriptor. Contains a pointer to a list of sector offset descriptors
 * plus the count of items, as sectors per track may not be uniform.
 */
typedef struct trk_desc {
    sect_desc   *sdesc;                 /* Sector descriptor list. */
    int         num_desc;               /* Number of list items. */
} trk_desc;


/* File (regular or compressed) access context. */
typedef struct td_file_ctx {
    img_fns     *cb;                    /* Image helpers. */
    img_file    imgf;                   /* Uncompressed image file. */
    bool        cmprsd;                 /* Compressed file flag. */
    long        mbuf_ofs;               /* Offset in decompressed data. */
    long        mbuf_sz;                /* Size of decompressed data. */
    uint8_t     *mbuf;                  /* Decompression buffer. */
} td_file_ctx;


/* Context structure for TeleDisk format. */
typedef struct td_ctx {
    img_file    imgf;                   /* Image file handle. */
    td_file_ctx fctx;                   /* TeleDisk file context. */
    uint8_t     trks;                   /* Number of tracks. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     first_id;               /* First sector ID (typically 1). */
    bool        trk0_dupes;             /* Duplicate sectors on track 0. */
    td_hdr      hdr;                    /* The image header. */
    char        *comment;               /* Optional comment. */
    trk_desc    trk_ofs[NTRK_MAX * 2];  /* Per-track sector descriptors. */
} td_ctx;


/* Read from a file or a decompressed buffer. */
size_t td_read( td_file_ctx *tf, void *buf, size_t cnt )
{
    size_t  rc;

    if( tf->cmprsd ) {
        size_t  max_avl;
        size_t  ncpy;

        max_avl = tf->mbuf_sz - tf->mbuf_ofs;
        if( max_avl < cnt )
            ncpy = max_avl;
        else
            ncpy = cnt;
        memcpy( buf, tf->mbuf + tf->mbuf_ofs, ncpy );
        tf->mbuf_ofs += ncpy;
        rc = ncpy;
    } else {
        rc = tf->cb->read( tf->imgf, buf, cnt );
    }
    return( rc );
}

/* Seek in a file or a decompressed buffer. */
void td_seek( td_file_ctx *tf, long pos )
{
    if( tf->cmprsd ) {
        /* The header is not part of decompressed data. */
        tf->mbuf_ofs = pos - sizeof( td_hdr );
    } else {
        tf->cb->seek( tf->imgf, pos );
    }
}


/* Compute/update a CRC given a block of data. */
uint16_t td_calc_crc( const void *p, unsigned len, uint16_t crc )
{
    const uint8_t   *data = p;
    int             i;

    while( len-- ) {
        crc ^= *data++ << 8;
        //@todo: precompute the CRC table
        for( i = 0; i < 8 ; ++i )
            crc = (crc << 1) ^ ((crc & 0x8000) ? 0xA097 : 0);
    }
    return( crc );
}

/* Load a TeleDisk format header. Tries to account for TeleGet
 * header differences. Validates header CRC.
 * NB: For TeleGet images, the CRC in converted TeleDisk-format
 * header won't be valid.
 * Returns 1 if TeleDisk image, 2 if TeleGet image, zero if
 * unknown or unsupported.
 */
int td_load_hdr( img_fns *cb, img_file imgf, td_hdr *phdr )
{
    td_hdr      hdr_td;
    tg_hdr      hdr_tg;
    int         rc;
    uint16_t    crc;

    /* Try reading a TeleDisk header. */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &hdr_td, sizeof( hdr_td ) );
    if( rc != sizeof( hdr_td ) )
        return( 0 );

    /* Fail if signature isn't 'TD' or 'td'. */
    if( !(hdr_td.signature[0] == 'T' && hdr_td.signature[1] == 'D') )
        if( !(hdr_td.signature[0] == 't' && hdr_td.signature[1] == 'd') )
            return( 0 );

    /* Check the CRC. */
    crc = td_calc_crc( &hdr_td, offsetof( td_hdr, crc ), 0 );
    if( crc == hdr_td.crc ) {
        /* Header looks good, copy. */
        memcpy( phdr, &hdr_td, sizeof( hdr_td ) );
        return( 1 );
    } else {
        /* Maybe it's TeleGet? */
        cb->seek( imgf, 0 );
        rc = cb->read( imgf, &hdr_tg, sizeof( hdr_tg ) );
        if( rc != sizeof( hdr_tg ) )
            return( 0 );

        /* Signature check has been done already. */
        crc = td_calc_crc( &hdr_tg, offsetof( tg_hdr, crc ), 0 );
        if( crc != hdr_tg.crc )
            return( 0 );

        /* Copy out the TeleGet header minus OEM ID. */
        memcpy( &phdr->signature, &hdr_tg.signature, sizeof( hdr_tg.signature ) );
        memcpy( &phdr->seq_no, &hdr_tg.seq_no, sizeof( td_hdr ) - sizeof( hdr_tg.signature ) );
        return( 2 );
    }
}

/* Identify a TeleDisk format image. Does not validate image. */
int td_identify( img_fns *cb, img_file imgf )
{
    td_hdr      hdr;

    /* Try to load TeleDisk or TeleGet header. Validates header CRC. */
    if( !td_load_hdr( cb, imgf, &hdr ) )
        return( 0 );

    /* Range check the stepping flag. */
    if( (hdr.step_hdr & 0x7F) > 2 )
        return( 0 );

    /* The image looks sensible enough... */
    return( sizeof( td_ctx ) );
}

/* Read sector data from image, decompress as needed; sdata_ofs is the image
 * offset of the sector data header (not sector header!). The img_read
 * argument points to a location where the number of bytes read from image is
 * returned (or NULL if that is not relevant).
 */
int td_decomp_sect( img_fns *cb, td_ctx *td, long sdata_ofs, void *buf, unsigned sec_sz, unsigned *img_read )
{
    sdata_hdr   dhdr;
    int         sdata_len;
    int         rc;
    td_rep_pat  rep_ctl;
    int         idx16;
    uint16_t    *buf16;
    td_rle_ctl  rle_ctl;
    int         rle_ofs;
    int         rle_len;
    uint8_t     *buf8;
    int         blk_ofs;
    int         i;

    /* Read the data header, which is followed by raw or compressed data. */
    td_seek( &td->fctx, sdata_ofs );
    rc = td_read( &td->fctx, &dhdr, sizeof( dhdr ) );
    if( rc != sizeof( dhdr ) )
        return( false );

    /* The length in data header includes the encoding byte. */
    sdata_len = dhdr.blk_sz - sizeof( dhdr.encoding );

    /* Check that the buffer is big enough; the assumption is that the
     * compressed data is never bigger than the full sector size.
     */
    if( sdata_len > sec_sz )
        return( false );

    switch( dhdr.encoding ) {
    case SDATA_ENC_RAW:
        /* Uncompressed sector data. */
        rc = td_read( &td->fctx, buf, sdata_len );
        if( rc != sdata_len )
            return( 0 );
        break;
    case SDATA_ENC_REP:
        rc = td_read( &td->fctx, &rep_ctl, sizeof( rep_ctl ) );
        if( rc != sizeof( rep_ctl ) )
            return( 0 );
        idx16 = 0;
        buf16 = buf;
        for( i = 0; i < rep_ctl.num_reps; ++i ) {
            buf16[idx16++] = rep_ctl.pattern;
        }
        assert( idx16 == sec_sz / 2 );  /* Can these repeat? */
        break;
    case SDATA_ENC_RLE:
        blk_ofs = 0;
        buf8    = buf;

        do {
            /* Read the RLE control byte. */
            rc = td_read( &td->fctx, &rle_ctl, sizeof( rle_ctl ) );
            if( rc != sizeof( rle_ctl ) )
                return( 0 );
            if( rle_ctl.method == 0 ) {
                /* Read a single block of data from image. */
                rc = td_read( &td->fctx, buf8 + blk_ofs, rle_ctl.rcnt );
                if( rc != rle_ctl.rcnt )
                    return( 0 );
                blk_ofs += rle_ctl.rcnt;
            } else {
                /* Repeat a block several times. The 'method' byte is
                 * the number of words (not bytes!) in this block.
                 */
                rle_len = rle_ctl.method * 2;
                rle_ofs = blk_ofs;
                /* Read in the first copy of the block from the image. */
                rc = td_read( &td->fctx, buf8 + blk_ofs, rle_len );
                if( rc != rle_len )
                    return( 0 );
                /* Replicate the block the requested number of times. */
                for( i = 0; i < rle_ctl.rcnt; ++i ) {
                    memcpy( buf8 + blk_ofs, buf8 + rle_ofs, rle_len );
                    blk_ofs += rle_len;
                }
            }
        } while( blk_ofs < sec_sz );
        assert( blk_ofs == sec_sz );
        break;
    default:
        /* If this happens, the image is corrupted. */
        assert( 0 );
        return( false );
    }

    /* Return the number of bytes read from image if requested. */
    if( img_read )
        *img_read = dhdr.blk_sz + sizeof( dhdr.blk_sz );

    return( true );
}

/* Sequentially scan the image, building a map of tracks/sectors.
   Also validates CRCs to get that out of the way. */
int td_build_track_map( img_fns *cb, td_ctx *td, long start_ofs )
{
    track_hdr   thdr;
    sect_hdr    shdr;
    long        curr_ofs;
    long        shdr_ofs;
    uint16_t    crc;
    int         trk_idx;
    int         trk_last;
    int         phys_sect;
    int         img_sect;
    int         i;
    int         rc;
    sect_desc   *sdesc;
    unsigned    img_read;
    unsigned    sec_size;
    bool        seen_2nd_side;
    bool        seen_mfm_trk;
    bool        skip_sec;
    uint8_t     sec_buf[IMG_SEC_SZ_MAX];

    curr_ofs      = start_ofs;
    trk_last      = 0;
    seen_2nd_side = false;
    seen_mfm_trk  = false;

    for( ;; ) {
        /* Read track header; even the EOF marker includes a full header,
         * despite the fact that only the first byte is meaningful.
         */
        rc = td_read( &td->fctx, &thdr, sizeof( thdr ) );
        if( rc != sizeof( thdr ) )
            if( (rc >= 1) && (thdr.num_sect == TRK_EOF_MARK) ) {
                /* Allow malformed incomplete track header that
                 * contains an EOF marker. The rest of the track header
                 * contents doesn't really matter in this case.
                 */
            } else if( rc == 0 ) {
                /* Also allow malformed images with no EOF marker at all. */
                thdr.num_sect = TRK_EOF_MARK;
            } else {
                return( IMG_ERR_READ );
            }
        curr_ofs += rc;

        /* Exit if end of image marker found. TeleDisk typically writes out
         * the previous track header with only the number of sectors changed.
         */
        if( thdr.num_sect == TRK_EOF_MARK ) {
            //@todo: Should the number of tracks really be what it says, i.e.
            // the # of tracks and not cylinders?
            td->trks = trk_last / 2 + 1;
            break;
        }

        /* Validate track header CRC. */
        crc = td_calc_crc( &thdr, offsetof( track_hdr, crc ), 0 );
        if( (crc & 0xFF) != thdr.crc )
            return( IMG_ERR_CSUM );

        /* TeleDisk is sometimes too good and manages to find bogus data
         * beyond the last 'regular' cylinder. Watch out for such junk.
         */

        /* Check for a phantom cylinder with no sectors. */
        if( thdr.num_sect == 0 ) {
            continue;
        }

        /* If there is an MFM track, guess that this is an MFM disk. */
        if( !(thdr.head & TRK_HFLG_FM) )
            seen_mfm_trk = true;

        /* Calculate and validate track number. */
        trk_idx = thdr.cylinder * 2 + (thdr.head & TRK_HEAD_MASK);
        if( trk_idx > sizeof( td->trk_ofs ) / sizeof( td->trk_ofs[0] ) )
            return( IMG_ERR_BAD_IMG );  /* Track out of bounds. */

        /* Update 'last valid track' counter, but skip junk FM tracks.
         * Heuristic: Guess that FM tracks are junk if there were MFM tracks
         * seen before.
         */
        if( (thdr.head & TRK_HFLG_FM) && seen_mfm_trk ) {
            /* Ignore track. */
        } else {
            trk_last = trk_idx;
            /* Check if it's a two-sided disk. */
            if( thdr.head & 1 )
                seen_2nd_side = true;
        }

        /* Allocate and link sector descriptors for this track. */
        sdesc = cb->m_alloc( thdr.num_sect * sizeof( sdesc[0] ) );
        if( !sdesc )
            return( IMG_ERR_MEM_ALLOC );    //@todo: free previously allocated bits
        td->trk_ofs[trk_idx].sdesc    = sdesc;

        /* Loop over all sectors on this track... */
        img_sect = 0;
        for( phys_sect = 0; phys_sect < thdr.num_sect; ++phys_sect ) {
            /* Read sector header to see what to do next. */
            shdr_ofs = curr_ofs;
            rc = td_read( &td->fctx, &shdr, sizeof( shdr ) );
            if( rc != sizeof( shdr ) )
                return( IMG_ERR_READ );
            curr_ofs += rc;

            sec_size = SEC_SZ_BYTES( shdr.sect_sz );

            /* If present, read the sector data header and actual data. */
            if( !(shdr.flags & SECTOR_NO_DATA) ) {
                assert( sizeof( sec_buf ) >= sec_size );
                rc = td_decomp_sect( cb, td, curr_ofs, sec_buf, sec_size, &img_read );
                if( !rc )
                    return( IMG_ERR_DECODE );
                curr_ofs += img_read;

                /* Extant TeleDisk image documentation may be misleading and
                 * claim that the sector CRC also covers the sector header and
                 * sector data header. In reality, it only covers the actual
                 * (uncompressed!) sector data.
                 */
                crc = td_calc_crc( &sec_buf, sec_size, 0 );
                assert( (crc & 0xFF) == shdr.crc );
                if( (crc & 0xFF) != shdr.crc )
                    return( IMG_ERR_CSUM );
            }

            /* Some TeleDisk images are very strange and contain too many sectors
             * on a track. For example, a 360K floppy image might have 15-18 sectors
             * stored on a track, which is not physically possible (10 512-byte
             * sectors is about the maximum). However, there might be only 9 or even
             * fewer unique sectors.
             * Check if this sector might be a duplicate and if so, skip it.
             */
            skip_sec = 0;
            for( i = 0; i < img_sect; ++i ) {
                if( sdesc[i].sect_id == shdr.sect_id ) {
                    if( sdesc[i].sect_size == sec_size ) {
                        /* If sector ID and size match, compare sector CRC. */
                        if( sdesc[i].sect_crc == crc ) {
                            /* Sector appears to be a duplicate; skip it. */
                            skip_sec = 1;
                        }
                    }
                }
            }

            /* Duplicate sector, skip it. */
            if( skip_sec ) {
                if( trk_idx == 0 )
                    td->trk0_dupes = true;
                continue;
            }

            /* Sector looks good; store vital data in descriptor. */
            sdesc[img_sect].file_ofs  = shdr_ofs;
            sdesc[img_sect].sect_id   = shdr.sect_id;
            sdesc[img_sect].sect_size = sec_size;
            sdesc[img_sect].sect_crc  = crc;
            img_sect++;
        }

        /* Store the sector number without duplicates. */
        td->trk_ofs[trk_idx].num_desc = img_sect;
    }

    td->heads = seen_2nd_side ? 2 : 1;
    return( IMG_OK );
}

/* Find the first usable track. Images of 5.25" ISIS-IV media have been
 * seen with track 0 completely missing (likely FM rather than MFM). Just
 * look at the next track.
 */
trk_desc *get_first_track( td_ctx *td )
{
    trk_desc    *tdesc;

    tdesc = &td->trk_ofs[0];
    /* If the first track isn't there, try the other side. */
    if( !tdesc->num_desc )
        tdesc = &td->trk_ofs[1];

    return( tdesc );
}

/* Find the lowest sector ID on the first track. */
uint8_t find_first_id( td_ctx *td )
{
    int         phys_sect;
    uint8_t     low_id;
    trk_desc    *tdesc;
    sect_desc   *sdesc;

    /* Get the sector descriptors for the first track. */
    tdesc = get_first_track( td );
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

/* The HP-150 and other 1980s HP systems have sixteen 256-byte data
 * sectors on each track, with IDs from 0 to 15, but also have a seventeenth
 * sector with ID 17 and only 128 bytes. This sector is perhaps a spare and
 * not part of the logical image. Try to factor it out by reducing the SPT.
 *
 * There are also PC floppy images which have duplicated sectors on track 0;
 * such images might have 15 or 18 sectors stored on the first track of a 360K
 * floppy, but only 8 sectors might be unique (instead of 9). In this case,
 * we look at side 1 in the hope that only side 0 is messed up.
 */
void adjust_spt( td_ctx *td )
{
    int         phys_sect;
    trk_desc    *tdesc;
    sect_desc   *sdesc;
    uint8_t     num_256s;
    uint8_t     num_128s;

    /* If there are duplicates on track 0 side 0, the SPT is unreliable. */
    if( td->trk0_dupes && (td->heads == 2) ) {
        tdesc = &td->trk_ofs[1];
        td->spt = tdesc->num_desc;
        return;
    }

    /* Get the sector descriptors for the first track. */
    tdesc = &td->trk_ofs[0];

    /* If the first track is empty, it's not a HP floppy. */
    if( !tdesc->num_desc )
        return;

    sdesc = tdesc->sdesc;
    assert( sdesc );
    num_128s = num_256s = 0;

    /* Look for the lowest sector ID. */
    for( phys_sect = 0; phys_sect < tdesc->num_desc; ++phys_sect ) {
        if( sdesc[phys_sect].sect_size == 128 )
            ++num_128s;
        else if( sdesc[phys_sect].sect_size == 256 )
            ++num_256s;
    }

    /* If there's exactly one 128-byte sector and 16 or 17 256-byte ones,
     * guess this is an HP disk (HP-150 and others) and adjust to 16 spt.
     * The HP format had spare sectors and tracks; note that images exist
     * with both 16*256b + 128b sector and 17*256b + 128b sector.
     */
    if( num_128s == 1 && (num_256s == 16 || num_256s == 17) )
        td->spt = 16;
}

/* Open an image for access. May fail if image is damaged or cannot be
 * represented as a raw format image.
 */
int td_open( img_fns *cb, img_file imgf, td_ctx *td )
{
    int         rc = IMG_ERR_BAD_IMG;
    int         nb;
    int         i;
    td_hdr      img_hdr;
    comment_hdr cmt_hdr;
    char        *comment;
    uint16_t    cmt_len;
    uint16_t    crc;
    long        curr_ofs;

    /* Read the header. We already ensured it's sensible. */
    if( !td_load_hdr( cb, imgf, &img_hdr ) )
        return( IMG_ERR_READ );

    curr_ofs = sizeof( img_hdr );

    /* Set up the file context. */
    td->fctx.cb       = cb;
    td->fctx.imgf     = imgf;
    td->fctx.cmprsd   = false;
    td->fctx.mbuf_ofs = 0;
    td->fctx.mbuf_sz  = 0;

    /* If the image is compressed, try to decompress it. */
    if( img_hdr.signature[0] == 't' && img_hdr.signature[1] == 'd' ) {
        void    *deco_buf;

        deco_buf = cb->m_alloc( DECOMP_BUF_SZ );
        if( !deco_buf )
            return( IMG_ERR_MEM_ALLOC );

        td->fctx.cmprsd = true;
        td->fctx.mbuf   = deco_buf;

        if( img_hdr.td_ver >= 20 )
            td->fctx.mbuf_sz = td_unpack_lzss( cb, imgf, td->fctx.mbuf, DECOMP_BUF_SZ );
        else
            td->fctx.mbuf_sz = td_unpack_lzw( cb, imgf, td->fctx.mbuf, DECOMP_BUF_SZ );
        if( !td->fctx.mbuf_sz )
            return( IMG_ERR_DECOMP );
    }

    /* Read in comment, if present. */
    comment = NULL;
    if( img_hdr.step_hdr & IMGHDR_HAVE_COMMENT ) {
        nb = td_read( &td->fctx, &cmt_hdr, sizeof( cmt_hdr ) );
        if( nb != sizeof( cmt_hdr ) )
            return( IMG_ERR_READ );

        curr_ofs += sizeof( cmt_hdr );

        cmt_len = cmt_hdr.data_len;
        if( cmt_len ) {
            comment = cb->m_alloc( cmt_len );
            if( !comment )
                goto error_cleanup;

            nb = td_read( &td->fctx, comment, cmt_len );
            if( nb != cmt_len )
                goto error_cleanup;
        }

        curr_ofs += cmt_len;

        /* Validate CRC of the header... */
        crc = td_calc_crc( (uint8_t *)&cmt_hdr + sizeof( uint16_t ),
                           sizeof( cmt_hdr ) - sizeof( uint16_t ), 0 );
        /* ... and the comment data. */
        crc = td_calc_crc( comment, cmt_len, crc );
        if( crc != cmt_hdr.crc )
            goto error_cleanup;

        /* After checksumming, convert null characters into newlines. */
        for( i = 0; i < cmt_len - 1; ++i ) {
            if( comment[i] == '\0' )
                comment[i] =  '\n';
        }
    }

    /* Store the comment and image pointers. */
    td->comment = comment;
    td->imgf    = imgf;

    /* Build a map of all the tracks in the image. Also validates CRCs and
     * suchlike. If the track map can be built, the image is assumed to be OK.
     */
    td->trk0_dupes = false;
    rc = td_build_track_map( cb, td, curr_ofs );
    if( rc )
        goto error_cleanup;

    /* Figure out the starting sector ID. */
    td->first_id    = find_first_id( td );

    /* Fill out the rest of the context structure. */
    td->spt         = get_first_track( td )->num_desc;
    td->hdr         = img_hdr;
    assert( td->spt );

    adjust_spt( td );

    return( IMG_OK );

error_cleanup:
    if( comment )
        cb->m_free( comment );

    return( rc );
}

/* Query the comment string. Returns NULL if no comment provided. */
const char *td_query_comment( img_fns *cb, td_ctx *td )
{
    return( td->comment );
}

//@todo: split out a worker with CHS addressing!
/* Read a single sector from the image. */
int td_read_sect( img_fns *cb, td_ctx *td, int sect_num, void *buf )
{
    trk_desc    *tdesc;
    sect_desc   *sdesc;
    sect_hdr    shdr;
    long        sec_ofs;
    unsigned    sec_size;
    int         track_num;
    int         sect_id;
    int         phys_sect;
    int         rc;

    /* Check if we're within image. */
    track_num = sect_num / td->spt;
    if( td->heads == 1 )
        track_num *= 2;
    sect_id   = sect_num % td->spt;
    if( track_num >= td->trks * 2 )
        return( IMG_ERR_NO_SECT );

    /* Logical sector IDs are typically 1-based. */
    sect_id += td->first_id;

    /* Get the sector descriptors for this track. */
    tdesc = &td->trk_ofs[track_num];

    /* If a track in the middle has not been recorded, make something up. */
    if( !tdesc->num_desc ) {
        memset( buf, 0, IMG_SEC_SZ_DEF );
        strcpy( buf, "TD track missing!" );
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
        strcpy( buf, "TD sector missing!" );
        return( IMG_SEC_SZ_DEF );
    }

    sec_size = sdesc[phys_sect].sect_size;
    sec_ofs  = sdesc[phys_sect].file_ofs;
//@todo: assert sec_ofs within image?

    /* If sector size is bigger than what caller expects, bail. */
    if( sec_size > IMG_SEC_SZ_MAX )
        return( IMG_ERR_CANT_CONV );

    /* Read the sector header. */
    td_seek( &td->fctx, sec_ofs );
    rc = td_read( &td->fctx, &shdr, sizeof( shdr ) );
    if( rc != sizeof( shdr ) )
        return( IMG_ERR_READ );

    assert( shdr.sect_id == sect_id );
    if( shdr.flags & SECT_SKIPPED ) {
        /* For skipped sectors, we don't know what was there. Assume
         * a freshly formatted disk.
         */
        memset( buf, FMT_BYTE, sec_size );
    } else if( shdr.flags & SECT_ID_ONLY ) {
        /* If the sector had no data at all, make something up. */
        memset( buf, 0, sec_size );
        strcpy( buf, "TD sector ID only!" );
    } else {
        /* Read/decompress sector data. */
        rc = td_decomp_sect( cb, td, sec_ofs + sizeof( shdr ), buf, sec_size, NULL );
        if( !rc )
            return( IMG_ERR_DECODE );
    }

    return( sec_size );
}

/* Close an image once all accesses are completed. */
void td_close( img_fns *cb, td_ctx *td )
{
    int     trk_idx;
    int     max_trk;

    assert( td );
    if( td->comment )
        cb->m_free( td->comment );

    if( td->fctx.cmprsd )
        cb->m_free( td->fctx.mbuf );

    max_trk = sizeof( td->trk_ofs ) / sizeof( td->trk_ofs[0] );
    for( trk_idx = 0; trk_idx < max_trk; ++trk_idx ) {
        if( td->trk_ofs[trk_idx].sdesc )
            cb->m_free( td->trk_ofs[trk_idx].sdesc );
    }
}
