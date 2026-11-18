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

typedef FILE    *img_file;
/* Needs to match img_help.h */
typedef struct {
    void    (* seek)( img_file img, long pos );
    long    (* fsize)( img_file img );
    size_t  (* read)( img_file img, void *buf, size_t cnt );
    void *  (* m_alloc)( size_t cnt );
    void *  (* m_alloc_z)( size_t cnt );
    void    (* m_free)( void *ptr );
} img_fns;
#include "td_lzss.h"
#include "td_lzw.h"


/* File (regular or compressed) access context. */
typedef struct td_file_ctx {
    img_fns     *cb;                    /* Image helpers. */
    img_file    imgf;                   /* Uncompressed image file. */
    bool        cmprsd;                 /* Compressed file flag. */
    long        mbuf_ofs;               /* Offset in decompressed data. */
    long        mbuf_sz;                /* Size of decompressed data. */
    uint8_t     *mbuf;                  /* Decompression buffer. */
} td_file_ctx;


size_t f_read( img_file imgf, void *buf, size_t cnt )
{
    return( fread( buf, 1, cnt, imgf ) );
}

void f_seek( img_file imgf, long pos )
{
    fseek( imgf, pos, SEEK_SET );
}

void *m_alloc_z( size_t cnt )
{
    return( calloc( 1, cnt ) );
}

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
        /* NB: Uses TD header size even for TeleGet images! */
        tf->mbuf_ofs = pos - 12; //sizeof( td_hdr );
    } else {
        tf->cb->seek( tf->imgf, pos );
    }
}


/* See img_td.c for TeleDisk format description. */

/* Decompression buffer is set to 2MB. A 3.5" HD disk image ought to
 * fit in that. So far the only known case where the decompression buffer
 * was too small is a corrupted TeleDisk image.
 */
#define DECOMP_BUF_SZ   (1024UL * 1024 * 2)

/* Somewhat arbitrary, but a regular drive shouldn't be able to do more. */
#define NTRK_MAX    84

/* TeleDisk image header. */
typedef struct td_hdr_s {
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

/* TeleGet image header. */
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
typedef struct comment_hdr_s {
    uint16_t    crc;                    /* CRC of the entire header/data. */
    uint16_t    data_len;               /* Length of following data block. */
    uint8_t     year;                   /* Years since 1900. */
    uint8_t     month;                  /* January = 0. */
    uint8_t     day;                    /* Day of the month. */
    uint8_t     hour;                   /* In 24-hr format. */
    uint8_t     minute;
    uint8_t     second;
} comment_hdr;


/* TeleDisk track header. */
typedef struct track_hdr_s {
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
typedef struct sect_hdr_s {
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
typedef struct sdata_hdr_s {
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
} sect_desc;


/* Context structure for TeleDisk format. */
typedef struct td_ctx {
    FILE        *imgf;                  /* Image file handle. */
    uint8_t     trks;                   /* Number of tracks. */
    uint8_t     spt;                    /* Sectors per track. */
    uint8_t     heads;                  /* Number of heads (1 or 2). */
    uint8_t     first_id;               /* First sector ID (typically 1). */
    td_hdr      hdr;                    /* The image header. */
    char        *comment;               /* Optional comment. */
    td_file_ctx *fcx;                   /* Regular/compressed file context. */
} td_ctx;


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
 * NB: For TeleGet images, the CRC in TeleDisk-format header
 * won't be valid.
 * Returns 1 if TeleDisk image, 2 if TeleGet image, zero if
 * unknown or unsupported.
 */
int td_load_hdr( FILE *imgf, td_hdr *phdr )
{
    td_hdr      hdr_td;
    tg_hdr      hdr_tg;
    int         rc;
    uint16_t    crc;

    /* Try reading a TeleDisk header. */
    fseek( imgf, 0, SEEK_SET );
    rc = fread( &hdr_td, 1, sizeof( hdr_td ), imgf );
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
        fseek( imgf, 0, SEEK_SET );
        rc = fread( &hdr_tg, 1, sizeof( hdr_tg ), imgf );
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
int td_identify( FILE *imgf )
{
    td_hdr      hdr;

    /* See if a valid header can be loaded. */
    if( !td_load_hdr( imgf, &hdr ) )
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
int td_decomp_sect( td_ctx *td, long sdata_ofs, void *buf, unsigned sec_sz, unsigned *img_read )
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
    td_seek( td->fcx, sdata_ofs );
    rc = td_read( td->fcx, &dhdr, sizeof( dhdr ) );
    if( rc != sizeof( dhdr ) ) {
        printf( "error: failed to read data header!\n" );
        return( false );
    }

    /* The length in data header includes the encoding byte. */
    sdata_len = dhdr.blk_sz - sizeof( dhdr.encoding );

    /* Check that the buffer is big enough; the assumption is that the
     * compressed data is never bigger than the full sector size.
     */
    if( sdata_len > sec_sz ) {
        printf( "error: too much data in sector!\n" );
        return( false );
    }
    printf( ":E%d/%03dB", dhdr.encoding, sdata_len );

    switch( dhdr.encoding ) {
    case SDATA_ENC_RAW:
        /* Uncompressed sector data. */
        rc = td_read( td->fcx, buf, sdata_len );
        if( rc != sdata_len ) {
            printf( "error: failed to read uncompressed sector data!\n" );
            return( 0 );
        }
        break;
    case SDATA_ENC_REP:
        rc = td_read( td->fcx, &rep_ctl, sizeof( rep_ctl ) );
        if( rc != sizeof( rep_ctl ) ) {
            printf( "error: failed to read repeated sector data!\n" );
            return( 0 );
        }
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
            rc = td_read( td->fcx, &rle_ctl, sizeof( rle_ctl ) );
            if( rc != sizeof( rle_ctl ) ) {
                printf( "error: failed to read RLE control byte!\n" );
                return( 0 );
            }
            if( rle_ctl.method == 0 ) {
                /* Read a single block of data from image. */
                rc = td_read( td->fcx, buf8 + blk_ofs, rle_ctl.rcnt );
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
                rc = td_read( td->fcx, buf8 + blk_ofs, rle_len );
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
        printf( "error: unknown sector data encoding!\n" );
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
int td_explore( td_ctx *td, long start_ofs )
{
    track_hdr   thdr;
    sect_hdr    shdr;
    long        curr_ofs;
    long        shdr_ofs;
    uint16_t    crc;
    int         trk_idx;
    int         trk_last;
    int         phys_sect;
    int         rc;
    bool        seen_mfm_trk;
    unsigned    img_read;
    unsigned    sec_size;
    uint8_t     sec_buf[4096];

    curr_ofs = start_ofs;
    trk_last = 0;
    seen_mfm_trk = false;

    /* Print image comment if it exists. */
    if( td->comment )
        puts( td->comment );

    for( ;; ) {
        /* Read track header; even the EOF marker includes a full header,
         * despite the fact that only the first byte is meaningful.
         */
        rc = td_read( td->fcx, &thdr, sizeof( thdr ) );
        if( rc != sizeof( thdr ) ) {
            if( rc >= 1 && thdr.num_sect == TRK_EOF_MARK ) {
                /* Except there are images that only have a one-byte
                 * EOF track header, or an incomplete header, sigh...
                 * If we read at least one byte and there's an EOF marker,
                 * consider it good because there are too many broken
                 * images.
                 */
                memset( &thdr, 0, sizeof( thdr ) );
                thdr.num_sect = TRK_EOF_MARK;
            } else if( rc == 0 ) {
                /* And there are even more broken images that have
                 * no EOF marker at all, they just end.
                 */
                memset( &thdr, 0, sizeof( thdr ) );
                thdr.num_sect = TRK_EOF_MARK;
            } else {
                printf( "error: failed to read track header!\n" );
                return( 1 );
            }
        }
        curr_ofs += rc;

        printf( " %02d/%d: ", thdr.cylinder, thdr.head & TRK_HEAD_MASK );

        /* Exit if end of image marker found. TeleDisk typically writes out
         * the previous track header with only the number of sectors changed.
         */
        if( thdr.num_sect == TRK_EOF_MARK ) {
            //@todo: Should the number of tracks really be what it says, i.e.
            // the # of tracks and not cylinders?
            td->trks = trk_last / 2 + 1;
            printf( "EOF (%d tracks)\n", td->trks );
            break;
        }

        /* Validate track header CRC. */
        crc = td_calc_crc( &thdr, offsetof( track_hdr, crc ), 0 );
        if( (crc & 0xFF) != thdr.crc ) {
            printf( "error: invalid track header CRC!\n" );
            return( 2 );
        }

        /* TeleDisk is sometimes too good and manages to find bogus data
         * beyond the last 'regular' cylinder. Watch out for such junk.
         */

        /* Check for a phantom cylinder with no sectors. */
        if( thdr.num_sect == 0 ) {
            printf( "empty track!\n" );
            continue;
        }

        /* Check for non-MFM tracks. */
        if( thdr.head & TRK_HFLG_FM ) {
            printf( "Track recorded as FM!\n" );
        } else {
            /* If there is an MFM track, guess that this is an MFM disk. */
            seen_mfm_trk = true;
        }

        /* Calculate and validate track number. */
        trk_idx = thdr.cylinder * 2 + (thdr.head & TRK_HEAD_MASK);
        if( trk_idx >= NTRK_MAX * 2 ) {
            printf( "error: track out of bounds!\n" );
            return( 3 );
        }

        printf( "%02dS ", thdr.num_sect );

        /* Update 'last valid track' counter, but skip junk FM tracks.
         * Heuristic: Guess that FM tracks are junk if there were MFM tracks
         * seen before.
         */
        if( (thdr.head & TRK_HFLG_FM) && seen_mfm_trk )
            ;   /* Ignore track. */
        else
            trk_last = trk_idx;

        /* Loop over all sectors on this track... */
        for( phys_sect = 0; phys_sect < thdr.num_sect; ++phys_sect ) {
            /* Read sector header to see what to do next. */
            shdr_ofs = curr_ofs;
            rc = td_read( td->fcx, &shdr, sizeof( shdr ) );
            if( rc != sizeof( shdr ) ) {
                printf( "error: failed to read sector header!\n" );
                return( 1 );
            }
            curr_ofs += rc;

            sec_size = SEC_SZ_BYTES( shdr.sect_sz );

            /* If present, read the sector data header and actual data. */
            if( !(shdr.flags & SECTOR_NO_DATA) ) {
                assert( sizeof( sec_buf ) >= sec_size );
                printf( " %d(%02X)@%06lX", shdr.sect_id, shdr.flags, curr_ofs );
                if( shdr.cyl_id != thdr.cylinder || shdr.head_id != (thdr.head  & TRK_HEAD_MASK) )
                    printf( "<-warn:mismatch phys C/H(%u/%u)--log C/H(%u/%u)",
                            thdr.cylinder, thdr.head & TRK_HEAD_MASK, shdr.cyl_id, shdr.head_id);

                rc = td_decomp_sect( td, curr_ofs, sec_buf, sec_size, &img_read );
                if( !rc )
                    return( 5 );
                curr_ofs += img_read;

                /* Extant TeleDisk image documentation may be misleading and
                 * claim that the sector CRC also covers the sector header and
                 * sector data header. In reality, it only covers the actual
                 * (uncompressed!) sector data.
                 */
                crc = td_calc_crc( &sec_buf, sec_size, 0 );
                if( (crc & 0xFF) != shdr.crc ) {
                    printf( "error: invalid sector data CRC!\n" );
                    return( 2 );
                }
            } else {
                printf( " %d(%02X)@------", shdr.sect_id, shdr.flags );
            }
        }
        printf( "\n" );
    }
    return( 0 );
}

const char *td_rate[] = { "250 kbps", "300 kbps", "500 kbps" };
const char *td_drvt[] = { "None", "360K", "1.2M", "720K", "1.44M" };


int main( int argc, char **argv )
{
    int         rc;
    int         nb;
    int         i;
    td_hdr      img_hdr;
    comment_hdr cmt_hdr;
    char        *comment;
    uint16_t    cmt_len;
    uint16_t    crc;
    long        curr_ofs;
    td_ctx      td;
    td_file_ctx fcx;
    img_fns     cb;
    FILE        *imgf;
    const char  *str;
    uint8_t     *deco_buf;

    if( argc != 2 ) {
        printf( "usage: %s <td_file>\n", argv[0] );
        return( 127 );
    }

    imgf = fopen( argv[1], "rb" );
    if( !imgf ) {
        printf( "error: failed to open `%s'\n", argv[1] );
        return( 126 );
    }

    if( !td_identify( imgf ) ) {
        printf( "error: `%s' is not a TeleDisk image.\n", argv[1] );
        return( 125 );
    }

    cb.seek      = f_seek;
    cb.read      = f_read;
    cb.m_alloc   = malloc;
    cb.m_alloc_z = m_alloc_z;
    cb.m_free    = free;

    /* Set up regular/compressed file context. */
    fcx.cmprsd   = false;
    fcx.mbuf     = NULL;
    fcx.imgf     = imgf;
    fcx.mbuf_ofs = 0;
    fcx.mbuf_sz  = 0;
    fcx.cb       = &cb;

    /* Read the image header in TD format. We already ensured it's sensible. */
    rc = td_load_hdr( imgf, &img_hdr );
    if( !rc ) {
        printf( "error: could not read TeleDisk image header!\n" );
        return( 1 );
    }

    printf( "%s format version %d.%d\n", rc == 2 ? "TeleGet" : "TeleDisk", img_hdr.td_ver / 10, img_hdr.td_ver % 10 );

    /* If the image is compressed, try to decompress it. */
    if( img_hdr.signature[0] == 't' && img_hdr.signature[1] == 'd' ) {
        deco_buf = malloc( DECOMP_BUF_SZ );
        if( !deco_buf ) {
            printf( "error: could not allocate buffer for uncompressed image!\n" );
            return( 2 );
        }

        printf( "Image compressed using %s\n", img_hdr.td_ver >= 20 ? "LZSS" : "LZW" );
        fcx.cmprsd   = true;
        fcx.mbuf     = deco_buf;

        /* The version appears to be stored as a decimal number. */
        if( img_hdr.td_ver >= 20 )
            fcx.mbuf_sz = td_unpack_lzss( &cb, imgf, fcx.mbuf, DECOMP_BUF_SZ );
        else
            fcx.mbuf_sz = td_unpack_lzw( &cb, imgf, fcx.mbuf, DECOMP_BUF_SZ );
        if( !fcx.mbuf_sz ) {
            printf( "error: decompression unsuccessful!\n" );
            return( 2 );
        }

        printf( "Compressed image: expanded to %lu bytes\n", fcx.mbuf_sz );
    }

    curr_ofs = sizeof( img_hdr );

    if( img_hdr.drate < sizeof( td_rate ) / sizeof( td_rate[0] ) )
        str = td_rate[img_hdr.drate];
    else
        str = "unknown";
    printf( "Data rate: %s, ", str );

    if( img_hdr.drv_typ < sizeof( td_drvt ) / sizeof( td_drvt[0] ) )
        str = td_drvt[img_hdr.drv_typ];
    else
        str = "unknown";
    printf( "Drive type: %s, ", str );

    printf( "%d sides, ", img_hdr.sides );

    /* Read in comment, if present. */
    comment = NULL;
    if( img_hdr.step_hdr & IMGHDR_HAVE_COMMENT ) {
        printf( "comment:\n" );
        nb = td_read( &fcx, &cmt_hdr, sizeof( cmt_hdr ) );
        if( nb != sizeof( cmt_hdr ) ){
            printf( "error: could not read TeleDisk image comment!\n" );
            return( 1 );
        }

        curr_ofs += sizeof( cmt_hdr );

        cmt_len = cmt_hdr.data_len;
        if( cmt_len ) {
            comment = malloc( cmt_len );
            if( !comment )
                goto error_cleanup;

            nb = td_read( &fcx, comment, cmt_len );
            if( nb != cmt_len ){
                printf( "error: could not read TeleDisk image comment!\n" );
                goto error_cleanup;
            }
        }

        curr_ofs += cmt_len;

        /* Validate CRC of the header... */
        crc = td_calc_crc( (uint8_t *)&cmt_hdr + sizeof( uint16_t ),
                           sizeof( cmt_hdr ) - sizeof( uint16_t ), 0 );
        /* ... and the comment data. */
        crc = td_calc_crc( comment, cmt_len, crc );
        if( crc != cmt_hdr.crc ){
            printf( "error: TeleDisk image comment checksum error!\n" );
            goto error_cleanup;
        }

        /* After checksumming, convert null characters into newlines. */
        for( i = 0; i < cmt_len - 1; ++i ) {
            if( comment[i] == '\0' )
                comment[i] =  '\n';
        }
    } else
        printf( "no comment\n" );

    /* Store the comment and image pointers. */
    td.comment = comment;
    td.imgf    = imgf;
    td.fcx     = &fcx;

    /* Build a map of all the tracks in the image. Also validates CRCs and
     * suchlike. If the track map can be built, the image is assumed to be OK.
     */
    rc = td_explore( &td, curr_ofs );
    fclose( imgf );
    if( rc ) {
        printf( "error: TeleDisk image not understood or corrupted!\n" );
        goto error_cleanup;
    }

    return( 0 );

error_cleanup:
    if( comment )
        free( comment );

    return( rc );
}
