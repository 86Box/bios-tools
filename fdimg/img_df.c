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
#include "img_df.h"


/* The DF diskette image format was used by the DF Utility, written by Mark
 * Vitt around 1993. The DF format is relatively simple, supporting only
 * standard DOS formats (360K, 720K, 1.2M, 1.44M). The DF Utility is somewhat
 * different from most in that it understands the FAT format.
 *
 * There are no provisions for compression, although it is possible to
 * truncate the image past the last occupied cluster. There are provisions to
 * identify and skip bad sectors. The image data is protected by a single CRC.
 *
 * The format also supports comments, and stores the date when the image was
 * made in the header.
 *
 * In the typical case, the image is essentially a raw image preceded by
 * a 512-byte header. Most of said header may contain uninitialized data.
 *
 * The implementation is based purely on analyzing floppy images created by
 * the DF Utility and there are many question marks. Sadly DF likes to leave
 * lots of junk in the header sector which makes it harder to discern valid
 * data from chaff.
 */


/* File magic definitions. */
#define DF_MAGIC_SZ     5
#define DF_NULLS_SZ     4
static const char df_nulls[] = "\0\0\0\0";

/* DF image header. */
typedef struct df_hdr_s {
    uint8_t     media_typ;      /* Type of media. */
    uint8_t     zero1[4];       /* Unused? */
    uint8_t     ver_major;      /* Major DF version. */
    uint8_t     ver_minor;      /* Minor DF version. */
    uint8_t     unk1;           /* Unknown. Flags? */
    uint8_t     cmt_len;        /* Comment length. */
    char        cmt[0x1F];      /* Comment (null terminated). */
    uint32_t    unk2;           /* Unknown. */
    uint32_t    crc32;          /* 32-bit CRC. */
    uint32_t    zero2;          /* Unused. */
    uint8_t     month;          /* Month (1-12). */
    uint8_t     day;            /* Day of the month (1-31). */
    uint16_t    year;           /* Year (16-bit binary). */
    uint16_t    unk3;           /* Timestamp? */
    char        sig[3];         /* Signature (author's initials). */
    uint8_t     unk4;           /* Unknown. */
} df_hdr;

typedef struct df_ctx {
    img_file    imgf;           /* Image file handle. */
    uint8_t     cyls;           /* Number of cylinders. */
    uint8_t     spt;            /* Sectors per track. */
    uint8_t     heads;          /* Number of heads (1 or 2). */
    df_hdr      hdr;            /* The image header. */
    long        start_ofs;      /* File offset of the first sector. */
    const char  *comment;       /* Image comment. */
} df_ctx;


typedef struct med_entry_s {
    uint8_t     id;             /* Identifier byte. */
    uint8_t     cyls;           /* Number of cylinders. */
    uint8_t     heads;          /* Number of heads. */
    uint8_t     spt;            /* Sectors per track. */
} med_entry;

static med_entry    media_tab[] = {
    { 0xF0, 80, 2, 18 },        /* 3.5"  1.44M disk. */
    { 0xF8, 80, 2, 9  },        /* 3.5"  720K  disk. */
    { 0xF9, 80, 2, 15 },        /* 5.25" 1.2M  disk. */
    { 0xFD, 40, 2, 9  },        /* 5.25" 360K  disk. */
    { 0, 0, 0, 0 }              /* Terminator. */
};


/* Identify a DF format image. Does not validate image. */
int df_identify( img_fns *cb, img_file imgf )
{
    uint8_t magic[DF_MAGIC_SZ];
    int     rc;

    /* The image starts with a byte identifying the disk type, followed
     * by four zero bytes. This is a bit of guesswork.
     */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &magic, sizeof( magic ) );
    if( rc != sizeof( magic ) )
        return( 0 );

    /* First byte is always F0h or greater. */
    if( magic[0] < 0xF0 )
        return( 0 );
    if( memcmp( &magic[1], df_nulls, DF_NULLS_SZ ) )
        return( 0 );
    else
        return( sizeof( df_ctx ) );
}


/* Open an image for access. May fail if image is damaged. */
int df_open( img_fns *cb, img_file imgf, df_ctx *ctx )
{
    int         rc;
    df_hdr      hdr;
    med_entry   *me;
    uint16_t    img_sec;
    long        img_size;

    /* Read the image format header. */
    cb->seek( imgf, 0 );
    rc = cb->read( imgf, &hdr, sizeof( hdr ) );
    if( rc != sizeof( hdr ) )
        return( IMG_ERR_READ );

    me = media_tab;
    while( me->id ) {
        if( hdr.media_typ == me->id )
            break;
        ++me;
    }
    if( !me->id )
        return( IMG_ERR_BAD_IMG );  /* Unsupported media type. */

    /* Currently hardcoded as we don't know any better. */
    ctx->start_ofs = 512;

    /* Verify image size. If it matches, image is likely to be good. */
    img_sec   = (uint16_t)me->cyls * me->spt * me->heads;
    img_size  = ctx->start_ofs;
    img_size += img_sec * IMG_SEC_SZ_DEF;
    if( img_size != cb->fsize( imgf ) )
        return( IMG_ERR_BAD_IMG );

    ctx->imgf  = imgf;
    ctx->cyls  = me->cyls;
    ctx->spt   = me->spt;
    ctx->heads = me->heads;
    ctx->hdr   = hdr;

    ctx->comment = ctx->hdr.cmt;

    return( IMG_OK );
}


/* Read a single sector from the image. */
int df_read_sect( img_fns *cb, df_ctx *ctx, int sect_num, void *buf )
{
    long    sec_ofs;

    /* Calculate the sector offset. Note the per-sector byte data. */
    sec_ofs = ctx->start_ofs + (long)sect_num * IMG_SEC_SZ_DEF;
#if 0
    /* Skip 8 bytes at the end of every track. */
    sec_ofs += sect_num / ctx->spt * 8; //@todo - accurate?
#endif
    /* Read the sector from image file. */
    cb->seek( ctx->imgf, sec_ofs );
    return( cb->read( ctx->imgf, buf, IMG_SEC_SZ_DEF ) );
}


/* Query the comment string. Returns NULL if no comment provided. */
const char *df_query_comment( img_fns *cb, df_ctx *ctx )
{
    return( ctx->comment );
}

/* Close an image once all accesses are completed. */
void df_close( img_fns *cb, df_ctx *ctx )
{
    assert( ctx );
}
