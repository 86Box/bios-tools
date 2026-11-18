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

/*
 * LZMW decompression based on a 1988 paper "Variations on a theme by Ziv
 * and Lempel", by Victor S. Miller and Mark N. Wegman.
 *
 * IBM called the LZMW algorithm "terse" and it was used in several IBM
 * products, including the DSKF image format.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <assert.h>

#include "img_defs.h"
#include "img_help.h"
#include "dsk_lzmw.h"


#define DSKF_SIG        0xAA    /* The first byte of a DKSF signature. */
#define DSKF_SIG_OLD    0x58    /* Second byte - old DSKF format. */
#define DSKF_SIG_NOCMP  0x59    /* Second byte - uncompressed image. */
#define DSKF_SIG_COMP   0x5A    /* Second byte - compressed (tersed) image. */

#if 0
    #define dprintf( ... )      printf( __VA_ARGS__ )
#else
    #define dprintf( ... )
#endif

/* Byte swap a 16-bit word. */
#define SWAP16( a )     (((uint16_t)a >> 8) | ((uint16_t)a << 8))

typedef struct {
    uint8_t     *str;       /* String associated with this code. */
    size_t      len;        /* Length of the string. */
    int16_t     next;       /* Next LRU queue entry. */
    int16_t     prev;       /* Previous LRU queue entry. */
    int         ancestor;   /* Parent entry (sans last character). */
} dict_entry;

typedef struct {
    int         read_two;   /* Flip-flop flag for code reads. */
    int         nibble;     /* Left-over nibble from previous read. */
    int         avail;      /* The next available entry. */
    dict_entry  e[4096];    /* All dictionary entries. */
} dict_t;

dict_t      D;

/* Initialize decompression state. */
void lzmw_dict_init( img_fns *cb, dict_t *dict )
{
    int     i;

    /* Initialize miscellaneous state. */
    dict->avail = 257;
    dict->read_two = 1;

    /* Initialize the dictionary. */
    dict->e[0].str = NULL;
    dict->e[0].len = 0;
    for( i = 1; i <= 256; ++i ) {
        dict->e[i].str  = cb->m_alloc( 1 );
        *dict->e[i].str = i - 1;
        dict->e[i].len  = 1;
        dict->e[i].next = -1;
    }
    for( i = 257; i < 4095; ++i ) {
        dict->e[i].next = i + 1;
    }
    dict->e[4095].next = -1;
}

/* Raise the reference count for a dictionary entry. */
void lzmw_dict_add_ref( dict_t *dict, int entry )
{
    int     k, l;

    assert( entry );
    if( entry == 0 )
        return;
    /* For (next < 0), reference count is -next. */
    if( dict->e[entry].next < 0 ) {
        /* Increase reference count. */
        dict->e[entry].next--;
        dprintf( "ref_inc %03X: %d\n", entry, -dict->e[entry].next );
    } else {
        /* Remove entry from the unreferenced list. */
        k = dict->e[entry].next;
        assert( !k || k > 256 );
        l = dict->e[entry].prev;
        assert( !l || l > 256 );
        dict->e[k].prev = l;
        dict->e[l].next = k;
        dict->e[entry].next = -1;   /* Set reference count to one. */
    }
    dprintf( "bump_ref  %03X: %03X <- 0 -> %03X\n", entry, dict->e[0].prev, dict->e[0].next );
}

/* Move an entry to the unreferenced (LRU) queue. */
void lzmw_dict_move_to_unref( dict_t *dict, int entry )
{
    int     k;

    assert( entry );
    k = dict->e[0].prev;
    dict->e[entry].prev = k;
    dict->e[k].next = entry;
    dict->e[entry].next = 0;
    dict->e[0].prev = entry;
    dprintf( "add_unref %03X: %03X <- 0 -> %03X\n", entry, dict->e[0].prev, dict->e[0].next );
}

/* Lower the reference count for a dictionary entry. */
void lzmw_dict_remove_ref( dict_t *dict, int entry )
{
    assert( entry );
    if( entry == 0 )
        return;
    /* Decrease reference count. */
    dict->e[entry].next++;
    dprintf( "ref_dec %03X: %d\n", entry, -dict->e[entry].next );
    /* If no longer referenced, move to LRU queue. */
    if( dict->e[entry].next == 0 )
        lzmw_dict_move_to_unref( dict, entry );
}

/* Obtain the next available slot in the dictionary. */
int lzmw_dict_get_avail_slot( img_fns *cb, dict_t *dict )
{
    int     k, l;

    if( dict->avail != -1 ) {
        /* An unused entry is available. */
        k = dict->avail;
        dict->avail = dict->e[k].next;
        dprintf( "avail: %03X\n", k );
    } else {
        /* Recycle the least recently used entry. */
        assert( dict->e[0].prev != dict->e[0].next );
        k = dict->e[0].next;
        l = dict->e[k].next;
        assert( k > 256 && l > 256 );
        dict->e[0].next = l;
        dict->e[l].prev = 0;
        dprintf( "avl_slot  %03X: %03X <- 0 -> %03X\n", k, dict->e[0].prev, dict->e[0].next );
        assert( dict->e[0].prev && dict->e[0].next );
        lzmw_dict_remove_ref( dict, dict->e[k].ancestor );
        cb->m_free( dict->e[k].str );
    }
    return( k );
}

int lzmw_dict_out( dict_t *dict, uint16_t code, uint8_t *dst, long buf_sz )
{
    if( dict->e[code].len <= buf_sz ) {
        memcpy( dst, dict->e[code].str, dict->e[code].len );
        return( dict->e[code].len );
    } else {
        memcpy( dst, dict->e[code].str, buf_sz );
        return( -buf_sz );
    }
}

void lzmw_dict_add( img_fns *cb, dict_t *dict, uint16_t code, uint16_t prev_code )
{
    int     j;
    size_t  p_len;

    assert( code && prev_code );
    if( prev_code == 0 )
        return;
    j = lzmw_dict_get_avail_slot( cb, dict );
    assert( j > 256 && j < 4096);
    p_len = dict->e[prev_code].len;
    assert( p_len );
    if( j == code ) {
        dprintf( "future code (cScSc case)!\n" );
        code = prev_code;
    }
    dict->e[j].len = p_len + 1;
    dict->e[j].str = cb->m_alloc( dict->e[j].len );
    lzmw_dict_add_ref( dict, prev_code );
    lzmw_dict_move_to_unref( dict, j );
    dict->e[j].ancestor = prev_code;
    memcpy( dict->e[j].str, dict->e[prev_code].str, p_len );
    dict->e[j].str[p_len] = dict->e[code].str[0];
}

/* Read the next 12-bit code from the compressed stream. */
int16_t lzmw_read_next_code( dict_t *dict, img_fns *cb, img_file imgf, int *nread )
{
    int16_t     code;
    uint16_t    tw;
    uint8_t     tb;

    if( dict->read_two ) {
        /* Read the first 16 bits of a code tuple. */
        *nread = cb->read( imgf, &tw, sizeof( tw ) );
        if( *nread != sizeof( tw ) )
            return( 0 );
        tw = SWAP16( tw );
        dict->nibble = tw & 0x0F;
        code = tw >> 4;
    } else {
        /* Read the final 8 bits of a code tuple. */
        *nread = cb->read( imgf, &tb, sizeof( tb ) );
        if( *nread != sizeof( tb ) )
            return( 0 );
        code = (dict->nibble << 8) | tb;
    }
    dict->read_two ^= 1;
    return( code );
}


/* Expand compressed data into the supplied output buffer.
 * It is assumed that the file pointer is at the beginning of the
 * compressed data, and the decompressor should not stop until
 * the output buffer is full (likely an error) or the end of the
 * input file is encountered.
 */
long dskf_unpack_lzmw( img_fns *cb, img_file imgf, uint8_t* dst, long buf_sz )
{
    long        unp_len;
    long        dst_sz = buf_sz;
    long        out_ofs = 0;
    int         nread;
    uint16_t    code;
    uint16_t    prev_code;
    dict_t      *dict = &D;

    /* Initialize the decompressor state. */
    lzmw_dict_init( cb, dict );
    prev_code = 0;

    /* The first code is output but not added to the dictionary. */
    prev_code = lzmw_read_next_code( dict, cb, imgf, &nread );
    out_ofs += lzmw_dict_out( dict, prev_code, dst, dst_sz );

    /* Process the remaining codes in a loop. */
    while( (code = lzmw_read_next_code( dict, cb, imgf, &nread )) != 0 ) {
        lzmw_dict_add( cb, dict, code, prev_code );
        unp_len = lzmw_dict_out( dict, code, dst + out_ofs, dst_sz );
        prev_code = code;
        dst_sz  -= unp_len;
        out_ofs += unp_len;
    };

    // Return the unpacked size
    return( out_ofs );
}
