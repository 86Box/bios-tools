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

/* A simple implementation of the disk image manipulation routines. */

#include <stdlib.h>
#include <stdio.h>

#include "img_help.h"

void imgfn_seek( img_file img, long ofs )
{
    FILE    *fp = img;

    fseek( fp, ofs, SEEK_SET );
}

long imgfn_fsize( img_file img )
{
    FILE    *fp = img;
    long    saved_pos;
    long    file_size;

    saved_pos = ftell( fp );
    fseek( fp, 0L, SEEK_END );
    file_size = ftell( fp );
    fseek( fp, saved_pos, SEEK_SET );
    return( file_size );
}

size_t imgfn_read( img_file img, void *buf, size_t cnt )
{
    FILE    *fp = img;

    return( fread( buf, 1, cnt, fp ) );
}

void *imgfn_m_alloc( size_t cnt )
{
    return( malloc( cnt ) );
}

void *imgfn_m_alloc_z( size_t cnt )
{
    return( calloc( 1, cnt ) );
}

void imgfn_m_free( void *ptr )
{
    free( ptr );
}

img_fns     ifn = {
    imgfn_seek,
    imgfn_fsize,
    imgfn_read,
    imgfn_m_alloc,
    imgfn_m_alloc_z,
    imgfn_m_free
};
