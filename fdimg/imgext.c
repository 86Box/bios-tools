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

/* Convert a floppy image in any of the supported formats to a raw image. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "img_defs.h"
#include "img_help.h"
#include "img_fns.h"

extern img_fns      ifn;

int main( int argc, char **argv )
{
    char        sect_buf[IMG_SEC_SZ_MAX];
    const char  *comment;
    img_handle  fsrc;
    int         sector;
    FILE        *fdst;
    int         rc;

    bool        no_raw = false;

    /* The -n option rejects images identified as raw data, so that callers
     * can tell whether an actual image format was recognized.
     */
    if( argc == 4 && !strcmp( argv[1], "-n" ) ) {
        no_raw = true;
        ++argv;
        --argc;
    }

    if( argc != 3 ) {
        printf( "usage: %s [-n] <src_img> <dst_raw_img>\n", argv[0] );
        printf( "       -n  Fail with exit code 2 if the source is a raw image.\n" );
        return( EXIT_FAILURE );
    }

    /* If the image layer opens (for reading) the same file we open
     * here for writing, the source will get trashed.
     */
    if( !strcmp( argv[1], argv[2] ) ) {
        printf( "Source and destination files must differ!\n" );
        return( EXIT_FAILURE );
    }

    rc = img_open( argv[1], &ifn, &fsrc );
    if( rc ) {
        printf( "Failed to open `%s' for reading!\n", argv[1] );
        printf( "Error code: %d\n", rc );
        return( EXIT_FAILURE );
    }

    if( no_raw && img_is_raw( fsrc ) ) {
        printf( "Source `%s' is a raw image.\n", argv[1] );
        img_close( fsrc );
        return( 2 );
    }

    fdst = fopen( argv[2], "wb" );
    if( !fdst ) {
        printf( "Failed to open `%s' for writing!\n", argv[2] );
        img_close( fsrc );
        return( EXIT_FAILURE );
    }

    comment = img_query_comment( fsrc );
    if( comment )
        puts( comment );

    sector = 0;
    while( (rc = img_read_sect( fsrc, sector++, &sect_buf )) > 0 ) {
        fwrite( &sect_buf, 1, rc, fdst );
    }

    /* 'No such sector' indicates the end of an image when we're reading
     * sequentially. Anything else is a real error.
     */
    if( rc != IMG_ERR_NO_SECT ) {
        printf( "Image extraction failed at sector %d (%d)\n", sector, rc );
    }

    img_close( fsrc );
    fclose( fdst );
    return( EXIT_SUCCESS );
}
