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

typedef struct cqm_ctx cqm_ctx;

/* Identify a CopyQM format image. Does not validate image. */
int cqm_identify( img_fns *cb, img_file imgf );

/* Open an image for access. May fail if image is damaged or too complex. */
int cqm_open( img_fns *cb, img_file imgf, cqm_ctx *cqm );

/* Query the comment string. Returns NULL if no comment provided. */
const char *cqm_query_comment( img_fns *cb, cqm_ctx *cqm );

/* Read a single sector from the image. */
int cqm_read_sect( img_fns *cb, cqm_ctx *cqm, int sect_num, void *buf );

/* Close an image once all accesses are completed. */
void cqm_close( img_fns *cb, cqm_ctx *cqm );
