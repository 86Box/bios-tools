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

/* Definitions shared by front ends and image back-ends. */

/* Default sector size. */
#define IMG_SEC_SZ_DEF  512

/* Largest (somewhat) common sector size. */
#define IMG_SEC_SZ_MAX  2048

/* Image decoding errors. */
#define IMG_OK              0       /* No error. */
#define IMG_ERR_NO_SECT     -1      /* Sector not found in image. */
#define IMG_ERR_MEM_ALLOC   -2      /* Failed to allocate memory. */
#define IMG_ERR_READ        -3      /* Failed to read image data. */
#define IMG_ERR_BAD_IMG     -4      /* Recognized but corrupted image. */
#define IMG_ERR_DECODE      -5      /* Failed to decode image data. */
#define IMG_ERR_CSUM        -6      /* Bad checksum (corrupted data). */
#define IMG_ERR_BAD_SECT    -7      /* Bad sector recorded in image. */
#define IMG_ERR_UNK_IMG     -8      /* Unrecognized image format. */
#define IMG_ERR_CANT_CONV   -9      /* Cannot convert source image. */
#define IMG_ERR_DECOMP      -10     /* Decompression failed. */
#define IMG_ERR_PASSWD      -11     /* Password protected image. */
