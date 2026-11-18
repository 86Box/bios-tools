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
#include <assert.h>

#include "img_defs.h"
#include "img_help.h"
#include "img_fns.h"

#include "img_apr.h"
#include "img_cp2.h"
#include "img_cqm.h"
#include "img_ddup.h"
#include "img_df.h"
#include "img_dim.h"
#include "img_drdi.h"
#include "img_dskf.h"
#include "img_dxp.h"
#include "img_hdcp.h"
#include "img_hdk.h"
#include "img_imd.h"
#include "img_nsi.h"
#include "img_sxd.h"
#include "img_td.h"
#include "img_tdup.h"
#include "img_v9k.h"
#include "img_wcd.h"
#include "img_qrst.h"
#include "img_raw.h"


typedef enum {
    IMG_NONE,
    IMG_APR,
    IMG_CQM,
    IMG_CP2,
    IMG_DDUP,
    IMG_DF,
    IMG_DIM,
    IMG_DRDI,
    IMG_DSKF,
    IMG_DXP,
    IMG_HDCP,
    IMG_HDK,
    IMG_IMD,
    IMG_NSI,
    IMG_SXD,
    IMG_TDUP,
    IMG_TELEDISK,
    IMG_V9K,
    IMG_WCD,
    IMG_QRST,
    IMG_RAW
} img_type;

typedef struct img_ctx {
    img_file    imgf;
    img_fns     *cb;
    img_type    imgt;
    char        fmt_private[];
} img_ctx;

#define IMG_DRV_PRIVATE( a )    ((void *)(&a->fmt_private))


int img_open( const char *fname, img_fns *cb, img_handle *imgh )
{
    img_ctx     *img = NULL;
    FILE        *imgf;
    img_type    imgt = IMG_NONE;
    int         rc = IMG_ERR_READ;
    int         priv_sz;

    imgf = fopen( fname, "rb" );
    if( imgf ) {
        /* Attempt to identify the file format. Note that the raw file
         * format check should be run last to avoid false positives.
         */
        if( (priv_sz = apr_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_APR;
        } else if( (priv_sz = cp2_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_CP2;
        } else if( (priv_sz = cqm_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_CQM;
        } else if( (priv_sz = ddup_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_DDUP;
        } else if( (priv_sz = df_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_DF;
        } else if( (priv_sz = dim_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_DIM;
        } else if( (priv_sz = drdi_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_DRDI;
        } else if( (priv_sz = dskf_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_DSKF;
        } else if( (priv_sz = dxp_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_DXP;
        } else if( (priv_sz = hdcp_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_HDCP;
        } else if( (priv_sz = hdk_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_HDK;
        } else if( (priv_sz = imd_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_IMD;
        } else if( (priv_sz = sxd_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_SXD;
        } else if( (priv_sz = tdup_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_TDUP;
        } else if( (priv_sz = td_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_TELEDISK;
        } else if( (priv_sz = v9k_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_V9K;
        } else if( (priv_sz = wcd_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_WCD;
        } else if( (priv_sz = qrst_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_QRST;
        } else if( (priv_sz = nsi_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_NSI;
        } else if( (priv_sz = raw_identify( cb, imgf )) > 0 ) {
            imgt  = IMG_RAW;
        }

        /* Allocate memory for generic and driver-specific context data. */
        if( imgt != IMG_NONE ) {
            img = cb->m_alloc( sizeof( img_ctx ) + priv_sz );
            img->imgf = imgf;
            img->cb   = cb;
            img->imgt = imgt;
        }

        /* Run format-specific image open routine. May fail! */
        rc = IMG_ERR_UNK_IMG;
        switch( imgt ) {
        case IMG_APR:
            rc = apr_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_CP2:
            rc = cp2_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_CQM:
            rc = cqm_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_DDUP:
            rc = ddup_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_DF:
            rc = df_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_DIM:
            rc = dim_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_DRDI:
            rc = drdi_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_DSKF:
            rc = dskf_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_DXP:
            rc = dxp_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_HDCP:
            rc = hdcp_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_HDK:
            rc = hdk_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_IMD:
            rc = imd_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_NSI:
            rc = nsi_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_SXD:
            rc = sxd_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_TDUP:
            rc = tdup_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_TELEDISK:
            rc = td_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_V9K:
            rc = v9k_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_WCD:
            rc = wcd_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_QRST:
            rc = qrst_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_RAW:
            rc = raw_open( img->cb, imgf, IMG_DRV_PRIVATE( img ) );
            break;
        case IMG_NONE:
            break;
        default:
            /* Not supposed to happen. */
            assert( 0 );
        }
        if( rc != IMG_OK && img ) {
            img->cb->m_free( img );
            img = NULL;
        }
    }

    *imgh = img;
    return( rc );
}

int img_read_sect( img_handle imgh, int sect_num, void *buf )
{
    img_ctx     *img = imgh;
    int         rc;

    switch( img->imgt ) {
    case IMG_APR:
        rc = apr_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_CP2:
        rc = cp2_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_CQM:
        rc = cqm_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_DDUP:
        rc = ddup_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_DF:
        rc = df_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_DIM:
        rc = dim_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_DRDI:
        rc = drdi_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_DSKF:
        rc = dskf_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_DXP:
        rc = dxp_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_HDCP:
        rc = hdcp_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_HDK:
        rc = hdk_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_IMD:
        rc = imd_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_NSI:
        rc = nsi_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_SXD:
        rc = sxd_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_TDUP:
        rc = tdup_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_TELEDISK:
        rc = td_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_V9K:
        rc = v9k_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_WCD:
        rc = wcd_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_QRST:
        rc = qrst_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    case IMG_RAW:
        rc = raw_read_sect( img->cb, IMG_DRV_PRIVATE( img ), sect_num, buf );
        break;
    default:
        rc = 0;
    }
    return( rc );
}

const char *img_query_comment( img_handle imgh )
{
    img_ctx     *img = imgh;
    const char  *cmt;

    switch( img->imgt ) {
    case IMG_APR:
        cmt = apr_query_comment( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_CQM:
        cmt = cqm_query_comment( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_DF:
        cmt = df_query_comment( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_DSKF:
        cmt = dskf_query_comment( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_DXP:
        cmt = dxp_query_comment( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_SXD:
        cmt = sxd_query_comment( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_TELEDISK:
        cmt = td_query_comment( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_WCD:
        cmt = wcd_query_comment( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_QRST:
        cmt = qrst_query_comment( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    default:
        /* No comment support in other image formats. */
        cmt = NULL;
    }
    return( cmt );
}

void img_close( img_handle imgh )
{
    img_ctx     *img = imgh;

    switch( img->imgt ) {
    case IMG_APR:
        apr_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_CQM:
        cqm_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_CP2:
        cp2_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_DDUP:
        ddup_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_DF:
        df_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_DIM:
        dim_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_DRDI:
        drdi_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_DSKF:
        dskf_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_DXP:
        dxp_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_HDCP:
        hdcp_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_HDK:
        hdk_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_IMD:
        imd_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_NSI:
        nsi_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_SXD:
        sxd_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_TDUP:
        tdup_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_TELEDISK:
        td_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_V9K:
        v9k_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_WCD:
        wcd_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_QRST:
        qrst_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    case IMG_RAW:
        raw_close( img->cb, IMG_DRV_PRIVATE( img ) );
        break;
    default:
        /* Not supposed to happen. */
        assert( 0 );
    }
    fclose( img->imgf );
    img->cb->m_free( img );
}
