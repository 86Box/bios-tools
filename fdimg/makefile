IMG_OBJS  = img_fns.obj &
            img_apr.obj &
	    img_cp2.obj &
	    img_cqm.obj &
	    img_ddup.obj &
	    img_df.obj &
            img_dim.obj &
	    img_drdi.obj &
	    img_dskf.obj &
	    dsk_lzmw.obj &
	    img_dxp.obj &
	    dxp_lh1.obj &
	    dxp_lh5.obj &
	    img_hdcp.obj &
	    img_hdk.obj &
	    img_imd.obj &
	    img_nsi.obj &
	    img_sxd.obj &
	    sxd_lzh.obj &
	    img_td.obj &
	    td_lzss.obj &
	    td_lzw.obj &
	    img_tdup.obj &
	    img_v9k.obj &
	    img_wcd.obj &
	    img_qrst.obj &
	    img_raw.obj

IEXT_OBJS = imgext.obj img_help.obj $(IMG_OBJS)

FDI_OBJS  = fdimg.obj img_help.obj $(IMG_OBJS)

MKI_OBJS  = mkimage.obj

APRI_OBJS = aprinfo.obj

CP2I_OBJS = cp2info.obj

IMDI_OBJS = imdinfo.obj

TDI_OBJS  = tdinfo.obj td_lzss.obj td_lzw.obj


all : imgext.exe fdimg.exe mkimage.exe aprinfo.exe imdinfo.exe cp2info.exe tdinfo.exe .symbolic


imgext.exe : $(IEXT_OBJS)
    wlink op q, map d all file { $(IEXT_OBJS) }

fdimg.exe  : $(FDI_OBJS)
    wlink op q, map d all file { $(FDI_OBJS) }

mkimage.exe : $(MKI_OBJS)
    wlink op q, map d all file { $(MKI_OBJS) }

aprinfo.exe : $(APRI_OBJS)
    wlink op q, map d all file { $(APRI_OBJS) }

cp2info.exe : $(CP2I_OBJS)
    wlink op q, map d all file { $(CP2I_OBJS) }

imdinfo.exe : $(IMDI_OBJS)
    wlink op q, map d all file { $(IMDI_OBJS) }

tdinfo.exe : $(TDI_OBJS)
    wlink op q, map d all file { $(TDI_OBJS) }

.c.obj : .autodepend
    wcc386 -q -d2 -wx $<

clean : .symbolic
    rm -f imgext.exe fdimg.exe
    rm -f imgext.map fdimg.map
    rm -f $(IMG_OBJS)
    rm -f imgext.obj fdimg.obj img_help.obj
