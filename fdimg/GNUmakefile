# GNU make build for Linux. The original Watcom wmake build is in "makefile",
# which GNU make ignores since it prefers this file.

CC      ?= cc
CFLAGS  ?= -O2
override CFLAGS += -D_GNU_SOURCE -DFNM_IGNORECASE=FNM_CASEFOLD

IMG_SRCS = img_fns.c img_apr.c img_cp2.c img_cqm.c img_ddup.c img_df.c \
           img_dim.c img_drdi.c img_dskf.c dsk_lzmw.c img_dxp.c dxp_lh1.c \
           dxp_lh5.c img_hdcp.c img_hdk.c img_imd.c img_nsi.c img_sxd.c \
           sxd_lzh.c img_td.c td_lzss.c td_lzw.c img_tdup.c img_v9k.c \
           img_wcd.c img_qrst.c img_raw.c img_help.c
IMG_OBJS = $(IMG_SRCS:.c=.o)

.PHONY: all clean

all: imgext fdimg

imgext: imgext.o $(IMG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

fdimg: fdimg.o $(IMG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c *.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f imgext fdimg *.o
