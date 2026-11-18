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
 * Types and constants for processing images of FAT-formatted disks.
 */

/* Attribute bits in directory entries. */
#define FAT_ATTR_RDO        0x01
#define FAT_ATTR_HID        0x02
#define FAT_ATTR_SYS        0x04
#define FAT_ATTR_VOL        0x08
#define FAT_ATTR_DIR        0x10
#define FAT_ATTR_ARC        0x20

/* Attribute combination used by LFN directory entries. */
#define FAT_ATTR_LFN        (FAT_ATTR_VOL | FAT_ATTR_SYS | \
                             FAT_ATTR_HID | FAT_ATTR_RDO)

/* All horrible misaligned stuff. */
#pragma pack(1)

typedef struct {
    uint8_t     jump[3];
    char        oem_name[8];
    uint16_t    bytes_per_sect;
    uint8_t     sec_per_clust;
    uint16_t    reserved_sect;
    uint8_t     num_of_fats;
    uint16_t    root_entries;
    uint16_t    total_sect;
    uint8_t     media_desc;
    uint16_t    sect_per_fat;
    uint16_t    sect_per_trk;
    uint16_t    num_heads;
    uint32_t    hidden_sect;
    uint32_t    ext_total_sect;
    uint8_t     phys_drive_no;
    uint8_t     rsvd2;
    uint8_t     ext_signature;
    uint32_t    vol_id;
    char        vol_label[11];
    uint8_t     rsvd3[8];
} fat_boot_sec;


/* The original BPB defined by DOS 2.0. The last three fields are optional
 * and not technically part of the BPB; they do not describe the FAT file
 * system per se but rather help the disk device driver understand the
 * medium structure.
 */
typedef struct {
    uint16_t    bytes_per_sect; /* Bytes per sector. */
    uint8_t     sec_per_clust;  /* Sectors per cluster (power of 2). */
    uint16_t    reserved_sect;  /* Reserved sectors before first FAT.*/
    uint8_t     num_of_fats;    /* Number of FATs (almost always 2). */
    uint16_t    root_entries;   /* Number of root directory entries. */
    uint16_t    total_sect;     /* Total sectors on logical image. */
    uint8_t     media_desc;     /* Media descriptor byte. */
    uint16_t    sect_per_fat;   /* Sectors per FAT. */
    uint16_t    sect_per_trk;   /* Sectors per track (optional). */
    uint16_t    num_heads;      /* Number of heads (optional). */
    uint32_t    hidden_sect;    /* Hidden sectors (optional). */
} bpb_dos_20;


/* The extended BPB introduced in DOS 4.0. The extended BPB signature in
 * the boot sector must contain 29h for the extended BPB to be valid.
 */
typedef struct {
    uint16_t    bytes_per_sect; /* Bytes per sector. */
    uint8_t     sec_per_clust;  /* Sectors per cluster (power of 2). */
    uint16_t    reserved_sect;  /* Reserved sectors before first FAT.*/
    uint8_t     num_of_fats;    /* Number of FATs (almost always 2). */
    uint16_t    root_entries;   /* Number of root directory entries. */
    uint16_t    total_sect;     /* Total sectors on logical image. */
    uint8_t     media_desc;     /* Media descriptor byte. */
    uint16_t    sect_per_fat;   /* Sectors per FAT. */
    uint16_t    sect_per_trk;   /* Sectors per track (optional). */
    uint16_t    num_heads;      /* Number of heads (optional). */
    uint32_t    hidden_sect;    /* Hidden sectors (optional). */
    uint32_t    ext_total_sect; /* 32-bit total sectors. */
} bpb_dos_40;


/* The 'modern' FAT directory entry, with 32 bytes per entry. PC DOS 1.0
 * only recorded creation date, not time. This is indistinguishable from
 * midnight (00:00:00). Some very old DOS releases also didn't record
 * creation date; a date of all zeros can be recognized as invalid.
 */
typedef struct {
    char        name[8];
    char        ext[3];
    uint8_t     attr;
    char        rsvd[10];
    uint16_t    time;
    uint16_t    date;
    uint16_t    cluster;
    uint32_t    size;
} fat_dir_entry;

/* Prehistoric 16-byte FAT directory entry, used up to about SCP 86-DOS 0.34.
 * There are no attributes, no timestamps, and only 24 bits of file size.
 * NB: Although the file size is recorded in bytes, 86-DOS versions which
 * used 16-byte directory entries likely always recorded file size
 * in multiples of 128 bytes.
 */
typedef struct {
    char        name[8];
    char        ext[3];
    uint16_t    cluster;
    uint8_t     size[3];
} fat_old_entry;

#pragma pack()

