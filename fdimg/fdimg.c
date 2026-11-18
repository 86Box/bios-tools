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
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>
#include <sys/stat.h>
//#include <sys/utime.h>
#include <utime.h>
#include <fnmatch.h>
//#include <direct.h>
#include "img_help.h"
#include "img_defs.h"
#include "img_fns.h"
#include "fat.h"

extern img_fns      ifn;


#define ACT_LIST            0
#define ACT_EXTRACT         1
#define PROC_RECURSIVE      0x0001
#define PROC_NODIRS         0x0002
#define PROC_VERBOSE        0x0004

typedef struct {
    uint32_t    bias;
    int         sec_sz;     /* Sector size in bytes. */
    int         de_sz;      /* Directory entry size (16 or 32 bytes). */
    int         clustlen;
    int         clustnum;
    int         clustsec;
    int         fat_sect;
    int         fat_entries;
    int         rootsect;
    int         datasect;
    bool        rainbow;
} img_info;

typedef struct {
    int         sect;
    int         pos;
} TDirPointer;

typedef struct {
    char            name[256];
    char            shortname[13];
    char            path[256];
    unsigned char   attr;
    unsigned long   cluster;
    unsigned long   sect;
    unsigned long   size;
    bool            no_date;
    time_t          timestamp;
} TFileInfo;

img_info        imginfo;
img_handle      imgfile;
uint32_t        *FAT;
unsigned char   *buf;
int             fat_bits;


int read_sector( int sect_no, void *dest )
{
    int     rc;

    /* For the Rainbow, we have to reorder sectors within a track. Thanks, DEC. */
    if( imginfo.rainbow ) {
        int     lace[] = { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };  /* Zero-based! */
        int     sect;

        sect    = sect_no % 10;     /* Sector number on a track. */
        sect_no = sect_no - sect;   /* Keep just whole tracks. */
        sect_no = sect_no + lace[sect];
    }

    rc = img_read_sect( imgfile, imginfo.bias + sect_no, dest );
    return( rc );
}

int read_sector_part( int sect_no, int offset, int len, void *dest )
{
    uint8_t     sect_buff[IMG_SEC_SZ_MAX];
    int         rc;

    rc = read_sector( sect_no, sect_buff );
    switch( rc ) {
    /* Support and detect 128/256/512/1024-byte sectors. */
    case  128:
    case  256:
    case  512:
    case 1024:
        memcpy( dest, sect_buff + offset, len );
        return( rc );
    default:
        return( 0 );
    }
}


void read_fat12( void )
{
    int             i, j, sect;
    unsigned char   byte1, byte2;

    i = 0;
    j = imginfo.sec_sz;
    byte2 = 0;
    sect = imginfo.fat_sect;
    while( i < imginfo.fat_entries ) {
        if( j >= imginfo.sec_sz ) {
            read_sector( sect, buf );
            sect++;
            j = 0;
        }
        byte1 = byte2;
        byte2 = buf[j++];
        if( (i & 1) == 0 ) {
            if( j >= imginfo.sec_sz ) {
                read_sector( sect, buf );
                sect++;
                j = 0;
            }
            byte1 = byte2;
            byte2 = buf[j++];
            FAT[i] = (byte1 + (byte2 << 8)) & 0xFFF;
        } else {
            FAT[i] = ((byte1 + (byte2 << 8)) >> 4) & 0xFFF;
        }
        if( (FAT[i] & 0xFF0) == 0xFF0 )
            FAT[i] = 0xFFFFFFFF;
        i++;
    }
}

void read_fat16( void )
{
    int             i, j, sect;
    uint16_t        entry;

    i = 0;
    j = imginfo.sec_sz;
    sect = imginfo.fat_sect;
    while( i < imginfo.fat_entries ) {
        if( j >= imginfo.sec_sz ) {
            read_sector( sect, buf );
            sect++;
            j = 0;
        }
        entry = buf[j] | (buf[j + 1] << 8);
        j += 2;
        FAT[i] = entry;
        if( (FAT[i] & 0xFFF0) == 0xFFF0 )
            FAT[i] = 0xFFFFFFFF;
        i++;
    }
}

int fdimg_open( const char *filename, int flags )
{
    int             total_sec;
    int             root_entries;
    int             sec_per_fat;
    int             sectors;
    int             sides;
    int             num_of_fats;
    int             apricot = 0;
    fat_boot_sec    bootsect;
    bpb_dos_40      bpb;

    img_open( filename, &ifn, &imgfile );
    if( !imgfile )
        return( 1 );

    /* Read what might be the BPB, and find the sector size. */
    imginfo.sec_sz = read_sector_part( 0, 0, sizeof( fat_boot_sec ), &bootsect );
    memcpy( &bpb, &bootsect.bytes_per_sect, sizeof( bpb ) );

    /* Default to 32-byte directory entries. */
    imginfo.de_sz = 32;

    /* Old ACT Apricot machines used a different boot sector with a BPB at
     * offset 0x50. Apricot used the media bytes same as IBM but with very
     * different meaning. Since Apricot started with DOS 2.x, the BPB is
     * always there.
     */
    if( bpb.bytes_per_sect != imginfo.sec_sz ) {
        apricot = 1;
        read_sector_part( 0, 0x50, sizeof( bpb ), &bpb );
    }

    /* BPB detection heuristic. */
    if( (bpb.bytes_per_sect == imginfo.sec_sz) && bpb.sec_per_clust
      && bpb.num_of_fats && (bpb.num_of_fats < 5)  ) {
        if( bpb.total_sect )
            total_sec = bpb.total_sect;
        else
            total_sec = bpb.ext_total_sect;
        root_entries  = bpb.root_entries;
        sec_per_fat   = bpb.sect_per_fat;
        sides         = bpb.num_heads;
        sectors       = bpb.sect_per_trk;
        num_of_fats   = bpb.num_of_fats;

        imginfo.sec_sz   = bpb.bytes_per_sect;
        imginfo.clustsec = bpb.sec_per_clust;
        imginfo.fat_sect = bpb.reserved_sect;
        imginfo.rootsect = imginfo.fat_sect + sec_per_fat * num_of_fats;

        /* Heuristic for broken BPBs created by DOS versions prior to 3.2.
         * Sector per cluster are erroneously listed as 2 in the BPB for
         * one-sided disks, but the actual (and standard) value is 1.
         */
        if( (bpb.num_heads == 1) && (bpb.total_sect < 400) )
            imginfo.clustsec = 1;

        if( flags & PROC_VERBOSE ) {
            printf( "INFO: Detected BPB with %d-byte sectors%s.\n", bpb.bytes_per_sect,
                    apricot ? " (Apricot style)" : "" );
            if( (bpb.num_heads == 1) && (bpb.total_sect < 400) && (bpb.sec_per_clust == 2) )
                printf( "INFO: Ignoring 2 sectors per cluster in BPB, using 1 instead.\n" );
        }
    } else {                /* Possibly a DOS 1.x disk with no BPB. */
        uint8_t     fat_hdr[3];

        /* The FAT normally starts at sector 1. */
        imginfo.fat_sect = 1;
        read_sector_part( imginfo.fat_sect, 0, sizeof( fat_hdr ), &fat_hdr );

        /* NorthStar 5.25" 86-DOS disks reserved 3 tracks. */
        if( (fat_hdr[1] != 0xFF || fat_hdr[2] != 0xFF) && (imginfo.sec_sz == 256) ) {
            imginfo.fat_sect = 30;
            read_sector_part( imginfo.fat_sect, 0, sizeof( fat_hdr ), &fat_hdr );
        }

        /* Some old 8" 86-DOS/MS-DOS disks reserved 2 tracks. */
        if( (fat_hdr[1] != 0xFF || fat_hdr[2] != 0xFF) && (imginfo.sec_sz != 512) ) {
            imginfo.fat_sect = 52;
            read_sector_part( imginfo.fat_sect, 0, sizeof( fat_hdr ), &fat_hdr );
        }

        /* DEC Rainbow 100 likewise reserved 2 tracks. DEC used 5.25" floppies
         * with 512-byte sectors, 80 tracks, and 10 sectors per track, single-sided!
         * DEC floppies were sadly interleaved ("interlaced") in a non-transparent
         * manner, with physical sectors 1-10 translated in software to logical
         * sectors 1,3,5,7,9,2,4,6,8,10.
         */
        if( (fat_hdr[1] != 0xFF || fat_hdr[2] != 0xFF) && (imginfo.sec_sz == 512) ) {
            imginfo.fat_sect = 20;
            read_sector_part( imginfo.fat_sect, 0, sizeof( fat_hdr ), &fat_hdr );
        }

        /* The media byte must be either in 0xF8-0xFF range or 0xF0. */
        if( fat_hdr[1] != 0xFF || fat_hdr[2] != 0xFF )
            return( 1 );    /* Not a FAT, can't be a DOS formatted disk. */
        if( (fat_hdr[0] & 0xF8) != 0xF8 && fat_hdr[0] != 0xF0 )
            return( 1 );    /* Not a valid media byte. */

        if( flags & PROC_VERBOSE )
            printf( "INFO: Disk with %d-byte sectors and no BPB, media byte %02Xh.\n", imginfo.sec_sz, fat_hdr[0] );

        if( imginfo.sec_sz == 512 ) {
            /* Decode the 5.25"/3.5" media descriptor byte. */
            sides        = 1 << (fat_hdr[0] & 1);
            sectors      = fat_hdr[0] & 2 ? 8 : 9;
            total_sec    = sides * sectors * 40;
            root_entries = sides == 2 ? 112 : 64;
            sec_per_fat  = sectors == 9 ? 2 : 1;

            imginfo.clustsec = sides;

            /* DEC Rainbow overrides. */
            if( imginfo.fat_sect == 20 ) {
                /* Media descriptor byte is likely 0xFA, which does not produce
                 * the right result when interpreted IBM style.
                 */
                sectors      = 10;
                root_entries = 96;
                total_sec    = sectors * 80;
                sec_per_fat  = 3;

                imginfo.rainbow  = true;
            } else if( fat_hdr[0] == 0xF8 && (bootsect.jump[0] == 0 || bootsect.jump[0] == 0xFF) ) {
                /* Sirius Victor 9000 overrides. The Victor used a variable speed
                 * drive with single- or double-sided disks. The single/double sided
                 * formats are different despite identical media descriptor.
                 */
                sectors             = 14;   /* A lie really. */
                root_entries        = 128;
                imginfo.clustsec    = 4;    /* Pretty fat clusters! */

                /* Layout depends on double-sided flag bit. */
                if( ((uint8_t *)&bootsect)[32] & 1 ) {
                    sides           = 2;
                    sec_per_fat     = 2;
                    total_sec       = 2391;
                } else {
                    sides           = 1;
                    sec_per_fat     = 1;
                    total_sec       = 1224;
                }
            }
        } else if( imginfo.sec_sz == 256 ) {
            /* Could be an SCP 86-DOS/MS-DOS disk in NorthStar SSSD format. */
            if( fat_hdr[0] == 0xFE ) {
                /* 5.25" SS/SD format. */
                sides        = 1;
                sectors      = 10;
                total_sec    = sides * sectors * 35;
                root_entries = 64;
                sec_per_fat  = 2;

                imginfo.clustsec = 1;   /* Clusters are 256 bytes. */
            }
        } else {
            /* Assume an 8" disk. The media byte works quite differently. */
            if( fat_hdr[0] == 0xFE ) {
                if( imginfo.sec_sz == 1024 ) {
                    /* 8" DS/DD format. */
                    sides        = 2;
                    sectors      = 8;
                    total_sec    = sides * sectors * 77;
                    root_entries = 192;
                    sec_per_fat  = 2;

                    imginfo.clustsec = 1;   /* Clusters are 1024 bytes. */
                } else if( imginfo.fat_sect == 52 ) {
                    /* Some old SCP disks reserved two tracks (rather than
                     * just one sector). They also had a smaller root dir.
                     */
                    sides        = 1;
                    sectors      = 26;
                    total_sec    = sides * sectors * 77;
                    root_entries = 64;
                    sec_per_fat  = 6;

                    imginfo.clustsec = 4;   /* Clusters are 512 bytes. */
                } else {
                    /* IBM 3740 SS/SD format. */
                    sides        = 1;
                    sectors      = 26;
                    total_sec    = sides * sectors * 77;
                    root_entries = 68;
                    sec_per_fat  = 6;

                    imginfo.clustsec = 4;   /* Clusters are 512 bytes. */
                }
            } else if( fat_hdr[0] == 0xFD ) {
                /* IBM 3740 DS/SD format. */
                sides        = 2;
                sectors      = 26;
                total_sec    = sides * sectors * 77;
                root_entries = 68;
                sec_per_fat  = 2;

                imginfo.clustsec = 0;   /* Not known/supported yet! */
            } else if( fat_hdr[0] == 0xF8 ) {
                /* NB: Currently it appears that F8h is the same as FEh. */
                if( imginfo.sec_sz == 1024 ) {
                    /* 8" DS/DD format. */
                    sides        = 2;
                    sectors      = 8;
                    total_sec    = sides * sectors * 77;
                    root_entries = 192;
                    sec_per_fat  = 2;

                    imginfo.clustsec = 1;   /* Clusters are 1024 bytes. */
                } else {
                    /* Yet another SCP disk variant. */
                    sides        = 1;
                    sectors      = 26;
                    total_sec    = sides * sectors * 77;
                    root_entries = 68;
                    sec_per_fat  = 6;

                    imginfo.clustsec = 4;   /* Clusters are 512 bytes. */
                }
            } else if( fat_hdr[0] == 0xFF ) {
                /* NB: Currently it appears that FFh is the same as FEh. */
                /* NEC-APC 8" SS/SD. */
                /* TODO: This may only occur in disks that have a good BBP. */
                sides        = 1;
                sectors      = 26;
                total_sec    = sides * sectors * 77;
                root_entries = 68;
                sec_per_fat  = 6;

                imginfo.clustsec = 4;   /* Clusters are 512 bytes. */
            } else
                return( 1 );    /* Not a supported 8" media byte. */

            /* The directory entries might be in the old 16-byte format.
             * The heuristic is very simple, check if the second 16 bytes
             * of the directory start with 11 uppercase ASCII characters.
             * 86-DOS 1.0/1.1 used the first FAT byte to decide whether
             * 16-byte entries were used; FFh meant 16-byte entries, anything
             * else 32-byte entries. In practice old 86-DOS disks used either
             * FFh (very old with 16-byte entries) or FEh (32-byte entries)
             * as the first FAT byte.
             */
            if( fat_hdr[0] == 0xFF ) {
                int     i;
                int     ofs = 16;
                char    c;
                char    dir[128];

                read_sector_part( imginfo.fat_sect + sec_per_fat * 2, 0, sizeof( dir ), &dir );
                for( i = 0; i < 11; ++i ) {
                    c = dir[ofs + i];
                    if( (c < ' ') || (c > '_') )
                        break;
                }
                if( i == 11 ) {
                    imginfo.de_sz = 16;
                    root_entries = 64;

                    if( flags & PROC_VERBOSE )
                        printf( "INFO: 16-byte directory entry detected.\n" );
                }
            }
        }

        /* NB: If the media byte is 0xF9 or 0xF0, the boot sector is highly
         * suspect and could contain a boot virus, for example. DOS versions
         * which supported those formats always created a valid BPB.
         */
        if( fat_hdr[0] == 0xF9 ) {
            uint32_t    dummy;

            if( flags & PROC_VERBOSE )
                printf( "INFO: Media byte %02Xh but no BPB!?\n", fat_hdr[0] );

            /* Serious trouble ahead. This could be a 1.2M disk or a 720K
             * disk. DOS guesses which it is based on the drive type the disk
             * is in, but that information is not available.
             * Try reading sector 2,000 and if that succeeds, guess that this
             * is a 1.2M disk.
             */
            if( read_sector_part( 2000, 0, sizeof( dummy ), &dummy ) ) {
                /* Adjust the guessed disk format. */
                sectors      = 15;
                total_sec    = sides * sectors * 80;
                root_entries = 224;
                sec_per_fat  = 7;

                imginfo.clustsec = 1;
            }
        } else if( fat_hdr[0] == 0xF0 ) {
            /* Probably a 1.44M disk. Adjust the disk format. */
            sectors      = 18;
            total_sec    = sides * sectors * 80;
            root_entries = 224;
            sec_per_fat  = 9;

            imginfo.clustsec = 1;
        }

        num_of_fats      = 2;
        imginfo.rootsect = imginfo.fat_sect + sec_per_fat * num_of_fats;

        /* NB: The number of sides and sectors per track is not part of the
         * BPB proper. If we do have a valid BPB, the information is not
         * necessarily available/valid. But here we do not have a BPB and
         * need to have valid data in order to synthesize the BPB.
         */
        if( flags & PROC_VERBOSE )
            printf( "INFO: Number of sides : %3.d,  sectors per track  : %d\n", sides, sectors );
    }
    imginfo.clustlen = imginfo.sec_sz * imginfo.clustsec;
    imginfo.datasect = imginfo.rootsect + (root_entries * imginfo.de_sz + imginfo.sec_sz - 1) / imginfo.sec_sz;
    imginfo.clustnum = (total_sec - imginfo.datasect) / imginfo.clustsec;
    imginfo.fat_entries = imginfo.sec_sz * sec_per_fat * 2 / 3;    /* For FAT12. */

    /* Quick heuristic, probably not always right. */
    fat_bits = imginfo.clustnum > 4090 ? 16 : 12;

    if( flags & PROC_VERBOSE ) {
        printf( "INFO: Reserved sectors: %3.d,  sectors per FAT    : %d\n", imginfo.fat_sect, sec_per_fat );
        printf( "INFO: Number of FATs  : %3.d,  sectors per cluster: %d\n", num_of_fats, imginfo.clustsec );
        printf( "INFO: Root dir entries: %3.d,  total sectors      : %d\n", root_entries, total_sec );
    }

    buf = malloc( imginfo.sec_sz );
    FAT = malloc( imginfo.fat_entries * sizeof( FAT[0] ) );

    if( fat_bits == 12 )
        read_fat12();
    else if( fat_bits == 16 )
        read_fat16();
    else
        assert( 0 );

    return( 0 );
}

void fdimg_close( void )
{
    free( buf );
    free( FAT );
    img_close( imgfile );
}

/* NB: The first data cluster is number 2; the first two FAT entries are used
 * by the media descriptor byte and padding.
 */
int clust_2_sect( int cluster )
{
    if( cluster == 0 )
        return( imginfo.rootsect );
    return( (cluster - 2) * imginfo.clustsec + imginfo.datasect );
}

int sect_2_clust( int sector )
{
    return( (sector - imginfo.datasect) / imginfo.clustsec + 2 );
}

int next_alloc_sect( int sector )
{
    int     cluster;

    if( sector < imginfo.datasect ) { // root dir
        if( sector < imginfo.datasect - 1 )
            return( sector + 1 );
        else
            return( -1 );
    }

    cluster = sect_2_clust( sector );
    if( cluster > (imginfo.clustnum + 2) ) {
        /* Actually an error - corrupted data. */
        return( -1 );
    }
    if( cluster == sect_2_clust( sector + 1 ) )
        return( sector + 1 );
    if( FAT[cluster] == 0xFFFFFFFF )
        return( -1 );
    return( clust_2_sect( FAT[cluster] ) );
}

void dir_srch_init( TDirPointer *dp, int sect )
{
    dp->sect    = sect;
    dp->pos     = 0;
}

void name_from_dentry( fat_dir_entry *entry, char *name )
{
    int     i, j;

    for( i = 0; i < 8 + 3 + 1 + 1; ++i )
        name[i] = '\0';
    /* Copy base name. */
    for( i = 0; i < 8; ++i )
        name[i] = entry->name[i];
    /* Strip trailing spaces, if any. */
    for( i = 7; i && name[i] == ' '; --i )
        name[i] = '\0';
    /* Normalize deleted entry marker. */
    if( name[0] == 0x05 )
        name[0] = 0xE5;
    /* Copy extension, if non-empty. */
    if( entry->ext[0] != ' ' || entry->ext[1] != ' ' || entry->ext[2] != ' ' ) {
        if( !(entry->attr & FAT_ATTR_VOL) ) /* No dots in volume labels. */
            name[strlen( name )] = '.';
        j = strlen( name );
        for( i = 0; i < 3; ++i )
            name[j + i] = entry->ext[i];
    }
    /* Strip trailing spaces from extension. */
    for( i = strlen( name ) - 1; i && name[i] == ' '; --i )
        name[i] = '\0';
}

int dir_srch_next( TDirPointer *dp, TFileInfo *info )
{
    int             i, j;
    fat_dir_entry   entry;
    fat_old_entry   old_entry;
    char            name[13];
    char            longname[256] = "";
    unsigned char   lfn_cksum;
    int             lfnpart = 0;
    struct tm       timestruct;

    while( dp->sect >= 0 ) {
        if( dp->pos >= imginfo.sec_sz ) {
            dp->sect = next_alloc_sect( dp->sect );
            if( dp->sect < 0 )
                break;
            dp->pos = 0;
        }
        read_sector( dp->sect, buf );
        i = dp->pos;

        if( imginfo.de_sz == 16 ) {
            uint32_t    size;

            memcpy( &old_entry, &buf[i], sizeof( old_entry ) );

            size  = old_entry.size[0];
            size |= (uint32_t)old_entry.size[1] << 8;
            size |= (uint32_t)old_entry.size[2] << 16;

            memset( &entry, 0, sizeof( entry ) );
            memcpy( entry.name, old_entry.name, sizeof( entry.name ) );
            memcpy( entry.ext,  old_entry.ext,  sizeof( entry.ext  ) );
            entry.cluster = old_entry.cluster;
            entry.size    = size;

            dp->pos += 16;
        } else {
            memcpy( &entry, &buf[i], sizeof( entry ) );
            dp->pos += 32;
        }

        if( entry.name[0] == (char)0xE5 )
            continue; // deleted file
        if( entry.name[0] == 0x00 )
            break; // last entry
        if( (entry.attr & FAT_ATTR_LFN) == FAT_ATTR_LFN ) { // part of LFN
            int partn = (buf[i] & 63);
            int partoffset = (partn - 1) * 13;

            if( buf[i] & 64 ) {
                longname[partoffset + 13] = 0;
                lfn_cksum = buf[i + 13];
                lfnpart   = partn;
            } else {
                lfnpart--;
                if( (lfnpart != partn) || (buf[i + 13] != lfn_cksum) ) {
                    lfnpart = -1; // somehing went wrong, discard LFN
                }
            }
            for( j = 0; j < 5; j++ )
                longname[partoffset + j]      = buf[i + 1 + j * 2];
            for( j = 0; j < 6; j++ )
                longname[partoffset + 5 + j]  = buf[i + 14 + j * 2];
            for( j = 0; j < 2; j++ )
                longname[partoffset + 11 + j] = buf[i + 28 + j * 2];
            continue;
        }

        name_from_dentry( &entry, name );

        timestruct.tm_sec   = (entry.time & 31) * 2;
        timestruct.tm_min   = (entry.time >> 5) & 63;
        timestruct.tm_hour  = (entry.time >> 11);
        timestruct.tm_mday  = (entry.date & 31);
        timestruct.tm_mon   = ((entry.date >> 5) & 15) - 1;
        timestruct.tm_year  = (entry.date >> 9) + 1980 - 1900;
        timestruct.tm_isdst = -1;

        /* Fix up missing (zero) date to get 1/1/1980. */
        if ( timestruct.tm_mon < 0 )
            timestruct.tm_mon = 0;
        if ( timestruct.tm_mday == 0 )
            timestruct.tm_mday = 1;

        /* Flag missing date stamps. A valid date cannot be zero. A valid
         * time can, which means we can't distinguish a 00:00:00 timestamp
         * from a completely missing timestamp (such as on DOS 1.0 disks).
         */
        info->no_date = !entry.date;

        if( longname[0] ) {
            unsigned char c = 0;

            for( j = 0; j < 11; j++ ) {
               if( c & 1 )
                   c = (c >> 1) | 0x80;
               else
                   c = c >> 1;
               if( j < 8 )
                   c += entry.name[j];
               else
                   c += entry.ext[j-8];
            }
            if( (lfn_cksum != c) || (lfnpart != 1) ) { // lfn is invalid - discard it
                longname[0] = 0;
            }
        }
        if( !longname[0] )
            strcpy( longname, name );

        strcpy( info->name, longname );
        strcpy( info->shortname, name );
        info->attr = entry.attr;
        info->cluster = entry.cluster;
        info->sect = clust_2_sect( entry.cluster );
        info->size = entry.size;
        info->timestamp = mktime( &timestruct );

        return( 0 );
    }
    return( 1 );
}

void print_file_info( TFileInfo *info )
{
    char        attr[5];
    struct tm   *timestruct;

    if( info->attr & FAT_ATTR_DIR ) {
        strcpy( attr, "DIR" );
    } else if( info->attr & FAT_ATTR_VOL ) {
        strcpy( attr, "VOL" );
    } else {
        strcpy( attr, "----" );
        if( info->attr & FAT_ATTR_RDO )
            attr[0] = 'r';
        if( info->attr & FAT_ATTR_HID )
            attr[1] = 'h';
        if( info->attr & FAT_ATTR_SYS )
            attr[2] = 's';
        if( info->attr & FAT_ATTR_ARC )
            attr[3] = 'a';
    }
    timestruct = localtime( &info->timestamp );

    printf( "%9ld %4s ", info->size, attr );
    if( info->no_date )
        printf( "--/--/---- " );
    else
        printf( "%02d/%02d/%04d ",
            timestruct->tm_mon + 1, timestruct->tm_mday,
            timestruct->tm_year + 1900 );
    printf( "%02d:%02d:%02d %s\n", timestruct->tm_hour,
            timestruct->tm_min, timestruct->tm_sec, info->name );
}

int extract_file( TFileInfo *info, char *destname )
{
    FILE            *f;
    unsigned long   size;
    unsigned long   sect;
    unsigned long   batch;
    unsigned long   written;
    struct utimbuf  timebuf;

    f = fopen( destname, "wb" );
    if( !f )
        return( 1 );

    size = info->size;
    sect = info->sect;
    while( size > 0 ) {
        batch = imginfo.sec_sz;
        if( batch > size )
            batch = size;

        read_sector( sect, buf );
        written = fwrite( buf, 1, batch, f );
        if( written < batch ) {
            fclose( f );
            return( 2 );
        }
        size -= batch;
        sect = next_alloc_sect( sect );
    }

    fclose( f );

    timebuf.actime = timebuf.modtime = info->timestamp;
    utime( destname, &timebuf );

    return( 0 );
}

int process_files( char *path, int action, int flags )
{
    int             i, newdir, pathpos, num, dirsect, firstfile;
    TDirPointer     dp;
    TFileInfo       info;
    char            search[256], curpath[256] = "", destname[256];
    char            last_dir[256];

    dirsect = imginfo.rootsect;
    dir_srch_init( &dp, dirsect );
    newdir = 1;
    firstfile = 1;
    pathpos = 0;
    num = 0;
    last_dir[0] = '\0';
    while( dir_srch_next( &dp, &info ) == 0 ) {
        if( newdir ) {
            newdir = 0;
            if( path[pathpos] == '\\' )
                pathpos++;
            strcpy( search, path + pathpos );
            if( strchr( path + pathpos, '\\' ) ) {
                i = strchr( path + pathpos, '\\' ) - (path + pathpos);
                search[i] = 0;
                pathpos += i;
            }
            if( !strlen( search ) )
                strcpy( search, "*" );
        }
        if( !fnmatch( search, info.name, FNM_IGNORECASE ) || !fnmatch( search, info.shortname, FNM_IGNORECASE ) ) {
            if( strchr( path + pathpos, '\\' ) ) {
                /* We descending into a given directory. */
                if( info.attr & FAT_ATTR_DIR ) {
                    dirsect = info.sect;
                    dir_srch_init( &dp, dirsect );
                    strcat( curpath, info.name );
                    strcat( curpath, "\\" );
                    newdir = 1;
                }
                /* Else not a directory; skip this entry. */
            } else {
                if( firstfile ) {
                    firstfile = 0;
                    printf( "Processing '\\%s%s':\n", curpath, search );
                }
                if( action == ACT_LIST ) {
                    print_file_info( &info );
                }
                if( info.attr & FAT_ATTR_VOL )
                    continue;   /* Don't extract volume labels. */
                if( action == ACT_EXTRACT ) {
                    if( flags & PROC_NODIRS ) {
                        strcpy( destname, info.name );
                    } else {
                        sprintf( destname, "%s%s", curpath, info.name );
                    }
                    if( info.attr & FAT_ATTR_DIR ) {
                        /* Skip the '..' directory entry. */
                        if( !strcmp( info.name, ".." ) )
                            continue;
                        /* Don't create the last directory again, or an empty dir. */
                        if( !strcmp( curpath, last_dir ) || !curpath[0] )
                            continue;
                        printf( "Creating '%s' ...\n", curpath );
                        mkdir( curpath, 0777 );
                        strcpy( last_dir, curpath );
                    } else {
                        printf( "Extracting '%s' ...\n", destname );
                        i = extract_file( &info, destname );
                        if( i == 1 )
                            printf( "Unable to create file!\n" );
                        if( i == 2 )
                            printf( "Unable to write file!\n" );
                    }
                }
                num++;
            }
        }
    }
    if( flags & PROC_RECURSIVE ) {
        dir_srch_init( &dp, dirsect );
        while( dir_srch_next( &dp, &info ) == 0 ) {
            if( (info.attr & FAT_ATTR_DIR) && strcmp( info.name, "." ) && strcmp( info.name, ".." ) ) {
                sprintf( destname, "%s%s\\%s", curpath, info.name, search );
                num += process_files( destname, action, flags );
            }
        }
    }
    return( num );
}

int main( int argc, char **argv )
{
    int     arg;
    int     arg_src = 0;
    int     nfiles;
    int     action = ACT_LIST;
    int     flags = 0;
    char    path[256] = "*";

    for( arg = 1; arg < argc; arg++ ) {
        if( argv[arg][0] == '-' ) {
            if( toupper( argv[arg][1]) == 'B' ) {
                ++arg;
                imginfo.bias = atoi( argv[arg] );
            }
            if( toupper( argv[arg][1]) == 'D' )
                flags |= PROC_NODIRS;
            if( toupper( argv[arg][1]) == 'E' )
                action = ACT_EXTRACT;
            if( toupper( argv[arg][1]) == 'R' )
                flags |= PROC_RECURSIVE;
            if( toupper( argv[arg][1]) == 'V' )
                flags |= PROC_VERBOSE;
        } else {
            if( !arg_src )
                arg_src = arg;
            else
                strcpy( path, argv[arg] );
        }
    }

    if( !arg_src ) {
        printf( "Usage: fdimg [options] <image> [pattern]\n" );
        printf( "Options:\n" );
        printf( " -b <n> : bias (hidden sectors)\n" );
        printf( " -e     : extract files\n" );
        printf( " -r     : recurse subdirectories\n" );
        printf( " -d     : strip (flatten) directories\n" );
        printf( " -v     : verbose operation\n" );
        return( 1 );
    }

    if( fdimg_open( argv[arg_src], flags ) ) {
        printf( "Unable to open file %s; no FAT found!\n", argv[arg_src] );
        return( 1 );
    }

    nfiles = process_files( path, action, flags );
    printf( "Found %d matching files.\n", nfiles );

    fdimg_close();

    return( 0 );
}
