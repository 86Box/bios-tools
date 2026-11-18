#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <direct.h>
#include "fat.h"

#define SECT_SIZE   512L
#define LFN_CHARS "+,;=[]" // Valid in long names, but not in short ones

/* Image creation options. */
typedef struct {
    int     num_fats;
    int     sec_per_clust;
    int     fat_type;
    int     num_heads;
    int     fat_sectors;
    int     sect_per_track;
    int     bytes_per_sect;
    int     num_tracks;
    int     rsvd_sectors;
    int     root_entries;
    int     root_sectors;
    int     total_sectors; // Should be long int?
    int     media_desc;
    int     cluster_size;
    int     verbose;
    int     data_sectors; // Should be long int?
    int     have_label;
    char    disk_label[12]; // Note: Disk labels can't use long names
    char    boot_template[PATH_MAX];
    int     sort;
    char    *date;
    char    *time;
    uint16_t dos_date;
    uint16_t dos_time;
} img_options;

/* Source file descriptor. */
typedef struct srcfd {
    struct srcfd    *next;
    struct srcfd    *first_child;
    long            fsize;
    struct tm       timestamp;
    char            attr; // Like dirent.d_attr
    char            localname[PATH_MAX]; // Local file system name
    char            pathname[PATH_MAX];
    char            fat_name[PATH_MAX]; // FAT (and possibly long) name
    int             how_short_is;
    char            short_name[8 + 1 + 3 +1]; // FAT short name
} srcfd;

/* Standard DOS floppy formats. */
struct {
    char    name[6];
    int     trks;
    int     sides;
    int     spt;
    int     spc;
    int     rdent;
    int     sfat;
    int     media_desc;
} std_fmts[] = {
    /* name  tracks    sides  sct/trk sct/clus nroot sct/fat media desc*/
    { "160",     40,     1,      8,       1,     64,   1,       0xfe },
    { "180",     40,     1,      9,       1,     64,   2,       0xfc },
    { "320",     40,     2,      8,       2,    112,   1,       0xff },
    { "360",     40,     2,      9,       2,    112,   2,       0xfd },
    { "720",     80,     2,      9,       2,    112,   3,       0xf9 },
    { "1.2",     80,     2,     15,       1,    224,   7,       0xf9 },
    { "1.44",    80,     2,     18,       1,    224,   9,       0xf0 },
    { "2.88",    80,     2,     36,       2,    240,   9,       0xf0 }
};
// Media descriptor for 1.44 disks was 0xf9 in DOS 3.2


/* Convert attributes to DOS format.
 * In DOS/Windows dirent.d_attr is already in FAT format,
 * but in Unix it would probably need to be converted.
 */
char attrib_to_dos( int attrib )
{
    return (char) attrib;
}

/* Convert time to DOS format. */
uint16_t time_to_dos( const struct tm *ts )
{
    uint16_t    dostime;

    assert( ts->tm_sec < 61 );
    assert( ts->tm_min < 61 );
    assert( ts->tm_hour < 25 );
    dostime  = ts->tm_sec / 2;
    dostime |= ts->tm_min << 5;
    dostime |= ts->tm_hour << 11;

    return( dostime );
}

/* Convert date to DOS format. */
uint16_t date_to_dos( const struct tm *ts )
{
    uint16_t    dosdate;
    int fat_year;

    assert( ts->tm_mday < 32 );
    assert( ts->tm_mon < 13 );
    dosdate  = ts->tm_mday;
    dosdate |= (ts->tm_mon + 1) << 5;
    fat_year = ts->tm_year + 1900 - 1980;
    if( fat_year < 0 || fat_year > 127 ) {
        fprintf( stderr, "File date year out of range (%d)\n", fat_year );
        exit( 1 ); //@todo: assign an exit code
    }
    dosdate |= fat_year << 9;

    return( dosdate );
}

/* Convert DOS date/time. */
void dos_to_time( struct tm *ts, uint16_t date, uint16_t time )
{
    ts->tm_sec   = (time & 31) * 2;
    ts->tm_min   = (time >> 5) & 63;
    ts->tm_hour  = (time >> 11);
    ts->tm_mday  = (date & 31);
    ts->tm_mon   = ((date >> 5) & 15) - 1;
    ts->tm_year  = (date >> 9) + 1980 - 1900;
    ts->tm_isdst = -1;
}

/* Convert time string to struct tm. */
uint16_t stringtime_to_dos( char * time )
{
    char *separators = ":";
    char *token;
    int i;
    int len = strlen( time ); // the string length will be modified
    struct tm ts;

    for( i = 0; i < len; i++)
        if( !isdigit( time[ i ] ) && (strpbrk( time + i, separators ) != time + i))
        {
            puts( "Illegal char in time" );
            exit( 1 );
        }

    //@todo: check that returned tokens consist of 2 numeric digits
    token = strtok( time, separators );
    if( token ) ts.tm_hour = atoi( token );
    token = strtok( NULL, separators );
    if( token ) ts.tm_min = atoi( token );
    token = strtok( NULL, separators );
    if( token )
    {
        ts.tm_sec = atoi( token );
        if( token + strlen( token ) - time < len ) // chars after second
        {
            puts( "Spare chars after second" );
            exit( 1 );
        }
        if( ts.tm_sec & 1 )
        {
            puts( "FAT can't store odd seconds" );
            exit( 1 );
        }
    }
    else // Missing hour, minute or second
    {
        puts( "Missing hour, minute or second" );
        exit( 1 );
    }

    return time_to_dos( &ts );
}

/* Convert date string to struct tm. */
uint16_t stringdate_to_dos( char * date )
{
    char *separators = "-/";
    char *token;
    int len = strlen( date ); // the string length will be modified
    struct tm ts;
    int i;

    for( i = 0; i < len; i++)
        if( !isdigit( date[ i ] ) && (strpbrk( date + i, separators ) != date + i))
        {
            puts( "Illegal char in date" );
            exit( 1 );
        }

    //@todo: check that returned tokens consist of 4, 2, 2 numeric digits
    token = strtok( date, separators );
    if( token ) ts.tm_year = atoi( token ) - 1900;
    token = strtok( NULL, separators );
    if( token ) ts.tm_mon = atoi( token ) - 1;
    token = strtok( NULL, separators );
    if( token )
    {
        ts.tm_mday = atoi( token );
        if( token + strlen( token ) - date < len ) // chars after day
        {
            puts( "Spare chars after day" );
            exit( 1 );
        }
    }
    else // Missing year, month or day
    {
        puts( "Missing year, month or day" );
        exit( 1 );
    }

    return date_to_dos( &ts );
}

/* Validate image parameters. Attempts to sanitize input so that
 * a more or less workable image can be created.
 */
int validate_parameters( img_options *opt )
{
    int     img_valid = 0;
    do {
        /* Allow a fairly wide range of sector per track values. */
        if( opt->sect_per_track < 4 || opt->sect_per_track > 255 ) {
            fprintf( stderr, "invalid number of sectors per track (%d)\n",
                     opt->sect_per_track );
            break;
        }
        /* Allow a decent range of the number of heads (sides). */
        if( opt->num_heads < 1 || opt->num_heads > 16 ) {
            fprintf( stderr, "invalid number of heads (%d)\n",
                     opt->num_heads );
            break;
        }
        /* Allow a sensible number of tracks. */
        if( opt->num_tracks < 20 || opt->num_tracks > 255 ) {
            fprintf( stderr, "invalid number of tracks (%d)\n",
                     opt->num_tracks );
            break;
        }
        /* Make sure the number of root dir entries is halfway sane. */
        if( opt->root_entries < 16 || opt->root_entries > 1024 ) {
            fprintf( stderr, "invalid number of root entries (%d)\n",
                     opt->root_entries );
            break;
        }
        /* Check the number of FAT copies. */
        if( opt->num_fats < 1 || opt->num_fats > 4 ) {
            fprintf( stderr, "invalid number FAT copies (%d)\n",
                     opt->num_fats );
            break;
        }
        /* Check the FAT type. */
        if( opt->fat_type != 12 && opt->fat_type != 16 ) {
            fprintf( stderr, "invalid FAT type (%d)\n",
                     opt->fat_type );
            break;
        }
        img_valid = 1;
    } while( 0 );

    return( img_valid );
}

/* Extra validations, after calculations with valid parameters. */
int extra_validations( img_options *opt )
{
    int     img_valid = 0;
    do {
        /* Check root dir entries. */
        if( opt->root_sectors * SECT_SIZE / sizeof( fat_dir_entry ) !=
            opt->root_entries ) {
            fprintf( stderr, "warning: root entries will be %d instead of %d\n",
                opt->root_sectors * SECT_SIZE / sizeof( fat_dir_entry ),
                opt->root_entries );
            opt->root_entries = opt->root_sectors * SECT_SIZE /
                sizeof( fat_dir_entry );
        }
        /* Check useless sectors at the end of the image. */
        if( opt->data_sectors % opt->sec_per_clust ) {
            fprintf( stderr,
                "warning: %d useless sector(s) (hint: increase root entries)\n",
                opt->data_sectors % opt->sec_per_clust );
        }
        img_valid = 1;
    } while( 0 );

    return( img_valid );
}

/* Set standard image parameters for common formats. Returns non-zero value
 * if specified format is not supported.
 */
int set_std_parameters( img_options *opt, const char *fmt )
{
    int     found = 0;
    int     i;

    for( i = 0; i < sizeof( std_fmts ) / sizeof( std_fmts[0] ); ++i ) {
        if( !strcmp( std_fmts[i].name, fmt ) ) {
            found = 1;
            break;
        }
    }
    if( found ) {
        opt->num_tracks       = std_fmts[i].trks;
        opt->num_heads        = std_fmts[i].sides;
        opt->sect_per_track   = std_fmts[i].spt;
        opt->sec_per_clust    = std_fmts[i].spc;
        opt->root_entries     = std_fmts[i].rdent;
        opt->fat_sectors      = std_fmts[i].sfat;
        opt->media_desc       = std_fmts[i].media_desc;
        /* The following are the same for all standard formats. */
        opt->bytes_per_sect   = 512;
        opt->num_fats         = 2;
        opt->fat_type         = 12;
    } else {
        fprintf( stderr, "format `%s' unsupported!\n", fmt );
    }
    return( !found );
}

/* Display image/format parameters. */
void print_parameters( const img_options *opt )
{
    fprintf( stderr, "Image:  %d tracks, %d sides, %d sectors/track, %d-byte sectors\n",
             opt->num_tracks, opt->num_heads,
             opt->sect_per_track, opt->bytes_per_sect );
    fprintf( stderr, "        (%d sectors, %dKB)\n", opt->total_sectors,
             opt->total_sectors * opt->bytes_per_sect / 1024 );

    fprintf( stderr, "Format: %d-bit FAT (%d copies), %d sectors per FAT\n",
             opt->fat_type, opt->num_fats, opt->fat_sectors );
    fprintf( stderr, "        %d sector(s) per cluster, %d root directory entries\n",
             opt->sec_per_clust, opt->root_entries );
}

/* Returns type of EBPB found in boot sector.
 * 0: No EBPB.
 * 40: 7-byte EBPB (I have never seen it)
 * 41: Full 26-byte EBPB as used since DOS 4.0x
 */
int ebpb_type( const fat_boot_sec * bootsec )
{
    int result = 0;
    int jump_dest = 0;

    if( bootsec->jump[0] == 0xeb ) // Boot sector starts with a short JMP
        jump_dest = 2 + bootsec->jump[1];
    else if( bootsec->jump[0] == 0xe9 ) // Boot sector starts with a near JMP
        jump_dest = 3 + *(int16_t *)&bootsec->jump[1];
    else if( bootsec->jump[0] == 0x90 && bootsec->jump[1] == 0xeb ) // NOP+JMP
        jump_dest = 3 + bootsec->jump[2];

    if( jump_dest >= &bootsec->vol_label[0] - &bootsec->jump[0] &&
            bootsec->ext_signature == 40) result = 40;
    else if( jump_dest >= &bootsec->rsvd3[8] - &bootsec->jump[0] &&
            bootsec->ext_signature == 41) result = 41;

    return result;
}

/* Returns type of BPB to use, based on OEM name found in boot sector.
 * 20: IBM or MS DOS 2.x
 * 30: IBM or MS DOS 3.0 - 3.1
 * 32: IBM or MS 3.2 - 3.3
 * 34: Compaq 3.31 or Zenith 3.30 plus (using "IBM  3.3" and "C ZDS3.3")
 * 40: IBM DOS 4.0 - 7.0 or MS DOS 4.0 - 8.0 (40 is like 34 + EBPB)
 */
int bpb_type( const fat_boot_sec * bootsec )
{
    char *ibm2_7  = "IBM  "; // Then 2.0 3.0 3.1 3.2 3.3 4.0 5.0 6.0 or 7.0
    // "IBM 20.0" doesn't match "IBM  " (2 blanks) but is XDF OEM string
    char *ms2_6   = "MSDOS"; // Then 2.0 3.2 3.3 4.0 or 5.0 (3.0 and 3.1?)
    char *ms7_8   = "MSWIN"; // Then 4.0 or 4.1
    int result = 0;
    char oem_name[ sizeof( bootsec->oem_name ) + 1 ];
    int is_printable;
    int i;

    memcpy( oem_name, bootsec->oem_name, sizeof( bootsec->oem_name ) );
    oem_name[ sizeof( bootsec->oem_name ) ] = '\0';
    for( i = 0; i < sizeof( bootsec->oem_name ) && isprint( oem_name[ i ] ); i++);
    is_printable = ( i == sizeof( bootsec->oem_name ) );

    if( is_printable )
        fprintf( stderr, "Boot sector OEM string is '%s'\n", oem_name );
    else
        fprintf( stderr, "Boot sector OEM string is not printable.\n" );

    if( !strncmp( oem_name, ibm2_7, strlen( ibm2_7 ) ) || // PC DOS 2.0 - 7.0
        !strncmp( oem_name, ms2_6, strlen( ms2_6 ) ) )    // MS DOS 2.0 - 6.22
    {
        int os_maj = oem_name[5] - '0';
        int os_min = oem_name[7] - '0';
        switch( os_maj )
        {
            case 2:
                result = 20;
                break;
            case 4: // Multitasking DOS 4 is "IBM  4.0" without EBPB,
            case 5: // but I don't know if BPB is type 30, 32 or 40
                result = 40;
                break;
            case 3: // Compaq 3.31 is 34 but uses "IBM  3.3", how to handle?
                result = (os_min < 2) ? 30 : 32;
                break;
            case 6:
            case 7:
                if( oem_name[0] == 'I' ) result = 40;
                break;
        }
    }
    else if( !strncmp( oem_name, ms7_8, strlen( ms7_8 ) ) ) // MS DOS 7 - 8
    {
        int os_maj = oem_name[5] - '0';
        int os_min = oem_name[7] - '0';
        if( os_maj == 4 && os_min >= 0 && os_min <= 1 ) result = 40;
    }

    if( result == 0 )
        fprintf( stderr, "Unsupported boot sector -- not updating BPB!\n" );
    else
        fprintf( stderr, "So it should use a 'version %d' BPB.\n", result );

    // If there should be an EBPB, check if it is really there
    // If it exists I will ignore if it is type 40 or 41... as I have never
    // seen a type 40 EBPB
    if( result >= 40 && !ebpb_type( bootsec ) )
    {
        fprintf( stderr,
            "But it has no EBPB, so I will act as for 'version 34' BPB.\n" );
        result = 34;
    }

    return result;
}

/* Build and write the boot sector. */
int build_bootsec( const img_options *opt, FILE *f )
{
    FILE            *bootf;
    int             rc = 1;
    uint8_t         bootsec[SECT_SIZE];
    fat_boot_sec    *fbs = (fat_boot_sec *)bootsec;
    int             type;

    memset( bootsec, 0, sizeof( bootsec ) );

    if( opt->boot_template[0] ) // Boot sector template specified
    {
        bootf = fopen( opt->boot_template, "rb" );
        if (! bootf )
        {
            fprintf( stderr, "cannot open `%s'\n", opt->boot_template );
            exit(1);
        }
        fread( bootsec, 1, sizeof( bootsec ), bootf );
        fclose( bootf );
        type = bpb_type( fbs );
    }
    else // No boot sector template
    {
        /* The jump instruction is vital for DOS to recognize the image. */
        memcpy( fbs->jump, "\xEB\x3C\x90", sizeof( fbs->jump ) );
        memcpy( fbs->oem_name, "IBM  3.3", 8 );
        type = 32;
    }

    if( type ) {
        /* Update the BPB in the boot sector. */
        fbs->bytes_per_sect   = opt->bytes_per_sect;
        fbs->sec_per_clust    = opt->sec_per_clust;
        fbs->reserved_sect    = opt->rsvd_sectors;
        fbs->num_of_fats      = opt->num_fats;
        fbs->root_entries     = opt->root_entries;
        fbs->total_sect       = opt->total_sectors;
        fbs->media_desc       = opt->media_desc;
        fbs->sect_per_fat     = opt->fat_sectors;
        if( type >= 30 )
        {
            fbs->sect_per_trk     = opt->sect_per_track;
            fbs->num_heads        = opt->num_heads;
            // Only for DOS 3.x, 1st u16 of "hidden sectors" is hidden sectors
            if( type < 40 )
                ((uint16_t *)&fbs->hidden_sect) [0] = 0; // 0 if no partitions
        }
    /* According to Wikipedia, for DOS >= 3.2 and < 3.31, 2nd u16 of "hidden
     * sectors" is total + hidden sectors... but I have never seen it.
     *   if( type >= 32 )
     *   {
     *       if( type < 40 )
     *           ((uint16_t *)&fbs->hidden_sect) [1] = opt->total_sectors +
     *               ((uint16_t *)&fbs->hidden_sect) [0];
     *   }
     */
        if( type >= 40 ) // DOS 3.31 BPB is type 40
        {
            fbs->hidden_sect = 0; // 0 if no partitions
            fbs->ext_total_sect = 0; // 0 if total sectors fit in the 16-bit field
            // Now write EBPB (by now I suppose that type >= 40 always has EBPB)
            memset( fbs->vol_label, ' ', sizeof( fbs->vol_label ) );
            memset( fbs->rsvd3, ' ', sizeof( fbs->rsvd3 ) );

            fbs->phys_drive_no = 0;
            fbs->ext_signature = 0x29;
            // fbs->vol_id =
            memcpy( fbs->vol_label, opt->disk_label, sizeof( fbs->vol_label ) );
            sprintf( fbs->rsvd3, "FAT%d", opt->fat_type );

        }
    }

    fwrite( &bootsec, 1, sizeof( bootsec ), f );

    return( rc );
}

/* Utility routine to convert a size in bytes to a number of clusters. */
unsigned fsize_to_clusters( const img_options *opt, long fsize )
{
    long        cl_size;
    unsigned    cl_count;

    cl_size  = opt->cluster_size;
    cl_count = (fsize + cl_size - 1) / cl_size;
    return( cl_count );
}

//////////////////////////////////////////////////////////////////////////
// LONG OR SHORT NAME RELATED FUNCTIONS
//////////////////////////////////////////////////////////////////////////

/* Calculates checksum for LFN entries.
 * The shortname must be in FCB format (blank-padded, no dot).
 */
unsigned char lfn_checksum( const unsigned char *shortname )
{
    int i;
    unsigned char sum=0;

    for( i=0; i < 11; i++ )
        sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + *shortname++;
    return sum;
}

/* Looks for given shortname in directory objects (non-recursively).
 * Returns pointer to first matching element or NULL if not found.
 */
srcfd *find( const char *name, const srcfd *src_dir )
{
    srcfd *src_item;
    for( src_item = src_dir->first_child; src_item &&
        strcmp( name, src_item->short_name ); src_item = src_item->next );
    return src_item;
}

/* Converts a local name to a valid FAT (long or short) name.
 * Charset conversion, if needed, could be done in this function.
 */
char *localname_to_fatname( char* fatname, const char* localname )
{
    int i, trailing_dots_or_spaces, len;
    len = strlen( localname );
    assert( len > 0 );

    /* Leading dots are allowed in long file names, but not trailing dots.
     * Not sure if I have to replace or discard them...
     * (Discarding them, names like .... would give an empty string)
     * (Discarding or replacing, new name could collide with an existing one)
     * By now I will replace them with underscores.
     */
    for( i = len - 1; localname[ i ] == '.' && i; fatname[ i-- ] = '_' );
    trailing_dots_or_spaces = len - i - 1;

    /* Trailing spaces DOESN'T SEEM to be valid either, I will replace them.
     * The same notes that for dots would apply here.
     * If trailing spaces were valid, I wouldn't replace them, and MS step 3
     * and search for extension in function fatname_to_shortname would need
     * additional lines.
     */
    if( !trailing_dots_or_spaces )
    {
        for( i = len - 1; localname[ i ] == ' ' && i; fatname[ i-- ] = '_' );
        trailing_dots_or_spaces = len - i - 1;
    }

    /* Copy the rest of src_name */    //@todo: replace illegal chars
    strncpy( fatname, localname, len - trailing_dots_or_spaces );

    fatname[ len ] = '\0';

    return fatname;
}

/* Given a valid FAT name, returns the short name unique for directory.
 * I will try to follow MS algorithm.
 * The caller shouldn't pass a name which is already a short name.
 * But it's not a big problem if the caller does it.
 */
char *fatname_to_shortname( char *shortname, const char *fatname,
    const srcfd *src_dir )
{
    int i, j, len, chars_to_ext, lossy;
    char lfn_chars[] = LFN_CHARS; // Valid in long names, but not in short ones
    char *pchar;
    char tmp[PATH_MAX];
    char name[9]; // 8 chars and terminating null
    char extension[5]; // dot, 3 chars and terminanting null

    len = strlen( fatname ); // len is FAT name length
    assert( len > 0 );
    lossy = 0;

    // MS algorithm step 3: Strip leading and embedded spaces
    for( i = 0; fatname[ i ] == ' ' && i < len; i++ );
    for( j = 0; i <= len; i++ )
        if( fatname[ i ] != ' ' ) tmp[ j++ ] = fatname[ i ];
    // basis_name is terminated because I said "while i <= len"
    len = --j; // Now len is tmp length

    // MS algorithm step 2: Replace LFN chars not allowed in short names
    // I better do it after step 3, when the FAT name has been copied to tmp
    //@todo: Unicode glyphs not mappable to OEM should be replaced as well
    while( pchar = strpbrk( tmp, lfn_chars ) )
    {
        *pchar++ = '_';
        lossy |= -1;
    }

    // MS algorithm step 4: Strip leading periods
    // Note: I just count them
    for( i = 0; tmp[ i ] == '.' && i < len; i++ );

    /* Search for extension and copy to local var (instead of step 6) */
    pchar = strrchr( tmp + i, '.' ); // Last embedded period
    if( !pchar )
    {
        extension[ 0 ] = '\0';
        chars_to_ext = len;
    }
    else
    {
        int len_ext = strlen( pchar );
        for( j = 0; j < 4 && j < len_ext; j++ ) // Step "1a" (for extension)
            extension[ j ] = toupper( pchar[ j ] ); // (look for "1b" below)
        extension[ j ] = '\0';
        chars_to_ext = pchar - tmp;
    }

    // MS algorithm step 5: Copy up to 8 chars up to extension or end.
    // Skipping periods.
    // MS algorithm step 1: Convert to upper case.
    // Note: In fact, step "1b" (for name).
    for( j = 0; j < 8 && i < chars_to_ext; i++ )
        if( tmp[ i ] != '.' ) name[ j++ ] = toupper( tmp[ i ] );
    name [ j ] = '\0';

    // MS algorithm step 6: Insert a period if there is extension
    // MS algorithm step 7: Copy up to 3 chars from the last period
    // Note: I did it after pass 4

    lossy |= strlen( fatname ) != strlen( name ) + strlen( extension );

    if( !lossy )
    {
        assert( !find( tmp, src_dir) );
        //@todo: not really an assertion, but an error to inform the user
        strcpy( shortname, name );
        if( pchar ) strcat( shortname, extension );
    }
    else // Calculate trail
    {
        int len_name, len_trail;
        char trail[8] = "~"; // tilde, 6 digits and terminating null

        strcpy( tmp, name );
        len_name = strlen( name );

        // The trailing number could reach 999999 but on diskettes we will
        // never go so far because there will never be so many filenames.
        // For bigger disks it should be changed.

        for( i = 1; i <= 32767; i++) // See above note for this limit
        {
            sprintf( trail+1, "%d", i );
            len_trail = strlen( trail );
            j = (len_name + len_trail > 8) ? (8 - len_trail) : len_name;
            strcpy( tmp + j, trail );
            strcpy( tmp + j + len_trail, extension );
            if( !find( tmp, src_dir ) )
                break;
        }
        strcpy( shortname, tmp );
    }
    return shortname;
}

/* Given a valid FAT name, returns "how short" it is:
   0: It is a valid short name.
   1: Almost a valid short name (just needs conversion to upper case).
   2: No valid short name (for any other reason than case conversion).
 */
int how_short_is( const char *fname )
{
    char *pfdot;
    char lfn_chars[] = LFN_CHARS; // Valid in long names, but not in short ones
    int dots, len, i, is_short;

    is_short = 2; // Initial supposition

    /* Find 1st dot */
    if( !( pfdot = strchr( fname, '.' ) ) ) dots = 0;
    else /* Find more dots */
    {
        if( !strchr( pfdot + 1, '.' ) ) dots = 1;
        else dots = 2; // More than one
    }

    // Short names can have at most one dot, but not as the 1st char
    //@todo: can short names have leading/embedded/trailing spaces?
    if( dots == 0 || dots == 1 && pfdot > fname )
    {
        len = strlen( fname );
        // And must fit in 8 (no dot) or 8.3 (one dot) chars
        if( dots == 0 && len <= 8 ||
            dots == 1 && (pfdot - fname <= 8) && (fname + len - pfdot <= 4 ) )
        {
            // And cannot contain any char in lfn_chars string
            if( !strpbrk( fname, lfn_chars ) )
            {
                for( i = 0; !islower( fname[ i ] ) && i < len; i++ );
                is_short = (i == len) ? 0 : 1; // Neither lower chars
            }
        }
    }

    return is_short;
}

/* Generate short names for all files and directories inside a given parent
 * directory (recursively).
 */
void generate_short_names( const srcfd *src_dir )
{
    int i;
    srcfd *child;

    assert( src_dir->attr & FAT_ATTR_DIR );

    /* First pass, assign short names to files with short names */
    for( child = src_dir->first_child; child; child = child->next )
    {
        if( child->how_short_is == 0 ) // Copy as is
            strcpy( child->short_name, child->fat_name );
        else if( child->how_short_is == 1 ) // Convert to upper case
            for( i = 0; i <= strlen( child->fat_name ); i++ )
                child->short_name[ i ] = toupper( child->fat_name[ i ] );
        if( child->how_short_is < 2 ) // Both cases treated above
            //@todo: not really an assertion, but an error to inform the user
            assert( find( child->short_name, src_dir ) == child );
    }

    /* Second pass, assign short names to files with long names */
    for( child = src_dir->first_child; child; child = child->next )
    {
        char shortname[8 + 1 + 3 + 1];

        if( child->how_short_is == 2 ) // Create short name
        {
            fatname_to_shortname( shortname, child->fat_name, src_dir );
            // Not copy to child->short_name until return from above call!
            strcpy( child->short_name, shortname );
        }
    }

    /* Recurse subdirs */
    for( child = src_dir->first_child; child; child = child->next )
        if( child->attr & FAT_ATTR_DIR ) generate_short_names( child );
}

//////////////////////////////////////////////////////////////////////////
// LONG OR SHORT NAME RELATED FUNCTIONS (END)
//////////////////////////////////////////////////////////////////////////

/* Returns the size (in clusters) of a given subdir object.
 * It is the entry size * number of (LFN + regular) entries.
 * Not to be used for root dir.
 */
unsigned dir_object_size( const img_options *opt, const srcfd *src_dir )
{
    const srcfd *child;
    int entries = 2;

    assert( src_dir->attr & FAT_ATTR_DIR ); // Must be a directory
    assert( src_dir->localname[0] ); // But not root directory
    for( child = src_dir->first_child; child; child = child->next )
    {
        assert( child->short_name[0] );
        entries++; // Always one entry for the short name
        if( child->how_short_is ) // Optionally, LFN entries
            entries += ( strlen( child->fat_name ) + 12 ) / 13;
    }
    return fsize_to_clusters( opt, sizeof( fat_dir_entry ) * entries );
}

/* Returns the size (in clusters) of the contents of a given directory.
 * That's the size of all objects contained in that directory (recursively).
 */
unsigned dir_contents_size( const img_options *opt, const srcfd *src_dir )
{
    const srcfd *child;
    unsigned clusters = 0;

    assert( src_dir->attr & FAT_ATTR_DIR );
    for( child = src_dir->first_child; child; child = child->next )
    {
        if( child->attr & FAT_ATTR_DIR )
            clusters += dir_contents_size( opt, child ) +
                dir_object_size( opt, child );
        else
            clusters += fsize_to_clusters( opt, child->fsize );
    }
    return clusters;
}

/* Write in the 32-bit FAT entries corresponding to a dir contents.
 * Starts writting at fat[fat_index]
 * Updates fat_index (adds number of entries written)
 */
int build_dir_fat( const img_options *opt, const srcfd *src_dir,
    uint32_t *fat, int fat_entries, int *fat_index )
{
    int rc = 0;
    const srcfd *child;

    for( child = src_dir->first_child; child; child = child->next )
    {
        unsigned clusters, i;

        if( child->attr & FAT_ATTR_DIR )
            clusters = dir_object_size( opt, child );
        else
            clusters = fsize_to_clusters( opt, child->fsize );

        if( clusters > 0 ) {    // Skip 0-byte files
            // Check if there is still enough room in the FAT
            if( *fat_index + clusters >= fat_entries ) {
                fprintf( stderr, "too much data for given FAT size\n" );
                rc = 1;
                break;
            }

            // Loop through every cluster but the last one
            for( i = 0; i < clusters - 1; i++ )
                fat[*fat_index + i] = *fat_index + i + 1; // Wouldn't dare to use ++ here
            fat[*fat_index + i] = ~0;
            (*fat_index) += clusters;
        }

        if( child->attr & FAT_ATTR_DIR ) {  // Recurse
            rc = build_dir_fat( opt, child, fat, fat_entries, fat_index );
            if( rc )
                break;
        }
    }
    return( rc );
}

/* Build and write the required number of FAT copies. */
int build_fats( const img_options *opt, const srcfd *src_dir, FILE *f )
{
    int         rc = 1;
    int         fat_entries;
    int         entry;
    int         i;
    uint32_t    *fat;
    uint8_t     *fat_packed;
    uint32_t    fat_tmp;

    /* Allocate a 32-bit FAT with the required number of entries.
     * NB: When using a 12-bit FAT it can happen that there isn't
     * room for an integral number of entries.
     */
    fat_entries = opt->fat_sectors * SECT_SIZE * 8 / opt->fat_type;

    fat = calloc( 1, sizeof( uint32_t ) * fat_entries );
    if( fat ) {
        if( opt->verbose ) {
            fprintf( stderr, "FAT entries allocated: %7d.\n",
                     fat_entries );
        }
        /* The first two FAT entries are special. */
        fat[0] = opt->media_desc | 0xFFFFFF00;
        fat[1] = ~0;

        entry = 2;

        rc = build_dir_fat( opt, src_dir, fat, fat_entries, &entry );
        if( rc )
            return( rc );

        /* Pack the FAT into the proper format in-place. */
        fat_packed = (uint8_t *)fat;
        for( entry = 0; entry < fat_entries; entry += 2 ) {
            if( opt->fat_type == 16 ) {
                fat_tmp = (fat[entry] & 0xFFFF) | (fat[entry + 1] << 16);
                memcpy( fat_packed, &fat_tmp, 4 );
                fat_packed += 4;
            } else if( opt->fat_type == 12 ) {
                fat_tmp = (fat[entry] & 0xFFF) | (fat[entry + 1] << 12);
                memcpy( fat_packed, &fat_tmp, 3 );
                fat_packed += 3;
            } else {
                assert( 0 );
            }
        }
        /* Write out the required number of FATs. */
        for( i = 0; i < opt->num_fats; ++i )
            fwrite( fat, 1, opt->fat_sectors * SECT_SIZE, f );

        free( fat );

        rc = 0;
    }
    return( rc );
}

/* Build and write a directory.
 * Needs to know the start cluster.
 * Needs to know the parent start cluster (to make the .. entry).
 */
int build_dir( const img_options *opt, const srcfd *src_dir,
    unsigned cluster, unsigned parent_cluster, FILE *f )
{
    int             rc = 0;
    int             i, j;
    unsigned        entries;
    unsigned        total_entries; // Used + empty ones
    fat_dir_entry   dir_entry;
    const srcfd     *child;

    entries = 0;
    memset( &dir_entry, 0, sizeof( dir_entry ) );

    if( !src_dir->localname[0] )
    {
        cluster = 2; // Root dir

        if( opt->have_label ) /* Create a volume label entry if requested. */
        {
            i = sizeof( dir_entry.name ) + sizeof( dir_entry.ext );
            memset( &dir_entry, ' ', i );
            memcpy( dir_entry.name, opt->disk_label,  strlen( opt->disk_label ) );

            dir_entry.attr    = FAT_ATTR_VOL;
            // Which date/time to use if no date/time for all files are specified?
            dir_entry.time    = opt->time ? opt->dos_time : 0;
            dir_entry.date    = opt->date ? opt->dos_date : 0;
            dir_entry.cluster = 0;
            dir_entry.size    = 0;
            fwrite( &dir_entry, 1, sizeof( dir_entry ), f );
            ++entries;
        }
    }
    else // Non-root
    {
        /* Create '.' and '..' entries, attr/date/time/size are the same for both */

        dir_entry.attr = FAT_ATTR_DIR;
        dir_entry.time = opt->time ? opt->dos_time :
            time_to_dos( &src_dir->timestamp );
        dir_entry.date = opt->date ? opt->dos_date :
            date_to_dos( &src_dir->timestamp );
        dir_entry.size = 0;

        memcpy( dir_entry.name, ".          ",
            sizeof( dir_entry.name ) + sizeof( dir_entry.ext ) );
        dir_entry.cluster = cluster;
        ++entries;
        fwrite( &dir_entry, 1, sizeof( dir_entry ), f );

        dir_entry.name[ 1 ] = '.';
        dir_entry.cluster = parent_cluster;
        ++entries;
        fwrite( &dir_entry, 1, sizeof( dir_entry ), f );

        cluster += dir_object_size( opt, src_dir ); // For 1st item in dir
    }

    /* Run through the list of source files and build the
     * corresponding directory entries.
     */
    for( child = src_dir->first_child; child; child = child->next )
    {
        char blankPaddedName[ sizeof( dir_entry.name ) +
            sizeof( dir_entry.ext ) ];
        memset( blankPaddedName, ' ', sizeof( blankPaddedName ) );

        for( i = 0; i < sizeof( dir_entry.name ); ++i ) {
            if( !child->short_name[i] )
                break;
            if( child->short_name[i] == '.' )
                break;
            blankPaddedName[i] = child->short_name[i];
        }
        if( child->short_name[i] == '.' ) {
            ++i;    /* Skip the dot. */
            for( j = 0; j < sizeof( dir_entry.ext ); ++j ) {
                if( !child->short_name[i + j] )
                    break;
                blankPaddedName[8 + j] = child->short_name[i + j];
            }
        }

        if( child->how_short_is != 0 ) // Not short name, needs LFN entries
        {
            unsigned char checksum;
            int len;
            int lfn_entries;
            char *lfn_entry;
            unsigned char positions[] =
                {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};

            checksum = lfn_checksum( blankPaddedName );
            len = strlen( child->fat_name );
            lfn_entry = &(dir_entry.name[0]);
            lfn_entries = (len + 12) / 13; // An LFN entry has up to 13 chars
            for( i = lfn_entries; i > 0; i-- )
            {
                memset( &dir_entry, 0xff, sizeof( dir_entry ) );
                dir_entry.name[0] = i | ((i == lfn_entries) ? 0x40 : 0);
                dir_entry.attr = FAT_ATTR_VOL | FAT_ATTR_SYS | FAT_ATTR_HID |
                    FAT_ATTR_RDO;
                dir_entry.rsvd[0] = 0;
                dir_entry.rsvd[1] = checksum;
                dir_entry.cluster = 0;
                // j <= len to copy terminating null if it fits
                for( j = (i-1) * 13; j < i * 13 && j <= len; j++ )
                    *(uint16_t *)&lfn_entry[positions[j%13]] = child->fat_name[j];
                if( ++entries > opt->root_entries ) {
                    fprintf( stderr, "Root directory entries exhausted.\n" );
                    exit( 1 ); //@todo: Use a good exit code, or return an rc
                }
                fwrite( &dir_entry, 1, sizeof( dir_entry ), f );
            }
        }

        /* Anyway, it will need a normal (short name) entry. */
        memset( &dir_entry, 0, sizeof( dir_entry ) );

        memcpy( &dir_entry, &(blankPaddedName[0]), sizeof( blankPaddedName ) );
        dir_entry.attr = child->attr;
        dir_entry.time = opt->time ? opt->dos_time :
            time_to_dos( &child->timestamp );
        dir_entry.date = opt->date ? opt->dos_date :
            date_to_dos( &child->timestamp );
        dir_entry.cluster = cluster;

        if( child->attr & FAT_ATTR_DIR )
        {
            dir_entry.size = 0;
            cluster += dir_object_size( opt, child ) +
                dir_contents_size( opt, child );
        }
        else
        {
            dir_entry.size = child->fsize;
            cluster += fsize_to_clusters( opt, child->fsize );
        }

        if( ++entries > opt->root_entries ) {
            fprintf( stderr, "Root directory entries exhausted.\n" );
            exit( 1 ); //@todo: Use a good exit code, or return an rc
        }

        fwrite( &dir_entry, 1, sizeof( dir_entry ), f );
    }

    /* Pad the directory to its full size. */
    memset( &dir_entry, 0, sizeof( dir_entry ) );

    if( !src_dir->localname[0] ) // Non-root dir
        total_entries = opt->root_entries;
    else
        total_entries = dir_object_size( opt, src_dir ) *
            opt->sec_per_clust * opt->bytes_per_sect /
            sizeof( fat_dir_entry );

    for( ; entries < total_entries; ++entries ) {
        fwrite( &dir_entry, 1, sizeof( dir_entry ), f );
    }

    return( rc );
}

/* Build and write the data area for a directory and its objects.
 * For root dir it just write its objects, not the dir itself.
 */
int build_data_area( const img_options *opt, const srcfd *src_dir,
    unsigned cluster, unsigned parent_cluster, FILE *f )
{
    int             rc = 1;
    const srcfd     *child;
    uint8_t         buf[SECT_SIZE];
    long            bytes_left;
    long            pad_bytes;
    FILE            *srcf;

    if( !src_dir->localname[0] ) // Root dir
    {
        parent_cluster = 0;
        cluster = 2;
    }
    else
    {
        build_dir( opt, src_dir, cluster, parent_cluster, f);
        parent_cluster = cluster;
        cluster += dir_object_size( opt, src_dir );
    }

    /* Run through the list of source files and dump out the file
     * contents (padding up to cluster size).
     */
    for( child = src_dir->first_child; child; child = child->next )
    {
        if( child->attr & FAT_ATTR_DIR )
        {
            build_data_area( opt, child, cluster, parent_cluster, f );
            cluster += dir_object_size( opt, child ) +
                dir_contents_size( opt, child );
        }
        else
        {
            /* Copy the source file. */
            //@todo: error checking!!
            srcf = fopen( child->pathname, "rb" );
            if( !srcf )
            {
                fprintf( stderr, "cannot open `%s'\n", child->pathname );
                rc = 2;
                break;
            }
            bytes_left = child->fsize;
            while( bytes_left > sizeof( buf ) )
            {
                fread( buf, 1, sizeof( buf ), srcf );
                fwrite( buf, 1, sizeof( buf ), f );
                bytes_left -= sizeof( buf );
            }
            assert( bytes_left <= sizeof( buf ) );
            fread( buf, 1, bytes_left, srcf );
            fwrite( buf, 1, bytes_left, f );

            fclose( srcf );

            /* Pad the written data to cluster size. */
            pad_bytes = child->fsize % opt->cluster_size;
            if( pad_bytes )
            {
                pad_bytes = opt->cluster_size - pad_bytes;
                memset( buf, 0, sizeof( buf ) );

                while( pad_bytes > sizeof( buf ) )
                {
                    fwrite( buf, 1, sizeof( buf ), f );
                    pad_bytes -= sizeof( buf );
                }
                assert( pad_bytes <= sizeof( buf ) );
                fwrite( buf, 1, pad_bytes, f );
            }
            cluster += fsize_to_clusters( opt, child->fsize );
        }
    }

    return( rc );
}

/* Builds a list of source files */
srcfd *build_source_list( const img_options *opt, const srcfd *parent,
    const char *src_dir )
{
    DIR             *dirp;
    struct dirent   *dentry;
    srcfd           *root = NULL;
    srcfd           *head = NULL;
    srcfd           *tail = NULL;
    srcfd           *curr = NULL;

    if( !parent ) // Non recursive call: Only for root dir
    {
        root = calloc( 1, sizeof( *root ) ); // Element to represent root dir
        root->attr = FAT_ATTR_DIR;
        strcpy( root->pathname, src_dir );
    }

    dirp = opendir( src_dir );
    if( dirp ) {
        if( opt->verbose )
            fprintf( stderr, "directory: %s\n", src_dir );
        for( ;; ) {
            dentry = readdir( dirp );
            if( !dentry )
                break;
            /* Skip '.' and '..' entries, if they exist. */
            if( !strcmp( dentry->d_name, "." ) )
                continue;
            if( !strcmp( dentry->d_name, ".." ) )
                continue;
            /* Skip volume labels, too. */
            if( dentry->d_attr & _A_VOLID )
                continue;
            /* Allocate descriptor and fill in the basics. */
            curr = calloc( 1, sizeof( *curr ) );
            strncpy( curr->localname, dentry->d_name,
                sizeof( curr->localname ) );
            dos_to_time( &curr->timestamp, dentry->d_date, dentry->d_time );
            curr->attr = attrib_to_dos( ((int) dentry->d_attr) & 0xff );

            //@todo: watch for buffer overflows
            strcpy( curr->pathname, src_dir );
            strcat( curr->pathname, "\\" ); // Use opposite slash for Unix/Windows
            strcat( curr->pathname, dentry->d_name );

            /* New srcfd fields (leave short_name still empty) */
            localname_to_fatname( curr->fat_name, curr->localname );
            curr->how_short_is = how_short_is( curr->localname );

            /* Link the descriptor into the list. */
            if( head ) {
                tail = tail->next = curr;
            } else {
                head = tail = curr;
            }

            /* Directories need special handling of course. */
            if( curr->attr & FAT_ATTR_DIR ) {
                curr->first_child = build_source_list( opt, curr,
                    curr->pathname );
                continue;
            }
            /* Print basic stats if requested. */
            if( opt->verbose ) {
                fprintf( stderr, " adding %9ld byte(s), %5u cluster(s) %s\n",
                         dentry->d_size,
                         fsize_to_clusters( opt, dentry->d_size ),
                         dentry->d_name );
            }
            curr->fsize = dentry->d_size;
        }
        closedir( dirp );
    }
    else fprintf( stderr, "failed to read directory `%s'\n", src_dir );

    if( root ) root->first_child = head;
    return root ? root : head;
}

void print_tree( srcfd *src_dir )
{
    srcfd *child;

    printf( "Dir: %s\n", src_dir->fat_name );
    for( child = src_dir->first_child; child; child = child->next )
        printf( "%2x %s\n", (unsigned int) child->attr, child->fat_name );

    for( child = src_dir->first_child; child; child = child->next )
        if( child->attr & FAT_ATTR_DIR ) print_tree( child );
}

/* Print usage summary. */
void usage( const char *pgm )
{
    fprintf( stderr, "usage: %s [<options>] [-o <dstimg>] <srcpath>\n", pgm );
    fprintf( stderr, "options:\n" );
    fprintf( stderr, "-a <n>      specify number of FATs\n" );
    fprintf( stderr, "-b <file>   specify boot sector template\n" );
    fprintf( stderr, "-c <n>      specify number of sectors per cluster\n" );
    fprintf( stderr, "-d <date>   specify date to apply to all files/directories\n" );
    fprintf( stderr, "-e <n>      specify FAT type (12 or 16)\n" );
    fprintf( stderr, "-f <fmt>    specify standard format (360/720/1.2/1.44)\n" );
    fprintf( stderr, "-h <n>      specify number of heads (sides)\n" );
    fprintf( stderr, "-i <n>      specify size of FAT in sectors\n" );
    fprintf( stderr, "-l <label>  specify disk label\n" );
    fprintf( stderr, "-m <time>   specify time to apply to all files/directories\n" );
    fprintf( stderr, "-n <n>      specify number of sectors per track\n" );
    fprintf( stderr, "-p          sort directory entries by name (directories first)\n" );
    fprintf( stderr, "-r <n>      specify number of root directory entries\n" );
    fprintf( stderr, "-s <n>      specify sector size in bytes\n" );
    fprintf( stderr, "-t <n>      specify number of tracks\n" );
    fprintf( stderr, "-v          verbose operation\n" );
}

//////////////////////////////////////////////////////////////////////////
// DIRECTORY SORTING FUNCTIONS
//////////////////////////////////////////////////////////////////////////

/* Note: Comparator functions may return 0, but not name or attrib-then-name
 * comparators in the context of this program (not 2 files in the same
 * directory with the same FAT name).
 */

/* Comparator function.
 * Compares FAT names of items (alphabetically, ignoring case).
 * Returns < 0, 0 or > 0 if item1 FAT name <, = or > item2 FAT name.
 */
int compare_names( const srcfd *item1, const srcfd *item2 )
{
    return strcmpi( item1->fat_name, item2->fat_name ); // WATCOM function
}

/* Comparator function.
 * Compares attributes (just dir or no dir) and then, names, of items.
 * Returns < 0, 0 or > 0 if item1 <, = or > item2 according to that order.
 */
int compare_attribs_names( const srcfd *item1, const srcfd *item2 )
{
     // If both or none of them are directories
    if( !( (item1->attr & FAT_ATTR_DIR) ^ (item2->attr & FAT_ATTR_DIR) ) )
        return compare_names( item1, item2 );
    else if( item1->attr & FAT_ATTR_DIR ) // 1st one is directory, 2nd one isn't
        return -1;
    else // 2nd one is directory, 1st one isn't
        return 1;
}

/* Sorts elements in a given directory using given comparator function. */
void sort_dir( srcfd *src_dir, int (*comparator) (const srcfd *, const srcfd *) )
{
    srcfd *head = NULL;
    srcfd *prev_out = NULL;
    srcfd *curr_out = NULL;
    srcfd *prev_min = NULL;
    srcfd *curr_in = NULL;
    srcfd *min = NULL;

    head = src_dir->first_child;

    if( !head ) return; // No items to sort

    curr_out = head;
    prev_out = NULL;

    while( curr_out->next )
    {
        min = curr_out;
        prev_min = prev_out;

        curr_in = curr_out;

        while( curr_in->next )
        {
            if( comparator( min, curr_in->next ) > 0 )
            {
                min = curr_in->next;
                prev_min = curr_in;
            }
            curr_in = curr_in->next;
        }

        if( min != curr_out ) // Place min before curr_out in list
        {
            srcfd *tmp;

            tmp = min->next; // Swap elements (re-linking them)
            min->next = curr_out;
            prev_min->next = tmp;
            if( !prev_out ) head = min;
            else prev_out->next = min;
        }

        // As min has taken the place of curr_out,
        // for next iteration curr_out will be min->next
        curr_out = min->next;
        prev_out = min;
    }

    src_dir->first_child = head;
}

/* Recursively sorts every directory in the tree. */
void sort_tree( srcfd *src_dir, int (*comparator) (const srcfd *, const srcfd *) )
{
    srcfd *child;

    sort_dir( src_dir, comparator );
    for( child = src_dir->first_child; child; child = child->next )
        if( child->attr & FAT_ATTR_DIR ) sort_tree( child, comparator );
}

//////////////////////////////////////////////////////////////////////////
// DIRECTORY SORTING FUNCTIONS (END)
//////////////////////////////////////////////////////////////////////////

int main( int argc, char **argv )
{
    int             c;
    img_options     options;
    const char      *img_file_name = NULL;
    const char      *src_dir       = NULL;
    srcfd           *src_list;
    FILE            *imgf;
    uint8_t         buf[SECT_SIZE];

    /* Set up default options. */
    memset( &options, 0, sizeof( options ) );
    set_std_parameters( &options, "1.44" );
    strncpy( options.disk_label, "NO NAME", sizeof( options.disk_label ) );
    options.verbose = 0;

    /* Process options. */
    while( (c = getopt( argc, argv, ":a:b:c:d:e:f:h:i:l:m:n:o:pr:s:t:v" )) != -1 ) {
        switch( c ) {
        case 'a':
            options.num_fats = atoi( optarg );
            break;
        case 'b':
            strncpy( options.boot_template, optarg,
                sizeof( options.boot_template ) - 1 );
            break;
        case 'c':
            options.sec_per_clust = atoi( optarg );
            break;
        case 'd':
            options.date = optarg;
            options.dos_date = stringdate_to_dos( optarg );
            break;
        case 'e':
            options.fat_type = atoi( optarg );
            break;
        case 'f':
            set_std_parameters( &options, optarg );
            break;
        case 'h':
            options.num_heads = atoi( optarg );
            break;
        case 'i':
            options.fat_sectors = atoi( optarg );
            break;
        case 'l':
            strncpy( options.disk_label, optarg, sizeof( options.disk_label ) - 1 );
            options.have_label = 1;
            break;
        case 'm':
            options.time = optarg;
            options.dos_time = stringtime_to_dos( optarg );
            break;
        case 'n':
            options.sect_per_track = atoi( optarg );
            break;
        case 'o':
            img_file_name = optarg;
            break;
        case 'p':
            options.sort = ~0;
            break;
        case 'r':
            options.root_entries = atoi( optarg );
            break;
        case 's':
            options.bytes_per_sect = atoi( optarg );
            break;
        case 't':
            options.num_tracks = atoi( optarg );
            break;
        case 'v':
            options.verbose = 1;
            break;
        case ':':
            fprintf( stderr, "option -%c requires argument\n", optopt );
            /* Fall through. */
        case '?':
            usage( argv[0] );
            return( EXIT_FAILURE );
        }
    }

    /* Get and check source directory. */
    src_dir = argv[optind];
    if( !src_dir ) {
        fprintf( stderr, "no source directory specified\n" );
        return( EXIT_FAILURE );
    }

    if( !validate_parameters( &options ) )
        return( EXIT_FAILURE );

    /* Calculate a few constants. */
    options.total_sectors = options.num_heads * options.num_tracks
                            * options.sect_per_track;
    options.cluster_size  = options.sec_per_clust * SECT_SIZE;
    options.root_sectors  = (options.root_entries * sizeof( fat_dir_entry )
                            + SECT_SIZE - 1) / SECT_SIZE;
    options.rsvd_sectors  = 1;
    options.data_sectors  = options.total_sectors - options.rsvd_sectors
                            - (options.num_fats * options.fat_sectors)
                            - options.root_sectors;
    if( !options.media_desc ) options.media_desc = 0xF0;

    if( !extra_validations( &options ) )
        return( EXIT_FAILURE );

    if( options.verbose ) {
        print_parameters( &options );
        fprintf( stderr, "Source directory: %s\n", src_dir );
        if( img_file_name ) {
            fprintf( stderr, "Image file: `%s'\n", img_file_name );
        }
    }

    /* Collect the source files. */
    src_list = build_source_list( &options, (srcfd *) NULL, src_dir );

    /* If sorting is needed this is a good place to do it. */
    if( options.sort )
        sort_dir( src_list, &compare_attribs_names );
    /* Anyway, do it between calls to build_source_list and build_fats */

    generate_short_names( src_list );
    imgf = fopen( img_file_name, "w+b" );
    if (! imgf )
    {
        fprintf( stderr, "cannot open `%s'\n", img_file_name );
        exit(1);
    }

    /* Build and write out the boot sector, FATs, the root directory,
     * and the data area.
     */
    build_bootsec( &options, imgf );
    if( build_fats( &options, src_list, imgf ) ) {
        fprintf( stderr, "building the FATs failed\n" );
        return( EXIT_FAILURE );
    }
    if( build_dir( &options, src_list, 0, 0, imgf ) ) {
        fprintf( stderr, "building root directory failed\n" );
        return( EXIT_FAILURE );
    }
    build_data_area( &options, src_list, 0, 0, imgf );

    /* Write empty data sectors */
    /* Better here or in build_data_area? (when called for root dir) */
    memset( buf, 0, sizeof( buf ) );
    for( c = options.data_sectors -
        dir_contents_size( &options, src_list ) * options.sec_per_clust;
        c; c-- )
        fwrite( buf, 1, sizeof( buf ), imgf);
    fclose( imgf );

    return( EXIT_SUCCESS );
}
