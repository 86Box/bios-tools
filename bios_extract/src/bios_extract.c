/*
 * Copyright 2009      Luc Verhaegen <libv@skynet.be>
 * Copyright 2021      RichardG <richardg867@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define _GNU_SOURCE		/* memmem is useful */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include "compat.h"
#include "bios_extract.h"
#include "lh5_extract.h"

static void HelpPrint(char *name)
{
	printf("\n");
	printf("Program to extract compressed modules from BIOS images.\n");
	printf("Supports AMI, Award, Phoenix and SystemSoft BIOSes.\n");
	printf("\n");
	printf("Usage:\n\t%s <filename>\n", name);
}

unsigned char *MMapOutputFile(char *filename, int size)
{
	unsigned char *Buffer;
	char *tmp;
	int fd;

	if ((size < 0) || (size > 16777216)) {
		fprintf(stderr, "Error: %s too big (%d bytes)\n", filename,
			size);
		return NULL;
	}

	/* all slash signs '/' in filenames will be replaced by a backslash sign '\' */
	tmp = filename;
	while ((tmp = strchr(tmp, '/')) != NULL)
		tmp[0] = '\\';

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "Error: unable to open %s: %s\n\n", filename,
			strerror(errno));
		return NULL;
	}

	/* grow file */
	if (lseek(fd, size - 1, SEEK_SET) == -1) {
		fprintf(stderr, "Error: Failed to grow \"%s\": %s\n", filename,
			strerror(errno));
		close(fd);
		return NULL;
	}

	if (write(fd, "", 1) != 1) {
		fprintf(stderr, "Error: Failed to write to \"%s\": %s\n",
			filename, strerror(errno));
		close(fd);
		return NULL;
	}

	Buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (Buffer == ((void *)-1)) {
		fprintf(stderr, "Error: Failed to mmap %s: %s\n", filename,
			strerror(errno));
		close(fd);
		return NULL;
	}

	close(fd);

	return Buffer;
}

unsigned char *remainder_buf = NULL;
static int remainder_size = 0, remainder_padding = 0;

void InitRemainder(unsigned char *BIOSImage, int BIOSLength)
{
	unsigned char *new_remainder_buf = realloc(remainder_buf, BIOSLength);
	if (new_remainder_buf) {
		remainder_buf = new_remainder_buf;
		remainder_size = BIOSLength;
	}

	if (!remainder_buf)
		return;

	/* Remove padding from the start only, as the end will have the entry point anyway. */
	if (remainder_size < BIOSLength)
		BIOSLength = remainder_size;
	unsigned char *p = BIOSImage, *q = BIOSImage + BIOSLength;
	while ((p < q) && ((*p == 0x00) || (*p == 0xff)))
		p++;

	remainder_padding = p - BIOSImage;
	if (remainder_padding > 0) {
		BIOSLength -= remainder_padding;
		memset(remainder_buf, 0x00, remainder_padding);
	}
	memset(remainder_buf + remainder_padding, 0xff, BIOSLength);
}

void SetRemainder(uint32_t Offset, uint32_t Length, int val)
{
	if (!remainder_buf)
		return;

	if ((remainder_size - Offset) < Length)
		Length = remainder_size - Offset;
	memset(remainder_buf + Offset, 0xff * !!val, Length);
}

int SaveRemainder(unsigned char *BIOSImage)
{
	if (!remainder_buf)
		return TRUE;

	if (remainder_padding > 0)
		printf("Padding (%6d bytes)   ->   [discarded]\n",
		       remainder_padding);

	int fd = open("remainder.rom", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "Error: unable to open remainder.rom: %s\n\n",
			strerror(errno));
		return FALSE;
	}

	int remaining = remainder_size, copy;
	unsigned char *p = remainder_buf, *q, c = *p;
	while (p) {
		c = ~c;
		q = memchr(p, c, remaining);
		if (q)
			copy = q - p;
		else
			copy = remaining;
		if (!c)
			write(fd, BIOSImage + (p - remainder_buf), copy);
		remaining -= copy;
		p = q;
	}

	printf("Remains (%6ld bytes)   ->   remainder.rom\n",
	       lseek(fd, 0, SEEK_CUR));

	close(fd);

	return TRUE;
}

/* TODO: Make bios identification more flexible */

static struct {
	char *String1;
	char *String2;
	 Bool(*Handler) (unsigned char *Image, int ImageLength, int ImageOffset,
			 uint32_t Offset1, uint32_t Offset2);
} BIOSIdentification[] = {
	{ /* TODO FIXME: NULs get discarded because of strlen */
	"AMI Flash Utility for ", "@ROM", AFUDOSExtract}, {
	"AMIBIOS W 04 ", "AMIBIOSC", AMI940725Extract}, {
	"AMIBIOS W 05 ", "AMIBIOSC", AMI941010Extract}, {
	"AMIBIOS W 05 ", "OSC10/10/94", AMI941010Extract}, { /* NexGen */
	"AMIBOOT ROM", "AMIBIOSC0", AMI95Extract}, {
	"SUPER   ROM", "AMIBIOSC0", AMI95Extract}, { /* Supermicro */
	"$ASUSAMI$", "AMIBIOSC0", AMI95Extract}, {
	"AMIEBBLK", "AMIBIOSC0", AMI95Extract}, {
	"AMIBIOSC06", NULL, AMI95Extract}, {
	"AMIBIOSC07", NULL, AMI95Extract}, {
	"AMIBIOSC08", NULL, AMI95Extract}, {
	"AMIBIOSC09", NULL, AMI95Extract}, { /* Hyper-V legacy BIOS */
	"AMIBIOSC\x00\x00\x00\x00", NULL, AMI95Extract}, { /* Gigabyte GA-8IPXDR F1 */
	"(AAMMIIBBIIOOSS)", "AMIBIOSC", AMI940725Extract}, { /* 12/15/93 */
	"= Award Decompression Bios =", NULL, AwardExtract}, {
	"awardext.rom", NULL, AwardExtract}, {
	"PowerBIOS Setup\x00", NULL, AwardExtract}, { /* Siemens PowerBIOS */
	"Phoenix Technologies", "BCPSEGMENT", PhoenixExtract}, {
	"\x00IBM AT Compatible Phoenix NuBIOS", "BCPSEGMENT", PhoenixExtract}, { /* Phoenix copyrights scrubbed (Gateway Solo 2500) */
	" 102-System Board Failure", "BCPCMP", PhoenixExtract}, { /* Phoenix-compressed Compaq BIOS (Presario 4800) */
	"You must load COMPAQ BASIC\r\n", "BC\xD6\xF1\x00\x00\x12", CompaqExtract}, { /* BCD6F1-compressed Compaq BIOS */
	"\xEE\x88SYSBIOS", "\xEE\x88", SystemSoftExtract}, {
	"\xEE\x88\x42IOS SCU", "\xEE\x88", SystemSoftExtract}, {
	"\xFF\x88SYSBIOS", "\xFF\x88", SystemSoftExtract}, { /* Insyde */
NULL, NULL, NULL},};

int main(int argc, char *argv[])
{
	int FileLength = 0;
	uint32_t BIOSOffset = 0;
	unsigned char *BIOSImage = NULL,
		      IntelAMI[256], /* could be shorter if not for LH5Decode overflowing the buffer */
		      *Buffer = NULL;
	int fd;
	uint32_t Offset1 = 0, Offset2 = 0;
	int i, len;
	unsigned char *tmp;

	if ((argc != 2) || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		HelpPrint(argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error: Failed to open %s: %s\n", argv[1],
			strerror(errno));
		return 1;
	}

	FileLength = lseek(fd, 0, SEEK_END);
	if (FileLength < 0) {
		fprintf(stderr, "Error: Failed to lseek \"%s\": %s\n", argv[1],
			strerror(errno));
		return 1;
	}

	BIOSOffset = (0x100000 - FileLength) & 0xFFFFF;

	BIOSImage = mmap(NULL, FileLength, PROT_READ, MAP_PRIVATE, fd, 0);
	if (BIOSImage < 0) {
		fprintf(stderr, "Error: Failed to mmap %s: %s\n", argv[1],
			strerror(errno));
		return 1;
	}

	printf("Using file \"%s\" (%ukB)\n", argv[1], FileLength >> 10);

	for (i = 0; BIOSIdentification[i].Handler; i++) {
		if ((i == 0) || strcmp(BIOSIdentification[i].String1, BIOSIdentification[i - 1].String1)) {
			len = strlen(BIOSIdentification[i].String1);
			tmp =
		    	memmem(BIOSImage, FileLength - len,
				   BIOSIdentification[i].String1, len);
			if (!tmp) {
				Offset1 = -1;
				continue;
			}
			Offset1 = tmp - BIOSImage;
		} else if (Offset1 == -1) {
			continue;
		}

		if (BIOSIdentification[i].String2) {
			len = strlen(BIOSIdentification[i].String2);
			if (BIOSIdentification[i].Handler == AFUDOSExtract) {
				/* Hack for AFUWIN containing another @ROM string. */
				tmp =
					memmem(BIOSImage + Offset1, FileLength - len - Offset1,
				       BIOSIdentification[i].String2, len);
			} else {
				tmp =
					memmem(BIOSImage, FileLength - len,
				       BIOSIdentification[i].String2, len);
			}
			if (!tmp)
				continue;
			Offset2 = tmp - BIOSImage;
		} else {
			Offset2 = Offset1;
		}

		InitRemainder(BIOSImage, FileLength);

		len = BIOSIdentification[i].Handler
		    (BIOSImage, FileLength, BIOSOffset, Offset1, Offset2);
		if (remainder_buf) {
			len &= SaveRemainder(BIOSImage);
			free(remainder_buf);
			remainder_buf = NULL;
		}
		return len ? 0 : 1;
	}

	/* Bruteforce Intel AMI Color fork LH5. */
	unsigned char *tempbuf = NULL;
	Offset2 = 1;
	for (Offset1 = 0; Offset1 < (FileLength - 10); Offset1 += 0x1000) {
		BIOSOffset = Offset1;
		i = 1;
retry:	if (((fd = LH5Decode(BIOSImage + BIOSOffset, FileLength - BIOSOffset, IntelAMI, 13)) > -1) &&
		    (!memcmp(IntelAMI, "AMIBIOS(C)AMI", 13) || ((IntelAMI[0] == 0x55) && (IntelAMI[1] == 0xaa)))) {
			if (Offset2 == 1) {
				printf("Found potential Intel AMIBIOS.\n");
				InitRemainder(BIOSImage, FileLength);
				Offset2 = 86; /* magic exit code if no main body found */
			}

			if (IntelAMI[0] == 0x55) {
				len = IntelAMI[2] * 512;
				sprintf((char *) IntelAMI, "intelopt_%05X.rom", BIOSOffset);
			} else {
				len = 65536;
				sprintf((char *) IntelAMI, "intelbody_%05X.rom", BIOSOffset);
				Offset2 = 0; /* main body found, all good */
			}

save:		tempbuf = realloc(tempbuf, len);
			memset(tempbuf, 0, len);

			i = len;
			int j = len / 2;
			while (1) {
				fd = LH5Decode(BIOSImage + BIOSOffset, FileLength - BIOSOffset, tempbuf, i);
				if (fd == -1)
					i -= j;
				else if ((i == len) || (j == 1))
					break;
				else
					i += j;
				j /= 2;
				if (j < 1)
					j = 1;
			}

			if ((fd > 0) && (i > 0)) {
				printf("0x%05X (%6d bytes)   ->   %s\t(%d bytes)\n",
		       			BIOSOffset, fd, IntelAMI, i);
				SetRemainder(BIOSOffset, fd, FALSE);

				Buffer = MMapOutputFile((char *) IntelAMI, i);
				if (!Buffer)
					return 1;
				memcpy(Buffer, tempbuf, i);
				munmap(Buffer, i);

				/* There may be compressed data after the main body. (Advanced/EV VBIOS) */
				if (fd & 1) /* padded to even byte */
					fd++;
				BIOSOffset += fd;
				i = 1;
				goto retry;
			}
		} else if (i) {
			BIOSOffset += 0x44; /* skip "Copyright Notice: Copyright Intel..." */
			i = 0;
			goto retry;
		} else if ((fd > -1) && !memcmp(BIOSImage + Offset1, "Copyright Notice: Copyright Intel", 33)) {
			BIOSOffset = Offset1;

			if (Offset2 == 1) {
				printf("Found potential Intel AMIBIOS.\n");
				InitRemainder(BIOSImage, FileLength);
				Offset2 = 86; /* magic exit code if no main body found */
			}

			len = 65536;
			sprintf((char *) IntelAMI, "intelunk_%05X.rom", BIOSOffset);
			goto save;
		}
	}

	if (Offset2)
		fprintf(stderr, "Error: Unable to detect BIOS Image type.\n");
	else
		return !SaveRemainder(BIOSImage);
	return Offset2;
}
