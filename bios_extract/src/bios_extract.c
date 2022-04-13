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

/* TODO: Make bios identification more flexible */

static struct {
	char *String1;
	char *String2;
	 Bool(*Handler) (unsigned char *Image, int ImageLength, int ImageOffset,
			 uint32_t Offset1, uint32_t Offset2);
} BIOSIdentification[] = {
	{
	"AMIBIOS (C)1993 American Megatrends Inc.,", "AMIBIOSC", AMI940725Extract}, {
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
	"AMI Flash Utility for DOS Command mode.", "@ROM", AFUDOSExtract}, {
	"= Award Decompression Bios =", NULL, AwardExtract}, {
	"awardext.rom", NULL, AwardExtract}, {
	"Phoenix Technologies", "BCPSEGMENT", PhoenixExtract}, {
	"\xEE\x88SYSBIOS", "\xEE\x88", SystemSoftExtract}, {
	"\xEE\x88\x42IOS SCU", "\xEE\x88", SystemSoftExtract}, {
	"\xFF\x88SYSBIOS", "\xFF\x88", SystemSoftExtract}, { /* Insyde */
NULL, NULL, NULL},};

int main(int argc, char *argv[])
{
	int FileLength = 0;
	uint32_t BIOSOffset = 0;
	unsigned char *BIOSImage = NULL,
		      IntelAMI[256], /* just 13 bytes needed, but LH5Decode overflows the buffer */
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
			tmp =
		    	memmem(BIOSImage, FileLength - len,
			       BIOSIdentification[i].String2, len);
			if (!tmp)
				continue;
			Offset2 = tmp - BIOSImage;
		} else {
			Offset2 = Offset1;
		}

		if (BIOSIdentification[i].Handler
		    (BIOSImage, FileLength, BIOSOffset, Offset1, Offset2))
			return 0;
		else
			return 1;
	}

	/* Bruteforce Intel AMI Color fork LH5. */
	for (i = 0; i < (FileLength - 10); i += 0x4000) {
		BIOSOffset = i;
CopyrightOffset:if ((LH5Decode(BIOSImage + BIOSOffset, FileLength - BIOSOffset, IntelAMI, 13) > -1) &&
		    !memcmp(IntelAMI, "AMIBIOS(C)AMI", 13)) {
			printf("Found Intel AMIBIOS.\nOffset: %X\n", BIOSOffset);

		    	Buffer = MMapOutputFile("intelbody.bin", 65536);
			if (!Buffer)
				return 1;

			i = 65536;
			while ((LH5Decode(BIOSImage + BIOSOffset, FileLength - BIOSOffset, Buffer, i) == -1) &&
				(i > 16))
				i--;

			munmap(Buffer, 65536);

			return 0;
		} else if (!(BIOSOffset & 0xff)) {
			BIOSOffset += 0x44;
			goto CopyrightOffset;
		}
	}

	fprintf(stderr, "Error: Unable to detect BIOS Image type.\n");
	return 1;
}
