/*
 * Decompression utility for ICL BIOSes in the LDB format.
 *
 * Copyright 2026      RichardG <richardg867@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "bios_extract.h"
#include "compat.h"
#include "lh5_extract.h"

Bool
LdbExtract(unsigned char *BIOSImage, int BIOSLength, int BIOSOffset,
		  uint32_t OKICLOffset, uint32_t FLPACKOffset)
{
	printf("Found ICL BIOS LDB\n");

	static const char *filename = "ldb.rom";

	int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "Error: unable to open %s: %s\n\n", filename,
			strerror(errno));
		return FALSE;
	}

	int Offset = FLPACKOffset + 0x18;
	int PackedLength = BIOSLength - Offset - 4;
	int DecompLength = be32toh(*((uint32_t *) &BIOSImage[Offset]));

	printf("0x%05X (%6d bytes) -> %-20s (%6d bytes)",
	       Offset, PackedLength, filename, DecompLength);

	unsigned char *PackedData = BIOSImage + Offset,
		      *DecodeBuffer = malloc(DecompLength);
	if (!DecodeBuffer)
		return FALSE;

	int DecodeBufferPos = unlzh(PackedData + 4, PackedLength, DecodeBuffer, DecompLength);
	if (DecodeBufferPos > -1) {
		write(fd, DecodeBuffer, DecodeBufferPos);
		free(DecodeBuffer);

		SetRemainder(PackedData - BIOSImage, PackedLength, FALSE);
	} else {
		printf(" (failed)");
	}
	printf("\n");

	close(fd);

	return TRUE;
}
