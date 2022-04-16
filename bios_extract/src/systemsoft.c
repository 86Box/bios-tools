/*
 * Decompression utility for SystemSoft and Insyde MobilePRO BIOSes.
 *
 * Copyright 2021      RichardG <richardg867@gmail.com>
 * Based on SYSODECO (c) 2000-2004 Veit Kannegieser
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

#define _GNU_SOURCE 1		/* for memmem */

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
SystemSoftExtract(unsigned char *BIOSImage, int BIOSLength, int BIOSOffset,
		  uint32_t SYSBIOSOffset, uint32_t EE88Offset)
{
	Bool IsPart, IsInsyde;
	uint16_t Magic, Length;
	uint32_t Offset, AdditionalBlockCount;
	char filename[256], ModuleName[32];
	int fd, i, j;

	struct part {
		uint16_t Magic; /* EE 88 */
		unsigned char Name[8];
		uint16_t AdditionalBlocks;
		uint16_t PackedLen;
		uint16_t Offset;
		uint16_t Segment;
		uint16_t Checksum;
	} *part;

	struct microcode {
		uint32_t Magic;
		uint32_t Unused;
		uint16_t Year;
		uint8_t Day;
		uint8_t Month;
	} *microcode;

	struct additional {
		uint16_t Magic; /* DD 88 */
		char Data[31];
	} *additional;

	printf("Found SystemSoft/Insyde BIOS\n");

	/* dump modules */
	Offset = 0;
	while (Offset < (BIOSLength - 20)) {
		IsPart = IsInsyde = 0;
		Length = 0;

		part = (struct part *)(BIOSImage + Offset);
		Magic = le16toh(part->Magic);
		if ((Magic == 0x88EE) || (Magic == 0x88FF)) {
			/* part */
			if (((part->Name[0] < 'A') || (part->Name[0] > 'Z')) &&
			    ((part->Name[1] < 'A') || (part->Name[1] > 'Z')) &&
			    (((part->Name[2] < 'A') || (part->Name[2] > 'Z')) &&
			    (part->Name[2] != ' ') && (part->Name[2] != 0x00))) {
				Offset += 2;
				continue;
			}

			Length = le16toh(part->PackedLen);
			sprintf(filename, "ssbody_%05X.rom", Offset);
			if (Magic == 0x88FF) {
				/* nobody seems to know how this compression works */
				strcpy(ModuleName, "Insyde module");
			} else {
				IsPart = 1;

				ModuleName[0] = ModuleName[sizeof(part->Name) + 1] = '"';
				ModuleName[sizeof(part->Name) + 2] = 0;
				for (i = 0; i < sizeof(part->Name); i++) {
					if ((part->Name[i] == 0x00) || (part->Name[i] == '\n'))
						ModuleName[i + 1] = ' ';
					else
						ModuleName[i + 1] = part->Name[i];
				}
			}

			AdditionalBlockCount = (le16toh(part->AdditionalBlocks) >> 4) & 7;
			Offset += 20 + (33 * AdditionalBlockCount);
		} else if (Magic == 0xAA55) {
			/* option ROM */
			Length = part->Name[0] * 512;
			sprintf(filename, "ssopt_%05X.rom", Offset);
			sprintf(ModuleName, "Option ROM");
		} else if ((Magic == 0x5349) && (part->Name[0] == 'A')) {
			/* ISA ROM */
			Length = 0x2000;
			sprintf(filename, "ssisa_%05X.rom", Offset);
			sprintf(ModuleName, "ISA ROM");
		} else if ((Magic == 0x061E) && (part->Name[0] == 0x8A) &&
			   (part->Name[1] == 0xD8) && (part->Name[2] == 0xB7)) {
			/* "Battery Management?" */
			Length = 0x800;
			sprintf(filename, "ssbat_%05X.rom", Offset);
			sprintf(ModuleName, "Battery Management?");
		} else {
			microcode = (struct microcode *)(BIOSImage + Offset);
			if ((le32toh(microcode->Magic) == 0x00000001) &&
			    (le16toh(microcode->Year) >= 1990) &&
			    (le16toh(microcode->Year) <= 2090) &&
			    (microcode->Day >= 1) && (microcode->Day <= 31) &&
			    (microcode->Month >= 1) && (microcode->Month <= 12)) {
			    	/* CPU microcode */
				Length = 0x800;
				sprintf(filename, "ssucode_%05X.rom", Offset);
				sprintf(ModuleName, "CPU Microcode");
			} else if (((Magic & 0xFF) == 0x00) || ((Magic & 0xFF) == 0xFF)) {
				/* ignore 0x00/0xFF sequences */
				while ((Offset < BIOSLength) &&
				       ((BIOSImage[Offset] == 0x00) ||
				       (BIOSImage[Offset] == 0xFF)))
					Offset++;
				continue;
			} else if ((BIOSLength - Offset) < 0x4000) {
				Length = BIOSLength - Offset;
				sprintf(filename, "ssboot.rom");
				sprintf(ModuleName, "Boot Block");
			} else {
				Offset += 2;
				continue;
			}
		}

		if (!Length)
			break;

		fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
		if (fd < 0) {
			fprintf(stderr, "Error: unable to open %s: %s\n\n", filename,
				strerror(errno));
			return FALSE;
		}

		printf("0x%05X (%6d bytes) -> %-20s",
		       Offset, Length, filename);

		if (IsPart) {
			/* arithmetic decoding */
			unsigned char *PackedData = BIOSImage + Offset,
				      *DecodeBuffer = malloc(65536);
			uint32_t DecodeBufferPos = 0;
			memset(DecodeBuffer, 0, 65536);

			while (Length > 0) {
				if (DecodeBufferPos >= 65536)
					break;

				i = *PackedData++;
				Length--;
				if (i <= 0x0F) {
					i += 1;
					memcpy(DecodeBuffer + DecodeBufferPos, PackedData, i);
					PackedData += i;
					Length -= i;
					DecodeBufferPos += i;
				} else {
					j = (i >> 4) + 1;
					i = ((i & 0x0F) << 8) | *PackedData++;
					Length--;
					if (i > DecodeBufferPos)
						break;
					/* copy manually, as memcpy and memmove corrupt data */
					i = DecodeBufferPos - i;
					while (j--)
						DecodeBuffer[DecodeBufferPos++] = DecodeBuffer[i++];
				}
			}

			write(fd, DecodeBuffer, DecodeBufferPos);
			free(DecodeBuffer);

			Offset = PackedData - BIOSImage;

			printf(" (%6d bytes)\t%s\n", DecodeBufferPos, ModuleName);

			for (i = 0; i < AdditionalBlockCount; i++) {
				additional = (struct additional *)(((unsigned char *)part) + 20 + (33 * i));

				printf("\t\t\t\t\t\t\t\t\"");
				for (j = 0; j < sizeof(additional->Data); j++) {
					if ((additional->Data[j] == 0x00) ||
					    (additional->Data[j] == '\n'))
						putchar(' ');
					else
						putchar(additional->Data[j]);
				}
				printf("\"\n");
			}
		} else {
			write(fd, BIOSImage + Offset, Length);

			Offset += Length;

			printf("\t\t\t%s\n", ModuleName);
		}

		i = ((unsigned char *)part) - BIOSImage;
		SetRemainder(i, Offset - i, FALSE);

		close(fd);
	}

	return TRUE;
}
