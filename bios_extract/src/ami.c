/*
 * Decompression utility for AMI BIOSes.
 *
 * Copyright 2009      Luc Verhaegen <libv@skynet.be>
 * Copyright 2000-2006 Anthony Borisow
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

#define _GNU_SOURCE 1		/* for memmem */

#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "bios_extract.h"
#include "compat.h"
#include "lh5_extract.h"

struct AMI95ModuleName {
	uint8_t Id;
	char *Name;
};

static struct AMI95ModuleName AMI95ModuleNames[] = {
	{0x00, "POST"},
	{0x01, "Setup Server"},
	{0x02, "RunTime"},
	{0x03, "DIM"},
	{0x04, "Setup Client"},
	{0x05, "Remote Server"},
	{0x06, "DMI Data"},
	{0x07, "Green PC"},
	{0x08, "Interface"},
	{0x09, "MP"},
	{0x0A, "Notebook"},
	{0x0B, "Int-10"},
	{0x0C, "ROM-ID"},
	{0x0D, "Int-13"},
	{0x0E, "OEM Logo"},
	{0x0F, "ACPI Table"},
	{0x10, "ACPI AML"},
	{0x11, "P6 Microcode"},
	{0x12, "Configuration"},
	{0x13, "DMI Code"},
	{0x14, "System Health"},
	{0x15, "Memory Sizing"},
	{0x16, "Memory Test"},
	{0x17, "Debug"},
	{0x18, "ADM (Display MGR)"},
	{0x19, "ADM Font"},
	{0x1A, "Small Logo"},
	{0x1B, "SLAB"},
	{0x1C, "BCP Info"},
	{0x1D, "Dual Logo"},
	{0x1E, "Intel OSB"},
	{0x20, "PCI AddOn ROM"},
	{0x21, "Multilanguage"},
	{0x22, "UserDefined"},
	{0x23, "ASCII Font"},
	{0x24, "BIG5 Font"},
	{0x25, "OEM Logo"},
	{0x26, "Debugger"},
	{0x27, "Debugger Port"},
	{0x28, "BMC Output"},
	{0x29, "MBI File"},
	{0x2A, "User ROM"},
	{0x2B, "PXE Code"},
	{0x2C, "AMI Font"},
	{0x2E, "User ROM"},
	{0x2D, "Battery Refresh"},
	{0x2F, "Serial Redirection"},
	{0x30, "Font Database"},
	{0x31, "OEM Logo Data"},
	{0x32, "Graphic Logo Code"},
	{0x33, "Graphic Logo Data"},
	{0x34, "Action Logo Code"},
	{0x35, "Action Logo Data"},
	{0x36, "Virus"},
	{0x37, "Online Menu"},
	{0x38, "Lang1 as ROM"},
	{0x39, "Lang2 as ROM"},
	{0x3A, "Lang3 as ROM"},
	{0x40, "AMD CIM-X NB binary"},
	{0x60, "AMD CIM-X SB binary"},
	{0x70, "OSD Bitmaps"},
	{0x80, "Image Info"},
	{0xab, "CompuTrace backdoor"},
	{0xf0, "Asrock Backup Util or Windows SLIC"},
	{0xf9, "Asrock AMD AHCI DLL"},
	{0xfa, "Asrock LOGO GIF"},
	{0xfb, "Asrock LOGO JPG"},
	{0xfc, "Asrock LOGO JPG"},
	{0xfd, "Asrock LOGO PCX - Instant boot"},
	{0, NULL}
};

static char *AMI95ModuleNameGet(uint8_t ID)
{
	int i;

	for (i = 0; AMI95ModuleNames[i].Name; i++)
		if (AMI95ModuleNames[i].Id == ID)
			return AMI95ModuleNames[i].Name;
	return NULL;
}

/*
 *
 */
Bool
AMI940725Extract(unsigned char *BIOSImage, int BIOSLength, int BIOSOffset,
		 uint32_t AMIBOffset, uint32_t ABCOffset)
{
	Bool Compressed;
	uint32_t Offset = ABCOffset + 0x10;
	char Date[9];
	unsigned char *ABWOffset;
	char Version[5];
	int i;

	struct b94 {
		const uint16_t PackLenLo;
		const uint16_t PackLenHi;
		const uint16_t RealLenLo;
		const uint16_t RealLenHi;
	} *b94;

	/* Get Date */
	memcpy(Date, BIOSImage + BIOSLength - 11, 8);
	Date[8] = 0;

	ABWOffset = memmem(BIOSImage, BIOSLength, "AMIBIOS W ", 10);
	if (ABWOffset) {
		Version[0] = *(ABWOffset + 10);
		Version[1] = *(ABWOffset + 11);
		Version[2] = *(ABWOffset + 13);
		Version[3] = *(ABWOffset + 14);
		Version[4] = 0;
	} else {
		Version[0] = 0;
	}
		

	printf("AMI94 Version\t: %s (%s)\n", Version, Date);

	/* First, the boot rom */
	uint32_t BootOffset;
	int fd;

	BootOffset = AMIBOffset & 0xFFFF0000;

	printf("0x%05X (%6d bytes) -> amiboot.rom\n", BootOffset,
	       BIOSLength - BootOffset);

	fd = open("amiboot.rom", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "Error: unable to open %s: %s\n\n",
			"amiboot.rom", strerror(errno));
		return FALSE;
	}

	write(fd, BIOSImage + BootOffset, BIOSLength - BootOffset);
	close(fd);

	for (i = 0; i < 0x80; i++) {
		char filename[64];
		unsigned char *Buffer;
		int BufferSize, ROMSize;

		b94 = (struct b94 *)(BIOSImage + Offset);

		if ((le16toh(b94->PackLenLo) == 0x0000)
		    || (le16toh(b94->RealLenLo) == 0x0000))
			break;

		sprintf(filename, "amibody_%02x.rom", i);

		Compressed = TRUE;

NotCompressed:
		ROMSize = le32toh(b94->PackLenLo);
		if (Compressed)
			BufferSize = le32toh(b94->RealLenLo);
		else
			BufferSize = ROMSize;

		printf("0x%05X (%6d bytes)", Offset + 8,
		       ROMSize);

		printf(" -> %-20s", filename);

		printf(" (%6d bytes)", BufferSize);

		printf("\n");

		Buffer = MMapOutputFile(filename, BufferSize);
		if (!Buffer)
			return FALSE;

		if (Compressed) {
			if (LH5Decode(BIOSImage + Offset + 8,
				      ROMSize, Buffer, BufferSize) == -1) {
				Compressed = FALSE;
				munmap(Buffer, BufferSize);
				unlink(filename);
				goto NotCompressed;
			}
		} else
			memcpy(Buffer, BIOSImage + Offset + 8,
			       BufferSize);

		munmap(Buffer, BufferSize);

		Offset += ROMSize;
	}

	return TRUE;
}

/*
 *
 */
Bool
AMI941010Extract(unsigned char *BIOSImage, int BIOSLength, int BIOSOffset,
		 uint32_t AMIBOffset, uint32_t ABCOffset)
{
	Bool Compressed;
	char Date[9];
	unsigned char *ABWOffset;
	char Version[5];
	int i;

	struct part {
		const uint16_t RealCS;
		const uint8_t PartID;
		const uint8_t IsComprs;
	} *part;

	struct headerinfo {
		const uint16_t ModuleCount;
	} *headerinfo;

	struct b94 {
		const uint16_t PackLenLo;
		const uint16_t PackLenHi;
		const uint16_t RealLenLo;
		const uint16_t RealLenHi;
	} *b94;

	/* Get Date */
	memcpy(Date, BIOSImage + BIOSLength - 11, 8);
	Date[8] = 0;

	if (AMIBOffset)
		ABWOffset = BIOSImage + AMIBOffset;
	else
		ABWOffset = memmem(BIOSImage + AMIBOffset, BIOSLength - AMIBOffset, "AMIBIOS W ", 10);
	if (ABWOffset) {
		Version[0] = *(ABWOffset + 10);
		Version[1] = *(ABWOffset + 11);
		Version[2] = *(ABWOffset + 13);
		Version[3] = *(ABWOffset + 14);
		Version[4] = 0;
	} else {
		Version[0] = 0;
	}

	if (BIOSImage[ABCOffset] == 'O') /* NexGen */
		ABCOffset -= 5;

	printf("AMI94 Version\t: %s (%s)\n", Version, Date);

	/* First, the boot rom */
	uint32_t BootOffset;
	int fd;

	BootOffset = AMIBOffset & 0xFFFF0000;

	printf("0x%05X (%6d bytes) -> amiboot.rom\n", BootOffset,
	       BIOSLength - BootOffset);

	fd = open("amiboot.rom", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "Error: unable to open %s: %s\n\n",
			"amiboot.rom", strerror(errno));
		return FALSE;
	}

	write(fd, BIOSImage + BootOffset, BIOSLength - BootOffset);
	close(fd);

	/* now dump the individual modules */
	headerinfo = (struct headerinfo *)(BIOSImage + ABCOffset + 0x10);
	for (i = 0; i < headerinfo->ModuleCount; i++) {
		char filename[64], *ModuleName;
		unsigned char *Buffer;
		int BufferSize, ROMSize;

		part = (struct part *)(BIOSImage + ABCOffset + 0x14 + (i * 4));
		b94 = (struct b94 *)(BIOSImage + ABCOffset + part->RealCS);

		if (part->IsComprs & 0x80)
			Compressed = FALSE;
		else
			Compressed = TRUE;

		sprintf(filename, "amibody_%02x.rom", i);

NotCompressed:
		if (Compressed) {
			ROMSize = le16toh(b94->PackLenLo);
			BufferSize = le16toh(b94->RealLenLo);
		} else {
			ROMSize = BufferSize = 0x10000 - part->RealCS;
		}

		printf("0x%05X (%6d bytes)", ABCOffset + part->RealCS + 8,
		       ROMSize);

		printf(" -> %-20s", filename);

		if (Compressed)
			printf(" (%6d bytes)", BufferSize);
		else
			printf("               ");

		ModuleName = AMI95ModuleNameGet(part->PartID);
		if (ModuleName)
			printf("  \"%s\"\n", ModuleName);
		else
			printf("\n");

		Buffer = MMapOutputFile(filename, BufferSize);
		if (!Buffer)
			return FALSE;

		if (Compressed) {
			if (LH5Decode(BIOSImage + ABCOffset + part->RealCS + 8,
				      ROMSize, Buffer, BufferSize) == -1) {
				Compressed = FALSE;
				munmap(Buffer, BufferSize);
				unlink(filename);
				goto NotCompressed;
			}
		} else
			memcpy(Buffer, BIOSImage + ABCOffset + part->RealCS,
			       BufferSize);

		munmap(Buffer, BufferSize);
	}

	return TRUE;
}

/*
 *
 */
Bool
AMI95Extract(unsigned char *BIOSImage, int BIOSLength, int BIOSOffset,
	     uint32_t AMIBOffset, uint32_t ABCOffset)
{
	Bool Compressed, ZeroVersion;
	uint32_t Offset, PackedOffset, NewOffset;
	char Date[9], OffsetMode;
	int i;

	struct abc {
		const char AMIBIOSC[8];
		const char Version[4];
		const uint16_t CRCLen;
		const uint32_t CRC32;
		const uint16_t BeginLo;
		const uint16_t BeginHi;
	} *abc;

	struct bigpart {
		const uint32_t CSize;
		const uint32_t Unknown;
	} *bigpart;

	struct part {
		/* When Previous Part Address is 0xFFFFFFFF, then this is the last part. */
		uint16_t PrePartLo;	/* Previous part low word */
		uint16_t PrePartHi;	/* Previous part high word */
		uint16_t CSize;	/* Header length */
		uint8_t PartID;	/* ID for this header */
		uint8_t IsComprs;	/* 0x80 -> compressed */
		uint32_t RealCS;	/* Old BIOSes:
					   Real Address in RAM where to expand to
					   Now:
					   Type 0x20 PCI ID of device for this ROM
					   Type 0x21 Language ID (ascii) */
		uint32_t ROMSize;	/* Compressed Length */
		uint32_t ExpSize;	/* Expanded Length */
	} *part;

	if (!ABCOffset) {
		if ((BIOSImage[8] == '1') && (BIOSImage[9] == '0') &&
		    (BIOSImage[11] == '1') && (BIOSImage[12] == '0'))
			return AMI941010Extract(BIOSImage, BIOSLength, BIOSOffset, 0, 0);
		else
			return AMI940725Extract(BIOSImage, BIOSLength, BIOSOffset, 0, 0);
	}

	if (ABCOffset + sizeof (struct abc) < BIOSLength) {
		abc = (struct abc *)(BIOSImage + ABCOffset);
		ZeroVersion = (memcmp(abc->Version, "0000", 4) == 0);
		if ((memcmp(abc->Version, "AMIN", 4) == 0) || ZeroVersion) {
			/* Skip to next one if immediately followed by "AMINCBLK"
			 * header or "0000" in place of a version number. */
			abc = (struct abc *)memmem (BIOSImage + ABCOffset + 1,
				BIOSLength - ABCOffset - 1 - sizeof (struct abc),
				"AMIBIOSC", 8);
			/* go back to the original if only a 0000 is present */
			if (!abc && ZeroVersion)
				abc = (struct abc *)(BIOSImage + ABCOffset);
		}
	} else
		abc = NULL;

	if (!abc) {
		fprintf(stderr,
			"Error: short read after AMIBIOSC signature.\n");
		return FALSE;
	}

	/* Get Date */
	memcpy(Date, BIOSImage + BIOSLength - 11, 8);
	Date[8] = 0;

	printf("AMI95 Version\t: %.4s (%s)\n", abc->Version, Date);

	/* First, the boot rom */
	uint32_t BootOffset;
	int fd;

	BootOffset = AMIBOffset & 0xFFFF0000;

	printf("0x%05X (%6d bytes) -> amiboot.rom\n", BootOffset,
	       BIOSLength - BootOffset);

	fd = open("amiboot.rom", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "Error: unable to open %s: %s\n\n",
			"amiboot.rom", strerror(errno));
		return FALSE;
	}

	write(fd, BIOSImage + BootOffset, BIOSLength - BootOffset);
	close(fd);

	/* now dump the individual modules */
	if (BIOSLength > 0x100000) {
		OffsetMode = 'A';
		Offset = (le16toh(abc->BeginHi) << 16) + le16toh(abc->BeginLo);
		if ((Offset - BIOSOffset) >= BIOSLength) {
OffsetModeB:
			OffsetMode = 'B';
			/* amideco considers 0x100000, but this only works up to 4 MB
			   8 MB is undecipherable so far */
			PackedOffset = 0x100000;
			Offset = (le16toh(abc->BeginHi) << 4) + le16toh(abc->BeginLo);
			Offset = BIOSLength - (PackedOffset - (Offset + sizeof(struct abc))) - sizeof(struct abc);
		}
	} else {
		OffsetMode = 'C';
		Offset = (le16toh(abc->BeginHi) << 4) + le16toh(abc->BeginLo);
	}

	for (i = 0; i < 0x80; i++) {
		char filename[64], *ModuleName;
		unsigned char *Buffer;
		int BufferSize, ROMSize;

		if ((Offset - BIOSOffset) >= BIOSLength) {
			fprintf(stderr, "Error: part overruns buffer at %05X\n",
				Offset - BIOSOffset);
			return FALSE;
		}
		part = (struct part *)(BIOSImage + (Offset - BIOSOffset));

		if (part->IsComprs & 0x80)
			Compressed = FALSE;
		else
			Compressed = TRUE;

		/* even they claim they are compressed they arent */
		if ((part->PartID == 0x40) || (part->PartID == 0x60))
			Compressed = FALSE;

		if (part->PartID == 0x20) {
			uint16_t vid = le32toh(part->RealCS) & 0xFFFF;
			uint16_t pid = le32toh(part->RealCS) >> 16;
			sprintf(filename, "amipci_%04X_%04X.rom", vid, pid);
		} else if (part->PartID == 0x21) {
			sprintf(filename, "amilang_%c%c.rom",
				(le32toh(part->RealCS) >> 8) & 0xFF,
				le32toh(part->RealCS) & 0xFF);
		} else
			sprintf(filename, "amibody_%02x.rom", part->PartID);

NotCompressed:
		if (Compressed) {
			ROMSize = le32toh(part->ROMSize);
			BufferSize = le32toh(part->ExpSize);
		} else {
			BufferSize = le16toh(part->CSize);
			if (!BufferSize || (BufferSize == 0xFFFF)) {
				bigpart =
				    (struct bigpart *)(BIOSImage +
						       (Offset - BIOSOffset) -
						       sizeof(struct bigpart));
				BufferSize = le32toh(bigpart->CSize);
			}
			ROMSize = BufferSize;
		}

		/* misunderstood an offset mode B image */
		if ((i == 0) && (OffsetMode == 'A') && (ROMSize == 0xFFFFFFFF))
			goto OffsetModeB;

		if (Compressed)
			printf("0x%05X (%6d bytes)", Offset - BIOSOffset + 0x14,
			       ROMSize);
		else
			printf("0x%05X (%6d bytes)", Offset - BIOSOffset + 0x0C,
			       ROMSize);

		printf(" -> %-20s", filename);

		if (Compressed)
			printf(" (%6d bytes)", BufferSize);
		else
			printf("               ");

		ModuleName = AMI95ModuleNameGet(part->PartID);
		if (ModuleName)
			printf("  \"%s\"\n", ModuleName);
		else
			printf("\n");

		Buffer = MMapOutputFile(filename, BufferSize);
		if (!Buffer) {
			if (Compressed) {
				Compressed = FALSE;
				goto NotCompressed;
			} else {
				return FALSE;
			}
		}

		NewOffset = Offset - BIOSOffset;
		if (Compressed)
			NewOffset += 0x14;
		else
			NewOffset += 0x0C;

		if ((NewOffset + ROMSize) >= BIOSLength)
			ROMSize = BIOSLength - NewOffset;

		if (Compressed) {
			if (LH5Decode(BIOSImage + NewOffset,
				      ROMSize, Buffer, BufferSize) == -1) {
				Compressed = FALSE;
				munmap(Buffer, BufferSize);
				unlink(filename);
				goto NotCompressed;
			}
		} else
			memcpy(Buffer, BIOSImage + NewOffset,
			       ROMSize);

		munmap(Buffer, BufferSize);

		if ((le16toh(part->PrePartHi) == 0xFFFF)
		    || (le16toh(part->PrePartLo) == 0xFFFF))
			break;

		switch (OffsetMode) {
			case 'B':
				Offset =
				    (le16toh(part->PrePartHi) << 4) +
				    le16toh(part->PrePartLo);
				Offset = BIOSLength - (PackedOffset - (Offset + sizeof(struct abc))) - sizeof(struct abc);
				if ((Offset - BIOSOffset) < BIOSLength)
					break;

			case 'A':
				Offset =
				    (le16toh(part->PrePartHi) << 16) +
				    le16toh(part->PrePartLo);
				break;

			case 'C':
				Offset =
				    (le16toh(part->PrePartHi) << 4) +
				    le16toh(part->PrePartLo);
				break;
		}
	}

	return TRUE;
}
