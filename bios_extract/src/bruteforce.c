#define _GNU_SOURCE 1		/* for memmem */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include "compat.h"
#include "bios_extract.h"
#include "lh5_extract.h"
#include "lzss_extract.h"

/* for phoenix.c */
unsigned char *MMapOutputFile(char *filename, int size) { return NULL; }
void InitRemainder(unsigned char *BIOSImage, int BIOSLength) {}
void SetRemainder(uint32_t Offset, uint32_t Length, int val) {}

static int try_realloc(uint8_t **pbuf, size_t orig_size, size_t new_size)
{
	void *newbuf = realloc(*pbuf, new_size);
	if (!newbuf)
		return orig_size;
	*pbuf = newbuf;
	return new_size;
}

int main(int argc, char *argv[])
{
	/* Check if this is being called directly. */
	if ((argc < 2) || strcmp(argv[1], "[magic]")) {
		printf("This is not meant to be called directly, please use bruteforce.py\n");
		return 1;
	}

	/* Disable stdout buffering. */
	setvbuf(stdout, NULL, _IONBF, 0);

	/* Tell compression algorithms we're in bruteforce mode. */
	lzari_in_bruteforce = 1;

	/* Create buffers. */
	struct {
		int size;
		uint8_t *buf;
	} bufs[8];
	for (int i = 0; i < (sizeof(bufs) / sizeof(bufs[0])); i++) {
		bufs[i].size = 0;
		bufs[i].buf = NULL;
	}

	/* Receive commands. */
	char cmd_s[256];
	int scanned, ret;
	unsigned int cmd, params[10];
	while (fgets(cmd_s, sizeof(cmd_s), stdin)) {
		/* Read command. */
		scanned = sscanf(cmd_s, "%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d", &cmd, &params[0], &params[1], &params[2], &params[3], &params[4], &params[5], &params[6], &params[7], &params[8], &params[9]);
		if (scanned < 2)
			continue;

		/* Clamp buffer number. */
		if (params[0] >= (sizeof(bufs) / sizeof(bufs[0])))
			params[0] = 0;

		/* Parse command. */
		if ((cmd == 0) && (scanned >= 2)) { /* loadfile;bufnum[LF]path[LF] */
			/* Read new file path. */
			fgets(cmd_s, sizeof(cmd_s), stdin);
			cmd_s[strlen(cmd_s) - 1] = '\0';

			/* Open file. */
			int fd = open(cmd_s, O_RDONLY);
			if (fd != -1) {
				int file_size = lseek(fd, 0, SEEK_END);
				if (file_size > bufs[params[0]].size)
					bufs[params[0]].size = try_realloc(&bufs[params[0]].buf, bufs[params[0]].size, file_size);

				/* Load file contents. */
				lseek(fd, 0, SEEK_SET);
				ret = read(fd, bufs[params[0]].buf, bufs[params[0]].size);
				close(fd);
			} else {
				ret = -1;
			}

			/* Write result. */
			printf("%d\n", ret);
		} else if ((cmd == 1) && (scanned >= 3)) { /* initbuf;bufnum;size */
			if (params[1] != bufs[params[0]].size) {
				bufs[params[0]].size = try_realloc(&bufs[params[0]].buf, bufs[params[0]].size, params[1]);
				memset(bufs[params[0]].buf, 0, bufs[params[0]].size);
			}

			/* Write result. */
			printf("%d\n", bufs[params[0]].size);
		} else if ((cmd == 2) && (scanned >= 4)) { /* readbuf;bufnum;offset;size */
			/* Clamp size. */
			if (!bufs[params[0]].buf || (params[1] >= bufs[params[0]].size))
				params[2] = 0;
			else if ((params[1] + params[2]) > bufs[params[0]].size)
				params[2] = bufs[params[0]].size - params[1];

			/* Write length. */
			printf("%d\n", params[2]);

			/* Write data. */
			if (params[2] > 0)
				fwrite(bufs[params[0]].buf + params[1], 1, params[2], stdout);
		} else if ((cmd == 3) && (scanned >= 8)) { /* decompress;srcbufnum;srcoffset;srcsize;destbufnum;destoffset;destsize;algo */
			/* Clamp buffer sizes. */
			if (!bufs[params[0]].buf || (params[1] >= bufs[params[0]].size))
				params[2] = 0;
			else if ((params[1] + params[2]) > bufs[params[0]].size)
				params[2] = bufs[params[0]].size - params[1];

			if (!bufs[params[3]].buf || (params[4] >= bufs[params[3]].size))
				params[5] = 0;
			else if ((params[1] + params[5]) > bufs[params[3]].size)
				params[5] = bufs[params[3]].size - params[4];

			/* Clear output buffer. */
			memset(bufs[params[3]].buf + params[4], 0, params[5]);

			/* Decompress using the specified algorithm. */
			switch (params[6]) {
				case 0:
					ret = LH5Decode(bufs[params[0]].buf + params[1], params[2], bufs[params[3]].buf + params[4], params[5]);
					break;

				case 1:
					ret = unlzari(bufs[params[0]].buf + params[1], params[2], bufs[params[3]].buf + params[4], params[5], ' ');
					break;

				case 2:
					PhoenixBCD6F1Decode(bufs[params[0]].buf + params[1], params[2], bufs[params[3]].buf + params[4], params[5]);
					ret = 0;
					break;

				case 3:
					ret = unlzh(bufs[params[0]].buf + params[1], params[2], bufs[params[3]].buf + params[4], params[5]);
					break;
			}

			/* Write result. */
			printf("%d\n", ret);
		} else if (((cmd == 4) || (cmd == 5)) && (scanned >= 5)) { /* memmem;bufnum;offset;size;needlesize[LF]needle OR memchr;bufnum;offset;size;needlechar */
			/* Clamp buffer size. */
			if (!bufs[params[0]].buf || (params[1] >= bufs[params[0]].size))
				params[2] = 0;
			else if ((params[1] + params[2]) > bufs[params[0]].size)
				params[2] = bufs[params[0]].size - params[1];

			uint8_t *p = NULL;
			if (cmd == 4) {
				/* Clamp memmem needle size. */
				if (params[3] > sizeof(cmd_s))
					params[3] = sizeof(cmd_s);

				/* Read memmem needle. */
				fread(cmd_s, 1, params[3], stdin);

				/* Search buffer. */
				if (params[2] > 0)
					p = memmem(bufs[params[0]].buf + params[1], params[2], cmd_s, params[3]);
			} else {
				/* Search buffer. */
				if (params[2] > 0)
					p = memchr(bufs[params[0]].buf + params[1], params[2], params[3]);
			}

			/* Write result. */
			printf("%ld\n", p ? (p - bufs[params[0]].buf) : -1);
		}
	}

	return 0;
}
