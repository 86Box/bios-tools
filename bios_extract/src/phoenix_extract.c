/*
 * Copyright 2022	  RichardG <richardg867@gmail.com>
 * Based on PHOEDECO (c) 1998-2006 Veit Kannegieser
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

/*
 * Decompressors for the compression schemes used by Phoenix BIOS modules.
 *
 * Phoenix's own tools name these "LZSS", "LZARI" and "LZHUF", and two of
 * the three names are honest:
 *
 *   "LZSS"  (module compression type 3) is Okumura's LZSS unchanged, except
 *           that the 4 KB history window is pre-filled with a "common
 *           character" taken from the BIOS's BCP table instead of ' '.
 *
 *   "LZARI" (type 2) is Okumura's LZARI unchanged - order-0 adaptive
 *           arithmetic coding over an LZSS token stream - again with the
 *           configurable window fill.
 *
 *   "LZHUF" (type 4) is NOT Okumura's LZHUF. It is a Phoenix-specific
 *           adaptive Huffman coder whose alphabet *grows on demand* through
 *           two escape symbols, feeding an LZSS window with a fixed,
 *           hand-built Huffman code for match distances. See the block
 *           comment above unnotlzh() for the format.
 */

#include <stdint.h>
#include <string.h>

#include "phoenix_extract.h"

/* ------------------------------------------------------------------ */
/* Bit reader. All three formats read bits MSB-first out of whole bytes */
/* and read zeroes past the end of the input.                           */

typedef struct {
	const uint8_t *pos, *end;
	uint8_t byte, mask;
} bitreader;

static void br_init(bitreader *br, const uint8_t *in, int insz)
{
	br->pos = in;
	br->end = in + insz;
	br->byte = 0;
	br->mask = 0;	/* forces a fetch on the first getbit() */
}

static int br_bit(bitreader *br)
{
	br->mask >>= 1;
	if (!br->mask) {
		br->byte = (br->pos < br->end) ? *br->pos : 0;
		br->pos++;
		br->mask = 0x80;
	}
	return !!(br->byte & br->mask);
}

static unsigned br_bits(bitreader *br, unsigned acc, int n)
{
	while (n-- > 0)
		acc = (acc << 1) | br_bit(br);
	return acc;
}

/* ------------------------------------------------------------------ */
/* Output sink with a hard limit.                                       */

typedef struct {
	uint8_t *pos, *end;
	uint8_t *start;
} outbuf;

static void ob_init(outbuf *ob, uint8_t *out, int outsz)
{
	ob->start = ob->pos = out;
	ob->end = out + outsz;
}

static int ob_put(outbuf *ob, uint8_t c)
{
	if (ob->pos >= ob->end)
		return 0;
	*ob->pos++ = c;
	return 1;
}

/* ================================================================== */
/* "LZSS": Okumura LZSS, 4 KB window, 18 byte lookahead.               */
/*                                                                     */
/* A flag byte supplies eight tags, LSB first. A 1 tag is followed by  */
/* one literal byte; a 0 tag by two bytes holding a 12 bit window       */
/* offset and a 4 bit length (stored as length - 3).                    */

#define LZSS_N		4096		/* window size */
#define LZSS_F		18		/* lookahead size */
#define LZSS_THRESHOLD	3		/* shortest encodable match */

int unnotlzss(unsigned char *in, int insz, unsigned char *out, int outsz,
	      char common)
{
	uint8_t window[LZSS_N];
	const uint8_t *ip = in, *iend = in + insz;
	unsigned r = LZSS_N - LZSS_F, flags = 0;
	outbuf ob;

	memset(window, common, sizeof(window));
	ob_init(&ob, out, outsz);

	for (;;) {
		/* Refill the tag bits every eight tokens. The 0xFF00 marker
		   walks down with the tags and hits bit 8 when they run out. */
		flags >>= 1;
		if (!(flags & 0x100)) {
			if (ip >= iend)
				break;
			flags = 0xFF00 | *ip++;
		}

		if (flags & 1) {	/* literal */
			if (ip >= iend)
				break;
			if (!ob_put(&ob, *ip))
				break;
			window[r] = *ip++;
			r = (r + 1) % LZSS_N;
		} else {		/* match */
			unsigned pos, len, k;

			if ((ip + 1) >= iend)
				break;
			pos = ip[0] | ((ip[1] & 0xF0) << 4);
			len = (ip[1] & 0x0F) + LZSS_THRESHOLD;
			ip += 2;

			for (k = 0; k < len; k++) {
				uint8_t c = window[(pos + k) % LZSS_N];
				if (!ob_put(&ob, c))
					return ob.pos - ob.start;
				window[r] = c;
				r = (r + 1) % LZSS_N;
			}
		}
	}

	return ob.pos - ob.start;
}

/* ================================================================== */
/* "LZHUF": Phoenix's own adaptive Huffman over a growing alphabet.    */
/*                                                                     */
/* Symbols are read from an adaptive Huffman tree kept in the four      */
/* parallel arrays below. The alphabet is not fixed: it starts with     */
/* just three symbols and grows as the encoder announces new ones.      */
/*                                                                     */
/*   0x000..0x0FF  literal byte                                         */
/*   0x100         escape: 8 raw bits give a literal that is not yet in */
/*                 the tree. It is added and emitted.                   */
/*   0x101         escape: 6 raw bits + 0x102 give a length symbol that */
/*                 is not yet in the tree. It is added and used.        */
/*   0x102         end of stream                                        */
/*   0x103..0x141  match of (symbol - 0x100) bytes, i.e. 3..65          */
/*                                                                     */
/* The initial tree holds exactly the three symbols that can occur      */
/* before anything has been announced:                                  */
/*                                                                     */
/*        root            0  -> 0x100   (escape: new literal)           */
/*       /    \          10  -> 0x102   (end of stream)                 */
/*    0x100    *         11  -> 0x101   (escape: new length)            */
/*            /   \                                                     */
/*         0x102  0x101                                                 */
/*                                                                     */
/* A new symbol is grafted in by splitting the most recently added leaf */
/* (see huf_split()), so fresh symbols always start at the deep end of  */
/* the tree and migrate upwards as huf_update() reorders nodes by       */
/* frequency.                                                           */
/*                                                                     */
/* Nodes live in one array ordered by descending frequency, root first, */
/* with the two children of a node always adjacent. huf_update() keeps  */
/* that ordering by swapping a node with the first node of equal        */
/* frequency before incrementing it - the sibling-property maintenance  */
/* common to all FGK-style adaptive Huffman coders.                     */

#define HUF_LITERALS	0x100		/* symbols below this are literals */
#define HUF_ESC_LIT	0x100		/* announce a new literal */
#define HUF_ESC_LEN	0x101		/* announce a new length symbol */
#define HUF_END		0x102		/* end of stream */
#define HUF_LEN_BASE	0x100		/* length = symbol - HUF_LEN_BASE */

/* The original keeps the four arrays 0x4F6 bytes apart, so it has room for
   635 nodes; anything beyond that would scribble over the next array. Each
   announced symbol costs two nodes and there are at most 256 + 64 of them,
   so a well-formed stream stays well inside this. */
#define HUF_MAX_NODES	1024

#define HUF_WINDOW	4096
#define HUF_LOOKAHEAD	60

typedef struct {
	uint16_t parent[HUF_MAX_NODES];
	uint16_t child[HUF_MAX_NODES];	/* high child; low child is child - 1 */
	uint16_t freq[HUF_MAX_NODES];
	uint8_t internal[HUF_MAX_NODES];
	uint16_t newest;		/* leaf that the next new symbol splits */
} huftree;

static void huf_init(huftree *t)
{
	static const uint16_t parent[5]	  = {     0,     0,     0,     1,     1 };
	static const uint16_t child[5]	  = {     2,     4, 0x100, 0x101, 0x102 };
	static const uint16_t freq[5]	  = {     3,     2,     1,     1,     1 };
	static const uint8_t  internal[5] = {     1,     1,     0,     0,     0 };

	memset(t, 0, sizeof(*t));
	memcpy(t->parent, parent, sizeof(parent));
	memcpy(t->child, child, sizeof(child));
	memcpy(t->freq, freq, sizeof(freq));
	memcpy(t->internal, internal, sizeof(internal));
	t->newest = 4;
}

/* Turn the most recently added leaf into an internal node, moving the symbol
   it held into the new low child and putting sym in the new high child. */
static int huf_split(huftree *t, uint16_t sym)
{
	uint16_t n = t->newest;

	if ((n + 2) >= HUF_MAX_NODES)
		return 0;

	t->parent[n + 2]   = n;
	t->child[n + 2]    = sym;
	t->freq[n + 2]     = 0;
	t->internal[n + 2] = 0;

	t->parent[n + 1]   = n;
	t->child[n + 1]    = t->child[n];
	t->freq[n + 1]     = t->freq[n];
	t->internal[n + 1] = t->internal[n];

	t->child[n]    = n + 2;
	t->internal[n] = 1;

	t->newest = n + 2;
	return 1;
}

/* Add one to the frequency of node n and of every node up to the root,
   restoring the descending-frequency ordering as it goes. */
static void huf_update(huftree *t, uint16_t n)
{
	for (;;) {
		uint16_t f;

		t->freq[n]++;
		if (n == 0)
			return;		/* reached the root */

		f = t->freq[n];
		if (f > t->freq[n - 1]) {
			/* Find the first node of this frequency block and swap
			   with it, so the array stays sorted. */
			uint16_t m = n, c;

			do {
				m--;
			} while (m > 0 && f > t->freq[m - 1]);

			if (t->internal[n]) {
				c = t->child[n];
				t->parent[c] = m;
				t->parent[c - 1] = m;
			}
			if (t->internal[m]) {
				c = t->child[m];
				t->parent[c] = n;
				t->parent[c - 1] = n;
			}

			c = t->child[n]; t->child[n] = t->child[m]; t->child[m] = c;
			c = t->freq[n];  t->freq[n]  = t->freq[m];  t->freq[m]  = c;
			c = t->internal[n];
			t->internal[n] = t->internal[m];
			t->internal[m] = c;

			n = m;
		}

		n = t->parent[n];
	}
}

/* Read one symbol, resolving the two escapes and updating the tree. */
static int huf_decode_symbol(huftree *t, bitreader *br)
{
	uint16_t n = 0;
	int sym;

	do {
		n = t->child[n];
		if (br_bit(br))
			n--;
		if (n >= HUF_MAX_NODES)
			return -1;
	} while (t->internal[n]);

	sym = t->child[n];

	if (sym == HUF_ESC_LIT || sym == HUF_ESC_LEN) {
		if (sym == HUF_ESC_LIT)
			sym = br_bits(br, 0, 8);
		else
			sym = br_bits(br, 0, 6) + HUF_END;

		if (!huf_split(t, sym))
			return -1;
		n = t->newest;
	}

	huf_update(t, n);
	return sym;
}

/* Match distances use a fixed Huffman code over the top six bits of the
   12 bit distance, followed by the low six bits verbatim. The encoder reads
   eight bits, looks the byte up in these two tables to learn the top six
   bits and how many more bits the code needed, then reads those. Code
   lengths run from 2 bits (distance 0x000..0x03F, the most recent bytes)
   to 7 bits. Generated by the erzeuge_huff()/"HUFF" table builder. */
static const uint8_t huf_dist_hi[256] = {
	0x3E, 0x3E, 0x3F, 0x3F, 0x3C, 0x3C, 0x3D, 0x3D, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x0C, 0x0C, 0x0D, 0x0D, 0x0E, 0x0E, 0x0F, 0x0F, 0x10, 0x10, 0x11, 0x11, 0x12, 0x12, 0x13, 0x13,
	0x14, 0x14, 0x15, 0x15, 0x16, 0x16, 0x17, 0x17, 0x18, 0x18, 0x19, 0x19, 0x1A, 0x1A, 0x1B, 0x1B,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x08, 0x08, 0x08, 0x09, 0x09, 0x09, 0x09, 0x0A, 0x0A, 0x0A, 0x0A, 0x0B, 0x0B, 0x0B, 0x0B,
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x1C, 0x1C, 0x1D, 0x1D, 0x1E, 0x1E, 0x1F, 0x1F, 0x20, 0x20, 0x21, 0x21, 0x22, 0x22, 0x23, 0x23,
	0x24, 0x24, 0x25, 0x25, 0x26, 0x26, 0x27, 0x27, 0x28, 0x28, 0x29, 0x29, 0x2A, 0x2A, 0x2B, 0x2B,
	0x2C, 0x2C, 0x2D, 0x2D, 0x2E, 0x2E, 0x2F, 0x2F, 0x30, 0x30, 0x31, 0x31, 0x32, 0x32, 0x33, 0x33,
	0x34, 0x34, 0x35, 0x35, 0x36, 0x36, 0x37, 0x37, 0x38, 0x38, 0x39, 0x39, 0x3A, 0x3A, 0x3B, 0x3B,
};

static const uint8_t huf_dist_extra[256] = {
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
};

static unsigned huf_decode_distance(bitreader *br)
{
	unsigned i = br_bits(br, 0, 8);
	unsigned hi = huf_dist_hi[i];
	unsigned extra = huf_dist_extra[i];

	/* The bits of i past the prefix are the top of the low six bits; the
	   remaining "extra" bits are shifted in below them. */
	if (extra)
		i = br_bits(br, i, extra);

	return (hi << 6) | (i & 0x3F);
}

int unnotlzh(unsigned char *in, int insz, unsigned char *out, int outsz)
{
	uint8_t window[HUF_WINDOW];
	huftree t;
	bitreader br;
	outbuf ob;
	unsigned r = HUF_WINDOW - HUF_LOOKAHEAD;

	memset(window, 0, sizeof(window));
	huf_init(&t);
	br_init(&br, in, insz);
	ob_init(&ob, out, outsz);

	for (;;) {
		int sym = huf_decode_symbol(&t, &br);

		if (sym < 0 || sym == HUF_END)
			break;

		if (sym < HUF_LITERALS) {		/* literal */
			if (!ob_put(&ob, sym))
				break;
			window[r] = sym;
			r = (r + 1) % HUF_WINDOW;
		} else {				/* match */
			unsigned src = (r - huf_decode_distance(&br) - 1) % HUF_WINDOW;
			unsigned len = sym - HUF_LEN_BASE, k;

			for (k = 0; k < len; k++) {
				uint8_t c = window[src % HUF_WINDOW];
				if (!ob_put(&ob, c))
					return ob.pos - ob.start;
				window[r] = c;
				r = (r + 1) % HUF_WINDOW;
				src++;
			}
		}
	}

	return ob.pos - ob.start;
}

/* ================================================================== */
/* "LZARI": Okumura LZARI. Order-0 adaptive arithmetic coding of the   */
/* same LZSS token stream, with a static, distance-biased model for    */
/* match positions. The stream opens with a 32 bit little endian       */
/* uncompressed length.                                                 */

#define ARI_N		4096			/* window size */
#define ARI_F		60			/* lookahead size */
#define ARI_THRESHOLD	2
#define ARI_N_CHAR	(256 - ARI_THRESHOLD + ARI_F)	/* 314 symbols */

#define ARI_M	15
#define ARI_Q1	(1UL << ARI_M)			/* 0x08000 */
#define ARI_Q2	(2 * ARI_Q1)			/* 0x10000 */
#define ARI_Q3	(3 * ARI_Q1)			/* 0x18000 */
#define ARI_Q4	(4 * ARI_Q1)			/* 0x20000 */
#define ARI_MAX_CUM (ARI_Q1 - 1)

typedef struct {
	bitreader br;
	uint32_t low, high, value;

	/* Adaptive order-0 model over the 314 symbols. Symbols are kept
	   sorted by descending frequency; char_to_sym/sym_to_char map
	   between a symbol value and its rank. */
	uint16_t char_to_sym[ARI_N_CHAR + 1];
	uint16_t sym_to_char[ARI_N_CHAR + 1];
	uint16_t sym_freq[ARI_N_CHAR + 1];
	uint16_t sym_cum[ARI_N_CHAR + 1];

	/* Static model for match positions: 10000/(i+200) weights the
	   recent history more heavily than the distant history. */
	uint16_t pos_cum[ARI_N + 1];
} aristate;

static void ari_start_model(aristate *s)
{
	int i;

	s->sym_cum[ARI_N_CHAR] = 0;
	for (i = ARI_N_CHAR; i >= 1; i--) {
		s->char_to_sym[i - 1] = i;
		s->sym_to_char[i] = i - 1;
		s->sym_freq[i] = 1;
		s->sym_cum[i - 1] = s->sym_cum[i] + 1;
	}
	s->sym_freq[0] = 0;

	s->pos_cum[ARI_N] = 0;
	for (i = ARI_N; i >= 1; i--)
		s->pos_cum[i - 1] = s->pos_cum[i] + 10000 / (i + 200);
}

static void ari_update_model(aristate *s, int sym)
{
	int i;

	if (s->sym_cum[0] >= ARI_MAX_CUM) {	/* halve every count */
		int c = 0;

		for (i = ARI_N_CHAR; i > 0; i--) {
			s->sym_cum[i] = c;
			s->sym_freq[i] = (s->sym_freq[i] + 1) / 2;
			c += s->sym_freq[i];
		}
		s->sym_cum[0] = c;
	}

	/* Promote sym to the front of its frequency block, then bump it. */
	for (i = sym; i > 0 && s->sym_freq[i] == s->sym_freq[i - 1]; i--)
		;
	if (i < sym) {
		int ch_i = s->sym_to_char[i], ch_sym = s->sym_to_char[sym];

		s->sym_to_char[i] = ch_sym;
		s->sym_to_char[sym] = ch_i;
		s->char_to_sym[ch_i] = sym;
		s->char_to_sym[ch_sym] = i;
	}
	s->sym_freq[i]++;
	while (i-- > 0)
		s->sym_cum[i]++;
}

static int ari_search_sym(aristate *s, unsigned x)
{
	int i = 1, j = ARI_N_CHAR;

	while (i < j) {
		int k = (i + j) / 2;

		if (s->sym_cum[k] > x)
			i = k + 1;
		else
			j = k;
	}
	return i;
}

static int ari_search_pos(aristate *s, unsigned x)
{
	int i = 1, j = ARI_N;

	while (i < j) {
		int k = (i + j) / 2;

		if (s->pos_cum[k] > x)
			i = k + 1;
		else
			j = k;
	}
	return i - 1;
}

/* Narrow the interval to [cum_hi, cum_lo) of total, then renormalise. */
static void ari_narrow(aristate *s, uint32_t cum_hi, uint32_t cum_lo,
		       uint32_t total)
{
	uint32_t range = s->high - s->low;

	s->high = s->low + (uint32_t)(((uint64_t)range * cum_hi) / total);
	s->low  = s->low + (uint32_t)(((uint64_t)range * cum_lo) / total);

	for (;;) {
		if (s->low >= ARI_Q2) {
			s->value -= ARI_Q2;
			s->low   -= ARI_Q2;
			s->high  -= ARI_Q2;
		} else if (s->low >= ARI_Q1 && s->high <= ARI_Q3) {
			s->value -= ARI_Q1;
			s->low   -= ARI_Q1;
			s->high  -= ARI_Q1;
		} else if (s->high > ARI_Q2) {
			break;
		}
		s->low   <<= 1;
		s->high  <<= 1;
		s->value = (s->value << 1) + br_bit(&s->br);
	}
}

static uint32_t ari_target(aristate *s, uint32_t total)
{
	uint32_t range = s->high - s->low;

	return (uint32_t)((((uint64_t)(s->value - s->low + 1) * total) - 1) / range);
}

static int ari_decode_char(aristate *s)
{
	int sym = ari_search_sym(s, ari_target(s, s->sym_cum[0]));
	int ch = s->sym_to_char[sym];

	ari_narrow(s, s->sym_cum[sym - 1], s->sym_cum[sym], s->sym_cum[0]);
	ari_update_model(s, sym);
	return ch;
}

static int ari_decode_position(aristate *s)
{
	int pos = ari_search_pos(s, ari_target(s, s->pos_cum[0]));

	ari_narrow(s, s->pos_cum[pos], s->pos_cum[pos + 1], s->pos_cum[0]);
	return pos;
}

int unnotlzari(unsigned char *in, int insz, unsigned char *out, int outsz,
	       char common)
{
	uint8_t window[ARI_N];
	aristate s;
	outbuf ob;
	uint32_t textsize, count = 0;
	unsigned r = ARI_N - ARI_F;
	int i;

	ob_init(&ob, out, outsz);
	if (insz < 4)
		return 0;

	textsize = in[0] | (in[1] << 8) | (in[2] << 16) | ((uint32_t)in[3] << 24);
	if (!textsize)
		return 0;

	memset(&s, 0, sizeof(s));
	memset(window, common, sizeof(window));
	br_init(&s.br, in + 4, insz - 4);

	s.low = 0;
	s.high = ARI_Q4;
	s.value = 0;
	for (i = 0; i < ARI_M + 2; i++)
		s.value = (s.value << 1) + br_bit(&s.br);

	ari_start_model(&s);

	while (count < textsize) {
		int c = ari_decode_char(&s);

		if (c < 256) {			/* literal */
			if (!ob_put(&ob, c))
				break;
			window[r] = c;
			r = (r + 1) % ARI_N;
			count++;
		} else {			/* match */
			unsigned src = (r - ari_decode_position(&s) - 1) % ARI_N;
			unsigned len = c - 255 + ARI_THRESHOLD, k;

			for (k = 0; k < len; k++) {
				uint8_t b = window[(src + k) % ARI_N];

				if (!ob_put(&ob, b))
					return ob.pos - ob.start;
				window[r] = b;
				r = (r + 1) % ARI_N;
				count++;
			}
		}
	}

	return ob.pos - ob.start;
}
