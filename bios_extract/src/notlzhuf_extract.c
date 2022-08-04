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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* This is a weird compression scheme that Phoenix tools and phoedeco call
   "LZHUF", but it nowhere near matches LZHUF.C... phoedeco has a decompressor
   implemented almost entirely in assembly code lifted out of a BIOS (the IDA
   labels give it away), and since decompilers obviously struggle with the lack
   of a defined calling convention in hand-written assembly, I wrote this static,
   janky and incomplete x86 CPU emulator. Let's call it "JankyBox" after 86Box. */

typedef struct {
	union {
		uint32_t u32;
		uint16_t u16[2];
		uint8_t u8[4];
	} regs[8];
	unsigned int sf: 1, zf: 1, of: 1, cf: 1, temp;

	uint8_t stack[256];

	uint8_t mem[1048576]; /* 64K decompression buffer + 64K source buffer + big destination buffer (64K overflows in some cases) */
} state_t;

#define eax state->regs[0].u32
#define ax state->regs[0].u16[0]
#define al state->regs[0].u8[0]
#define ah state->regs[0].u8[1]
#define ecx state->regs[1].u32
#define cx state->regs[1].u16[0]
#define cl state->regs[1].u8[0]
#define ch state->regs[1].u8[1]
#define edx state->regs[2].u32
#define dx state->regs[2].u16[0]
#define dl state->regs[2].u8[0]
#define dh state->regs[2].u8[1]
#define ebx state->regs[3].u32
#define bx state->regs[3].u16[0]
#define bl state->regs[3].u8[0]
#define bh state->regs[3].u8[1]
#define esp state->regs[4].u32
#define sp state->regs[4].u16[0]
#define ebp state->regs[5].u32
#define bp state->regs[5].u16[0]
#define esi state->regs[6].u32
#define si state->regs[6].u16[0]
#define edi state->regs[7].u32
#define di state->regs[7].u16[0]

#define daten state->mem /* decompression buffer stored at start of memory for convenience */
#define smallword(a) *((uint16_t *) &a)
#define doubleword(a) *((uint32_t *) &a)

#define mov(a, b) a = b
#define movzx(a, b) a = b
#define xchg(a, b) { state->temp = a; a = b; b = state->temp; }

#define aluflags(a) { state->of = 0; state->sf = !!((a) & (0x80 << ((sizeof(a) - 1) * 8))); state->zf = !(a); }
#define or(a, b) { a |= b; aluflags(a); }
#define and(a, b) { a &= b; aluflags(a); }
#define xor(a, b) { a ^= b; aluflags(a); }
#define shr(a, b) { state->cf = (a >> (b - 1)) & 1; a >>= b; aluflags(a); }
#define shl(a, b) { state->cf = !!((a << (b - 1)) & (0x80 << ((sizeof(a) - 1) * 8))); a <<= b; aluflags(a); }

#define add(a, b) { a += b; aluflags(a); state->of = ((typeof(a))(a + b) != (a + b)); state->cf = ((a + b) >= (1 << sizeof(a))); }
#define subflags(a, b) { state->of = ((a - b) != ((int64_t) a) - ((int64_t) b)); state->cf = a < b; }
#define sub(a, b) { a -= b; aluflags(a); subflags(a, b); }
#define inc(a) { (a)++; aluflags(a); state->of = !(a); }
#define dec(a) { (a)--; aluflags(a); state->of = ((a) == ((typeof(a)) -1)); }

#define cmp(a, b) { aluflags(a - b); subflags(a, b); }
#define test(a, b) aluflags(a & b)

#define stosb() state->mem[edi++] = al
#define repe_stosd() { while (ecx) { *((uint32_t *) &state->mem[edi]) = eax; edi += 4; ecx--; } }

#define jmp(a) goto a
#define jz(a) { if (state->zf) goto a; }
#define jnz(a) { if (!state->zf) goto a; }
#define jnb(a) { if (!state->cf) goto a; }
#define jbe(a) { if (state->cf || state->zf) goto a; }
#define ja(a) { if (!state->cf && !state->zf) goto a; }
#define loop(a) { if (--ecx) goto a; }

#define call(a) a(state)
#define push(a) { *((typeof(a) *) &state->stack[esp]) = a; esp += sizeof(a); }
#define pushad() { uint32_t origesp = esp; push(eax); push(ecx); push(edx); push(ebx); push(origesp); push(ebp); push(esi); push(edi); }
#define pop(a) { esp -= sizeof(a); a = *((typeof(a) *) &state->stack[esp]); }
#define popad() { pop(edi); pop(esi); pop(ebp); esp -= 4; pop(ebx); pop(edx); pop(ecx); pop(eax); }

void e5(state_t *state) {
	push(eax);
	push(esi);

loc_0_72E0:
	inc(smallword(daten[edi + 0x1A27]));
	or(edi, edi);
	jz(loc_0_7351);
	mov(ax, smallword(daten[edi + 0x1A27]));
	cmp(ax, smallword(daten[edi + 0x1A25]));
	jbe(loc_0_734B);
	mov(esi, edi);

loc_0_72F4:
	sub(si, 2);
	cmp(ax, smallword(daten[esi + 0x1A25]));
	ja(loc_0_72F4);
	test(smallword(daten[edi + 0x1F1D]), 1);
	jz(loc_0_7311);
	movzx(ebx, smallword(daten[edi + 0x1531]));
	mov(smallword(daten[ebx + 0x103B]), si);
	mov(smallword(daten[ebx + 0x1039]), si);

loc_0_7311:
	test(smallword(daten[esi + 0x1F1D]), 1);
	jz(loc_0_7325);
	movzx(ebx, smallword(daten[esi + 0x1531]));
	mov(smallword(daten[ebx + 0x103B]), di);
	mov(smallword(daten[ebx + 0x1039]), di);

loc_0_7325:
	mov(ax, smallword(daten[esi + 0x1531]));
	xchg(ax, smallword(daten[edi + 0x1531]));
	mov(smallword(daten[esi + 0x1531]), ax);
	mov(ax, smallword(daten[esi + 0x1A27]));
	xchg(ax, smallword(daten[edi + 0x1A27]));
	mov(smallword(daten[esi + 0x1A27]), ax);
	mov(ax, smallword(daten[esi + 0x1F1D]));
	xchg(ax, smallword(daten[edi + 0x1F1D]));
	mov(smallword(daten[esi + 0x1F1D]), ax);
	mov(edi, esi);

loc_0_734B:
	movzx(edi, smallword(daten[edi + 0x103B]));
	jmp(loc_0_72E0);

loc_0_7351:
	pop(esi);
	pop(eax);
}

void hole_bit(state_t *state) {
hole_bit00:
	shr(dh, 1);
	or(dh, dh);
	jnz(loc_0_7362);
	mov(dl, state->mem[esi]);
	mov(dh, 0x80);
	inc(esi);

loc_0_7362:
	shl(ax, 1);
	test(dl, dh);
	jz(loc_0_736A);
	or(al, 1);

loc_0_736A:
	loop(hole_bit00);
}

void e4(state_t *state) {
	push(eax);
	push(esi);

	movzx(esi, smallword(daten[0x2413]));
	mov(smallword(daten[esi + 0x103F]), si);
	mov(smallword(daten[esi + 0x1535]), ax);
	mov(smallword(daten[esi + 0x1A2B]), 0);
	mov(smallword(daten[esi + 0x1F21]), 0);
	mov(smallword(daten[esi + 0x103D]), si);
	mov(bx, smallword(daten[esi + 0x1531]));
	mov(smallword(daten[esi + 0x1533]), bx);
	mov(ax, smallword(daten[esi + 0x1A27]));
	mov(smallword(daten[esi + 0x1A29]), ax);
	mov(ax, smallword(daten[esi + 0x1F1D]));
	mov(smallword(daten[esi + 0x1F1F]), ax);
	mov(bx, 4);
	add(bx, si);
	mov(smallword(daten[esi + 0x1531]), bx);
	or(smallword(daten[esi + 0x1F1D]), 1);
	add(smallword(daten[0x2413]), 4);

	pop(esi);
	pop(eax);
}

void e3(state_t *state) {
	push(ebx);
	push(edi);

	xor(edi, edi);

loc_0_73BD:
	shr(dh, 1);
	or(dh, dh);
	jnz(loc_0_73CB);
	mov(dl, state->mem[esi]);
	mov(dh, 0x80);
	inc(esi);

loc_0_73CB:
	movzx(edi, smallword(daten[edi + 0x1531]));
	test(dh, dl);
	jz(loc_0_73D6);
	sub(di, 2);

loc_0_73D6:
	test(smallword(daten[edi + 0x1F1D]), 1);
	jnz(loc_0_73BD);
	mov(ax, smallword(daten[edi + 0x1531]));
	cmp(ax, 0x176);
	jnb(loc_0_7416);
	cmp(ax, 0x0FF);
	jbe(loc_0_7416);
	mov(ecx, 8);
	cmp(ax, 0x100);
	jz(loc_0_73FC);
	mov(ecx, 6);
	cmp(ax, 0x101);
	jnz(loc_0_7416);

loc_0_73FC:
	push(cx);
	xor(ax, ax);
	call(hole_bit);
	pop(cx);
	cmp(cl, 6);
	jnz(loc_0_740B);
	add(ax, 0x102);

loc_0_740B:
	movzx(edi, ax);
	shl(di, 1);
	call(e4);
	movzx(edi, smallword(daten[0x2413]));

loc_0_7416:
	call(e5);

	pop(edi);
	pop(ebx);
}

static void e6(state_t *state) {
	push(eax);
	push(edi);

	xor(eax, eax);
	mov(ecx, 8);
	call(hole_bit);
	movzx(edi, ax);
	movzx(ebp, daten[edi + 0x2415]);
	shl(bp, 6);
	movzx(ecx, daten[edi + 0x2515]);
	or(ecx, ecx);
	jz(loc_0_743C);
	call(hole_bit);

loc_0_743C:
	and(eax, 0x3F);
	or(ax, bp);
	mov(bp, bx);
	sub(bp, ax);

	pop(edi);
	pop(eax);
}

static void erzeuge_huff(state_t *state) {
	uint32_t kennung = 'H' + ('U' << 8) + ('F' << 16) + ('F' << 24);
	struct {
		uint8_t b;
		uint16_t anzahl;
	} __attribute__((packed)) word_0_7448[9] = {
		{ .b = 5, .anzahl =  8 },
		{ .b = 3, .anzahl =  8 },
		{ .b = 2, .anzahl = 16 },
		{ .b = 5, .anzahl = 32 },
		{ .b = 0, .anzahl = 64 },
		{ .b = 4, .anzahl = 16 },
		{ .b = 2, .anzahl = 16 },
		{ .b = 3, .anzahl = 32 },
		{ .b = 5, .anzahl = 64 }
	};
	struct {
		uint8_t von;
		uint8_t bis;
		uint8_t anzahl;
	} __attribute__((packed)) byte_0_745A[10] = {
		{ .von = 0x3E, .bis = 0x40, .anzahl =    2 },
		{ .von = 0x3C, .bis = 0x3E, .anzahl =    2 },
		{ .von =    3, .bis =    4, .anzahl =    8 },
		{ .von =    1, .bis =    2, .anzahl = 0x10 },
		{ .von = 0x0C, .bis = 0x1C, .anzahl =    2 },
		{ .von =    0, .bis =    1, .anzahl = 0x40 },
		{ .von =    8, .bis = 0x0C, .anzahl =    4 },
		{ .von =    2, .bis =    3, .anzahl = 0x10 },
		{ .von =    4, .bis =    8, .anzahl =    8 },
		{ .von = 0x1C, .bis = 0x3C, .anzahl =    2 }
	};

	if (*((uint32_t *) &daten[0x2615]) == kennung)
		return;

	uint8_t *ziel = &daten[0x2515];
	int zaehler;
	for (zaehler = 0; zaehler < (sizeof(word_0_7448) / sizeof(word_0_7448[0])); zaehler++) {
		memset(ziel, word_0_7448[zaehler].b, word_0_7448[zaehler].anzahl);
		ziel += word_0_7448[zaehler].anzahl;
	}

	ziel = &daten[0x2415];
	for (zaehler = 0; zaehler < (sizeof(byte_0_745A) / sizeof(byte_0_745A[0])); zaehler++) {
		uint8_t zeichen = byte_0_745A[zaehler].von;
		while (zeichen < byte_0_745A[zaehler].bis) {
			memset(ziel, zeichen, byte_0_745A[zaehler].anzahl);
			zeichen++;
			ziel += byte_0_745A[zaehler].anzahl;
		}
	}

	*((uint32_t *) &daten[0x2615]) = kennung;
}

static void e1(state_t *state) {
	uint16_t word_0_74BE[4][5] = {
		{0xffff, 0, 0, 2, 2},
		{4, 8, 0x100, 0x101, 0x102},
		{3, 2, 1, 1, 1},
		{1, 1, 0, 0, 0}
	};
	memcpy(&daten[0x103B], word_0_74BE[0], 10);
	memcpy(&daten[0x1531], word_0_74BE[1], 10);
	memcpy(&daten[0x1A27], word_0_74BE[2], 10);
	memcpy(&daten[0x1F1D], word_0_74BE[3], 10);
	smallword(daten[0x2413]) = 8;
}

static void entpacker(state_t *state) {
	xor(edx, edx);
	push(edi);
	push(esi);
	mov(eax, 0);
	mov(edi, 0);
	mov(ecx, 0x3f1);
	repe_stosd();
	pushad();
	call(e1);
	call(erzeuge_huff);
	popad();
	pop(esi);
	pop(edi);
	mov(ebx, 4036);

loc_0_7545:
	call(e3);
	or(ah, ah);
	jnz(loc_0_7559);
	stosb();
	mov(daten[ebx], al);
	inc(bx);
	and(bx, 0x0fff);
	jmp(loc_0_7545);

loc_0_7559:
	cmp(ax, 0x102);
	jz(loc_0_7585);
	call(e6);
	dec(bp);
	sub(ax, 0x100);
	xor(ecx, ecx);

loc_0_7567:
	cmp(cx, ax);
	jnb(loc_0_7545);
	push(ax);
	and(ebp, 0x0fff);
	mov(al, daten[ebp]);
	stosb();
	mov(daten[ebx], al);
	inc(bp);
	inc(cx);
	inc(bx);
	and(ebx, 0x0fff);
	pop(ax);
	jmp(loc_0_7567);

loc_0_7585:
	return;
}

int unnotlzh(unsigned char *in, int insz, unsigned char *out, int outsz) {
	state_t state_s = {0}, *state = &state_s;

	int srcoffset = 65536, destoffset = 131072;

	if (insz > (destoffset - srcoffset))
		insz = destoffset - srcoffset;
	memcpy(&state->mem[srcoffset], in, insz);

	esi = srcoffset;
	edi = destoffset;
	entpacker(state);

	if (outsz > (sizeof(state->mem) - destoffset))
		outsz = sizeof(state->mem) - destoffset;
	memcpy(out, &state->mem[destoffset], outsz);

	return edi - destoffset;
}
