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

#include <stdint.h>
#include <string.h>

/* Phoenix used a bunch of weird compression algorithms that were misnomers:
   LZSS that is not LZSS, LZHUF that is not LZHUF and LZARI that is not LZARI.
   Even their own tools use these wrong names. As for decompressing this mess,
   phoedeco got away with just lifting the x86 assembly code out of actual
   BIOS implementations, but that approach has many issues, including but not
   limited to a lack of portability. The assembly was all handwritten, which
   stumps decompilers due to a lack of calling convention. I managed to use a
   Ghidra decompilation of the "LZSS" algorithm as it's contained in a single
   function; as for the other algorithms, I wrote this very dodgy and very
   incomplete static x86 CPU emulator, which I'll call "JankyBox" after 86Box. */

typedef struct {
	union {
		uint32_t u32;
		uint16_t u16[2];
		uint8_t u8[4];
	} regs[8];
	uint16_t gs;
	union {
		struct {
			uint32_t sf: 1, zf: 1, of: 1, cf: 1;
		} flags;
		uint32_t eflags;
	};
	uint64_t temp;

	uint8_t stack[256];

	uint8_t mem[1048576]; /* big buffer because 64k overflows in some cases */
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

#define smallword(a) *((uint16_t *) &a)
#define doubleword(a) *((uint32_t *) &a)

#define mov(a, b) a = b
#define movzx(a, b) a = b
#define xchg(a, b) { state->temp = a; a = b; b = state->temp; }

#define aluflags(a) { state->flags.of = 0; state->flags.sf = !!((a) & (0x80 << ((sizeof(a) - 1) * 8))); state->flags.zf = !(a); }
#define or(a, b) { a |= b; aluflags(a); }
#define and(a, b) { a &= b; aluflags(a); }
#define xor(a, b) { a ^= b; aluflags(a); }
#define shr(a, b) { state->flags.cf = (a >> (b - 1)) & 1; a >>= b; aluflags(a); }
#define shl(a, b) { state->flags.cf = !!((a << (b - 1)) & (0x80 << ((sizeof(a) - 1) * 8))); a <<= b; aluflags(a); }

#define add(a, b) { state->flags.of = ((typeof(a))(a + b) != (a + b)); state->flags.cf = ((a + b) >= (1 << sizeof(a))); a += b; aluflags(a); }
#define subflags(a, b) { state->flags.of = ((a - b) != ((int64_t) a) - ((int64_t) b)); state->flags.cf = a < b; }
#define sub(a, b) { subflags(a, b); a -= b; aluflags(a); }
#define inc(a) { (a)++; aluflags(a); state->flags.of = !(a); }
#define dec(a) { (a)--; aluflags(a); state->flags.of = ((a) == ((typeof(a)) -1)); }
#define mul(a) { \
	switch (sizeof(a)) { \
		case 1: \
			ax = al * a; \
			state->flags.cf = state->flags.of = !!ah; \
			break; \
		case 2: \
			state->temp = (uint32_t) ax * (uint32_t) a; \
			ax = state->temp; \
			dx = state->temp >> 16; \
			state->flags.cf = state->flags.of = !!dx; \
			break; \
		case 4: \
			state->temp = (uint64_t) eax * (uint64_t) a; \
			eax = state->temp; \
			edx = state->temp >> 32; \
			state->flags.cf = state->flags.of = !!edx; \
			break; \
	} \
}
#define div(a) { \
	switch (sizeof(a)) { \
		case 1: \
			state->temp = ax; \
			al = state->temp / a; \
			ah = state->temp % a; \
			break; \
		case 2: \
			state->temp = ((uint32_t) dx << 16) | ax; \
			ax = state->temp / a; \
			dx = state->temp % a; \
			break; \
		case 4: \
			state->temp = ((uint64_t) edx << 32) | eax; \
			eax = state->temp / a; \
			edx = state->temp % a; \
			break; \
	} \
}

#define cmp(a, b) { subflags(a, b); aluflags(a - b); }
#define test(a, b) aluflags(a & b)
#define setnz(a) a = !state->flags.zf

#define lodsb() al = state->mem[esi++]
#define lodsd() { eax = doubleword(state->mem[esi]); esi += 4; }
#define stosb() state->mem[edi++] = al
#define repe_stosd() { while (ecx) { *((uint32_t *) &state->mem[edi]) = eax; edi += 4; ecx--; } }

#define jmp(a) goto a
#define jz(a) { if (state->flags.zf) goto a; }
#define jnz(a) { if (!state->flags.zf) goto a; }
#define jnb(a) { if (!state->flags.cf) goto a; }
#define jb(a) { if (state->flags.cf) goto a; }
#define jbe(a) { if (state->flags.cf || state->flags.zf) goto a; }
#define ja(a) { if (!state->flags.cf && !state->flags.zf) goto a; }
#define loop(a) { if (--ecx) goto a; }

#define call(a) a(state)
#define push(a) { *((typeof(a) *) &state->stack[esp]) = a; esp += sizeof(a); }
#define pushad() { uint32_t origesp = esp; push(eax); push(ecx); push(edx); push(ebx); push(origesp); push(ebp); push(esi); push(edi); }
#define pushfd() push(state->eflags)
#define pop(a) { esp -= sizeof(a); a = *((typeof(a) *) &state->stack[esp]); }
#define popad() { pop(edi); pop(esi); pop(ebp); esp -= 4; pop(ebx); pop(edx); pop(ecx); pop(eax); }
#define popfd() pop(state->eflags)

/* "LZHUF" algorithm implemented using JankyBox. */

static uint8_t daten[65536];

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
		{ .von = 0x3E, .bis = 0x40, .anzahl =	 2 },
		{ .von = 0x3C, .bis = 0x3E, .anzahl =	 2 },
		{ .von =	3, .bis =	 4, .anzahl =	 8 },
		{ .von =	1, .bis =	 2, .anzahl = 0x10 },
		{ .von = 0x0C, .bis = 0x1C, .anzahl =	 2 },
		{ .von =	0, .bis =	 1, .anzahl = 0x40 },
		{ .von =	8, .bis = 0x0C, .anzahl =	 4 },
		{ .von =	2, .bis =	 3, .anzahl = 0x10 },
		{ .von =	4, .bis =	 8, .anzahl =	 8 },
		{ .von = 0x1C, .bis = 0x3C, .anzahl =	 2 }
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

	int srcoffset = 0, destoffset = 65536;

	if (insz > (destoffset - srcoffset))
		insz = destoffset - srcoffset;
	memcpy(&state->mem[srcoffset], in, insz);

	esi = srcoffset;
	edi = destoffset;
	call(entpacker);

	if (outsz > (sizeof(state->mem) - destoffset))
		outsz = sizeof(state->mem) - destoffset;
	memcpy(out, &state->mem[destoffset], outsz);

	return edi - destoffset;
}

/* "LZARI" algorithm implemented using JankyBox. */

static uint32_t d_0, d_4, d_8, d_c,
				tw_10[0x13a], tw_284[0x13b], tw_4fa[0x13b], tw_770[0x13a],
				w_9e4, tw_9e6[0x1000],
				w_29e6, tb_29e8[0xfc4 + 10000];
static uint16_t gs_;

static void getbit_ax(state_t *state) {
	push(ebx);

	mov(bx, gs_);
	shr(bl, 1);
	jnz(noch_was_uebrig);

	lodsb();
	mov(bh, al);
	mov(bl, 0x80);

noch_was_uebrig:
	mov(gs_, bx);
	test(bl, bh);
	setnz(al);
	and(eax, 1);

	pop(ebx);
}

static void auspacken_3(state_t *state) {
	push(eax);
	push(ebx);
	push(edx);
	push(esi);

	xor(ebx, ebx);
	mov(esi, ebx);
	xor(eax, eax);
	mov(w_9e4, eax);
	mov(esi, 0x13A);

loc_0_6820:
	mov(ebx, esi);
	dec(ebx);
	mov(tw_10[ebx], esi);
	mov(tw_284[esi], ebx);
	mov(tw_4fa[esi], 1);
	mov(eax, tw_770[esi]);
	inc(eax);
	and(eax, 0xffff);
	dec(esi);
	mov(tw_770[esi], eax);
	cmp(esi, 1);
	jnb(loc_0_6820);
	xor(eax, eax);
	mov(tw_4fa[0], eax);
	xor(eax, eax);
	mov(w_29e6, eax);
	mov(esi, 0x1000);

loc_0_6861:
	mov(eax, 10000);
	mov(ebx, esi);
	add(ebx, 200);
	xor(edx, edx);
	div(ebx);
	add(eax, tw_9e6[esi]);
	and(eax, 0xffff);
	dec(esi);
	mov(tw_9e6[esi], eax);
	cmp(esi, 1);
	jnb(loc_0_6861);

	pop(esi);
	pop(edx);
	pop(ebx);
	pop(eax);
}

static void auspacken_6(state_t *state) {
	push(eax);
	push(ebx);
	push(ecx);
	push(edx);
	push(esi);
	push(edi);
	push(ebp);

	xor(ebx, ebx);
	mov(esi, ebx);
	mov(ecx, eax);
	cmp(tw_770[0], 0x7FFF);
	jb(loc_0_68CD);

	xor(ebp, ebp);
	mov(esi, 0x13A);

loc_0_68A9:
	mov(tw_770[esi], ebp);
	mov(eax, tw_4fa[esi]);
	inc(eax);
	and(eax, 0xffff);
	shr(eax, 1);
	mov(tw_4fa[esi], eax);
	add(ebp, eax);
	and(ebp, 0xffff);
	dec(esi);
	jnz(loc_0_68A9);
	mov(tw_770[0], ebp);

loc_0_68CD:
	mov(esi, ecx);

loc_0_68CF:
	dec(esi);
	and(esi, 0xffff);
	mov(eax, tw_4fa[esi]);
	inc(esi);
	and(esi, 0xffff);
	cmp(tw_4fa[esi], eax);
	jnz(loc_0_68E6);
	dec(esi);
	and(esi, 0xffff);
	jmp(loc_0_68CF);

loc_0_68E6:
	cmp(esi, ecx);
	jnb(loc_0_6920);
	mov(edx, tw_284[esi]);
	mov(ebx, ecx);
	mov(edi, tw_284[ebx]);
	mov(tw_284[esi], edi);
	mov(tw_284[ebx], edx);
	mov(ebx, edx);
	mov(tw_10[ebx], ecx);
	mov(ebx, edi);
	mov(tw_10[ebx], esi);

loc_0_6920:
	inc(tw_4fa[esi]);
	and(tw_4fa[esi], 0xffff);

loc_0_6928:
	sub(si, 1);
	jb(loc_0_6937);
	inc(tw_770[esi]);
	and(tw_770[esi], 0xffff);
	jmp(loc_0_6928);

loc_0_6937:
	pop(ebp);
	pop(edi);
	pop(esi);
	pop(edx);
	pop(ecx);
	pop(ebx);
	pop(eax);
}

static void auspacken_5(state_t *state) {
	push(ebx);
	push(ecx);
	push(edx);
	push(esi);

	xor(ebx, ebx);
	mov(ecx, eax);
	mov(esi, 1);
	mov(edx, 0x13A);

loc_0_6951:
	cmp(esi, edx);
	jnb(loc_0_696E);
	mov(ebx, esi);
	add(ebx, edx);
	and(ebx, 0xffff);
	shr(ebx, 1);
	cmp(tw_770[ebx], ecx);
	jbe(loc_0_696A);
	mov(esi, ebx);
	inc(esi);
	and(esi, 0xffff);
	jmp(loc_0_696C);

loc_0_696A:
	mov(edx, ebx);

loc_0_696C:
	jmp(loc_0_6951);

loc_0_696E:
	mov(eax, esi);

	pop(esi);
	pop(edx);
	pop(ecx);
	pop(ebx);
}

static void auspacken_8(state_t *state) {
	push(ebx);
	push(ecx);
	push(edx);
	push(esi);

	xor(ebx, ebx);
	mov(ecx, eax);
	mov(esi, 1);
	mov(dx, 0x1000);

loc_0_6986:
	cmp(esi, edx);
	jnb(loc_0_69A3);
	mov(ebx, esi);
	add(ebx, edx);
	and(ebx, 0xffff);
	shr(ebx, 1);
	cmp(tw_9e6[ebx], ecx);
	jbe(loc_0_699F);
	mov(esi, ebx);
	inc(esi);
	and(esi, 0xffff);
	jmp(loc_0_69A1);

loc_0_699F:
	mov(edx, ebx);

loc_0_69A1:
	jmp(loc_0_6986);

loc_0_69A3:
	mov(eax, esi);
	dec(eax);
	and(eax, 0xffff);

	pop(esi);
	pop(edx);
	pop(ecx);
	pop(ebx);
}

static void bits_17(state_t *state) {
	push(eax);
	push(ecx);

	mov(ecx, 17);

sl1:
	shl(d_c, 1);
	xor(eax, eax);
	call(getbit_ax);
	add(d_c, eax);
	loop(sl1);

	pop(ecx);
	pop(eax);
}

static void auspacken_4(state_t *state) {
	push(ebx);
	push(ecx);
	push(edx);
	push(edi);
	push(ebp);

	xor(ebx, ebx);
	mov(edi, d_8);
	sub(edi, d_4);
	mov(eax, d_c);
	sub(eax, d_4);
	inc(eax);
	mov(ecx, tw_770[0]);
	mul(ecx);
	dec(eax);
	xor(edx, edx);
	div(edi);
	call(auspacken_5);
	mov(ebx, eax);
	dec(ebx);
	and(ebx, 0xffff);
	mov(eax, tw_770[ebx]);
	inc(ebx);
	and(ebx, 0xffff);
	mul(edi);
	mov(ebp, ecx);
	xor(edx, edx);
	div(ebp);
	add(eax, d_4);
	mov(d_8, eax);
	mov(eax, tw_770[ebx]);
	mul(edi);
	mov(ebp, ecx);
	xor(edx, edx);
	div(ebp);
	add(d_4, eax);

loc_0_6A3C:
	cmp(d_4, 0x10000);
	jb(kleiner_64k);
	sub(d_c, 0x10000);
	sub(d_4, 0x10000);
	sub(d_8, 0x10000);
	jmp(loc_0_6AA4);

kleiner_64k:
	cmp(d_4, 0x8000);
	jb(loc_0_6A97);
	cmp(d_8, 0x18000);
	ja(loc_0_6A97);

//loc_0_6A7A:
	sub(d_c, 0x8000);
	sub(d_4, 0x8000);
	sub(d_8, 0x8000);
	jmp(loc_0_6AA4);

loc_0_6A97:
	cmp(d_8, 0x10000);
	jbe(loc_0_6AA4);
	jmp(loc_0_6AC1);

loc_0_6AA4:
	shl(d_4, 1);
	shl(d_8, 1);
	shl(d_c, 1);
	xor(eax, eax);
	call(getbit_ax);
	add(d_c, eax);
	jmp(loc_0_6A3C);

loc_0_6AC1:
	mov(ecx, tw_284[ebx]);
	mov(eax, ebx);
	call(auspacken_6);
	mov(eax, ecx);

	pop(ebp);
	pop(edi);
	pop(edx);
	pop(ecx);
	pop(ebx);
}

static void auspacken_7(state_t *state) {
	push(ebx);
	push(ecx);
	push(edx);
	push(edi);
	push(ebp);

	xor(ebx, ebx);
	mov(edi, d_8);
	sub(edi, d_4);
	mov(eax, d_c);
	sub(eax, d_4);
	inc(eax);
	mov(ecx, tw_9e6[0]);
	mul(ecx);
	dec(eax);
	xor(edx, edx);
	div(edi);
	call(auspacken_8);
	mov(ebx, eax);
	mov(eax, tw_9e6[ebx]);
	mul(edi);
	mov(ebp, ecx);
	xor(edx, edx);
	div(ebp);
	add(eax, d_4);
	mov(d_8, eax);
	inc(ebx);
	and(ebx, 0xffff);
	mov(eax, tw_9e6[ebx]);
	dec(ebx);
	and(ebx, 0xffff);
	mul(edi);
	mov(ebp, ecx);
	xor(edx, edx);
	div(ebp);
	add(d_4, eax);

loc_0_6B4F:
	cmp(d_4, 0x10000);
	jb(loc_0_6B77);
	sub(d_c, 0x10000);
	sub(d_4, 0x10000);
	sub(d_8, 0x10000);
	jmp(loc_0_6BB7);

loc_0_6B77:
	cmp(d_4, 0x8000);
	jb(loc_0_6BAA);
	cmp(d_8, 0x18000);
	ja(loc_0_6BAA);
	sub(d_c, 0x8000);
	sub(d_4, 0x8000);
	sub(d_8, 0x8000);
	jmp(loc_0_6BB7);

loc_0_6BAA:
	cmp(d_8, 0x10000);
	jbe(loc_0_6BB7);
	jmp(loc_0_6BD4);

loc_0_6BB7:
	shl(d_4, 1);
	shl(d_8, 1);
	shl(d_c, 1);
	xor(eax, eax);
	call(getbit_ax);
	add(d_c, eax);
	jmp(loc_0_6B4F);

loc_0_6BD4:
	mov(eax, ebx);
	and(eax, 0xffff);

	pop(ebp);
	pop(edi);
	pop(edx);
	pop(ecx);
	pop(ebx);
}

static void auspacken_2(state_t *state) {
	pushad();
	pushfd();

	uint32_t index, var_6, var_4, var_2;

	xor(eax, eax);
	mov(d_0, eax);
	mov(d_4, eax);
	mov(d_8, 0x20000);
	mov(d_c, eax);
	mov(gs_, ax);

	lodsd();
	mov(d_0, eax);
	or(eax, eax);
	jz(auspacken_fertig);

	call(bits_17);
	call(auspacken_3);
	mov(index, 0x0FC4);
	xor(ecx, ecx);

weiter_auspacken:
	call(auspacken_4);
	mov(edx, eax);
	cmp(edx, 0x100);
	jnb(loc_0_6C60);
	mov(al, dl);
	stosb();
	mov(ebx, index);
	mov(tb_29e8[ebx], dl);
	inc(index);
	and(index, 0x0FFF);
	inc(ecx);
	jmp(pruefe_laenge);

loc_0_6C60:
	call(auspacken_7);
	mov(ebx, index);
	sub(ebx, eax);
	dec(ebx);
	and(ebx, 0x0FFF);
	mov(var_2, ebx);
	mov(eax, edx);
	add(eax, 2);
	sub(eax, 0x0FF);
	mov(var_4, eax);
	mov(var_6, 0);

loc_0_6C80:
	mov(eax, var_6);
	cmp(eax, var_4);
	jnb(pruefe_laenge);
	mov(ebx, var_2);
	add(ebx, var_6);
	and(ebx, 0x0FFF);
	mov(dl, tb_29e8[ebx]);
	mov(al, dl);
	stosb();
	mov(ebx, index);
	mov(tb_29e8[ebx], dl);
	inc(index);
	and(index, 0x0FFF);
	inc(ecx);
	inc(var_6);
	jmp(loc_0_6C80);

pruefe_laenge:
	cmp(ecx, d_0);
	jb(weiter_auspacken);

auspacken_fertig:
	popfd();
	popad();
}

int unnotlzari(unsigned char *in, int insz, unsigned char *out, int outsz, char common) {
	state_t state_s = {0}, *state = &state_s;

	int srcoffset = 0, destoffset = 65536;

	if (insz > (destoffset - srcoffset))
		insz = destoffset - srcoffset;
	memcpy(&state->mem[srcoffset], in, insz);

	w_9e4 = 0;
	w_29e6 = 0;
	memset(tb_29e8, common, sizeof(tb_29e8));

	esi = srcoffset;
	edi = destoffset;
	ecx = insz;
	call(auspacken_2);

	if (outsz > (sizeof(state->mem) - destoffset))
		outsz = sizeof(state->mem) - destoffset;
	memcpy(out, &state->mem[destoffset], outsz);

	return edi - destoffset;
}

/* "LZSS" algorithm implemented using a Ghidra decompilation of the assembly code. */

void unnotlzss(unsigned char *in, int insz,
			   unsigned char *out, int outsz, char common) {
	uint8_t DAT_00729668[0x1000];
	memset(DAT_00729668, common, sizeof(DAT_00729668));
	uint8_t bVar1;
	uint8_t *pbVar2;
	int32_t iVar3;
	uint32_t uVar4;
	uint32_t uVar5;
	uint32_t uVar6;
	uint8_t *unaff_ESI = in;
	uint8_t *pbVar7;
	uint8_t *unaff_EDI = out;

	pbVar2 = unaff_ESI + insz;
	uVar4 = 0;
	uVar5 = 0xfee;
	do {
		uVar4 = uVar4 >> 1;
		pbVar7 = unaff_ESI;
		if ((uVar4 & 0x100) == 0) {
			if (unaff_ESI == pbVar2) break;
			pbVar7 = unaff_ESI + 1;
			uVar4 = 0xff00 | *unaff_ESI;
		}
		if ((uVar4 & 1) == 0) {
			if (pbVar7 == pbVar2) break;
			if (pbVar7 + 1 == pbVar2) break;
			unaff_ESI = pbVar7 + 2;
			uVar6 = (uint32_t)pbVar7[1];
			iVar3 = (uVar6 & 0xf) + 3;
			uVar6 = (uint32_t)*pbVar7 | (uVar6 & 0xf0) << 4;
			pbVar7 = unaff_EDI;
			do {
				bVar1 = DAT_00729668[uVar6];
				uVar6 = (uVar6 + 1) & 0xfff;
				unaff_EDI = pbVar7 + 1;
				*pbVar7 = bVar1;
				DAT_00729668[uVar5] = bVar1;
				uVar5 = (uVar5 + 1) & 0xfff;
				iVar3 = iVar3 + -1;
				pbVar7 = unaff_EDI;
			} while (iVar3 != 0);
		}
		else {
			if (pbVar7 == pbVar2 || unaff_EDI >= (out + outsz)) break;
			unaff_ESI = pbVar7 + 1;
			bVar1 = *pbVar7;
			*unaff_EDI = bVar1;
			DAT_00729668[uVar5] = bVar1;
			uVar5 = (uVar5 + 1) & 0xfff;
			unaff_EDI = unaff_EDI + 1;
		}
	} while( 1 );
}
