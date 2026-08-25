"""
Extractor for ICL ErgoPro flash images (*.LDB, "OKICL1" / "FL_PACK").

Layout of a .LDB file (128 KB flash image):

	0x00000  "OKICL1", 0x28: "FL_PACK"          - 0x40-byte header
	0x00040  LZHUF-compressed module set        - the "main BIOS body"
	......   0xFF padding
	0x1C850  loader / decompressor (plain code) - the LZHUF decoder itself,
			 followed by its d_code[256] / d_len[256] tables and a table
			 of module names
	0x1E000  boot block (plain code, "BBlk" tag at 0x1FF80)

The compressed body is Haruhiko Okumura's LZHUF (LZSS + adaptive Huffman,
the algorithm behind LHA's "-lh1-"), with the stock parameters
N=4096, F=60, THRESHOLD=2, N_CHAR=314, T=627, R=626, MAX_FREQ=0x8000.

Only deviation from LZHUF.C: the 4-byte uncompressed-length prefix that
starts the stream is stored BIG-endian (LZHUF.C writes it little-endian).

Decompressed output is a concatenation of BIOS modules; the last one is
the system BIOS itself (ends with the classic "MM/DD/YY", model-byte
signature at the top of the 1 MB address space).
"""

import sys

N, F, THRESHOLD = 4096, 60, 2
N_CHAR = 256 - THRESHOLD + F        # 314
T = N_CHAR * 2 - 1                  # 627
R = T - 1                           # 626
MAX_FREQ = 0x8000

# Stock LZHUF position-code tables (byte-identical to the copies held at
# 0x1CCE8 / 0x1CDE8 inside B37_C.LDB).
d_code = bytes(
	[0x00] * 32 + [0x01] * 16 + [0x02] * 16 + [0x03] * 16 +
	[c for c in range(0x04, 0x0C) for _ in range(8)] +
	[c for c in range(0x0C, 0x18) for _ in range(4)] +
	[c for c in range(0x18, 0x30) for _ in range(2)] +
	list(range(0x30, 0x40)))
d_len = bytes([3] * 32 + [4] * 48 + [5] * 64 + [6] * 48 + [7] * 48 + [8] * 16)
assert len(d_code) == 256 and len(d_len) == 256


class LzhufDecoder:
	def __init__(self, data):
		self.d, self.p = data, 0
		self.getbuf = self.getlen = 0
		self.freq = [0] * (T + 1)
		self.prnt = [0] * (T + N_CHAR)
		self.son = [0] * T
		self._start_huff()

	# ---- bit input ----------------------------------------------------
	def _byte(self):
		c = self.d[self.p] if self.p < len(self.d) else 0
		self.p += 1
		return c

	def _fill(self):
		while self.getlen <= 8:
			self.getbuf = (self.getbuf | (self._byte() << (8 - self.getlen))) & 0xFFFF
			self.getlen += 8

	def get_bit(self):
		self._fill()
		i = self.getbuf
		self.getbuf = (self.getbuf << 1) & 0xFFFF
		self.getlen -= 1
		return 1 if i & 0x8000 else 0

	def get_byte(self):
		self._fill()
		i = self.getbuf
		self.getbuf = (self.getbuf << 8) & 0xFFFF
		self.getlen -= 8
		return (i >> 8) & 0xFF

	# ---- adaptive Huffman tree ----------------------------------------
	def _start_huff(self):
		for i in range(N_CHAR):
			self.freq[i] = 1
			self.son[i] = i + T
			self.prnt[i + T] = i
		i, j = 0, N_CHAR
		while j <= R:
			self.freq[j] = self.freq[i] + self.freq[i + 1]
			self.son[j] = i
			self.prnt[i] = self.prnt[i + 1] = j
			i += 2
			j += 1
		self.freq[T] = 0xFFFF
		self.prnt[R] = 0

	def _reconst(self):
		j = 0
		for i in range(T):
			if self.son[i] >= T:
				self.freq[j] = (self.freq[i] + 1) // 2
				self.son[j] = self.son[i]
				j += 1
		i, j = 0, N_CHAR
		while j < T:
			f = self.freq[j] = self.freq[i] + self.freq[i + 1]
			k = j - 1
			while f < self.freq[k]:
				k -= 1
			k += 1
			for l in range(j, k, -1):
				self.freq[l] = self.freq[l - 1]
				self.son[l] = self.son[l - 1]
			self.freq[k] = f
			self.son[k] = i          # children pair index, not the node index
			i += 2
			j += 1
		for i in range(T):
			k = self.son[i]
			self.prnt[k] = i
			if k < T:
				self.prnt[k + 1] = i

	def _update(self, c):
		if self.freq[R] == MAX_FREQ:
			self._reconst()
		c = self.prnt[c + T]
		while True:
			self.freq[c] += 1
			k = self.freq[c]
			l = c + 1
			if k > self.freq[l]:
				while k > self.freq[l]:
					l += 1
				l -= 1
				self.freq[c], self.freq[l] = self.freq[l], k
				i = self.son[c]
				self.prnt[i] = l
				if i < T:
					self.prnt[i + 1] = l
				j = self.son[l]
				self.son[l] = i
				self.prnt[j] = c
				if j < T:
					self.prnt[j + 1] = c
				self.son[c] = j
				c = l
			c = self.prnt[c]
			if c == 0:
				break

	def decode_char(self):
		c = self.son[R]
		while c < T:
			c = self.son[c + self.get_bit()]
		c -= T
		self._update(c)
		return c

	def decode_position(self):
		i = self.get_byte()
		c = d_code[i] << 6
		for _ in range(d_len[i] - 2):
			i = ((i << 1) + self.get_bit()) & 0xFFFF
		return c | (i & 0x3F)

	# ---- main loop ----------------------------------------------------
	def decode(self):
		size = 0
		for _ in range(4):                 # big-endian length prefix
			size = (size << 8) | self._byte()
		buf = bytearray([0x20] * N)
		r = N - F
		out = bytearray()
		while len(out) < size:
			c = self.decode_char()
			if c < 256:
				out.append(c)
				buf[r] = c
				r = (r + 1) & (N - 1)
			else:
				i = (r - self.decode_position() - 1) & (N - 1)
				for k in range(c - 255 + THRESHOLD):
					ch = buf[(i + k) & (N - 1)]
					out.append(ch)
					buf[r] = ch
					r = (r + 1) & (N - 1)
					if len(out) >= size:
						break
		return bytes(out), size


def unpack_ldb(image):
	if image[:6] != b'OKICL1':
		raise ValueError('not an ICL LDB image (missing "OKICL1" magic)')
	if image[0x28:0x2F] != b'FL_PACK':
		raise ValueError('missing "FL_PACK" tag at 0x28')
	return LzhufDecoder(image[0x40:]).decode()


def main():
	if len(sys.argv) not in (2, 3):
		sys.exit('usage: %s <file.LDB> [out.bin]' % sys.argv[0])
	src = sys.argv[1]
	dst = sys.argv[2] if len(sys.argv) == 3 else src + '.bin'
	data, size = unpack_ldb(open(src, 'rb').read())
	open(dst, 'wb').write(data)
	print('%s -> %s (%d bytes, declared %d)' % (src, dst, len(data), size))


if __name__ == '__main__':
	main()
