"""
Extractor for Evergreen Spectra ".ETI" / ".ETB" archives (INSTL2.EXE).

Format
------
Payload compression is the PKWARE Data Compression Library "implode"
algorithm (a.k.a. DCL implode / "blast"), with every byte of each
compressed stream XOR-ed with the constant 0xDE.

  archive header (.ETI only, 31 bytes)
	0x00  char[10]  library/tool version, NUL padded   ("01.00.0", "04.33.0")
	0x0A  char[10]  build date "MM/DD/YY", NUL padded
	0x14  char[11]  build time "HH:MM:SS", NUL padded

  then 1..n members, back to back:
	tag       3 bytes   language member: index byte (0=English, 1=Francais,
						2=Deutsch per LANGUAGE.DAT) + 2 reserved bytes
			  13 bytes  named member: NUL-terminated 8.3 name in a fixed,
						never-cleared 13-byte buffer (stale tail bytes)
	crc       uint32le  CRC-32 of the DECOMPRESSED member
						(poly 0xEDB88320, init 0xFFFFFFFF, NO final XOR)
	clen      uint32le  length of the compressed stream that follows
	data      clen bytes: DCL-imploded stream, each byte XOR 0xDE

  .ETB files (BIOS backups written at install time) carry no archive header:
  they are bare XOR-0xDE DCL streams laid end to end, separated by a few
  bytes of bookkeeping, with a trailing crc+length record.

INSTL2.EXE writes out only the member matching the language index in
LANGUAGE.DAT / PREVLANG.DAT, which is why CONTACT.ETI (1307 bytes) yields a
746-byte CONTACT.TXT: the other two members hold the French and German text.
"""

import os
import struct
import sys

MASK = 0xDE

# --------------------------------------------------------------------------
# PKWARE DCL "implode" decompressor (explode).  Port of Mark Adler's blast.c.
# Note DCL Huffman codes are stored inverted, hence the `^ 1` in decode().
# --------------------------------------------------------------------------

_MAXBITS = 13
_LEN_REP = bytes([2, 35, 36, 53, 38, 23])
_DIST_REP = bytes([2, 20, 53, 230, 247, 151, 248])
_BASE = [3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264]
_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]


def _build(rep):
	"""Expand run-length-coded code lengths into a canonical Huffman table."""
	lens = []
	for b in rep:
		lens += [b & 15] * ((b >> 4) + 1)
	count = [0] * (_MAXBITS + 1)
	for l in lens:
		count[l] += 1
	offs = [0] * (_MAXBITS + 2)
	for l in range(1, _MAXBITS + 1):
		offs[l + 1] = offs[l] + count[l]
	symbol = [0] * len(lens)
	for i, l in enumerate(lens):
		if l:
			symbol[offs[l]] = i
			offs[l] += 1
	return count, symbol


_LENCODE = _build(_LEN_REP)
_DISTCODE = _build(_DIST_REP)


class _Bits:
	__slots__ = ('d', 'pos', 'buf', 'cnt')

	def __init__(self, d):
		self.d, self.pos, self.buf, self.cnt = d, 0, 0, 0

	def bits(self, need):
		val, cnt = self.buf, self.cnt
		while cnt < need:
			if self.pos >= len(self.d):
				raise EOFError("ran out of input")
			val |= self.d[self.pos] << cnt
			self.pos += 1
			cnt += 8
		self.buf, self.cnt = val >> need, cnt - need
		return val & ((1 << need) - 1)

	def decode(self, table):
		count, symbol = table
		code = first = index = 0
		for l in range(1, _MAXBITS + 1):
			code |= self.bits(1) ^ 1          # DCL stores codes inverted
			c = count[l]
			if code - c < first:
				return symbol[index + (code - first)]
			index += c
			first = (first + c) << 1
			code <<= 1
		raise ValueError("invalid Huffman code")


def explode(data):
	"""Decompress one DCL stream. Returns (plaintext, bytes_consumed)."""
	s = _Bits(data)
	coded_literals = s.bits(8)
	if coded_literals not in (0, 1):
		raise ValueError("bad literal flag %d" % coded_literals)
	if coded_literals:
		raise NotImplementedError("coded-literal mode is not used by these files")
	dict_bits = s.bits(8)
	if not 4 <= dict_bits <= 6:
		raise ValueError("bad dictionary size %d" % dict_bits)
	out = bytearray()
	while True:
		if s.bits(1):                                   # length/distance pair
			sym = s.decode(_LENCODE)
			length = _BASE[sym] + s.bits(_EXTRA[sym])
			if length == 519:                           # end-of-stream code
				break
			shift = 2 if length == 2 else dict_bits
			dist = (s.decode(_DISTCODE) << shift) + s.bits(shift) + 1
			if dist > len(out):
				raise ValueError("distance reaches before start of output")
			for _ in range(length):
				out.append(out[-dist])
		else:                                           # uncoded literal byte
			out.append(s.bits(8))
	return bytes(out), s.pos


# --------------------------------------------------------------------------
# CRC-32 as used by the PKWARE DCL: reflected, init 0xFFFFFFFF, no final XOR.
# --------------------------------------------------------------------------

_CRCTAB = []
for _i in range(256):
	_c = _i
	for _ in range(8):
		_c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
	_CRCTAB.append(_c)


def crc32(b):
	c = 0xFFFFFFFF
	for x in b:
		c = _CRCTAB[(c ^ x) & 0xFF] ^ (c >> 8)
	return c


# --------------------------------------------------------------------------
# Container parsing
# --------------------------------------------------------------------------

HEADER_LEN = 0x1F


def _is_stream_start(data, k):
	return (k + 1 < len(data)
			and (data[k] ^ MASK) == 0
			and (data[k + 1] ^ MASK) in (4, 5, 6))


def read_members(data, headered=True):
	"""Yield dicts describing each member of an .ETI (headered) or .ETB file."""
	off = HEADER_LEN if headered else 0
	while off + 2 <= len(data):
		if not headered:
			# .ETB: bare streams laid end to end, with a few bytes of
			# bookkeeping between them; skip forward to the next signature.
			while off < len(data) and not _is_stream_start(data, off):
				off += 1
			if off >= len(data):
				return
			plain, used = explode(bytes(b ^ MASK for b in data[off:]))
			yield dict(tag=b'', crc=None, clen=used, used=used, off=off, data=plain)
			off += used
			continue
		# The tag is 3 or 13 bytes; find the stream by its DCL signature and
		# take the 8 bytes in front of it as crc + compressed length.
		for k in range(off + 8, min(off + 32, len(data))):
			if not _is_stream_start(data, k):
				continue
			clen = struct.unpack('<I', data[k - 4:k])[0]
			if 0 < clen <= len(data) - k:
				break
		else:
			return
		crc, clen = struct.unpack('<II', data[k - 8:k])
		plain, used = explode(bytes(b ^ MASK for b in data[k:k + clen]))
		yield dict(tag=data[off:k - 8], crc=crc, clen=clen, used=used,
				   off=k, data=plain)
		off = k + clen


LANGUAGES = {0: 'ENG', 1: 'FRE', 2: 'GER'}


def member_name(m, index, stem):
	"""Name a member the way INSTL2.EXE would."""
	tag = m['tag']
	if len(tag) >= 13:                      # named member (8.3, NUL-terminated)
		name = tag.split(b'\0')[0].decode('latin1')
		if name:
			return name
	if not tag:
		return '%s.%03d' % (stem, index)
	lang = LANGUAGES.get(tag[0], '%03d' % tag[0])
	return '%s.%s.TXT' % (stem, lang)


def main(argv):
	if len(argv) < 2:
		print(__doc__)
		print("usage: %s [-x OUTDIR] FILE.ETI ..." % os.path.basename(argv[0]))
		return 2
	outdir = None
	args = argv[1:]
	if args[0] == '-x':
		outdir = args[1]
		args = args[2:]
		os.makedirs(outdir, exist_ok=True)
	rc = 0
	for path in args:
		data = open(path, 'rb').read()
		base = os.path.basename(path)
		stem, ext = os.path.splitext(base)
		headered = ext.upper() != '.ETB'
		if headered:
			ver, date, tm = (data[0:10].rstrip(b'\0').decode('latin1'),
							 data[10:20].rstrip(b'\0').decode('latin1'),
							 data[20:31].rstrip(b'\0').decode('latin1'))
			print("== %s  version %s  built %s %s  (%d bytes)"
				  % (base, ver, date, tm, len(data)))
		else:
			print("== %s  (headerless, %d bytes)" % (base, len(data)))
		end = 0
		for i, m in enumerate(read_members(data, headered)):
			name = member_name(m, i, stem)
			ok = "-" if m['crc'] is None else (
				"crc ok" if crc32(m['data']) == m['crc'] else "CRC MISMATCH")
			if ok == "CRC MISMATCH":
				rc = 1
			print("   [%2d] %-16s %7d -> %8d bytes  %s"
				  % (i, name, m['clen'], len(m['data']), ok))
			if outdir:
				with open(os.path.join(outdir, name), 'wb') as f:
					f.write(m['data'])
			end = m['off'] + m['clen']
		print("   %d/%d bytes accounted for" % (end, len(data)))
	return rc


if __name__ == '__main__':
	sys.exit(main(sys.argv))
