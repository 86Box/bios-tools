#!/usr/bin/python3
#
# 86Box          A hypervisor and IBM PC system emulator that specializes in
#                running old operating systems and software designed for IBM
#                PC systems and compatibles from 1981 through fairly recent
#                system designs based on the PCI bus.
#
#                This file is part of the 86Box BIOS Tools distribution.
#
#                BIOS and archive extraction classes.
#
#
#
# Authors:       RichardG, <richardg867@gmail.com>
#
#                Copyright 2021 RichardG.
#
import array, codecs, io, math, os, re, shutil, struct, subprocess
try:
	import PIL.Image
except ImportError:
	PIL = lambda x: x
	PIL.Image = None
from . import util

class Extractor:
	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		"""Extract the given file into one of the destination directories:
		   dest_dir allows extracted files to be reprocessed in the next run,
		   while dest_dir_0 does not. This must return either:
		   - False if this extractor can't handle the given file
		   - True if this extractor can handle the given file, but no output was produced
		   - a string with the produced output file/directory path"""
		raise NotImplementedError()

	def log_print(self, *args):
		"""Print a log line."""
		print('{0}:'.format(self.__class__.__name__), *args, file=sys.stderr)


class ArchiveExtractor(Extractor):
	"""Extract known archive types."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Known signatures for archive files.
		self._archive_signatures = [
			b'PK\x03\x04', # zip
			b'Rar!\x1A\x07', # rar
			b'7z\xBC\xAF\x27\x1C', # 7z
			b'MSCF', # cab
			b'\x1F\x8B', # gzip
			b'BZh', # bzip2
			b'\xFD7zXZ\x00', # xz
			b'LHA\x20', # lha
			b'ZOO', # zoo
		]

		# /dev/null handle for suppressing output.
		self._devnull = open(os.devnull, 'wb')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		"""Extract an archive."""

		# Determine if this is an archive through file signatures.
		is_archive = False
		for signature in self._archive_signatures:
			if file_header[:len(signature)] == signature:
				is_archive = True
				break

		# Stop if this is apparently not an archive.
		if not is_archive:
			return False

		# Do the actual extraction.
		return self._extract_archive(file_path, dest_dir)

	def _extract_archive(self, file_path, dest_dir, remove=True):
		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Run 7z command to extract the archive.
		# The dummy password prevents any password prompts from stalling 7z.
		subprocess.run(['7z', 'x', '-y', '-ppassword', '--', os.path.abspath(file_path)], stdout=self._devnull, stderr=subprocess.STDOUT, cwd=dest_dir)

		# Assume failure if nothing was extracted.
		if len(os.listdir(dest_dir)) < 1:
			return False

		# Remove archive file.
		if remove:
			try:
				os.remove(file_path)
			except:
				pass

		# Return destination directory path.
		return dest_dir


class BIOSExtractor(Extractor):
	"""Extract a bios_extract-compatible BIOS file."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Path to the bios_extract utility.
		self._bios_extract_path = os.path.abspath(os.path.join('bios_extract', 'bios_extract'))
		if not os.path.exists(self._bios_extract_path):
			self._bios_extract_path = None

		# /dev/null handle for suppressing output.
		self._devnull = open(os.devnull, 'wb')

		# Built-in instance of ImageExtractor for converting
		# any extracted BIOS logo images that were found.
		self._image_extractor = ImageExtractor()

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if bios_extract is not available.
		if not self._bios_extract_path:
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir_0):
			return True

		# Start bios_extract process.
		file_path_abs = os.path.abspath(file_path)
		try:
			subprocess.run([self._bios_extract_path, file_path_abs], timeout=30, stdout=self._devnull, stderr=subprocess.STDOUT, cwd=dest_dir_0)
		except:
			# Bad data can cause infinite loops.
			pass

		# Assume failure if nothing was extracted. A lone amiboot.bin also counts as a failure, since
		# the AMI extractor writes the boot block before attempting to extract any actual BIOS modules.
		dest_dir_files = os.listdir(dest_dir_0)
		num_files_extracted = len(dest_dir_files)
		if num_files_extracted < 1:
			return False
		elif num_files_extracted == 1 and dest_dir_files[0] in ('amiboot.rom', 'ssboot.rom'):
			# Remove amiboot so that the destination directory can be rmdir'd later.
			try:
				os.remove(os.path.join(dest_dir_0, dest_dir_files[0]))
			except:
				pass
			return False

		# Convert any BIOS logo images in-line (to the same destination directory).
		self._image_extractor.convert_inline(dest_dir_files, dest_dir_0)

		# Create flag file on the destination directory for the analyzer to
		# treat it as a big chunk of data.
		open(os.path.join(dest_dir_0, ':combined:'), 'wb').close()

		# Copy any header file to extracted directory, for identifying Intel BIOSes.
		# See AMIAnalyzer.can_handle for more information.
		try:
			shutil.copy(os.path.join(os.path.dirname(file_path_abs), ':header:'), os.path.join(dest_dir_0, ':header:'))
		except:
			pass

		# Remove BIOS file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir_0


class DellExtractor(Extractor):
	"""Extract Dell/Phoenix ROM BIOS PLUS images.
	   Based on dell_inspiron_1100_unpacker.py"""

	def _memcpy(self, arr1, off1, arr2, off2, count):
		while count:
			if off1 < len(arr1):
					try:
						arr1[off1] = arr2[off2]
					except:
						break
			elif off1 == len(arr1):
					try:
						arr1.append(arr2[off2])
					except:
						break
			else:
					break
			off1 += 1
			off2 += 1
			count -= 1

	def _dell_unpack(self, indata):
		srcoff = 0
		dstoff = 0
		src = bytearray(indata)
		dst = bytearray()
		inlen = len(indata)
		while srcoff < inlen:
				b = src[srcoff]
				nibl, nibh = b & 0x0F, (b >> 4) & 0x0F
				srcoff += 1
				if nibl:
						if nibl == 0xF:
								al = src[srcoff]
								ah = src[srcoff+1]
								srcoff += 2
								cx = nibh | (ah << 4)
								count = (cx & 0x3F) + 2
								delta = ((ah >> 2) << 8) | al
						else:
								count = nibl + 1
								delta = (nibh << 8) | src[srcoff]
								srcoff += 1
						self._memcpy(dst, dstoff, dst, dstoff - delta - 1, count)
						dstoff += count
				elif nibh == 0x0E:
						count = src[srcoff] + 1
						srcoff += 1
						self._memcpy(dst, dstoff, dst, dstoff - 1, count)
						dstoff += count
				else:
						if nibh == 0x0F:
								count = src[srcoff] + 15
								srcoff += 1
						else:
								count = nibh + 1
						self._memcpy(dst, dstoff, src, srcoff, count)
						dstoff += count
						srcoff += count

		return dst

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Read up to 16 MB as a safety net.
		file_header += util.read_complement(file_path, file_header)

		# Stop if this is not the type of BIOS we're looking for.
		copyright_string = b'\xF0\x00Copyright 1985-\x02\x04\xF0\x0F8 Phoenix Technologies Ltd.'
		offset = file_header.find(copyright_string)
		if offset < 5:
			return False

		# Determine the length format.
		if file_header[offset - 5] == 1:
			# 32-bit length.
			length_size = 5
			struct_format = '<BI'
		elif file_header[offset - 3] == 1:
			# 16-bit length.
			length_size = 3
			struct_format = '<BH'
		else:
			# Unknown length format.
			return False
		offset -= length_size

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir_0):
			return True

		# Create header file with the copyright string, to tell the analyzer
		# this BIOS went through this extractor.
		f = open(os.path.join(dest_dir_0, ':header:'), 'wb')
		f.write(copyright_string)
		f.close()

		# Create flag file on the destination directory for the analyzer to
		# treat it as a big chunk of data.
		open(os.path.join(dest_dir_0, ':combined:'), 'wb').close()

		# Extract any preceding data as EC code.
		if offset > 0:
			f = open(os.path.join(dest_dir_0, 'ec.bin'), 'wb')
			f.write(file_header[:offset])
			f.close()

		# Extract modules.
		file_size = len(file_header)
		module_number = 0
		while (offset + length_size) < file_size:
			# Read module type and length.
			module_type, module_length = struct.unpack(struct_format, file_header[offset:offset + length_size])
			if module_type == 0xFF:
				break
			offset += length_size

			# Decompress data if required.
			data = file_header[offset:offset + module_length]
			if module_type != 0x0C:
				try:
					data = self._dell_unpack(data)
				except:
					pass
			offset += module_length

			# Write module.
			f = open(os.path.join(dest_dir_0, 'module_{0:02}.bin'.format(module_number)), 'wb')
			f.write(data)
			f.close()

			# Increase filename counter.
			module_number += 1

		# Remove BIOS file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir_0

class DiscardExtractor(Extractor):
	"""Detect and discard known non-useful file types."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# File signatures to discard.
		self._signature_pattern = re.compile(
			# images
			b'''\\xFF\\xD8\\xFF|GIF8|\\x89PNG|'''
			# documents (a cursory check for HTML ought not to upset anyone)
			b'''%PDF|\\xD0\\xCF\\x11\\xE0\\xA1\\xB1\\x1A\\xE1|\\x3F\\x5F\\x03\\x00|<(?:\![Dd][Oo][Cc][Tt][Yy][Pp][Ee]|[Hh][Tt][Mm][Ll])[ >]|'''
			# executables
			b'''(\\x7FELF)|'''
			# reports
			b'''CPU-Z TXT Report|\s{7}File:   A|-+\[ AIDA32 |HWiNFO64 Version |3DMARK2001 PROJECT|Report Dr. Hardware|\r\n(?:\s+HWiNFO v|\r\n\s+\r\n\s+Microsoft Diagnostics version )|SIV[^\s]+ - System Information Viewer V|UID,Name,Score,'''
		)

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Determine if this is a known non-useful file type through the signature pattern.
		match = self._signature_pattern.match(file_header)
		if match:
			# Don't discard LinuxBIOS ELFs.
			if match.group(1) and file_header[128:136] == b'ELFBoot\x00':
				return False

			# Remove file and stop.
			try:
				os.remove(file_path)
			except:
				pass
			return True

		# Not a known file type, cleared to go.
		return False


class ImageExtractor(Extractor):
	"""Extract BIOS logo images by converting them into PNG."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Standard EGA/VGA palette for v1 and palette-less v2 Award EPAs.
		self._vga_palette = [
			0x000000, 0x0000aa, 0x00aa00, 0x00aaaa, 0xaa0000, 0xaa00aa, 0xaa5500, 0xaaaaaa, 0x555555, 0x5555ff, 0x55ff55, 0x55ffff, 0xff5555, 0xff55ff, 0xffff55, 0xffffff,
			0x000000, 0x101010, 0x202020, 0x353535, 0x454545, 0x555555, 0x656565, 0x757575, 0x8a8a8a, 0x9a9a9a, 0xaaaaaa, 0xbababa, 0xcacaca, 0xdfdfdf, 0xefefef, 0xffffff,
			0x0000ff, 0x4100ff, 0x8200ff, 0xbe00ff, 0xff00ff, 0xff00be, 0xff0082, 0xff0041, 0xff0000, 0xff4100, 0xff8200, 0xffbe00, 0xffff00, 0xbeff00, 0x82ff00, 0x41ff00,
			0x00ff00, 0x00ff41, 0x00ff82, 0x00ffbe, 0x00ffff, 0x00beff, 0x0082ff, 0x0041ff, 0x8282ff, 0x9e82ff, 0xbe82ff, 0xdf82ff, 0xff82ff, 0xff82df, 0xff82be, 0xff829e,
			0xff8282, 0xff9e82, 0xffbe82, 0xffdf82, 0xffff82, 0xdfff82, 0xbeff82, 0x9eff82, 0x82ff82, 0x82ff9e, 0x82ffbe, 0x82ffdf, 0x82ffff, 0x82dfff, 0x82beff, 0x829eff,
			0xbabaff, 0xcabaff, 0xdfbaff, 0xefbaff, 0xffbaff, 0xffbaef, 0xffbadf, 0xffbaca, 0xffbaba, 0xffcaba, 0xffdfba, 0xffefba, 0xffffba, 0xefffba, 0xdfffba, 0xcaffba,
			0xbaffba, 0xbaffca, 0xbaffdf, 0xbaffef, 0xbaffff, 0xbaefff, 0xbadfff, 0xbacaff, 0x000071, 0x1c0071, 0x390071, 0x550071, 0x710071, 0x710055, 0x710039, 0x71001c,
			0x710000, 0x711c00, 0x713900, 0x715500, 0x717100, 0x557100, 0x397100, 0x1c7100, 0x007100, 0x00711c, 0x007139, 0x007155, 0x007171, 0x005571, 0x003971, 0x001c71,
			0x393971, 0x453971, 0x553971, 0x613971, 0x713971, 0x713961, 0x713955, 0x713945, 0x713939, 0x714539, 0x715539, 0x716139, 0x717139, 0x617139, 0x557139, 0x457139,
			0x397139, 0x397145, 0x397155, 0x397161, 0x397171, 0x396171, 0x395571, 0x394571, 0x515171, 0x595171, 0x615171, 0x695171, 0x715171, 0x715169, 0x715161, 0x715159,
			0x715151, 0x715951, 0x716151, 0x716951, 0x717151, 0x697151, 0x617151, 0x597151, 0x517151, 0x517159, 0x517161, 0x517169, 0x517171, 0x516971, 0x516171, 0x515971,
			0x000041, 0x100041, 0x200041, 0x310041, 0x410041, 0x410031, 0x410020, 0x410010, 0x410000, 0x411000, 0x412000, 0x413100, 0x414100, 0x314100, 0x204100, 0x104100,
			0x004100, 0x004110, 0x004120, 0x004131, 0x004141, 0x003141, 0x002041, 0x001041, 0x202041, 0x282041, 0x312041, 0x392041, 0x412041, 0x412039, 0x412031, 0x412028,
			0x412020, 0x412820, 0x413120, 0x413920, 0x414120, 0x394120, 0x314120, 0x284120, 0x204120, 0x204128, 0x204131, 0x204139, 0x204141, 0x203941, 0x203141, 0x202841,
			0x2d2d41, 0x312d41, 0x352d41, 0x3d2d41, 0x412d41, 0x412d3d, 0x412d35, 0x412d31, 0x412d2d, 0x41312d, 0x41352d, 0x413d2d, 0x41412d, 0x3d412d, 0x35412d, 0x31412d,
			0x2d412d, 0x2d4131, 0x2d4135, 0x2d413d, 0x2d4141, 0x2d3d41, 0x2d3541, 0x2d3141, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000
		]

		# Header pattern for common format images.
		self._pil_pattern = re.compile(
			b'''\\x0A[\\x00-\\x05][\\x00-\\x01][\\x01\\x02\\x04\\x08]|''' # PCX
			b'''BM|''' # BMP
			b'''\\xFF\\xD8\\xFF|''' # JPEG
			b'''GIF8|''' # GIF
			b'''\\x89PNG''' # PNG
		)

	def convert_inline(self, dest_dir_files, dest_dir_0):
		# Detect and convert image files.
		for dest_dir_file in dest_dir_files:
			# Read 8 bytes, which is enough to ascertain any potential logo type.
			dest_dir_file_path = os.path.join(dest_dir_0, dest_dir_file)
			f = open(dest_dir_file_path, 'rb')
			dest_dir_file_header = f.read(8)
			f.close()

			# Run ImageExtractor.
			image_dest_dir = dest_dir_file_path + ':'
			if self.extract(dest_dir_file_path, dest_dir_file_header, image_dest_dir, image_dest_dir):
				# Remove destination directory if it was created but is empty.
				util.rmdirs(image_dest_dir)

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if PIL is not available or this file is too small.
		if not PIL.Image or len(file_header) < 8:
			return False

		# Determine if this is an image, and which type it is.
		if file_header[:4] == b'AWBM':
			# Get width and height for a v2 EPA.
			width, height = struct.unpack('<HH', file_header[4:8])

			# Determine if this file is a 4-bit or 8-bit EPA according to the file size.
			if os.path.getsize(file_path) >= 8 + (width * height):
				func = self._convert_epav2_8b
			else:
				func = self._convert_epav2_4b
		else:
			# Determine if this file is the right size for a v1 EPA.
			width, height = struct.unpack('BB', file_header[:2])
			if os.path.getsize(file_path) == 72 + (15 * width * height):
				func = self._convert_epav1
			else:
				# Determine if this is a common image format.
				if self._pil_pattern.match(file_header):
					func = self._convert_pil
				else:
					# Stop if this is not an image.
					return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir_0):
			return True

		# Read up to 16 MB as a safety net.
		file_header += util.read_complement(file_path, file_header)

		# Stop if the file was cut off, preventing parsing exceptions.
		if len(file_header) == 16777216:
			return True

		# Run extractor function, and stop if it was not successful.
		if not func(file_header, width, height, dest_dir_0):
			return True

		# Remove original file.
		try:
			os.remove(file_path)
		except:
			pass

		return dest_dir_0

	def _convert_epav1(self, file_data, width, height, dest_dir_0):
		# Write file type as a header.
		self._write_type(dest_dir_0, 'EPA v1')

		# Fill color map.
		color_map = []
		index = 2
		for x in range(width * height):
			# Read character cell color information.
			color = file_data[index]
			index += 1

			# Save RGB background and foreground color.
			color_map.append((self._vga_palette[color & 0x0f], self._vga_palette[color >> 4]))

		# Create output image.
		image = PIL.Image.new('RGB', (width * 8, height * 14))

		# Read image data.
		for y in range(height):
			for x in range(width):
				# Determine foreground/background colors for this character cell.
				fg_color, bg_color = color_map.pop(0)

				# Read the 14 row bitmaps.
				for cy in range(14):
					# Stop row bitmap processing if the file is truncated.
					if index >= len(file_data):
						width = height = 0
						break

					# Read bitmap byte.
					bitmap = file_data[index]
					index += 1

					# Parse the foreground/background bitmap.
					for cx in range(8):
						# Determine palette color and write pixel.
						color = (bitmap & (1 << cx)) and fg_color or bg_color
						image.putpixel(((x * 8) + (7 - cx), (y * 14) + cy),
									 ((color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff))

				# Stop column processing if the file is truncated.
				if width == 0 or len(color_map) == 0:
					break

			# Stop row processing if the file is truncated.
			if height == 0 or len(color_map) == 0:
				break

		# Save output image.
		return self._save_image(image, dest_dir_0)

	def _convert_epav2_4b(self, file_data, width, height, dest_dir_0):
		# Read palette if the file contains one, while
		# writing the file type as a header accordingly.
		palette = self._read_palette_epav2(file_data, -52, False)
		if palette:
			self._write_type(dest_dir_0, 'EPA v2 4-bit (with palette)')
		else:
			self._write_type(dest_dir_0, 'EPA v2 4-bit (without palette)')

			# Use standard EGA palette.
			palette = self._vga_palette

		# Create output image.
		image = PIL.Image.new('RGB', (width, height))

		# Read image data.
		index = 8
		bitmap_width = math.ceil(width / 8)
		for y in range(height):
			for x in range(bitmap_width):
				# Stop column processing if the file is truncated.
				if index + x + (bitmap_width * 3) >= len(file_data):
					index = 0
					break

				for cx in range(8):
					# Skip this pixel if it's outside the image width.
					output_x = (x * 8) + cx
					if output_x >= width:
						continue

					# Read color values. Each bit is stored in a separate bitmap.
					pixel  =  (file_data[index + x]                      >> (7 - cx)) & 1
					pixel |= ((file_data[index + x + bitmap_width]       >> (7 - cx)) & 1) << 1
					pixel |= ((file_data[index + x + (bitmap_width * 2)] >> (7 - cx)) & 1) << 2
					pixel |= ((file_data[index + x + (bitmap_width * 3)] >> (7 - cx)) & 1) << 3

					# Determine palette color and write pixel.
					if pixel > len(palette):
						pixel = len(palette) - 1
					color = palette[pixel]
					image.putpixel((output_x, y),
								 ((color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff))

			# Stop row processing if the file is truncated.
			if index == 0:
				break

			# Move on to the next set of 4 bitmaps.
			index += bitmap_width * 4

		# Save output image.
		return self._save_image(image, dest_dir_0)

	def _convert_epav2_8b(self, file_data, width, height, dest_dir_0):
		# Read palette if the file contains one, while
		# writing the file type as a header accordingly.
		palette = self._read_palette_epav2(file_data, -772)
		if palette:
			self._write_type(dest_dir_0, 'EPA v2 8-bit (with palette)')
		else:
			self._write_type(dest_dir_0, 'EPA v2 8-bit (without palette)')

			# Use standard VGA palette.
			palette = self._vga_palette

		# Create output image.
		image = PIL.Image.new('RGB', (width, height))

		# Read image data.
		index = 8
		for y in range(height):
			for x in range(width):
				# Read pixel.
				pixel = file_data[index]
				index += 1

				# Determine palette color and write pixel.
				if pixel > len(palette):
					pixel = len(palette) - 1
				color = palette[pixel]
				image.putpixel((x, y),
							 ((color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff))

		# Save output image.
		return self._save_image(image, dest_dir_0)

	def _convert_pil(self, file_data, width, height, dest_dir_0):
		# Load image.
		try:
			image = PIL.Image.open(io.BytesIO(file_data))
			if not image:
				raise Exception('no image')

			# Don't save image if it's too small.
			x, y = image.size
			if (x * y) < 10000:
				raise Exception('too small')
		except:
			return False

		# Write the file type as a header.
		self._write_type(dest_dir_0, image.format)

		# Save output image.
		return self._save_image(image, dest_dir_0)

	def _read_palette_epav2(self, file_data, rgbs_offset, rgb=True):
		# Stop if this file has no palette.
		if file_data[rgbs_offset:rgbs_offset + 4] != b'RGB ':
			return None

		# Read 6-bit palette entries, while converting to 8-bit.
		palette = []
		index = rgbs_offset + 4
		while index < 0:
			palette.append((file_data[index]     << (rgb and 18 or 2)) |
						   (file_data[index + 1] << 10)                |
						   (file_data[index + 2] << (rgb and 2 or 18)))
			index += 3

		return palette

	def _save_image(self, image, dest_dir_0):
		# Save image to destination directory.
		image_path = os.path.join(dest_dir_0, 'image.png')
		try:
			image.save(image_path)
			return True
		except:
			# Clean up.
			try:
				os.remove(image_path)
			except:
				pass
			try:
				os.remove(os.path.join(dest_dir_0, ':header:'))
			except:
				pass
			return False

	def _write_type(self, dest_dir_0, identifier):
		f = open(os.path.join(dest_dir_0, ':header:'), 'w')
		f.write(identifier)
		f.close()

class FATExtractor(ArchiveExtractor):
	"""Extract FAT disk images."""

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Determine if this is a FAT filesystem.

		# Stop if this file is too small.
		if len(file_header) < 512:
			return False

		# Stop if there's no bootstrap jump.
		if (file_header[0] != 0xEB or file_header[2] != 0x90) and file_header[0] != 0xE9:
			return False

		# Stop if there's no media descriptor type.
		if file_header[21] < 0xF0:
			return False

		# Extract this as an archive.
		return self._extract_archive(file_path, dest_dir)


class HexExtractor(Extractor):
	"""Extract Intel HEX format ROMs."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._hex_start_pattern = re.compile(b''':(?:[0-9A-F]{2}){1,}\\r?\\n''')
		self._hex_eof_pattern = re.compile(b''':00[0-9A-F]{4}01[0-9A-F]{2}\\r?\\n?$''')
		self._hex_data_pattern = re.compile(b''':([0-9A-F]{2})([0-9A-F]{4})00([0-9A-F]{2,})\\r?\\n''')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this is not a HEX.
		if not self._hex_start_pattern.match(file_header):
			return False

		# Read up to 16 MB as a safety net.
		file_header += util.read_complement(file_path, file_header)

		# Stop if no EOF was found.
		if not self._hex_eof_pattern.search(file_header):
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Create destination file.
		f = open(os.path.join(dest_dir, 'intelhex.bin'), 'wb')

		# Extract data blocks.
		for match in self._hex_data_pattern.finditer(file_header):
			length, addr, data = match.groups()

			# Move on to the next block if the data length doesn't match.
			if ((len(data) >> 1) - 1) != int(length, 16):
				continue

			# Decode data.
			data = codecs.decode(data[:-2], 'hex')

			# Write data block at the specified address.
			f.seek(int(addr, 16))
			f.write(data)

		# Finish destination file.
		f.close()

		# Create dummy header file.
		open(os.path.join(dest_dir, ':header:'), 'wb').close()

		# Remove file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory.
		return dest_dir


class ISOExtractor(ArchiveExtractor):
	"""Extract ISO 9660 images."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._eltorito_pattern = re.compile(b'''\\x01\\x00\\x00\\x00[\\x00-\\xFF]{26}\\x55\\xAA\\x88\\x04[\\x00-\\xFF]{3}\\x00[\\x00-\\xFF]{2}([\\x00-\\xFF]{4})''')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this is not an ISO.
		if file_header[32769:32775] != b'CD001\x01':
			return False

		# Extract this as an archive.
		ret = self._extract_archive(file_path, dest_dir, False)

		# Some El Torito hard disk images have an MBR (Lenovo ThinkPad UEFI updaters).
		# 7-Zip doesn't care about MBRs and just takes the El Torito sector count field
		# for granted, even though it may be inaccurate. Try to detect such inaccuracies.
		if type(ret) == str:
			# Check what 7-Zip tried to extract, if anything.
			elt_path = os.path.join(ret, '[BOOT]', 'Boot-HardDisk.img')
			try:
				elt_size = os.path.getsize(elt_path)
			except:
				elt_size = 0

			# Does the size match known bad extractions?
			if elt_size == 512:
				# Read file.
				f = open(elt_path, 'rb')
				data = f.read(512)
				f.close()

				# Check for MBR boot signature.
				if data[-2:] == b'\x55\xAA':
					# Read up to 16 MB of the ISO as a safety net.
					file_header += util.read_complement(file_path, file_header)

					# Look for El Torito data.
					match = self._eltorito_pattern.search(file_header)
					if match:
						# Start a new El Torito extraction file.
						f_o = open(elt_path, 'wb')

						# Copy the entire ISO data starting from the boot offset.
						# Parsing the MBR would have pitfalls of its own...
						f_i = open(file_path, 'rb')
						f_i.seek(struct.unpack('<I', match.group(1))[0] * 2048)
						data = b' '
						while data:
							data = f_i.read(1048576)
							f_o.write(data)
						f_i.close()

						# Finish new file.
						f_o.close()

		# Remove ISO file if it was successfully extracted.
		if ret:
			try:
				os.remove(file_path)
			except:
				pass

		return ret


class IntelExtractor(Extractor):
	"""Extract Intel multi-part BIOS updates."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self._part_extensions = []
		for base_extension in ('bio', 'bbo'): # potential extensions for main BIOS part files
			# Produce all possible variants (ext, ex1-ex9, exa-) for this extension.
			extension_chars = base_extension[-1] + '123456789abcdefghijklm'
			for x in range(len(extension_chars)):
				extension = base_extension[:2] + extension_chars[x]
				# Every pair should be inverted.
				if (x % 2) == 0:
					self._part_extensions.append(extension)
				else:
					self._part_extensions.insert(len(self._part_extensions) - 1, extension)

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this is not an Intel BIOS update.
		if file_header[90:95] != b'FLASH' and file_header[602:607] != b'FLASH':
			return False

		# Stop if this file has no extension.
		file_name = os.path.basename(file_path)
		if file_name[-4:-3] != '.':
			return True

		# Stop if this file is too small (may be a copied header).
		if len(file_header) <= 608:
			return True

		# Stop if this file has an irrelevant extension.
		file_name_lower = file_name.lower()
		if file_name_lower[-3:] not in self._part_extensions:
			# Remove file.
			try:
				os.remove(file_path)
			except:
				import traceback
				traceback.print_exc()
				pass
			return True

		# Scan this directory's contents.
		dir_path = os.path.dirname(file_path)
		dir_files = {}
		for dir_file_name in os.listdir(dir_path):
			dir_file_name_lower = dir_file_name.lower()
			dir_file_path = os.path.join(dir_path, dir_file_name)

			# Remove irrelevant files which lack an Intel header.
			if dir_file_name_lower[-4:] in ('.lng', '.rcv', '.rec'):
				try:
					os.remove(dir_file_path)
				except:
					pass
				continue

			# Add to the file list.
			dir_files[dir_file_name_lower] = dir_file_path

		# Try to find matching parts in the same directory.
		file_name_base = file_name[:-3]
		file_name_base_lower = file_name_lower[:-3]
		found_parts = []
		largest_part_size = 0

		# Try all part extensions.
		for extension in self._part_extensions:
			# Check if this part exists in the directory.
			found_part_path = dir_files.get(file_name_base_lower + extension, None)
			if found_part_path:
				# Get the part's file size.
				try:
					found_part_size = os.path.getsize(found_part_path)
				except:
					continue

				# Add it to the part list.
				found_parts.append((found_part_path, found_part_size))

				# Update the largest part size.
				if found_part_size > largest_part_size:
					largest_part_size = found_part_size

		# Stop if no parts were found somehow.
		if len(found_parts) == 0:
			return True

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Copy the header to a file, so we can still get the BIOS version from
		# it in case the payload somehow cannot be decompressed successfully.
		out_f = open(os.path.join(dest_dir, ':header:'), 'wb')
		start_offset = (file_header[90:95] != b'FLASH') and 512 or 0
		part_data_offset = (file_header[start_offset + 127:start_offset + 128] == b'\x00') and 128 or 160
		out_f.write(file_header[start_offset:start_offset + part_data_offset])
		out_f.close()

		# Create destination file.
		out_f = open(os.path.join(dest_dir, 'intel.bin'), 'wb')

		# Create a copy of the found parts list for concurrent modification.
		found_parts_copy = found_parts[::]

		# Copy parts to the destination file.
		while len(found_parts_copy) > 0:
			found_part_path, found_part_size = found_parts_copy.pop(0)

			try:
				f = open(found_part_path, 'rb')

				# Skip header.
				file_header = f.read(128)
				if file_header[127:128] != b'\x00':
					f.seek(160)

				# Copy data.
				part_data = b' '
				while part_data:
					part_data = f.read(1048576)
					out_f.write(part_data)

				# Write padding.
				padding_size = largest_part_size - found_part_size
				while padding_size > 0:
					out_f.write(b'\xFF' * min(padding_size, 1048576))
					padding_size -= 1048576

				f.close()
			except:
				import traceback
				traceback.print_exc()
				pass
			
			# Remove this part.
			try:
				os.remove(found_part_path)
			except:
				pass

		# Finish destination file.
		out_f.close()

		# Return destination directory.
		return dest_dir


class InterleaveExtractor(Extractor):
	"""Detect and de-interleave any interleaved ROMs."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# List of strings an interleaved BIOS might contain once deinterleaved.
		self._deinterleaved_strings = [
			b'ALL RIGHTS RESERVED',
			b'All Rights Reserved',
			b'Illegal Interrupt No.',
			b'Phoenix Technologies Ltd.', # Phoenix
			b' COPR. IBM 198', # IBM and Tandon
			b'memory (parity error)',
			b'Copyright COMPAQ Computer Corporation', # Compaq
			b'Press any key when ready', # Access Methods
		]

		# Interleave the strings.
		self._interleaved_odd = [string[1::2] for string in self._deinterleaved_strings]
		self._interleaved_even = [string[::2] for string in self._deinterleaved_strings]

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this was already deinterleaved.
		dir_path, file_name = os.path.split(file_path)
		if os.path.exists(os.path.join(dir_path, ':combined:')):
			return False

		# Read up to 128 KB.
		file_header += util.read_complement(file_path, file_header, max_size=131072)

		# Check for interleaved strings.
		interleaved = 0
		for string in self._interleaved_odd:
			if string in file_header:
				interleaved = 1
				break
		if not interleaved:
			for string in self._interleaved_even:
				if string in file_header:
					interleaved = 2
					break

		# Stop if not interleaved.
		if not interleaved:
			return False

		# Try to find this file's counterpart in the directory.
		counterpart_candidates = []
		file_size = os.path.getsize(file_path)
		for file_in_dir in os.listdir(dir_path):
			# Skip this file.
			if file_in_dir == file_name:
				continue

			# Skip any files which differ in size.
			file_in_dir_path = os.path.join(dir_path, file_in_dir)
			if os.path.getsize(file_in_dir_path) != file_size:
				continue

			# Read up to 128 KB.
			file_in_dir_data = util.read_complement(file_in_dir_path, max_size=131072)
			if not file_in_dir_data:
				continue

			# Determine if this is a counterpart.
			counterpart = False
			if interleaved == 1:
				for string in self._interleaved_even:
					if string in file_in_dir_data:
						counterpart = True
						break
			elif interleaved == 2:
				for string in self._interleaved_odd:
					if string in file_in_dir_data:
						counterpart = True
						break

			# Move on if this is not a counterpart.
			if not counterpart:
				continue

			# Add to the list of candidates.
			counterpart_candidates.append(file_in_dir)

		# Find the closest counterpart candidate to this
		# file, and stop if no counterpart was found.
		counterpart_candidate = util.closest_prefix(file_name, counterpart_candidates, lambda x: util.remove_extension(x).lower())
		if not counterpart_candidate:
			return False
		counterpart_path = os.path.join(dir_path, counterpart_candidate)

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Deinterleave in both directions, as some pairs may contain the
		# same interleaved string on both parts. Also save interleaved
		# copies, as some pairs deinterleave incorrectly.
		f_ia = open(file_path, 'rb')
		f_ib = open(counterpart_path, 'rb')
		f_oa = open(os.path.join(dest_dir, 'deinterleaved_a.bin'), 'wb')
		f_ob = open(os.path.join(dest_dir, 'deinterleaved_b.bin'), 'wb')
		f_ca = open(os.path.join(dest_dir, 'interleaved_a.bin'), 'wb')
		f_cb = open(os.path.join(dest_dir, 'interleaved_b.bin'), 'wb')
		data = bytearray(1048576)
		write_len = 1
		while True:
			# Read both parts.
			data_a = f_ia.read(len(data))
			data_b = f_ib.read(len(data))
			write_len = min(len(data_a), len(data_b))

			# Stop if we've read everything.
			if not write_len:
				break

			# Set slice lengths.
			data_a_slice = len(data_a) * 2
			data_b_slice = len(data_b) * 2
			write_len *= 2

			# Write in one direction.
			data[:data_a_slice:2] = data_a
			data[1:data_b_slice:2] = data_b
			f_oa.write(data[:write_len])

			# Write in the other direction.
			data[:data_b_slice:2] = data_b
			data[1:data_a_slice:2] = data_a
			f_ob.write(data[:write_len])

			# Write interleaved copies.
			f_ca.write(data_a)
			f_cb.write(data_b)
		f_ia.close()
		f_ib.close()
		f_oa.close()
		f_ob.close()
		f_ca.close()
		f_cb.close()

		# Remove both files.
		try:
			os.remove(file_path)
		except:
			pass
		try:
			os.remove(counterpart_path)
		except:
			pass

		# Create flag file on the destination directory for the analyzer to
		# treat it as a big chunk of data, combining both deinterleave directions.
		open(os.path.join(dest_dir, ':combined:'), 'wb').close()

		# Return destination directory path.
		return dest_dir


class MBRSafeExtractor(ArchiveExtractor):
	"""Extract MBR disk images which appear to have a valid MBR."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._mbr_pattern = re.compile(b'''(?:Error loading|Missing) operating system''')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Extract this as an archive if MBR signatures are present.
		if file_header[510:512] == b'\x55\xAA' and self._is_mbr(file_header):
			return self._extract_archive(file_path, dest_dir)

		# No MBR found.
		return False

	def _is_mbr(self, file_header):
		# Helper function to determine if this *really* looks like some kind of MBR.
		return self._mbr_pattern.search(file_header[:510])


class MBRUnsafeExtractor(MBRSafeExtractor):
	"""Extract MBR disk images which have the MBR signature."""

	def _is_mbr(self, file_header):
		# Anything goes over here.
		return True


class OMFExtractor(ArchiveExtractor):
	"""Extract Fujitsu/ICL OMF BIOS files."""

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this is not an OMF file.
		if file_header[0:1] != b'\xB2':
			return False

		# Stop if this file is too small (may be a copied header).
		if len(file_header) <= 112:
			return False

		# Stop if the OMF payload is incomplete or the sizes are invalid.
		# Should catch other files which start with 0xB2.
		file_size = os.path.getsize(file_path)
		if struct.unpack('<I', file_header[1:5])[0] > file_size:
			return False
		elif struct.unpack('<I', file_header[108:112])[0] > file_size - 112:
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Separate file and header.
		try:
			# Open OMF file.
			in_f = open(file_path, 'rb')

			# Copy header.
			out_f = open(os.path.join(dest_dir, ':header:'), 'wb')
			out_f.write(in_f.read(112))
			out_f.close()

			# Copy payload.
			out_f = open(os.path.join(dest_dir, 'omf.bin'), 'wb')
			data = b' '
			while data:
				data = in_f.read(1048576)
				out_f.write(data)
			out_f.close()

			# Remove OMF file.
			in_f.close()
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir


class PEExtractor(ArchiveExtractor):
	"""Extract PE executables."""

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Determine if this is a PE/MZ.
		# The MZ signature is way too short. Check extension as well to be safe.
		if file_header[:2] != b'MZ' or file_path[-4:].lower() not in ('.exe', '.dll', '.scr'):
			return False

		# Read up to 16 MB as a safety net.
		file_header += util.read_complement(file_path, file_header)

		# Extract embedded ROM from AMIBIOS 8 AFUWIN.
		if b'Software\\AMI\\AFUWIN' in file_header:
			afuwin_result = self._extract_afuwin(file_path, file_header, dest_dir)
			if afuwin_result:
				return afuwin_result

		# Extract this as an archive.
		return self._extract_archive(file_path, dest_dir)

	def _extract_afuwin(self, file_path, file_header, dest_dir):
		# Stop if there's no embedded ROM.
		rom_start_idx = file_header.find(b'_EMBEDDED_ROM_START_\x00')
		if rom_start_idx == -1:
			return False
		rom_end_idx = file_header.find(b'_EMBEDDED_ROM_END_\x00', rom_start_idx)
		if rom_end_idx == -1:
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Write area before and after the embedded ROM as a header.
		try:
			f = open(os.path.join(dest_dir, ':header:'), 'wb')
			f.write(file_header[:rom_start_idx])
			f.write(file_header[rom_end_idx + 19:])
			f.close()
		except:
			pass

		# Extract ROM.
		try:
			f = open(os.path.join(dest_dir, 'afuwin.bin'), 'wb')
			f.write(file_header[rom_start_idx + 21:rom_end_idx])
			f.close()
		except:
			return True

		# Remove file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir


class TarExtractor(ArchiveExtractor):
	"""Extract tar archives."""

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Determine if this is a tar archive.
		for offset in (0, 257):
			for pattern in (
				b'ustar\x00\x00\x00', # POSIX tar
				b'ustar\x20\x20\x00', # GNU tar
				b'ustar\x00\x30\x30', # some other form of tar?
			):
				if file_header[offset:offset + len(pattern)] == pattern:
					# Extract this as an archive.
					return self._extract_archive(file_path, dest_dir)

		# Not a tar archive.
		return False


class TrimondExtractor(Extractor):
	"""Extract Trimond/Mitsubishi BIOS updates."""

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Act only on files at least 128 KB with a chunk of 8-32 KB missing, as a
		# safety margin since only 256-minus-16 KB images have been observed so far.
		try:
			file_size = os.path.getsize(file_path)
		except:
			return False
		if file_size < 131072:
			return False
		pow2 = 1 << math.ceil(math.log2(file_size))
		if pow2 - file_size not in (8192, 16384, 32768):
			return False

		# As a second safety layer, check for Trimond's flasher files.
		dir_path, file_name = os.path.split(file_path)
		dir_files = os.listdir(dir_path)
		dir_files_lower = [filename.lower() for filename in dir_files]
		if 'aflash.exe' not in dir_files_lower or 'cnv.exe' not in dir_files_lower or 'b.bat' not in dir_files_lower:
			return False

		# Look for other counterpart candidates.
		counterpart_candidates = []
		for counterpart_name in dir_files:
			if counterpart_name == file_name:
				continue

			try:
				counterpart_size = os.path.getsize(os.path.join(dir_path, counterpart_name))
			except:
				continue

			# Must add up to the next power of two.
			if (file_size + counterpart_size) == pow2:
				counterpart_candidates.append(counterpart_name)

		# Find the closest counterpart candidate to this
		# file, and stop if no counterpart was found.
		counterpart_candidate = util.closest_prefix(file_name, counterpart_candidates, lambda x: util.remove_extension(x).lower())
		if not counterpart_candidate:
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Join both files together.
		counterpart_path = os.path.join(dir_path, counterpart_candidate)
		f_o = open(os.path.join(dest_dir, counterpart_candidate), 'wb')
		f_i = open(file_path, 'rb')
		data = b' '
		while data:
			data = f_i.read(1048576)
			f_o.write(data)
		f_i.close()
		f_i = open(counterpart_path, 'rb')
		data = b' '
		while data:
			data = f_i.read(1048576)
			f_o.write(data)
		f_i.close()
		f_o.close()

		# Create dummy header file on the destination directory.
		open(os.path.join(dest_dir, ':header:'), 'wb').close()

		# Remove files.
		try:
			os.remove(file_path)
		except:
			pass
		try:
			os.remove(counterpart_path)
		except:
			pass

		return dest_dir


class UEFIExtractor(Extractor):
	"""Extract UEFI BIOS images."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Ignore padding and microcode files.
		self._invalid_file_pattern = re.compile('''(?:Padding|Microcode)_''')

		# Path to the UEFIExtract utility.
		self._uefiextract_path = os.path.abspath('UEFIExtract')
		if not os.path.exists(self._uefiextract_path):
			self._uefiextract_path = None

		# /dev/null handle for suppressing output.
		self._devnull = open(os.devnull, 'wb')

		# Built-in instance of ImageExtractor for converting
		# any extracted BIOS logo images that were found.
		self._image_extractor = ImageExtractor()

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if UEFIExtract is not available.
		if not self._uefiextract_path:
			return False

		# Start UEFIExtract process.
		file_path_abs = os.path.abspath(file_path)
		try:
			subprocess.run([self._uefiextract_path, file_path_abs, 'unpack'], timeout=30, stdout=self._devnull, stderr=subprocess.STDOUT)
		except:
			pass

		# Remove report file.
		try:
			os.remove(file_path_abs + '.report.txt')
		except:
			pass

		# Stop if the dump directory was somehow not created.
		dump_dir = file_path_abs + '.dump'
		if not os.path.isdir(dump_dir):
			try:
				os.remove(report_file)
			except:
				pass
			return False

		# Move dump directory over to the destination.
		try:
			# Move within the same filesystem.
			os.rename(dump_dir, dest_dir_0)
			if not os.path.isdir(dest_dir_0):
				raise Exception()
		except:
			try:
				# Move across filesystems.
				shutil.move(dump_dir, dest_dir_0)
				if not os.path.isdir(dest_dir_0):
					raise Exception()
			except:
				# Remove left-overs and stop if the move failed.
				for to_remove in (dump_dir, dest_dir_0):
					try:
						shutil.rmtree(to_remove)
					except:
						pass
				return True

		# Go through the dump, counting valid .bin files and removing .txt ones.
		valid_file_count = 0
		for scan_file_name in os.listdir(dest_dir_0):
			if scan_file_name[-4:] == '.bin':
				# Non-UEFI images will only produce padding and microcode files.
				if not self._invalid_file_pattern.match(scan_file_name):
					valid_file_count += 1
			else:
				try:
					os.remove(os.path.join(dest_dir_0, scan_file_name))
				except:
					pass

		# Assume failure if nothing valid was extracted.
		# Actual UEFI images produce thousands of files, so 5 is a safe barrier.
		if valid_file_count < 1:
			return False
		elif valid_file_count < 5:
			# Remove left-overs and stop.
			try:
				shutil.rmtree(dest_dir_0)
			except:
				pass
			return False

		# Convert any BIOS logo images in-line (to the same destination directory).
		self._image_extractor.convert_inline(os.listdir(dest_dir_0), dest_dir_0)

		# Create header file with a dummy string, to tell the analyzer
		# this BIOS went through this extractor.
		f = open(os.path.join(dest_dir_0, ':header:'), 'wb')
		f.write(b'\x00\xFFUEFIExtract\xFF\x00')
		f.close()

		# Create flag file on the destination directory for the analyzer to
		# treat it as a big chunk of data.
		open(os.path.join(dest_dir_0, ':combined:'), 'wb').close()

		# Remove BIOS file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir_0
