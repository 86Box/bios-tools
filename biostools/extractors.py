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
import array, codecs, datetime, io, itertools, math, os, re, shutil, socket, struct, subprocess, sys, time, zlib
try:
	import PIL.Image
except ImportError:
	PIL = lambda x: x
	PIL.Image = None
from . import util


class MultifileStaleException(Exception):
	"""Exception raised by Extractor.multifile_lock_acquire() if the
	   file has gone missing after the multi-file lock was acquired."""
	pass

class Extractor:
	def __init__(self):
		self.debug = True
		self.multifile_locked = False

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		"""Extract the given file into one of the destination directories:
		   dest_dir allows extracted files to be reprocessed in the next run,
		   while dest_dir_0 does not. This must return either:
		   - False if this extractor can't handle the given file
		   - True if this extractor can handle the given file, but no output was produced
		   - a string with the produced output file/directory path"""
		raise NotImplementedError()

	def debug_print(self, *args):
		"""Print a log line if debug output is enabled."""
		print(self.__class__.__name__ + ':', *args, file=sys.stderr)

	def multifile_lock_acquire(self, file_path):
		"""Acquire the global multi-file lock. The lock is automatically released
		   by the main module after extract() returns or raises an exception."""
		self.multifile_lock.acquire()
		self.multifile_locked = True

		# Raise the special exception if another extractor already processed this file.
		try:
			return os.path.getsize(file_path)
		except:
			raise MultifileStaleException()


class ApricotExtractor(Extractor):
	"""Extract Apricot BIOS recovery files. Only one instance of this format
	   (Trimond Trent) has been observed, let us know if you find any other!"""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Apricot version signature.
		self._apricot_pattern = re.compile(b'''@\\(#\\)Apricot ''')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this isn't a slightly-bigger-than-power-of-two file.
		# The only observed file has a 2071-byte header.
		try:
			file_size = os.path.getsize(file_path)
		except:
			return False
		if file_size < 4096:
			return False
		pow2 = 1 << math.floor(math.log2(file_size))
		if file_size <= pow2 or file_size > pow2 + 4096:
			return False

		# Look for the Apricot signature as a safety net.
		if not self._apricot_pattern.search(file_header):
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Separate payload and header.
		try:
			# Open Apricot file.
			in_f = open(file_path, 'rb')

			# Read header.
			header = in_f.read(file_size - pow2)

			# Copy payload.
			try:
				out_f = open(os.path.join(dest_dir, 'apricot.bin'), 'wb')
				data = b' '
				while data:
					data = in_f.read(1048576)
					out_f.write(data)
				out_f.close()
			except:
				in_f.close()
				return True

			# Write header.
			try:
				out_f = open(os.path.join(dest_dir, ':header:'), 'wb')
				out_f.write(header)
				out_f.close()
			except:
				pass

			# Remove Apricot file.
			in_f.close()
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir


class ArchiveExtractor(Extractor):
	"""Extract known archive types."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Known signatures for archive files.
		self._signature_pattern = re.compile(
			b'''PK(?:00PK)?\\x03\\x04|''' # zip
			b'''Rar!\\x1A\\x07|''' # rar
			b'''7z\\xBC\\xAF\\x27\\x1C|''' # 7z
			b'''MSCF|''' # cab
			b'''\\x1F\\x8B|''' # gzip
			b'''BZh|''' # bzip2
			b'''\\xFD7zXZ\\x00|''' # xz
			b'''[\\x00-\\xFF]{2}-l(?:h[0467]|z4)-|''' # lha (methods supported by 7-Zip - HACK: except lh5 due to Award)
			b'''ZOO''' # zoo
		)

		# /dev/null handle for suppressing output.
		self._devnull = open(os.devnull, 'wb')

		# 7-Zip has this annoying quirk where it scans the archive's parent
		# directory structure before extracting the archive itself. This
		# takes a very long time if any of the parent directories has a lot
		# of files. Therefore, we try to find a location as close to / as
		# possible, so we can symlink the archive there and make that parent
		# scan as quick as possible. Igor recognizes this is an inefficiency
		# in p7zip, but even the native Linux 7-Zip 21.07 still has it...?
		dirs = []
		my_file_path = os.path.abspath(__file__)
		for dir_path in (os.path.dirname(my_file_path), os.getcwd(), '/tmp', '/run/user/' + str(hasattr(os, 'getuid') and os.getuid() or 0)):
			# Get file count for all levels of the path.
			levels = []
			while True:
				try:
					list_len = len(os.listdir(dir_path))
				except:
					list_len = 2 ** 32
				levels.append((dir_path, list_len))
				parent_dir_path = os.path.dirname(dir_path)
				if parent_dir_path == dir_path:
					break
				dir_path = parent_dir_path

			# Go through levels in ascending (therefore closest to /) order.
			levels.sort()
			total_count = 0
			for level_dir, level_count in levels:
				total_count += level_count
				dirs.append((level_dir, total_count))

		# Remove duplicates and sort by total children count.
		dirs = list(set(dirs))
		dirs.sort(key=lambda x: (x[1], x[0]))

		# See where we can create a symlink.
		temp_file_name = 'biostools_{0}_{1}_{2}'.format(socket.gethostname(), hex(os.getpid())[2:], hex(id(self))[2:])
		self._temp_paths = []
		for dir_path, dir_children in dirs:
			# Test symlink creation.
			link_path = os.path.join(dir_path, temp_file_name)
			try:
				# Create symlink and check if it was actually created.
				os.symlink(my_file_path, link_path)
				if os.readlink(link_path) == my_file_path:
					# Test passed, add to temporary path list.
					self._temp_paths.append(link_path)
			except:
				pass

			# Remove any created symlink.
			try:
				os.remove(link_path)
			except:
				pass

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		"""Extract an archive."""

		# Stop if this is apparently not an archive.
		match = self._signature_pattern.match(file_header)
		if not match:
			return False

		# Do the actual extraction.
		return self._extract_archive(file_path, dest_dir)

	def _extract_archive(self, file_path, dest_dir, remove=True):
		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Try creating temporary symlink with the archive's extension.
		file_path_abs = os.path.abspath(file_path)
		_, ext = os.path.splitext(file_path_abs)
		link_path = file_path_abs
		for temp_path in self._temp_paths:
			temp_path_ext = temp_path + ext
			try:
				# Create symlink and check if it was actually created.
				os.symlink(file_path_abs, temp_path_ext)
				if os.readlink(temp_path_ext) == file_path_abs:
					# Test passed, make this link the new path.
					link_path = temp_path_ext
					break
				else:
					# Remove link if it was created.
					os.remove(temp_path_ext)
			except:
				pass

		# Run 7z command to extract the archive.
		# The dummy password prevents any password prompts from stalling 7z.
		subprocess.run(['7z', 'x', '-y', '-aou', '-ppassword', '--', link_path], stdout=self._devnull, stderr=subprocess.STDOUT, cwd=dest_dir)

		# Remove temporary symlink.
		if link_path != file_path_abs:
			while os.path.islink(link_path):
				try:
					os.remove(link_path)
				except:
					break

		# Assume failure if nothing was extracted.
		files_extracted = os.listdir(dest_dir)
		if len(files_extracted) < 1:
			self.debug_print('Extraction produced no files:', file_path)
			return False

		# Rename single file. (gzip/bzip2/etc.)
		if len(files_extracted) == 1 and link_path != file_path_abs:
			link_name = os.path.splitext(os.path.basename(link_path))[0]
			if files_extracted[0][:len(link_name)] == link_name:
				try:
					shutil.move(os.path.join(dest_dir, files_extracted[0]), os.path.join(dest_dir, os.path.splitext(os.path.basename(file_path))[0] + files_extracted[0][len(link_name):]))
				except:
					pass

		# Remove archive file.
		if remove:
			try:
				os.remove(file_path)
			except:
				pass

		# Return destination directory path.
		return dest_dir


class ASTExtractor(Extractor):
	"""Extract AST BIOS flash floppy images. These appear to contain a specially
	   crafted FAT filesystem, likely with static sector offsets for the payload,
	   so we work on the entire image before FATExtractor has a chance to claim it."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# AST flash signature.
		self._ast_start_pattern = re.compile(b'''This is a flash update from AST Research, Inc\\.''')
		self._ast_payload_pattern = re.compile(b'''AST FLASH UPDATE''')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this file is too small.
		try:
			file_size = os.path.getsize(file_path)
		except:
			return False
		if file_size <= 0x9083:
			return False

		# Look for the AST signatures.
		if not self._ast_start_pattern.match(file_header[0x4200:0x422e]):
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Open AST image.
		try:
			with open(file_path, 'rb') as in_f:
				# Skip the initial 72 sectors.
				in_f.seek(0x9000)

				# Copy payload.
				header = b''
				dest_file_path = os.path.join(dest_dir, 'ast.bin')
				try:
					with open(dest_file_path, 'wb') as out_f:
						data = remaining = True
						while data and remaining > 0:
							payload_size = 15 * 512
							if data == True:
								# Check the header on the first payload sector.
								header += in_f.read(0x83)
								if not self._ast_payload_pattern.match(header[:0x10]):
									raise Exception('missing header')

								# Subtract header from payload.
								remaining, = struct.unpack('<I', header[-5:-1])
								payload_size -= 0x83

							# Copy the next 15 sectors of payload.
							data = in_f.read(min(payload_size, remaining))
							out_f.write(data)
							remaining -= len(data)

							# Skip the next 3 blank sectors.
							in_f.seek(3 * 512, 1)
				except:
					try:
						os.remove(dest_file_path)
					except:
						pass
					return True

				# Write header.
				try:
					with open(os.path.join(dest_dir, ':header:'), 'wb') as out_f:
						out_f.write(header)
				except:
					pass
		except:
			pass

		# Remove AST image.
		os.remove(file_path)

		# Return destination directory path.
		return dest_dir


class BIOSExtractor(Extractor):
	"""Extract a bios_extract-compatible BIOS file."""

	# BIOS entrypoint signatures (faster search)
	_entrypoint_pattern = re.compile(
		b'''\\xEA[\\x00-\\xFF]{2}\\x00\\xF0|''' # typical AMI/Award/Phoenix
		b'''\\x0F\\x09\\xE9|''' # Intel AMIBIOS 6
		b'''\\xE9[\\x00-\\xFF]{2}\\x00{5}''' # weird Intel (observed in SRSH4)
	)

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Fallback BIOS signatures (slower search), based on bios_extract.c
		self._signature_pattern = re.compile(
			b'''AMI(?:BIOS(?: \\(C\\)1993 American Megatrends Inc.,| W 0[45]|C0[6789]|C\\x00{4})|BOOT ROM|EBBLK| Flash Utility for DOS Command mode\\.)|'''
			b'''SUPER   ROM|'''
			b'''\\$ASUSAMI\\$|'''
			b'''= Award Decompression Bios =|'''
			b'''awardext.rom|'''
			b'''Phoenix Technologies|'''
			b'''IBM AT Compatible Phoenix NuBIOS|'''
			b'''[\\xEE\\xFF]\\x88SYSBIOS|'''
			b'''\\xEE\\x88\\x42IOS SCU'''
		)

		# Workaround for an annoying PhoenixNet entry type where the size field is wrong (compressed?)
		fn = b'''[^\\x01-\\x1F\\x7F-\\xFF\\\\/:\\*\\?"<>\\|]'''
		self._phoenixnet_workaround_pattern = re.compile(
			fn + b'''(?:\\x00{7}|''' +
			fn + b'''(?:\\x00{6}|''' +
			fn + b'''(?:\\x00{5}|''' +
			fn + b'''(?:\\x00{4}|''' +
			fn + b'''(?:\\x00{3}|''' +
			fn + b'''(?:\\x00{2}|''' +
			fn + b'''(?:\\x00{1}|''' +
			fn + b''')))))))''' +
			fn + b'''(?:\\x00{2}|''' +
			fn + b'''(?:\\x00{1}|''' +
			fn + b'''))'''
		)

		# Path to the bios_extract utility.
		self._bios_extract_path = os.path.abspath(os.path.join('bios_extract', 'bios_extract'))
		if not os.path.exists(self._bios_extract_path):
			self._bios_extract_path = None

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if bios_extract is not available.
		if not self._bios_extract_path:
			return False

		# Read up to 16 MB as a safety net.
		file_header += util.read_complement(file_path, file_header)

		# Stop if no BIOS signatures are found.
		if not BIOSExtractor._entrypoint_pattern.match(file_header[-16:]) and not self._signature_pattern.search(file_header):
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir_0):
			return True

		# Start bios_extract process.
		file_path_abs = os.path.abspath(file_path)
		try:
			proc = subprocess.run([self._bios_extract_path, file_path_abs], timeout=30, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=dest_dir_0)
		except:
			# Bad data can cause infinite loops.
			proc = None
			self.debug_print('Processing timed out on:', file_path)
		if proc and proc.returncode not in (0, 1, 86):
			self.debug_print('Bad return code:', proc.returncode)

		# Assume failure if nothing was extracted. A lone remainder file also counts as a failure.
		dest_dir_files = os.listdir(dest_dir_0)
		num_files_extracted = len(dest_dir_files)
		if num_files_extracted < 1:
			self.debug_print('Extraction produced no files:', file_path)
			return False
		elif num_files_extracted == 1 and dest_dir_files[0] == 'remainder.rom':
			# Remove remainder file so that the destination directory can be rmdir'd later.
			self.debug_print('Extraction only produced remainder file:', file_path)
			util.remove_all(dest_dir_files, lambda x: os.path.join(dest_dir_0, x))
			return False
		elif proc and proc.returncode == 86:
			# We received the magic exit code that tells us the Intel pipeline found
			# an option ROM but not the main body. This could indicate a non-Intel
			# BIOS with LH5-compressed option ROMs. Check the files just in case.
			have_intelopt = have_intelbody = False
			for dest_dir_file in dest_dir_files:
				if dest_dir_file[:9] in ('intelopt_', 'intelunk_'):
					have_intelopt = True
				elif dest_dir_file[:10] == 'intelbody_':
					have_intelbody = True
					break
			if have_intelopt and not have_intelbody:
				# Remove all files so that the destination directory can be rmdir'd later.
				self.debug_print('Extraction produced Intel option ROM without main body:', file_path)
				util.remove_all(dest_dir_files, lambda x: os.path.join(dest_dir_0, x))
				return False

		# A missing remainder.rom may indicate an extraction interrupted by a segfault
		# or something else gone wrong. Copy the original file to its place for safety.
		if 'remainder.rom' not in dest_dir_files:
			self.debug_print('Creating remainder stand-in for:', file_path)
			util.hardlink_or_copy(file_path, os.path.join(dest_dir_0, 'remainder.rom'))

		# Remove extraneous files containing Intel body remains. (Batman's Revenge 04/15/1994)
		if not proc or b'intelbody_' in proc.stdout:
			intel_bodies = [dest_dir_file for dest_dir_file in dest_dir_files if dest_dir_file[:10] == 'intelbody_']
			if len(intel_bodies) > 1:
				# Get size for all body files.
				for x in range(len(intel_bodies)):
					try:
						body_size = os.path.getsize(os.path.join(dest_dir_0, intel_bodies[x]))
					except:
						body_size = 0
					intel_bodies[x] = (body_size, intel_bodies[x])

				# Remove all but the largest body file.
				intel_bodies.sort(reverse=True)
				self.debug_print('Keeping Intel body file', intel_bodies[0], 'and discarding', intel_bodies[1:])
				util.remove_all(intel_bodies[1:], lambda x: os.path.join(dest_dir_0, x[1]))

				# Remove removed files from file list.
				for _, body_name in intel_bodies[1:]:
					dest_dir_files.remove(body_name)

		# Extract Award BIOS PhoenixNet ROS filesystem.
		if not proc or b'Found Award BIOS.' in proc.stdout:
			for dest_dir_file in dest_dir_files:
				# Read and check for ROS header.
				dest_dir_file_path = os.path.join(dest_dir_0, dest_dir_file)
				if not os.path.isfile(dest_dir_file_path):
					continue
				with open(dest_dir_file_path, 'rb') as in_f:
					if in_f.read(3) == b'ROS':
						self.debug_print('Extracting PhoenixNet ROS:', dest_dir_file)

						# Create new destination directory for the expanded ROS.
						dest_dir_ros = os.path.join(dest_dir_0, dest_dir_file + ':')
						if util.try_makedirs(dest_dir_ros):
							# Skip initial header.
							in_f.seek(32)

							# Parse file entries.
							while True:
								# Read file entry header.
								header = in_f.read(32)
								if len(header) != 32:
									break
								file_size, = struct.unpack('<H', header[10:12])

								# Read data.
								if header[28] & 0x10:
									# Workaround for an annoying entry type where the size field is wrong (compressed?)
									pos = in_f.tell()
									data = in_f.read(65536 + 32)
									match = self._phoenixnet_workaround_pattern.search(data)
									if match:
										file_size = match.start(0) - 17
										in_f.seek(pos + file_size)
										data = data[:file_size]
									else:
										in_f.seek(0, 2)
								else:
									data = in_f.read(file_size)

								# Generate a file name.
								file_name = (util.read_string(header[17:25]) + '.' + util.read_string(header[25:28])).replace('/', '\\')

								# Write data.
								if len(file_name) > 1:
									self.debug_print('ROS file:', file_name)
									with open(os.path.join(dest_dir_ros, file_name), 'wb') as out_f:
										out_f.write(data)

							# Run image converter on the destination directory.
							self.image_extractor.convert_inline(os.listdir(dest_dir_ros), dest_dir_ros)

							# Don't remove ROS as the analyzer uses it for PhoenixNet detection.
							# Just remove the destination directory if it's empty.
							util.rmdirs(dest_dir_ros)

		# Convert any BIOS logo images in-line (to the same destination directory).
		self.image_extractor.convert_inline(dest_dir_files, dest_dir_0)

		# Create flag file on the destination directory for the analyzer to
		# treat it as a big chunk of data.
		open(os.path.join(dest_dir_0, ':combined:'), 'wb').close()

		# Hardlink or copy any header file to extracted directory, to help with
		# identifying Intel BIOSes. See AMIAnalyzer.can_handle for more information.
		parent_header = os.path.join(os.path.dirname(file_path_abs), ':header:')
		if os.path.exists(parent_header):
			util.hardlink_or_copy(parent_header, os.path.join(dest_dir_0, ':header:'))

		# Remove BIOS file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir_0


class CPUZExtractor(Extractor):
	"""Extract CPU-Z BIOS dump reports."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Patterns for parsing a report hex dump.
		self._cpuz_pattern = re.compile(b'''CPU-Z version\\t+([^\\r\\n]+)''')
		self._hex_pattern = re.compile(b'''[0-9A-F]+\\t((?:[0-9A-F]{2} ){16})\\t''')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this is not a CPU-Z dump.
		cpuz_match = self._cpuz_pattern.search(file_header)
		if not cpuz_match:
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Read up to 16 MB as a safety net.
		file_header += util.read_complement(file_path, file_header)

		# Convert hex back to binary.
		try:
			f = open(os.path.join(dest_dir, 'cpuz.bin'), 'wb')
			for match in self._hex_pattern.finditer(file_header):
				f.write(codecs.decode(match.group(1).replace(b' ', b''), 'hex'))
			f.close()
		except:
			return True

		# Create header file with the CPU-Z version string.
		try:
			f = open(os.path.join(dest_dir, ':header:'), 'wb')
			f.write(cpuz_match.group(1))
			f.close()
		except:
			pass

		# Remove report file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir


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
			elif off1 >= len(arr1):
				while off1 >= len(arr1):
					arr1.append(0xFF)
				continue
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

	def _dell_unpack_alt(self, indata):
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
				count = nibl + 1
				delta = (nibh << 8) | src[srcoff]
				srcoff += 1
				self._memcpy(dst, dstoff, dst, dstoff - delta - 1, count)
				dstoff += count
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
		alt_mode = False
		offset = file_header.find(copyright_string)
		if offset < 5:
			alt_mode = True
			copyright_string = b'\xE0Copyright 1985-\x02\x04\xF08 Phoenix Techno\xD0logies Ltd.'
			offset = file_header.find(copyright_string)
			if offset < 2:
				copyright_string = b'Copyright 1985-1988 Phoenix Technologies Ltd.'
				offset = file_header.find(copyright_string)
				if offset > 2 and (offset & 0xffff) == 0 and file_header[2] == 0xf0: # partial compression (OptiPlex 5xx)
					offset = 2
				else:
					return False

		# Determine the length format.
		if alt_mode:
			# 16-bit length (no module type prefix) with different compression.
			length_size = 2
			struct_format = '<0sH'
		elif file_header[offset - 5] == 1:
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

		# Create flag file on the destination directory for the analyzer to
		# treat it as a big chunk of data.
		open(os.path.join(dest_dir_0, ':combined:'), 'wb').close()

		# Extract any preceding data as EC code.
		if offset > 0:
			self.debug_print('Extracting', offset, 'bytes of EC code')
			f = open(os.path.join(dest_dir_0, 'ec.bin'), 'wb')
			f.write(file_header[:offset])
			f.close()

		# Extract modules.
		file_size = len(file_header)
		module_number = 0
		while (offset + length_size) < file_size:
			# Read module type and length.
			module_type, module_length = struct.unpack(struct_format, file_header[offset:offset + length_size])
			if (alt_mode and module_length in (0, 0xFFFF)) or module_type == 0xFF:
				break
			self.debug_print('Extracting module number', module_number, 'type', module_type, 'size', module_length)
			offset += length_size

			# Decompress data if required.
			data = file_header[offset:offset + module_length]
			if module_type != 0x0C:
				try:
					data = (alt_mode and self._dell_unpack_alt or self._dell_unpack)(data)
					if len(data) == 0:
						self.debug_print('Extraction produced blank output')
				except:
					self.debug_print('Extraction failed')
			offset += module_length

			# Write module.
			f = open(os.path.join(dest_dir_0, 'module_{0:02}.bin'.format(module_number)), 'wb')
			f.write(data)
			f.close()

			# Increase filename counter.
			module_number += 1

		# Extract remainder if applicable.
		if offset < file_size:
			try:
				f = open(os.path.join(dest_dir_0, 'remainder.bin'), 'wb')
				f.write(file_header[offset:])
				f.close()
			except:
				pass

		# Create header file with the copyright string, to tell the analyzer
		# this BIOS went through this extractor.
		try:
			f = open(os.path.join(dest_dir_0, ':header:'), 'wb')
			f.write(copyright_string)
			f.close()
		except:
			pass

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
			b'''\\x0A[\\x00-\\x05][\\x00-\\x01][\\x01\\x02\\x04\\x08]|''' # PCX
			b'''BM|''' # BMP
			b'''\\xFF\\xD8\\xFF|''' # JPEG
			b'''GIF8|''' # GIF
			b'''\\x89PNG|''' # PNG
			# documents
			b'''%PDF|''' # PDF
			b'''\\xD0\\xCF\\x11\\xE0\\xA1\\xB1\\x1A\\xE1|''' # Office (mszip)
			b'''\\x3F\\x5F\\x03\\x00|''' # WinHelp
			b'''<(?:\\![Dd][Oo][Cc][Tt][Yy][Pp][Ee]|[Hh][Tt][Mm][Ll])[ >]|''' # HTML (a cursory check ought not to upset anyone)
			# executables
			b'''(\\x7FELF)|''' # ELF
			# reports
			b'''CPU-Z TXT Report|\\s{7}File:   A|-+\\[ AIDA32 |HWiNFO64 Version |3DMARK2001 PROJECT|Report Dr. Hardware|'''
			b'''\\r\\n(?:\\s+HWiNFO v|\\r\\n\\s+\\r\\n\\s+Microsoft Diagnostics version )|'''
			b'''SIV[^\\s]+ - System Information Viewer V|UID,Name,Score,'''
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
			# Read 64 KB, which is enough to ascertain any potential logo type,
			# even if embedded in the file. (Monorail SiS 550x: PCX in AMI module)
			dest_dir_file_path = os.path.join(dest_dir_0, dest_dir_file)
			if os.path.isdir(dest_dir_file_path) or dest_dir_file == ':header:':
				continue
			f = open(dest_dir_file_path, 'rb')
			dest_dir_file_header = f.read(65536)
			f.close()

			# Run ImageExtractor.
			image_dest_dir = dest_dir_file_path + ':'
			if self.extract(dest_dir_file_path, dest_dir_file_header, image_dest_dir, image_dest_dir, any_offset=True):
				# Remove destination directory if it was created but is empty.
				util.rmdirs(image_dest_dir)

	def extract(self, file_path, file_header, dest_dir, dest_dir_0, any_offset=False):
		# Stop if PIL is not available or this file is too small.
		if not PIL.Image or len(file_header) < 16:
			return False

		# Determine if this is an image, and which type it is.
		func = None
		image_data_offset = 0
		if file_header[:4] == b'AWBM':
			# Get width and height for a v2 EPA.
			width, height = struct.unpack('<HH', file_header[4:8])

			# Determine if this file is a 4-bit or 8-bit EPA according to the file size.
			try:
				file_size = os.path.getsize(file_path)
			except:
				file_size = len(file_header)
			if file_size >= 8 + (width * height):
				func = self._convert_epav2_8b
			else:
				func = self._convert_epav2_4b
		elif file_header[:2] == b'PG':
			# Get width and height for a Phoenix Graphics image.
			width, height = struct.unpack('<HH', file_header[10:14])
			if width == 0 and height == 0 and file_header[2:17] == b'\x09\x00\x00\x80\x02\x16\x00\x00\x00\x00\x00\x00\x00\x00\x0F':
				# Ignore invalid image at the beginning of the compressed payload (Micronics Tigercat)
				if not any_offset or os.path.basename(file_path) == 'remainder.rom':
					return False

				# Some HP 4.0R6 have a width and height of 0 on 640x480 images.
				width = 640
				height = 480

			# Check if the file is actually paletted, as some
			# images (PhoenixNet) are incorrectly set as paletted.
			paletted = file_header[3] != 0
			payload_size = math.ceil((width * height) / 2)
			if paletted:
				try:
					file_size = os.path.getsize(file_path)
				except:
					file_size = len(file_header)
				if file_size > 18 + payload_size:
					palette_size, = struct.unpack('<H', file_header[10:12])
					file_header += util.read_complement(file_path, file_header, max_size=len(file_header) + (4 * palette_size))
					post_palette = file_header[12 + (4 * palette_size):16 + (4 * palette_size)]
					if len(post_palette) == 4:
						width, height = struct.unpack('<HH', post_palette)
						payload_size = math.ceil((width * height) / 2)
						if file_size >= 20 + (4 * palette_size) + payload_size:
							# Special marker that the palette should be read.
							width = -width

			if width != 0 and height != 0:
				func = self._convert_pgx
		if not func:
			# Determine if this file has valid dimensions and is the right size for a v1 EPA.
			width, height = struct.unpack('BB', file_header[:2])
			if width < 80 and height < 25 and len(file_header) == 72 + (15 * width * height):
				func = self._convert_epav1
			else:
				# Determine if this is a common image format.
				match = (any_offset and self._pil_pattern.search or self._pil_pattern.match)(file_header)
				if match:
					func = self._convert_pil
					image_data_offset = match.start(0)
					self.debug_print('PIL signature', match.group(0), 'on', file_path, '@', hex(image_data_offset))
				else:
					# Stop if this is not an image.
					return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir_0):
			return True

		# Read up to 16 MB (+ data offset) as a safety net.
		max_size = 16777216 + image_data_offset
		file_header += util.read_complement(file_path, file_header, max_size)

		# Stop if the file was cut off, preventing parsing exceptions.
		if len(file_header) == max_size:
			return True

		# Run extractor function, and stop if it was not successful.
		self.debug_print('Calling', func.__name__, 'on', file_path)
		ret = func(file_header, image_data_offset, width, height, dest_dir_0)
		if not ret:
			return True

		# Remove original file if it's the entire image (with a maximum margin of 1 byte).
		if ret == True or len(file_header) - ret <= 1:
			try:
				os.remove(file_path)
			except:
				pass

		return dest_dir_0

	def _convert_epav1(self, file_data, image_data_offset, width, height, dest_dir_0):
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

	def _convert_epav2_4b(self, file_data, image_data_offset, width, height, dest_dir_0):
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

	def _convert_epav2_8b(self, file_data, image_data_offset, width, height, dest_dir_0):
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

	def _convert_pgx(self, file_data, image_data_offset, width, height, dest_dir_0):
		# Read palette if the file contains one, while
		# writing the file type as a header accordingly.
		if width < 0:
			# Normalize width.
			width = -width

			# Read palette.
			palette_size, = struct.unpack('<H', file_data[10:12])
			palette = self._vga_palette[::] # start with standard EGA palette
			palette_index = 0
			index = 12
			while palette_index < palette_size:
				palette_color = file_data[index:index + 4]
				if len(palette_color) != 4:
					break
				palette[palette_index], = struct.unpack('>I', palette_color) # shortcut to parse _RGB value
				palette_index += 1
				index += 4

			self._write_type(dest_dir_0, 'PGX (with {0}-color palette)'.format(palette_size))
		else:
			# Use standard EGA palette.
			palette = self._vga_palette

			self._write_type(dest_dir_0, 'PGX (without palette)')

		# Create output image.
		image = PIL.Image.new('RGB', (width, height))

		# Read image data. This looks a lot like EPA v2 4-bit but it's slightly different.
		index = 18
		bitmap_width = math.ceil(width / 8)
		bitmap_size = height * bitmap_width
		for y in range(height):
			for x in range(bitmap_width):
				# Stop column processing if the file is truncated.
				if index + x + (bitmap_size * 3) >= len(file_data):
					index = 0
					break

				for cx in range(8):
					# Skip this pixel if it's outside the image width.
					output_x = (x * 8) + cx
					if output_x >= width:
						continue

					# Read color values. Each bit is stored in a separate bitmap.
					pixel  =  (file_data[index + x]                     >> (7 - cx)) & 1
					pixel |= ((file_data[index + x + bitmap_size]       >> (7 - cx)) & 1) << 1
					pixel |= ((file_data[index + x + (bitmap_size * 2)] >> (7 - cx)) & 1) << 2
					pixel |= ((file_data[index + x + (bitmap_size * 3)] >> (7 - cx)) & 1) << 3

					# Determine palette color and write pixel.
					if pixel > len(palette):
						pixel = len(palette) - 1
					color = palette[pixel]
					image.putpixel((output_x, y),
								 ((color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff))

			# Stop row processing if the file is truncated.
			if index == 0:
				break

			# Move on to the next line in the 4 bitmaps.
			index += bitmap_width

		# Save output image.
		return self._save_image(image, dest_dir_0)

	def _convert_pil(self, file_data, image_data_offset, width, height, dest_dir_0):
		# Load image.
		try:
			file_data_io = io.BytesIO(file_data[image_data_offset:])
			image = PIL.Image.open(file_data_io)

			# Don't save image if it's too small.
			x, y = image.size
			if (x * y) < 10000:
				raise Exception('too small')
		except:
			self.debug_print('PIL open failed')
			return False

		# Write the file type as a header.
		self._write_type(dest_dir_0, image.format)

		# Save output image.
		if image.format in ('GIF', 'PNG', 'JPEG'):
			if image.format == 'JPEG':
				ext = 'jpg'
			else:
				ext = image.format.lower()
			try:
				f = open(os.path.join(dest_dir_0, 'image.' + ext), 'wb')
				f.write(file_data[image_data_offset:])
				f.close()
				return True
			except:
				self.debug_print('As-is copy failed')
				return False
		elif self._save_image(image, dest_dir_0):
			return file_data_io.tell()
		else:
			return False

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
			self.debug_print('PIL save failed')

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
		self.debug_print('Type:', identifier)
		try:
			f = open(os.path.join(dest_dir_0, ':header:'), 'w')
			f.write(identifier)
			f.close()
		except:
			pass

class FATExtractor(ArchiveExtractor):
	"""Extract FAT disk images."""

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Determine if this is a FAT filesystem.

		# Stop if this file is too small.
		if len(file_header) < 512:
			return False

		# Stop if this doesn't appear to be a FAT filesystem.
		if not self._is_fat(file_header):
			# Check for 20-byte Unisys header followed by FAT filesystem.
			# Only 4 samples (from the Aquanta line) were found, the header is identical across all of them.
			if file_header[:20] == b'\x1A\x12\x34\x1A\x0E\x00\x00\x01\x01\x00\x04\x00\x02\x00\x12\x00\x02\x00\x50\x00' and self._is_fat(file_header[20:]):
				self.debug_print('Unisys header found')
				return self._extract_payload(file_path, dest_dir, 20, 'unisys.bin')

			# Check for 4-byte AST header followed by FAT filesystem.
			ast_size, unknown = struct.unpack('<HH', file_header[:4])
			try:
				file_size = os.path.getsize(file_path)
			except:
				file_size = 2 ** 32
			if (ast_size * 512) <= (file_size - 4) and self._is_fat(file_header[4:]):
				self.debug_print('AST size', hex(ast_size), 'sectors, unknown field', hex(unknown))
				return self._extract_payload(file_path, dest_dir, 4, 'ast.bin')

			return False

		# Inject the 55 AA signature (expected by 7-Zip) on images that don't have it.
		if file_header[510:512] != b'\x55\xAA':
			try:
				with open(file_path, 'r+b') as f:
					f.seek(510)
					f.write(b'\x55\xAA')
			except:
				pass

		# Extract this as an archive.
		return self._extract_archive(file_path, dest_dir)

	def _is_fat(self, file_header):
		# Check for bootstrap jump.
		if (file_header[0] != 0xEB or file_header[2] != 0x90) and file_header[0] != 0xE9:
			return False

		# Check for media descriptor type.
		if file_header[21] < 0xF0:
			return False

		return True

	def _extract_payload(self, file_path, dest_dir, header_size, dest_file_name):
		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Separate payload and header.
		try:
			# Open file.
			with open(file_path, 'rb') as in_f:
				# Read header.
				header = in_f.read(header_size)

				# Copy payload.
				try:
					with open(os.path.join(dest_dir, dest_file_name), 'wb') as out_f:
						data = b' '
						while data:
							data = in_f.read(1048576)
							out_f.write(data)
				except:
					return True

				# Write header.
				try:
					with open(os.path.join(dest_dir, ':header:'), 'wb') as out_f:
						out_f.write(header)
				except:
					pass

			# Remove file.
			os.remove(file_path)
		except:
			pass

		# Return destination directory.
		return dest_dir


class HexExtractor(Extractor):
	"""Extract Intel HEX format ROMs."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Signatures for parsing a HEX.
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

		try:
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
		except:
			return True

		# Create dummy header file.
		try:
			open(os.path.join(dest_dir, ':header:'), 'wb').close()
		except:
			pass

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

		# Signature for identifying El Torito header data.
		self._eltorito_pattern = re.compile(b'''\\x01\\x00\\x00\\x00[\\x00-\\xFF]{26}\\x55\\xAA\\x88\\x04[\\x00-\\xFF]{3}\\x00[\\x00-\\xFF]{2}([\\x00-\\xFF]{4})''')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this is not an ISO.
		if file_header[32769:32774] != b'CD001' and file_header[32777:32782] != b'CDROM':
			return False

		# Extract this as an archive.
		ret = self._extract_archive(file_path, dest_dir, remove=False)

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
				try:
					f = open(elt_path, 'rb')
					data = f.read(512)
					f.close()
				except:
					data = b''

				# Check for MBR boot signature.
				if data[-2:] == b'\x55\xAA':
					# Read up to 16 MB of the ISO as a safety net.
					file_header += util.read_complement(file_path, file_header)

					# Look for El Torito data.
					match = self._eltorito_pattern.search(file_header)
					if match:
						# Start a new El Torito extraction file.
						out_f = open(elt_path, 'wb')

						# Copy the entire ISO data starting from the boot offset.
						# Parsing the MBR would have pitfalls of its own...
						in_f = open(file_path, 'rb')
						in_f.seek(struct.unpack('<I', match.group(1))[0] * 2048)
						data = b' '
						while data:
							data = in_f.read(1048576)
							out_f.write(data)
						in_f.close()

						# Finish new file.
						out_f.close()

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

		# Fill a list of potential extensions for BIOS part files.
		self._part_extensions = []
		for base_extension in ('bio', 'bbo'):
			# Produce all possible variants (ext, ex1-ex9, exa-) for this extension. While the boot blocks are
			# always one file, they are technically able to form a chain, so count them in here for safety.
			extension_chars = base_extension[-1] + '123456789abcdefghijklm'
			for x in range(len(extension_chars)):
				extension = base_extension[:2] + extension_chars[x]
				self._part_extensions.append(extension)

		# Add recovery boot block extension.
		self._part_extensions.append('rcv')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this is not an Intel BIOS update.
		if file_header[90:95] != b'FLASH' and file_header[602:607] != b'FLASH':
			return False

		# Stop if this is a boot block file, as those have a separate
		# part count which breaks the main body part count check.
		if file_header[40:50].upper() == b'BOOT BLOCK':
			return True

		# Stop if this file is too small (may be a copied header).
		if len(file_header) <= 608:
			return True

		# Stop if this file has no extension.
		file_name = os.path.basename(file_path)
		if file_name[-4:-3] != '.':
			return True

		# Acquire the multi-file lock.
		self.multifile_lock_acquire(file_path)

		# Stop if this file has an irrelevant extension.
		file_name_lower = file_name.lower()
		if file_name_lower[-3:] not in self._part_extensions:
			# Remove file.
			try:
				os.remove(file_path)
			except:
				pass
			return True

		# Scan this directory's contents.
		dir_path = os.path.dirname(file_path)
		dir_files = {}
		for dir_file_name in os.listdir(dir_path):
			dir_file_name_lower = dir_file_name.lower()
			dir_file_path = os.path.join(dir_path, dir_file_name)

			# Remove irrelevant files which lack an Intel header.
			if dir_file_name_lower[-4:] in ('.lng', '.rec'):
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
		found_parts_main = []
		found_parts_boot = []
		have_bbo = False
		have_rcv = False
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

				# Treat main and non-main body parts differently.
				if extension[:2] == 'bi':
					# Add part to the main body part list.
					found_parts_main.append((found_part_path, found_part_size))
				else:
					# Add part to the boot block part list.
					found_parts_boot.append((found_part_path, found_part_size))

					# Flag the presence of main and recovery boot block files.
					if extension[:2] == 'bb':
						have_bbo = True
					elif extension[:2] == 'rc':
						have_rcv = True

				# Update largest part size.
				if found_part_size > largest_part_size:
					largest_part_size = found_part_size

		# Stop if no main body parts were found somehow.
		if len(found_parts_main) == 0:
			return True

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Determine header-related sizes and offsets.
		start_offset = (file_header[90:95] != b'FLASH') and 512 or 0

		version = util.read_string(file_header[start_offset + 112:]) # this assumes the chain name is less than 32 characters
		header_size = 112 + len(version) + 1                         # and the logical area name is less than 24 characters,
		remaining = header_size & 31                                 # but there's no fast detection of Intel files otherwise
		if remaining: # padded to 32 bytes
			header_size += 32 - remaining

		part_data_offset = start_offset + header_size

		# Subtract header from largest part size.
		largest_part_size -= part_data_offset

		# Determine if this is an inverted BIOS. This is quite tricky, since
		# the header data and presence of boot blocks in the main body isn't
		# super accurate, so we make a best guess through the following rules:
		if have_rcv and not have_bbo:
			# Recovery boot block file present but no main boot block file present => inverted
			invert = True
		elif have_bbo and not have_rcv:
			# Main boot block file present but no recovery boot block file present => non-inverted
			invert = False
		elif len(version) <= 16:
			# Short version (first AMI and Phoenix runs) => inverted
			invert = True
		else:
			# Long version (second AMI and Phoenix runs) => non-inverted
			invert = have_rcv # backup check for AN430TX which is inverted but has rcv

		# Join the part lists together.
		found_parts = found_parts_main + found_parts_boot

		# Create destination file.
		dest_file_path = os.path.join(dest_dir, 'intel.bin')
		out_f = open(dest_file_path, 'wb')
		self.debug_print('Found', len(found_parts), 'parts, header size', header_size, 'bytes, largest part size', largest_part_size, 'bytes')

		# Copy parts to the destination file.
		bootblock_offset = None
		end_offset = 0
		while len(found_parts) > 0:
			found_part_path, found_part_size = found_parts.pop(0)

			try:
				f = open(found_part_path, 'rb')

				# Read and parse header if present.
				if found_part_path[-4:].lower() == '.rcv':
					header = b''
					logical_area = dest_offset = 0
					logical_area_size = data_length = found_part_size
				else:
					f.seek(start_offset)
					header = f.read(part_data_offset)
					logical_area, logical_area_size = struct.unpack('<BI', header[32:37])
					dest_offset, data_length, _, last_part = struct.unpack('<IIBB', header[80:90])

					# Update ROM end offset.
					if logical_area_size > end_offset:
						end_offset = logical_area_size

					# Apply inversion if needed.
					if invert:
						dest_offset ^= 0x10000

				# Determine the part's location.
				if logical_area == 0:
					# Place boot block at the end of the ROM. Usually, the last part is cut
					# short and the boot block slots in at the end of the gap, but D845PT has
					# a full 64 KB last part containing a copy of the BBO boot block data.
					if bootblock_offset == None:
						bootblock_offset = end_offset - data_length
						if bootblock_offset < 0:
							bootblock_offset = 0
					dest_offset += bootblock_offset
				out_f.seek(dest_offset)

				# Copy data.
				self.debug_print(data_length, 'bytes @', hex(dest_offset), '=>', found_part_path)
				remaining = max(data_length, largest_part_size)
				part_data = b' '
				while part_data and remaining > 0:
					part_data = f.read(min(remaining, 1048576))
					out_f.write(part_data)
					remaining -= len(part_data)

				# Write padding.
				if logical_area == 1 and last_part == 0xff:
					if data_length <= 8192 and len(found_parts_boot) == 0:
						# Workaround for JN440BX, which requires its final
						# part (sized 8 KB) to be at the end of the image.
						self.debug_print('> Final part non-padded')
						remaining = 0
					elif data_length == largest_part_size and ((dest_offset >> 16) & 1) == int(invert):
						# Workaround for SE440BX-2 and SRMK2, which require a
						# gap at the final 64 KB where the boot block goes.
						if BIOSExtractor._entrypoint_pattern.match(part_data[-16:]):
							# This does not apply to N440BX, which ends
							# its parts with an entry point as expected.
							self.debug_print('> Entry point found, not applying final part gap')
						else:
							self.debug_print('> Final part gap')
							remaining += largest_part_size
				elif logical_area == 0 and dest_offset == bootblock_offset:
					# Don't pad a boot block insertion.
					remaining = 0
				if remaining > 0:
					self.debug_print('> Adding', remaining, 'padding bytes')
					while remaining > 0:
						out_f.write(b'\xFF' * min(remaining, 1048576))
						remaining -= 1048576

				f.close()

				# Update ROM end offset.
				part_end_offset = out_f.tell()
				if part_end_offset > end_offset:
					end_offset = part_end_offset

				# Remove part.
				os.remove(found_part_path)
			except:
				import traceback
				traceback.print_exc()
				pass

		out_f.close()

		# Create new file with padding if the total size isn't a power of two.
		if end_offset > 0:
			padding_size = (1 << math.ceil(math.log2(end_offset))) - end_offset
			if padding_size > 0:
				try:
					# Create a new file.
					out_f = open(dest_file_path + '.padded', 'wb')

					# Write padding.
					self.debug_print('Adding', padding_size, 'bytes of initial padding')
					while padding_size > 0:
						out_f.write(b'\xFF' * min(padding_size, 1048576))
						padding_size -= 1048576

					# Write the original file contents.
					f = open(dest_file_path, 'rb')
					part_data = b' '
					while part_data:
						part_data = f.read(1048576)
						out_f.write(part_data)
					f.close()

					out_f.close()

					# Remove the old file.
					try:
						os.remove(dest_file_path)
					except:
						pass

					# Move the new file into place.
					shutil.move(dest_file_path + '.padded', dest_file_path)
				except:
					pass

		# Copy the header to a file, so we can still get the BIOS version
		# from it in case the payload cannot be decompressed successfully.
		try:
			out_f = open(os.path.join(dest_dir, ':header:'), 'wb')
			out_f.write(file_header[start_offset:part_data_offset])
			out_f.close()
		except:
			pass

		# Return destination directory.
		return dest_dir


class IntelNewExtractor(Extractor):
	"""Extract newer Intel single-part BIOS updates."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# BIOS payload header. Checking the first bytes makes sure
		# we don't accidentally parse $IBIOSI$ version strings.
		self._ibi_pattern = re.compile(b'''\\$IBI[\\x00-\\x4E\\x50-\\xFF][\\x00-\\x52\\x54-\\xFF][\\x00-\\x23\\x25-\\xFF][\\x00-\\xFF]([\\x00-\\xFF]{8})''')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if the payload header couldn't be found.
		match = self._ibi_pattern.search(file_header)
		if not match:
			return False

		# Parse payload header and stop if the sizes appear to be wrong.
		header_sizes = match.group(1)
		if header_sizes == b'\xAA\x55\xAA\x55\x55\xAA\x55\xAA':
			# This is a :header: file with an invalidated size field.
			return True
		header_size, payload_size = struct.unpack('<II', header_sizes)
		self.debug_print('$IBI header at', hex(match.start(1)), 'declaring header size', header_size, 'and payload size', payload_size)
		if header_size > 65536 or payload_size > 16777216:
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Separate payload and header.
		try:
			# Open update file.
			in_f = open(file_path, 'rb')

			# Copy payload.
			payload_offset = match.start(0) + header_size
			try:
				in_f.seek(payload_offset)
				out_f = open(os.path.join(dest_dir, 'intel.bin'), 'wb')
				while payload_size > 0:
					data = in_f.read(min(payload_size, 1048576))
					out_f.write(data)
					payload_size -= len(data)
				out_f.close()
			except:
				in_f.close()
				return True

			# Copy header.
			try:
				out_f = open(os.path.join(dest_dir, ':header:'), 'wb')

				# Copy data before the header size fields.
				in_f.seek(0)
				size = match.start(1)
				while size > 0:
					data = in_f.read(min(size, 1048576))
					out_f.write(data)
					size -= len(data)

				# Invalidate the size fields so we don't process the header again.
				out_f.write(b'\xAA\x55\xAA\x55\x55\xAA\x55\xAA')

				# Write the rest of the header.
				in_f.seek(match.end(1))
				size = payload_offset - match.end(1)
				while size > 0:
					data = in_f.read(min(size, 1048576))
					out_f.write(data)
					size -= len(data)

				# Copy data after the payload.
				in_f.seek(payload_offset + payload_size)
				data = b' '
				while data:
					data = in_f.read(1048576)
					out_f.write(data)

				out_f.close()
			except:
				pass

			# Remove update file.
			in_f.close()
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
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
			b'* AMPRO Little Board', # AMPRO
			b'Philips ROM BIOS ', # Philips
			b'The following POST errors have been ' # Acer
		]

		# Interleave the strings.
		self._interleaved_odd = [string[1::2] for string in self._deinterleaved_strings]
		self._interleaved_even = [string[::2] for string in self._deinterleaved_strings]
		self._interleaved_q3 = [string[3::4] for string in self._deinterleaved_strings]
		self._interleaved_q2 = [string[2::4] for string in self._deinterleaved_strings]
		self._interleaved_q1 = [string[1::4] for string in self._deinterleaved_strings]
		self._interleaved_q0 = [string[::4] for string in self._deinterleaved_strings]

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this was already deinterleaved.
		dir_path, file_name = os.path.split(file_path)
		if os.path.exists(os.path.join(dir_path, ':combined:')):
			return False

		# Read up to 128 KB.
		file_header += util.read_complement(file_path, file_header, max_size=131072)

		# Check for interleaved strings.
		counterpart_string_sets = None
		sets_2 = [self._interleaved_odd, self._interleaved_even]
		sets_4 = [self._interleaved_q0, self._interleaved_q1, self._interleaved_q2, self._interleaved_q3]
		for part_set in (sets_2, sets_4):
			# Go through sets.
			for counterpart_set in part_set:
				# Go through strings.
				for string in counterpart_set:
					# Check if the string is present.
					if string in file_header:
						# Generate new string set list without this set.
						counterpart_string_sets = [new_set for new_set in part_set if new_set != counterpart_set]
						break

				# Stop if a set was found.
				if counterpart_string_sets:
					break
			if counterpart_string_sets:
				break

		# Stop if no interleaved strings could be found.
		if not counterpart_string_sets:
			return False

		# Acquire the multi-file lock.
		file_size = self.multifile_lock_acquire(file_path)

		# Create temporary interleaved data array.
		part_size = min(file_size, 16777216)
		data = []

		# Look for each counterpart.
		dir_files = os.listdir(dir_path)
		dir_files.sort()
		counterpart_paths = [file_path]
		for counterpart_string_set in counterpart_string_sets:
			# Try to find this file's counterpart in the directory.
			counterpart_candidates = []
			file_size = os.path.getsize(file_path)
			for file_in_dir in dir_files:
				# Skip seen files.
				file_in_dir_path = os.path.join(dir_path, file_in_dir)
				if file_in_dir_path in counterpart_paths:
					continue

				# Skip any files which differ in size.
				file_in_dir_size = 0
				try:
					file_in_dir_size = os.path.getsize(file_in_dir_path)
				except:
					continue
				if file_in_dir_size != file_size:
					continue

				# Read up to 128 KB.
				file_in_dir_data = util.read_complement(file_in_dir_path, max_size=131072)
				if not file_in_dir_data:
					continue

				# Determine if this is a counterpart.
				counterpart = False
				for string in counterpart_string_set:
					if string in file_in_dir_data:
						counterpart = True
						break
				del file_in_dir_data

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
			counterpart_paths.append(counterpart_path)

			# Read into the data array.
			f = open(counterpart_path, 'rb')
			data.append(f.read(part_size))
			f.close()

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Read this file into the data array.
		f = open(file_path, 'rb')
		data.insert(0, f.read(part_size))
		f.close()

		# Write all deinterleaved permutations, as some sets may
		# contain the same interleaved string on more than one part.
		file_counter = 0
		part_count = len(data)
		buf = bytearray(part_size * part_count)
		for permutation in itertools.permutations(range(part_count)):
			# Deinterleave from the array into the buffer.
			data_offset = 0
			for data_index in permutation:
				buf[data_offset::part_count] = data[data_index]
				data_offset += 1

			# Write deinterleaved file.
			f = open(os.path.join(dest_dir, 'deinterleaved_' + ''.join(util.base62[data_index] for data_index in permutation) + '.bin'), 'wb')
			f.write(buf)
			f.close()
			file_counter += 1

		# Save some memory. Might be placebo, but it doesn't hurt.
		del buf
		del data

		# Move interleaved files to preserve them,
		# as some sets may deinterleave incorrectly.
		file_counter = 0
		for counterpart_path in counterpart_paths:
			# Move original file.
			try:
				shutil.move(counterpart_path, os.path.join(dest_dir, 'interleaved_' + util.base62[file_counter] + '.bin'))
			except:
				pass
			file_counter += 1

			# Remove the original file in case moving failed.
			try:
				os.remove(counterpart_path)
			except:
				pass

		# Create flag file on the destination directory for the analyzer
		# to treat it as a big chunk of data, combining all permutations.
		f = open(os.path.join(dest_dir, ':combined:'), 'wb')
		f.write(b'\x00' * part_count)
		f.close()

		# Return destination directory path.
		return dest_dir


class MBRSafeExtractor(ArchiveExtractor):
	"""Extract MBR disk images which appear to have a valid MBR."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Signature for identifying typical MBRs.
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


class OCFExtractor(Extractor):
	"""Extract Fujitsu/ICL OCF BIOS files."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# RLE header.
		self._snipac_pattern = re.compile(b'''SNIPAC([0-9A-F]{2})([\\x00-\\xFF]{4})''')

	def _expand_rle(self, match):
		length, = struct.unpack('<I', match.group(2))
		return bytes([int(match.group(1), 16)]) * length

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this is not an RLE compressed file.
		if not self._snipac_pattern.search(file_header):
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Read up to 16 MB as a safety net.
		file_header += util.read_complement(file_path, file_header)

		# Decompress RLE data.
		file_header = self._snipac_pattern.sub(self._expand_rle, file_header)

		# Write decompressed data.
		try:
			out_f = open(os.path.join(dest_dir, 'ocf.bin'), 'wb')
			out_f.write(file_header)
			out_f.close()
		except:
			return True

		# Create dummy header file.
		try:
			open(os.path.join(dest_dir, ':header:'), 'wb').close()
		except:
			pass

		# Remove OCF file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir


class OMFExtractor(Extractor):
	"""Extract Fujitsu/ICL OMF BIOS files."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Quick header signature for checking validity.
		self._header_pattern = re.compile(
			b'''[\\x00-\\xFF]''' # arbitrary byte (not always B2!)
			b'''([\\x00-\\xFF]{4})''' # file size
			b'''([\\x1A\\x20-\\x7E]{32})''' # file timestamp
			b'''[\\x00-\\xFF]{14}''' # more fields
			b'''([\\x00\\x20-\\x7E]{8})''' # file signature (can be all 00 on auxiliary files at least)
		)

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this file is too small (may be a copied header).
		if len(file_header) <= 112:
			return False

		# Stop if this is not an OMF file.
		header_offset = 0
		match = self._header_pattern.match(file_header)
		if not match: # whatever has this offset header was lost to time
			header_offset = 112
			match = self._header_pattern.match(file_header[header_offset:header_offset + 112])
		if not match:
			return False

		# Stop if the OMF size is invalid. Should catch other files that match the quick check.
		try:
			file_size = os.path.getsize(file_path)
		except:
			return False
		omf_size, = struct.unpack('<I', match.group(1))
		if omf_size > file_size:
			return False
		self.debug_print('Size', omf_size, 'timestamp', match.group(2), 'signature', match.group(3))

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Separate payload and header.
		try:
			# Open OMF file.
			in_f = open(file_path, 'rb')

			# Read header.
			in_f.seek(header_offset)
			header = in_f.read(112)

			# Copy payload.
			try:
				out_f = open(os.path.join(dest_dir, 'omf.bin'), 'wb')
				data = b' '
				while data:
					data = in_f.read(1048576)
					out_f.write(data)

				# Truncate payloads with an extra byte.
				pos = out_f.tell()
				if pos & 1:
					out_f.truncate(pos - 1)

				out_f.close()
			except:
				in_f.close()
				return True

			# Write header.
			try:
				out_f = open(os.path.join(dest_dir, ':header:'), 'wb')
				out_f.write(header)
				out_f.close()
			except:
				pass

			# Remove OMF file.
			in_f.close()
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir


class PEExtractor(ArchiveExtractor):
	"""Extract PE executables."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Signatures for flash tool executables which may have an embedded ROM.
		self._flashtool_pattern = re.compile(
			b'''(?P<afuwin>Software\\\\AMI\\\\AFUWIN)|''' # AMIBIOS 8 AFUWIN (many ASRock)
			b'''(?P<aopen>AOpen FLASH ROM Utility R)|''' # AOpen (AP61)
			b'''Micro Firmware, Incorporated \\* |''' # Micro Firmware (Intel Monsoon surfaced so far)
			b'''(?P<asus>ASUS Floppy Image Self-Extrator\\.)''' # ASUS floppy self-extractor (P4VP-MX)
		)

		# Path to the deark utility.
		self._deark_path = os.path.abspath(os.path.join('deark', 'deark'))
		if not os.path.exists(self._deark_path):
			self._deark_path = None

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Determine if this is a PE/MZ.
		if file_header[:2] != b'MZ':
			return False

		# Cover PKZIP self-extractor (with PKLITE-compressed stub)
		# with an incorrect extension. This does appear to happen.
		if file_header[30:36] != b'PKLITE' or b'PK\x03\x04' not in file_header:
			# The MZ signature is way too short. Check extension as well to be safe.
			# This also stops :header: files from being re-processed as flash tools.
			if file_path[-4:].lower() not in ('.exe', '.dll', '.scr'):
				return False

			# Determine if this executable can be extracted with deark.
			ret = self.extract_deark(file_path, file_header, dest_dir)
			if ret:
				return ret

		# Cover Inno Setup installers.
		if file_header[48:52] == b'Inno':
			# Determine if this executable can be extracted with innoextract.
			ret = self._extract_inno(file_path, file_header, dest_dir)
			if ret:
				return ret

		# Read up to 16 MB as a safety net.
		file_header += util.read_complement(file_path, file_header)

		# Determine if this executable may have an embedded ROM.
		match = self._flashtool_pattern.search(file_header)
		if match:
			# Extract embedded ROM and stop if extraction was successful.
			ret = self._extract_flashtool(file_path, file_header, dest_dir, match)
			if ret:
				return ret

		# Extract this as an archive.
		return self._extract_archive(file_path, dest_dir)

	def extract_deark(self, file_path, file_header, dest_dir, remove=True, delegated=False):
		# Stop if deark is not available.
		if not self._deark_path:
			return False

		# Determine if deark can extract this file as an executable, and stop if it can't.
		file_path_abs = os.path.abspath(file_path)
		if not delegated:
			proc = subprocess.run([self._deark_path, '-opt', 'execomp', '-l', file_path_abs], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
			if proc.stdout[:12] != b'Module: exe\n' or proc.stdout[-16:] != b'\noutput.000.exe\n':
				return False
			self.debug_print('Using deark')

		# Stop if this is a dry run.
		if not dest_dir:
			return True

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Run deark command to extract the executable.
		orig_basename, orig_ext = os.path.splitext(os.path.basename(file_path_abs))
		subprocess.run([self._deark_path, '-opt', 'execomp', '-o', orig_basename, file_path_abs], stdout=self._devnull, stderr=subprocess.STDOUT, cwd=dest_dir)

		# Assume failure if nothing was extracted.
		files_extracted = os.listdir(dest_dir)
		if len(files_extracted) < 1:
			self.debug_print('deark produced no files:', file_path)
			return False

		# Rename single file.
		if len(files_extracted) == 1:
			_, dest_ext = os.path.splitext(files_extracted[0])
			if orig_ext.lower() == dest_ext.lower(): # keep casing if the extension hasn't changed
				dest_ext = orig_ext
			self.debug_print('Renaming', repr(files_extracted[0]), 'to', repr(orig_basename + dest_ext))
			try:
				new_fn = orig_basename + dest_ext
				shutil.move(os.path.join(dest_dir, files_extracted[0]), os.path.join(dest_dir, new_fn))
				if delegated:
					files_extracted = [new_fn]
			except:
				pass

		# Remove original file.
		if remove:
			try:
				os.remove(file_path)
			except:
				pass

		# Return destination directory path or first file path.
		if delegated:
			return os.path.join(dest_dir, files_extracted[0])
		else:
			return dest_dir

	def _extract_flashtool(self, file_path, file_header, dest_dir, match):
		# Determine embedded ROM start and end offsets.
		dest_file_name = 'flashtool.bin'
		if match.group('afuwin'):
			# Look for markers and stop if one of them wasn't found.
			rom_start_offset = file_header.find(b'_EMBEDDED_ROM_START_\x00')
			if rom_start_offset == -1:
				return False
			rom_start_offset += 21

			rom_end_offset = file_header.find(b'_EMBEDDED_ROM_END_\x00', rom_start_offset)
			if rom_end_offset == -1:
				return False
		elif match.group('asus'):
			# Change output file name.
			dest_file_name = 'floppy.img'

			# Extract zlib compressed data.
			try:
				file_header = file_header[:0xc000] + zlib.decompress(file_header[0xc000:])
			except:
				self.debug_print('ASUS zlib decompression failed')
				return False
			rom_start_offset = 0xc000
			rom_end_offset = len(file_header)
		else: # others
			# Round ROM size down to a power of two.
			try:
				file_size = os.path.getsize(file_path)
			except:
				file_size = len(file_header)
			rom_size = 1 << math.floor(math.log2(file_size))
			rom_start_offset = file_size - rom_size # ROM located at the end of the file
			rom_end_offset = file_size

			# Adjust offsets if needed.
			if match.group('aopen'):
				# Stop if this file appears to be standalone AOFLASH.
				if file_size < 32768:
					return False

				# Skip checksum word at the end. All files I've seen
				# contain it, but check for its presence just in case.
				remaining = file_size & 15
				if remaining == 2:
					rom_start_offset -= remaining
					rom_end_offset -= remaining

				# Skip BBOO data block. Same caveat as above.
				rom_half_offset = int((rom_start_offset + rom_end_offset) / 2)
				if file_header[rom_half_offset:rom_half_offset + 6] == b'*BBOO*':
					rom_end_offset = rom_half_offset

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Extract ROM.
		try:
			f = open(os.path.join(dest_dir, dest_file_name), 'wb')
			f.write(file_header[rom_start_offset:rom_end_offset])
			f.close()
		except:
			return True

		# Write data before and after the embedded ROM as a header.
		try:
			f = open(os.path.join(dest_dir, ':header:'), 'wb')
			f.write(file_header[:rom_start_offset])
			f.write(file_header[rom_end_offset:])
			f.close()
		except:
			pass

		# Remove file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir

	def _extract_inno(self, file_path, file_header, dest_dir):
		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Run innoextract command.
		try:
			subprocess.run(['innoextract', '-e', os.path.abspath(file_path)], stdout=self._devnull, stderr=subprocess.STDOUT, cwd=dest_dir)
		except:
			pass

		# Assume failure if nothing was extracted.
		files_extracted = os.listdir(dest_dir)
		if len(files_extracted) < 1:
			self.debug_print('Extraction produced no files:', file_path)
			return False

		# Remove file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir


class TarExtractor(ArchiveExtractor):
	"""Extract tar archives."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# 00 00 00 = POSIX tar
		# 20 20 00 = GNU tar
		# 00 30 30 = some other form of tar?
		self._signature_pattern = re.compile(b'''ustar(?:\\x00(?:\\x00\\x00|\\x30\\x30)|\\x20\\x20\\x00)''')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Determine if this is a tar archive.
		for offset in (0, 257):
			if self._signature_pattern.match(file_header[offset:offset + 8]):
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

		# Acquire the multi-file lock.
		self.multifile_lock_acquire(file_path)

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
		out_f = open(os.path.join(dest_dir, counterpart_candidate), 'wb')
		in_f = open(file_path, 'rb')
		data = b' '
		while data:
			data = in_f.read(1048576)
			out_f.write(data)
		in_f.close()
		in_f = open(counterpart_path, 'rb')
		data = b' '
		while data:
			data = in_f.read(1048576)
			out_f.write(data)
		in_f.close()
		out_f.close()

		# Create dummy header file on the destination directory.
		try:
			open(os.path.join(dest_dir, ':header:'), 'wb').close()
		except:
			pass

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

		# Known UEFI signatures.
		self._signature_pattern = re.compile(b'''EFI_|D(?:xe|XE)|P(?:ei|EI)|NVAR[\\x00-\\xFF]{7}(?:StdDefaults|PlatformLang|AMITSESetup|SecureBootSetup)\\x00''')

		# Ignore padding and microcode files.
		self._invalid_file_pattern = re.compile('''(?:Padding|Microcode)_''')

		# Path to the UEFIExtract utility.
		self._uefiextract_path = os.path.abspath('UEFIExtract')
		if not os.path.exists(self._uefiextract_path):
			self._uefiextract_path = None

		# /dev/null handle for suppressing output.
		self._devnull = open(os.devnull, 'wb')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if UEFIExtract is not available.
		if not self._uefiextract_path:
			return False

		# Read up to 32 MB as a safety net.
		file_header += util.read_complement(file_path, file_header, 33554432)

		# Stop if no UEFI signatures are found.
		if not self._signature_pattern.search(file_header):
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
		self.image_extractor.convert_inline(os.listdir(dest_dir_0), dest_dir_0)

		# Create header file with a dummy string, to tell the analyzer
		# this BIOS went through this extractor.
		try:
			f = open(os.path.join(dest_dir_0, ':header:'), 'wb')
			f.write(b'\x00\xFFUEFIExtract\xFF\x00')
			f.close()
		except:
			pass

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


class UnshieldExtractor(Extractor):
	"""Extract InstallShield CAB archives."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# InstallShield CAB signature.
		self._signature_pattern = re.compile(b'''ISc\\x28''')

		# /dev/null handle for suppressing output.
		self._devnull = open(os.devnull, 'wb')

	def extract(self, file_path, file_header, dest_dir, dest_dir_0):
		# Stop if this is apparently not an InstallShield CAB.
		match = self._signature_pattern.match(file_header)
		if not match:
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Run unshield command.
		try:
			subprocess.run(['unshield', 'x', os.path.abspath(file_path)], stdout=self._devnull, stderr=subprocess.STDOUT, cwd=dest_dir)
		except:
			pass

		# Assume failure if nothing was extracted.
		files_extracted = os.listdir(dest_dir)
		if len(files_extracted) < 1:
			self.debug_print('Extraction produced no files:', file_path)
			return False

		# Remove archive file.
		try:
			os.remove(file_path)
		except:
			pass

		# Return destination directory path.
		return dest_dir_0


class VMExtractor(PEExtractor):
	"""Extract files which must be executed in a virtual machine."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Known signatures.
		self._floppy_pattern = re.compile(
			b'''(?P<fastpacket> FastPacket V[0-9])|''' # Siemens Nixdorf FastPacket
			b''', Sydex, Inc\\. All Rights Reserved\\.|''' # IBM Sydex
			b'''Disk eXPress Self-Extracting Diskette Image|''' # HP DXP
			b'''(?P<nec>\\x00Diskette Image Decompression Utility(?: +v%s|\\.)\\x00)|''' # NEC in-house
			b'''(?P<ardi>Copyright Daniel Valot |\\x00ARDI -  \\x00)|''' # IBM ARDI
			b'''(?P<zenith>Ready to build distribution image with the following attributes:)|''' # Zenith in-house
			b'''(?P<softpaq>Error reading the Softpaq File information)|''' # Compaq Softpaq
			b'''(?P<dell>Intel Flash Memory Update Utility|DELLXBIOS[\\x00-\\xFF]+;C_FILE_INFO)[\\x00-\\xFF]+<<NMSG>>''' # Dell in-house
		)
		self._eti_pattern = re.compile(b'''[0-9\\.\\x00]{10}[0-9]{2}/[0-9]{2}/[0-9]{2}\\x00{2}[0-9]{2}:[0-9]{2}:[0-9]{2}\\x00{3}''')
		self._rompaq_pattern = re.compile(b'''[\\x00-\\xFF]{12}[A-Z0-9]{7}\\x00[0-9]{2}/[0-9]{2}/[0-9]{2}\\x00''')

		# Filename sanitization pattern.
		self._dos_fn_pattern = re.compile('''[\\x00-\\x1F\\x7F-\\xFF\\\\/:\\*\\?"<>\\|]''')

		# /dev/null handle for suppressing output.
		self._devnull = open(os.devnull, 'wb')

		# Path to QEMU.
		self._qemu_path = None
		for path in ('qemu-system-i386', 'qemu-system-x86_64'):
			try:
				subprocess.run([path, '-version'], stdout=self._devnull, stderr=subprocess.STDOUT).check_returncode()
				self._qemu_path = path
				break
			except:
				pass

		# Check for other dependencies.
		self._dep_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(util.__file__))), 'vm')
		for dep in ('floppy.144', 'freedos.img'):
			if not os.path.exists(os.path.join(self._dep_dir, dep)):
				self._qemu_path = None
				break

	def extract(self, file_path, file_header, dest_dir, dest_dir_0, *, allow_deark=True):
		# Stop if QEMU or other dependencies are not available.
		if not self._qemu_path:
			return False

		# Check for cases which require this extractor.
		# All signatures should be within the first 32 KB or so.
		extractor = None
		extractor_kwargs = {}
		if file_header[:2] == b'MZ' and b'PK\x03\x04' not in file_header: # skip ZIP self-extractors with compressed stubs
			# Read up to 16 MB as a safety net.
			file_header += util.read_complement(file_path, file_header)

			match = self._floppy_pattern.search(file_header)
			if match:
				extractor = self._extract_floppy
				extractor_kwargs['match'] = match
			elif allow_deark and self.extract_deark(file_path, file_header, None): # avoid infinite loops
				# Acquire the multi-file lock if this is a ROMPAQ.EXE.
				# This is required for ROMPAQ extraction below.
				if os.path.basename(file_path).lower() == 'rompaq.exe':
					self.multifile_lock_acquire(file_path)

				extractor = self._extract_deark
		elif self._eti_pattern.match(file_header):
			extractor = self._extract_eti
		elif self._rompaq_pattern.match(file_header):
			# Acquire the multi-file lock.
			self.multifile_lock_acquire(file_path)

			# The ROMPAQ format appears to be version specific in some way.
			# We will only extract files that have a ROMPAQ.EXE next to them.
			dir_path = os.path.dirname(file_path)
			rompaq_path = None
			for file_in_dir in os.listdir(dir_path):
				if file_in_dir.lower() == 'rompaq.exe':
					rompaq_path = os.path.join(dir_path, file_in_dir)
					break

			# Now look for a PKLITE-decompressed ROMPAQ.EXE.
			dest_parent_dir = os.path.dirname(dest_dir)
			if not rompaq_path and os.path.isdir(dest_parent_dir):
				for file_in_dir in os.listdir(dest_parent_dir):
					if file_in_dir.lower() == 'rompaq.exe:':
						rompaq_path = os.path.join(dest_parent_dir, file_in_dir, file_in_dir[:-1])
						if os.path.exists(rompaq_path):
							break
						else:
							rompaq_path = None

			# Enter ROMPAQ mode if the EXE was found.
			if rompaq_path:
				extractor = self._extract_rompaq
				extractor_kwargs['rompaq_path'] = rompaq_path

		# Stop if no case was found.
		if not extractor:
			return False

		# Create destination directory and stop if it couldn't be created.
		if not util.try_makedirs(dest_dir):
			return True

		# Run extractor.
		self.debug_print('Running', extractor.__name__)
		return extractor(file_path, file_header, dest_dir, dest_dir_0, **extractor_kwargs)

	def _run_qemu(self, hdd=None, hdd_snapshot=True, floppy=None, floppy_snapshot=True, vvfat=None, boot='c', monitor_cmd=None, monitor_flag_file=None):
		# Build QEMU arguments.
		args = [self._qemu_path, '-m', '32', '-boot', boot]
		if not self.debug or not os.getenv('DISPLAY'):
			args += ['-display', 'none', '-vga', 'none']
		if monitor_cmd:
			args += ['-monitor', 'stdio']
		for drive, drive_snapshot, drive_if in ((floppy, floppy_snapshot, 'floppy'), (hdd, hdd_snapshot, 'ide')):
			# Don't add this drive if an image was not specified.
			if not drive:
				# Add dummy floppy to prevent errors if no floppy is specified.
				if drive_if == 'floppy':
					drive = os.path.join(self._dep_dir, 'floppy.144')
					drive_snapshot = True
				else:
					continue

			# Add drive.
			args += ['-drive', 'if=' + drive_if + ',snapshot=' + (drive_snapshot and 'on' or 'off') + ',format=raw,file=' + drive.replace(',', ',,')]
		if vvfat:
			# Add vvfat if requested.
			args += ['-drive', 'if=ide,driver=vvfat,rw=on,dir=' + vvfat.replace(',', ',,')] # regular vvfat syntax can't handle : in path

		# Run QEMU.
		self.debug_print('Running QEMU with args:', args)
		proc = None
		try:
			if monitor_cmd and monitor_flag_file:
				proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=self._devnull, stderr=subprocess.STDOUT)

				# Wait for flag file if one was specified.
				if monitor_flag_file:
					spins = 0
					while not os.path.exists(monitor_flag_file) and spins < 60:
						time.sleep(1)
						spins += 1
					if spins < 60:
						self.debug_print('Monitor flag file found')
					else:
						self.debug_print('Monitor flag file timed out')

				# Send monitor command if one was specified, and wait for the QEMU process.
				proc.communicate(input=monitor_cmd, timeout=60)
			else:
				subprocess.run(args, input=monitor_cmd, timeout=60, stdout=self._devnull, stderr=subprocess.STDOUT)
		except:
			self.debug_print('Running QEMU failed (timed out?)')
			try:
				proc.communicate()
			except:
				pass

	def _extract_floppy(self, file_path, file_header, dest_dir, dest_dir_0, *, match):
		"""Extract DOS-based floppy self-extractors."""

		# Only support 1.44 MB floppies for now.
		floppy_media = 'floppy.144'

		# Copy original file and blank floppy image to the destination directory.
		if match.group('dell'): # Dell in-house names the extracted file after the executable
			exe_name = 'dell.exe'
		else:
			exe_name = util.random_name(8, charset=util.random_name_nosymbols).lower() + '.exe'
		exe_path = os.path.join(dest_dir, exe_name)
		image_path = os.path.join(dest_dir, util.random_name(8) + '.img')
		shutil.copy2(file_path, exe_path)
		shutil.copy2(os.path.join(self._dep_dir, floppy_media), image_path)
		flag_name = flag_path = None

		# Create batch file for calling the executable.
		bat_path = os.path.join(dest_dir, 'autoexec.bat')
		f = open(bat_path, 'wb')
		if match.group('nec'):
			# This SFX has trouble with (at least) the FreeDOS memory manager.
			# Work around that by moving config.sys out of the way to disable the
			# memory manager, rebooting the system, then executing the SFX proper.
			f.write(b'c:\r\n')
			f.write(b'if not exist config.sys goto sfx\r\n')
			f.write(b'move /y config.sys config.old\r\n')
			f.write(b'echo o cf9 6|debug\r\n') # TRC reset
			f.write(b'exit\r\n') # just in case
			f.write(b':sfx\r\n')
			f.write(b'move /y config.old config.sys\r\n') # just in case again (snapshot shouldn't persist changes)
			f.write(b'echo 0|') # later revision prompts for standard or LS-120 drive
		elif match.group('ardi'):
			f.write(b'echo.|')
		elif match.group('zenith') or match.group('dell'):
			f.write(b'a:\r\n')
		elif match.group('softpaq'):
			# Create flag file for sending the monitor commands.
			flag_name = util.random_name(8, charset=util.random_name_nosymbols).lower() + '.dat'
			flag_path = os.path.join(dest_dir, flag_name)
			f.write(b'echo. >d:\\' + flag_name.encode('cp437', 'ignore') + b'\r\n')
		f.write(b'd:' + exe_name.encode('cp437', 'ignore'))
		if match.group('fastpacket'):
			f.write(b' /b a:\r\n')
		elif match.group('ardi') or match.group('softpaq'):
			f.write(b'\r\n')
		elif match.group('zenith'):
			f.write(b' <c:\\agreed.txt\r\n')
		elif match.group('dell'):
			f.write(b' -writeromfile\r\n')
		else:
			f.write(b' a: <c:\\y.txt\r\n')
		f.close()

		# Assemble QEMU monitor commands for Compaq Softpaq.
		monitor_cmd = None
		if match.group('softpaq'):
			monitor_cmd = (
				b'sendkey pgdn\n'
				b'sendkey a\n'
				b'sendkey g\n'
				b'sendkey r\n'
				b'sendkey e\n'
				b'sendkey e\n'
				b'sendkey a\n'
				b'sendkey kp_enter\n'
				b'sendkey kp_enter\n'
				b'sendkey kp_enter\n'
				b'sendkey kp_enter\n'
				b'sendkey kp_enter\n'
				b'sendkey esc\n'
			)

		# Run QEMU.
		self._run_qemu(hdd=os.path.join(self._dep_dir, 'freedos.img'), floppy=image_path, floppy_snapshot=False, vvfat=dest_dir, monitor_cmd=monitor_cmd, monitor_flag_file=flag_path)

		# Detect and recover from a Softpaq crash.
		if match.group('softpaq'):
			temp_image_path = os.path.join(dest_dir, 'image')
			if os.path.exists(temp_image_path) and os.path.getsize(temp_image_path) > 0:
				try:
					os.remove(image_path)
				except:
					pass
				image_path = temp_image_path

		# Remove temporary files. (exename.tmp = FastPacket)
		util.remove_all((bat_path, exe_path, exe_path[:-3] + 'tmp', os.path.join(dest_dir, exe_name[:-3].upper() + 'TMP'), flag_path))

		# Extract image as an archive.
		ret = self._extract_archive(image_path, dest_dir, remove=False)
		if type(ret) == str and len(os.listdir(dest_dir)) > 1:
			# Remove original file.
			try:
				os.remove(file_path)
			except:
				pass

			# Flag success.
			ret = dest_dir
		else:
			ret = False

		# Remove image.
		try:
			os.remove(image_path)
		except:
			pass

		return ret

	def _extract_eti(self, file_path, file_header, dest_dir, dest_dir_0):
		"""Extract Evergreen ETI files."""

		# Read ETI header.
		in_f = open(file_path, 'rb')
		header = in_f.read(0x1f)

		# Parse creation date and time.
		try:
			date = header[10:18].decode('cp437', 'ignore')
			time = header[20:28].decode('cp437', 'ignore')
			dt = datetime.datetime.strptime(date + ' ' + time, '%m/%d/%y %H:%M:%S')
			ctime = (dt - datetime.datetime(1970, 1, 1)).total_seconds()
		except:
			ctime = 0

		# Start the extraction batch file.
		bat_f = open(os.path.join(dest_dir, 'autoexec.bat'), 'wb')
		bat_f.write(b'd:\r\n')

		# Extract files into individual ETIs.
		temp_files = ['autoexec.bat', 'contact.eti', 'contact.txt', 'prevlang.dat']
		while True:
				# Parse file header.
				fn = in_f.read(12) # filename
				if fn == None:
					break
				nul_index = fn.find(b'\x00')
				if nul_index > -1:
					fn = fn[:nul_index]
				if len(fn) == 0:
					break
				fn = fn.decode('cp437', 'ignore')
				self.debug_print('ETI file:', fn)
				in_f.read(5) # rest of header
				size = struct.unpack('<I', in_f.read(4))[0] # size

				# Create filename for the individual ETI.
				eti_name = temp_files[0] # dummy
				while eti_name in temp_files:
					eti_name = util.random_name(8, charset=util.random_name_nosymbols).lower() + '.eti'
				temp_files.append(eti_name)

				# Sanitize extracted filename to not overwrite ourselves.
				if fn.lower() in temp_files:
					fn = fn[:-1] + '_'
				fn = self._dos_fn_pattern.sub('_', fn)

				# Add individual ETI to the batch file.
				bat_f.write(b'del CONTACT.ETI CONTACT.TXT PREVLANG.DAT\r\n') # remove old files
				bat_f.write(b'c:move /y ' + eti_name.encode('cp437', 'ignore') + b' CONTACT.ETI\r\n') # insert ourselves
				bat_f.write(b'c:instl2o\r\n') # run hacked executable
				bat_f.write(b'c:move /y CONTACT.TXT ' + fn.encode('cp437', 'ignore') + b'\r\n') # rename decompressed file

				# Write individual ETI.
				out_f = open(os.path.join(dest_dir, eti_name), 'wb')
				out_f.write(header) # file header
				out_f.write(b'\x00\x00\x00\xB3\xD2\x40\xC6') # single-file header
				out_f.write(b'\xFF\xFF\xFF\x00') # unpacked size (unknown, assume 16 MB at most)
				while size > 0:
					data = in_f.read(min(size, 1048576))
					out_f.write(data) # data
					size -= len(data)
				out_f.close()

		# Finish the batch file.
		bat_f.close()

		# Run QEMU.
		self._run_qemu(hdd=os.path.join(self._dep_dir, 'freedos.img'), vvfat=dest_dir)

		# Remove temporary files.
		util.remove_all(temp_files, lambda x: (os.path.join(dest_dir, x), os.path.join(dest_dir, x.upper())))

		# Check if anything was extracted.
		dest_dir_files = os.listdir(dest_dir)
		if len(dest_dir_files) > 0:
			# Remove original file.
			try:
				os.remove(file_path)
			except:
				pass

			# Set timestamps if applicable.
			if ctime > 0:
				for fn in dest_dir_files:
					try:
						os.utime(os.path.join(dest_dir, fn), (ctime, ctime))
					except:
						pass

			return dest_dir
		else:
			return True

	def _extract_deark(self, file_path, file_header, dest_dir, dest_dir_0):
		"""Extract compressed executables with deark and run them through the same pipeline.
		   This is required for the following self-extractors, which contain a compressed stub:
		   - Compaq Softpaq (PKLITE)
		   - Dell in-house (LZEXE with no LZ91 signature)
		   - NEC in-house (PKLITE)
		   - Siemens Nixdorf FastPacket (LZEXE)
		   - Zenith in-house (PKLITE)
		   The decompressed files cannot be executed (they're garbage), so the pipeline has to run
		   with the original file path, while file_header gets the decompressed executable's data."""

		# Run deark extractor and stop if it wasn't successful.
		unpacked_path = self.extract_deark(file_path, file_header, dest_dir, remove=False, delegated=True)
		if type(unpacked_path) != str:
			return unpacked_path

		# Read unpacked file.
		decomp_file_data = util.read_complement(unpacked_path)

		# Run this same extractor with detectors pointed at the unpacked data.
		ret = self.extract(file_path, decomp_file_data, dest_dir, dest_dir_0, allow_deark=False)

		# Remove original file.
		try:
			os.remove(file_path)
		except:
			pass

		# Stop if extraction was successful.
		if ret:
			# Remove unpacked file.
			try:
				os.remove(unpacked_path)
			except:
				pass

			return ret

		# Keep the unpacked file around for other extractors to process.
		return dest_dir

	def _extract_rompaq(self, file_path, file_header, dest_dir, dest_dir_0, *, rompaq_path):
		"""Extract Compaq ROMPAQ-compressed BIOS images using a ROMPAQ.EXE provided next to the image."""

		# Copy original file and ROMPAQ.EXE to the destination directory.
		# Also determine output file name.
		rom_name = util.random_name(8, charset=util.random_name_nosymbols).lower() + '.bin'
		rom_path = os.path.join(dest_dir, rom_name)
		exe_name = util.random_name(8, charset=util.random_name_nosymbols).lower() + '.exe'
		exe_path = os.path.join(dest_dir, exe_name)
		try:
			shutil.copy2(file_path, rom_path)
			shutil.copy2(rompaq_path, exe_path)
		except:
			return True

		# Set a name for the unpacked file.
		unpacked_name = 'rompaq.bin'
		unpacked_path = os.path.join(dest_dir, unpacked_name)

		# Create batch file for extraction.
		bat_path = os.path.join(dest_dir, 'autoexec.bat')
		f = open(bat_path, 'wb')
		f.write(b'd:\r\n' + exe_name.encode('cp437', 'ignore') + b' /D ' + rom_name.encode('cp437', 'ignore') + b' ' + unpacked_name.encode('cp437', 'ignore') + b'\r\n')
		f.close()

		# Run QEMU.
		self._run_qemu(hdd=os.path.join(self._dep_dir, 'freedos.img'), vvfat=dest_dir)

		# Remove temporary files.
		util.remove_all((bat_path, rom_path, exe_path))

		# Stop if unpacking was not successful.
		if not os.path.exists(unpacked_path):
			unpacked_path = os.path.join(dest_dir, unpacked_name.upper()) # just in case
			if not os.path.exists(unpacked_path):
				return False

		# Remove original file.
		try:
			os.remove(file_path)
		except:
			pass

		# Create dummy header file.
		try:
			open(os.path.join(dest_dir, ':header:'), 'wb').close()
		except:
			pass

		# Return destination directory path.
		return dest_dir
