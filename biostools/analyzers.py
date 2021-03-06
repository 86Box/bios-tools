#!/usr/bin/python3
#
# 86Box          A hypervisor and IBM PC system emulator that specializes in
#                running old operating systems and software designed for IBM
#                PC systems and compatibles from 1981 through fairly recent
#                system designs based on the PCI bus.
#
#                This file is part of the 86Box BIOS Tools distribution.
#
#                BIOS image analyzer classes.
#
#
#
# Authors:       RichardG, <richardg867@gmail.com>
#
#                Copyright 2021 RichardG.
#
import codecs, os, re, struct, sys
from . import util

class Checker:
	def __init__(self, pattern, flags):
		self.pattern = pattern
		self.flags = flags

	def match(self, line):
		raise NotImplementedError()


class AlwaysRunChecker(Checker):
	def match(self, line):
		return True


SUBSTRING_CASE_SENSITIVE = 0
SUBSTRING_CASE_INSENSITIVE = 1
SUBSTRING_FULL_STRING = 2
SUBSTRING_BEGINNING = 4

class SubstringChecker(Checker):
	def __init__(self, pattern, flags):
		super().__init__(pattern, flags)

		if self.flags & SUBSTRING_CASE_INSENSITIVE:
			self.pattern = self.pattern.lower()

	def match(self, line):
		if self.flags & SUBSTRING_CASE_INSENSITIVE:
			line = line.lower()

		if self.flags & SUBSTRING_FULL_STRING:
			return self.pattern == line
		elif self.flags & SUBSTRING_BEGINNING:
			return self.pattern == line[:len(self.pattern)]
		else:
			index = line.find(self.pattern)
			if index > -1:
				return (index,)
			else:
				return False

	def __repr__(self):
		return '{cls}({pattern}{case})'.format(
			cls=self.__class__.__name__,
			pattern=repr(self.pattern),
			case=self.flags and ', case_insensitive' or ''
		)


class RegexChecker(Checker):
	def __init__(self, pattern, flags):
		super().__init__(pattern, flags)

		if pattern:
			self.pattern = re.compile(pattern, flags=flags)

			if pattern[0:1] == '^':
				pattern = pattern[1:]
				self.re_func = self.pattern.match
			else:
				self.re_func = self.pattern.search
		else:
			self.pattern = None
			self.re_func = self._dummy_always_false

	def _dummy_always_false(self, line):
		return False

	def match(self, line):
		return self.re_func(line)

	def __repr__(self):
		return '{cls}({pattern}, {func})'.format(
			cls=self.__class__.__name__,
			pattern=self.pattern,
			func=self.re_func == self.pattern.match and 'match' or 'search'
		)


class AbortAnalysisError(Exception):
	pass


class Analyzer:
	def __init__(self, vendor):
		self.vendor_id = self.vendor = vendor
		self.debug = True # to speed up analyze_line

		self._check_list = []

		self.reset()

	def analyze_line(self, line):
		"""Analyze a string found on the given file."""
		for callback, checker in self._check_list:
			if type(callback) == tuple:
				pre_check_func, callback_func = callback
				if not pre_check_func(line):
					continue
			else:
				callback_func = callback

			checker_result = checker.match(line)
			if checker_result:
				callback_result = callback_func(line, checker_result)
				if callback_result:
					if self.debug:
						self.debug_print(callback_func.__name__, '=>', repr(line))
					return callback_result

	def can_analyze(self):
		"""Returns True if the given file's strings should be analyzed."""
		return len(self._check_list) > 0

	def can_handle(self, file_path, file_data, header_data):
		"""Returns True if this analyzer can handle the given file data.
		   header_data contains data from the :header: flag file, or
		   None if no such file exists."""
		return True

	def debug_print(self, *args):
		"""Print a log line if debug output is enabled."""
		print(self.__class__.__name__ + ':', *args, file=sys.stderr)

	def register_check_list(self, check_list):
		"""Register the list of checks this analyzer will handle.

		   This function accepts a list of tuples, each containing:
		   - callback or (pre-checker, callback)
		   - checker class
		   - checker flags (optional)
		"""
		for entry in check_list:
			# Make a tuple out of a non-tuple.
			if type(entry) != tuple:
				entry = (entry,)

			# Extract parameters.
			if len(entry) >= 3:
				callback, checker_class, flags = entry
			else:
				callback, checker_class = entry
				flags = 0

			# Add to check list.
			if type(callback) == tuple:
				pattern = callback[1].__doc__
			else:
				pattern = callback.__doc__
			self._check_list.append((callback, checker_class(pattern, flags)))

	def reset(self):
		"""Restore this analyzer to its initial state."""
		self.version = ''
		self.string = ''
		self.signon = ''
		self.metadata = []
		self.oroms = []

class NoInfoAnalyzer(Analyzer):
	"""Special analyzer for BIOSes which can be identified,
	   but contain no information to be extracted."""

	_entrypoint_date_pattern = re.compile(b'''(?:\\xEA[\\x00-\\xFF]{2}\\x00\\xF0|\\xE9[\\x00-\\xFF]{2})((?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/[0-9]{2})''')

	def can_handle(self, file_path, file_data, header_data):
		# Check if this file can be handled by this specific analyzer.
		if not self.has_strings(file_data):
			return False

		# Unknown version.
		self.version = '?'

		# Look for entrypoint dates.
		self.get_entrypoint_dates(file_data)

		return True

	def get_entrypoint_dates(self, file_data):
		"""Set string to the newest date found after an entrypoint."""
		for match in NoInfoAnalyzer._entrypoint_date_pattern.finditer(file_data):
			# Extract the date as a string if newer than any previously-found date.
			date = match.group(1).decode('cp437', 'ignore')
			if not self.string or util.date_gt(date, self.string, util.date_pattern_mmddyy):
				self.string = date

	def has_strings(self, file_data):
		"""Returns True if this analyzer can handle the given file data."""
		raise NotImplementedError()


class AcerAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Acer', *args, **kwargs)

		self.register_check_list([
			(self._signon_486,							RegexChecker),
			((self._version_precheck, self._version),	RegexChecker),
			(self._string,								RegexChecker),
		])

	def reset(self):
		super().reset()
		self._cpus = []
		self._trap_version = False

	def can_handle(self, file_path, file_data, header_data):
		return b'Copyright (C) Acer Incorporated 1990' in file_data or b'Acer Boot Block v1.0' in file_data

	def _version_precheck(self, line):
		return self._trap_version

	def _version_r(self, line, match):
		'''^R([0-9])\.([0-9])'''

		# Extract version.
		self.version = match.group(0)

		return True

	def _version(self, line, match):
		'''V([0-9])\.([0-9])'''

		# Extract version.
		self.version = match.group(0)

		return True

	def _signon_486(self, line, match):
		'''^(?:((?:PCI/)?(?:E)?ISA) )?(.+) BIOS $'''

		# Stop if the CPU is invalid.
		cpu = match.group(2)
		if cpu in ('E)', 'AM') or 'SCSI' in cpu or '(tm)' in cpu:
			# "E)", "SCSI" (V55LA-2 R03-B1S0)
			# "(tm)" (Fortress 1100)
			# "AM" (V66LT)
			return False

		# Add CPU to the sign-on if it wasn't already seen.
		if cpu not in self._cpus:
			self._cpus.append(cpu)
			linebreak_index = self.signon.find('\n')
			if linebreak_index > -1:
				first_signon_line = self.signon[:linebreak_index]
			else:
				first_signon_line = self.signon

			if first_signon_line:
				first_signon_line += '/'
			first_signon_line += cpu

			if linebreak_index > -1:
				self.signon = first_signon_line + self.signon[linebreak_index:]
			else:
				self.signon = first_signon_line

		# Add any prefix to the sign-on.
		prefix = match.group(1)
		if prefix and self.signon[:len(prefix) + 1] != (prefix + ' '):
			self.signon = prefix + ' ' + self.signon

		# Read revision on the next non-string line.
		self._trap_version = True

		return True

	def _string(self, line, match):
		'''([A-Z]{3}[0-9A-F]{2}[A-Z0-9]{3}-[A-Z0-9]{3}-[0-9]{6}-[^\s]+)(?:\s+(.+))?'''

		# Extract string.
		self.string = match.group(1)

		# Extract sign-on if present.
		signon = match.group(2)
		if signon:
			if self.signon:
				self.signon += '\n'
			self.signon = signon.strip()

		# Read version on the next line.
		self._trap_version = True

		return True


class AcerMultitechAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('AcerMultitech', *args, **kwargs)
		self.vendor = 'Acer'

		self._version_pattern = re.compile(b'''Multitech Industrial Corp\..BIOS ([^\s]+ [^\s\\x00]+)''')

	def can_handle(self, file_path, file_data, header_data):
		# Look for version and date.
		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Set static version.
		self.version = 'Multitech'

		# Extract date and version as a string.
		self.string = match.group(1).decode('cp437', 'ignore')

		return True


class AMIAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('AMI', *args, **kwargs)

		self._check_pattern = re.compile(b'''American Megatrends Inc|AMIBIOSC| Access Methods Inc\\.|AMI- ([0-9]{2}/[0-9]{2}/[0-9]{2}) (?:IBM is a TM of IBM|[\\x00-\\xFF]{2}   AMI-[^-]+-BIOS )''')
		self._date_pattern = re.compile(b'''([0-9]{2}/[0-9]{2}/[0-9]{2})[^0-9]''')
		self._uefi_csm_pattern = re.compile('''63-0100-000001-00101111-[0-9]{6}-Chipset-0AAAA000$''')
		self._intel_86_pattern = re.compile('''[0-9A-Z]{8}\\.86[0-9A-Z]\\.[0-9A-Z]{3,4}\\.[0-9A-Z]{1,4}\\.[0-9]{10}$''')
		# The "All Rights Reserved" is important to not catch the same header on other files.
		# "All<Rights Reserved" (Tatung TCS-9850 9600x9, corrupted during production?)
		# AMIBIOS 6+ version corner cases:
		# - Second digit not 0 (I forget which one had 000000)
		# - Can be 4-digit instead of 6-digit (Biostar)
		self._id_block_pattern = re.compile(b'''(?:AMIBIOS (?:(0[1-9][0-9]{2}[\\x00-\\xFF]{2})[\\x00-\\xFF]{2}|W ([0-9]{2}) ([0-9]{2})[\\x00-\\xFF])|0123AAAAMMMMIIII|\\(AAMMIIBBIIOOSS\\))([\\x00-\\xFF]{2}/[0-9]{2}/[0-9]{2})\\(C\\)[0-9]{4} American Megatrends,? Inc(?:\\.,?.All.Rights.Reserved|/Hewlett-Packard Company)''')
		# Weird TGem identifier (TriGem 486-BIOS)
		self._precolor_block_pattern = re.compile(b'''\\(C\\)(?:[0-9]{4}(?:AMI,404-263-8181|TGem-HCS,PSC,JGS)|( Access Methods Inc\\.))''')
		# "Date:-" might not have a space after it (Intel AMI)
		# "\xFF\xFF\xFF\xFFFLASH-" (Everex EISA 386-BIOS)
		# Encoded "EVALUATION COPY" as a backup ("ami2939", possibly others without a date)
		self._precolor_date_pattern = re.compile(b'''(?:(?: Date:- ?|AMI- )[0-9]{2}/[0-9]{2}/[0-9]{2}|DDaattee(?:::|  )--(?:  )?([0-9])\\1([0-9])\\2//([0-9])\\3([0-9])\\4//([0-9])\\5([0-9])\\6|\\xFF{4}FLASH-[0-9]{6})|\\xFE\\xD5\\x4D\\xF5\\x9D\\x55\\xF5\\x5D\\xB5\\x85\\x8D\\xFE\\xE5\\x85\\x7D\\x35\\x9E\\xFE\\x8D\\x85\\x5D\\xFE\\xCD\\x85\\x6D\\xFE\\x65\\xF5\\x9D\\xD5''')
		# Variable gap between sync bytes (first bytes of the ROM) and the date.
		# "\xFF\xFF\xFF\xFFFLASH-" (Everex EISA 386-BIOS)
		self._precolor_core_date_pattern = re.compile(b'''\\xAA\\x55[\\x00-\\xFF]{1,16}([0-9]{2}/[0-9]{2}/[0-9]{2})|\\xFF{4}FLASH-([0-9]{2})([0-9]{2})([0-9]{2})''')
		# Decoded: "\xFE([^- ]{4}-(?:[^-]{4}-)?[^-]{6}|Ref\. [\x00-\xFF]{1,64})"
		# "Ref. " (Everex EISA 386-BIOS) - let the code handle termination
		self._precolor_string_pattern = re.compile(b'''\\xFE([\\x00-\\x95\\x97-\\xFD\\xFF]{4}\\x96(?:[\\x00-\\x95\\x97-\\xFF]{4}\\x96)?[\\x00-\\x95\\x97-\\xFF]{6}|\\x6D\\xD4\\xCC\\x8E\\xFE[\\x00-\\xFF]{1,64})''')
		self._precolor_signon_pattern = re.compile(b'''BIOS \\(C\\).*(?:AMI|American Megatrends Inc), for ([\\x0D\\x0A\\x20-\\x7E]+)''')
		self._precolor_type_pattern = re.compile(b'''([0-9]86|8(?:08)?8)-BIOS \\(C\\)''')
		# Decoded: "\(C\)AMI, \(([^\)]{11,64})\)" (the 64 is arbitrary)
		self._8088_string_pattern = re.compile(b'''\\xEC\\x5F\\x6C\\x60\\x5A\\x5C\\xEA\\xF0\\xEC([\\x00-\\x6B\\x6D-\\xFF]{11,64})\\x6C''')

		self.register_check_list([
			(self._string_pcchips,			RegexChecker),
			(self._string_setupheader,		RegexChecker),
			(self._signon_intel,			RegexChecker),
			(self._addons_color,			SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_easy,				SubstringChecker, SUBSTRING_BEGINNING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_hiflex,			SubstringChecker, SUBSTRING_BEGINNING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_intel,			SubstringChecker, SUBSTRING_BEGINNING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_new,				SubstringChecker, SUBSTRING_BEGINNING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_simple,			SubstringChecker, SUBSTRING_BEGINNING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_winbios,			SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
		])

	def can_handle(self, file_path, file_data, header_data):
		check_match = self._check_pattern.search(file_data)
		if not check_match:
			return False

		# Some Intel BIOSes may fail to decompress, in which case, we have to
		# rely on the header version data to get the Intel version sign-on.
		if header_data:
			is_intel = AMIIntelAnalyzer.can_handle(self, file_path, file_data, header_data)
			if is_intel:
				self.debug_print('Intel data found')
		else:
			is_intel = False

		# Check post-Color identification block.
		match = self._id_block_pattern.search(file_data)
		if match:
			# Determine location of the identification block.
			id_block_index = match.start(0)
			self.debug_print('ID block starts at', hex(id_block_index))

			# Extract version.
			version_6plus = match.group(1)
			if version_6plus:
				# AMIBIOS 6 onwards.
				self.version = version_6plus.decode('cp437', 'ignore')
				self.debug_print('Version (6+):', repr(self.version))

				# Pad 4-digit versions. (Biostar)
				if self.version[-1] not in '0123456789':
					self.version = self.version[:4] + '00'
			else:
				# WinBIOS (AMIBIOS 4/5)
				version_winbios_maj = match.group(2)
				version_winbios_min = match.group(3)
				if version_winbios_maj and version_winbios_min:
					self.version = (version_winbios_maj + version_winbios_min).decode('cp437', 'ignore')
					self.debug_print('Version (4-5):', repr(self.version))
					self.version += '00'
					self.metadata.append(('Setup', 'WinBIOS'))
				else:
					# AMI Color (or WinBIOS 12/15/93) date.
					self.version = match.group(4).decode('cp437', 'ignore')
					self.debug_print('Version (Color):', repr(self.version))

			# Extract string.
			self.string = util.read_string(file_data[id_block_index + 0x78:id_block_index + 0xa0])
			self.debug_print('Raw string:', repr(self.string))

			# Add identification tag to the string if one is present.
			id_tag = util.read_string(file_data[id_block_index + 0xec:id_block_index + 0x100])
			self.debug_print('String tag:', repr(id_tag))
			if id_tag[:4] == '_TG_':
				self.string = self.string.rstrip() + '-' + id_tag[4:].lstrip()

			# Stop if this BIOS is actually Aptio UEFI CSM.
			if isinstance(self, AMIUEFIAnalyzer):
				# This is the UEFI sub-class, we actually want the string and nothing more.
				self.debug_print('Returning to UEFI analyzer')
				return True
			elif self._uefi_csm_pattern.match(self.string):
				self.debug_print('String matches UEFI CSM, aborting')
				return False

			# Ignore unwanted string terminator on sign-on. (TriGem Lisbon-II)
			signon_terminator = b'\x00'
			if file_data[id_block_index + 0x123:id_block_index + 0x12b] == b' Inc.,\x00 ':
				self.debug_print('Applying sign-on terminator hack')
				signon_terminator += b'\x00'

			# Extract sign-on, while removing carriage returns.
			self.signon = util.read_string(file_data[id_block_index + 0x100:id_block_index + 0x200], terminator=signon_terminator)
			self.debug_print('Raw sign-on:', repr(self.signon))

			# The actual sign-on starts on the second line.
			self.signon = '\n'.join(x.rstrip('\r').strip() for x in self.signon.split('\n')[1:] if x != '\r').strip('\n')
		elif len(file_data) < 1024:
			# Ignore false positives from sannata readmes.
			self.debug_print('False positive by size of', len(file_data), 'bytes')
			return False
		elif self._precolor_date_pattern.search(file_data):
			self.debug_print('Potential pre-Color')
			self.debug_print([x.group(0) for x in self._precolor_date_pattern.finditer(file_data)])

			# Check date, using a different pattern to differentiate core date from build date.
			match = self._precolor_core_date_pattern.search(file_data)
			if match:
				date_start = match.start(0)
				self.debug_print('Pre-Color data starts at', hex(date_start))
			else:
				match = self._date_pattern.search(file_data)
				date_start = 0
				self.debug_print('Pre-Color data start is unknown')
			if match:
				# Extract date as the version.
				self.version = (match.group(1) or (match.group(2) + b'/' + match.group(3) + b'/' + match.group(4))).decode('cp437', 'ignore')
				self.debug_print('Version (pre-Color):', self.version)

				# Check pre-Color identification block.
				match = self._precolor_block_pattern.search(file_data)
				if match:
					# Determine location of the identification block.
					id_block_index = match.start(0)
					self.debug_print('Pre-Color ID block starts at', hex(id_block_index))

					# Locate the encoded string.
					match = self._precolor_string_pattern.search(file_data[date_start:])
					if match:
						# Extract string.
						buf = []
						for c in file_data[date_start + match.start(1):]:
							c = ~c & 0xff
							c = (c << 5) | (c >> 3)
							buf.append(c & 0x7f)
							if c & 0x80: # MSB termination
								break
						self.string = bytes(buf).decode('cp437', 'ignore')
						if 'Intel Corporation' in self.string or len(self.string) <= 8: # (later Intel AMI with no string)
							self.string = ''
							self.debug_print('Intel with no string')
						else:
							self.debug_print('Base string:', repr(self.string))

						# Remove "-K" KBC suffix.
						# Note: K without preceding - is possible (Atari PC5)
						if self.string[-1:] == 'K':
							self.string = self.string[:-1]
							if self.string[-1:] == '-':
								self.string = self.string[:-1]
					else:
						# Fallback if we can't find the encoded string.
						self.string = '????'

						# Add vendor ID.
						self.string += '-' + codecs.encode(file_data[id_block_index - 0xbb:id_block_index - 0xb9], 'hex').decode('ascii', 'ignore').upper()

						# Add date.
						self.string += '-' + util.read_string(file_data[id_block_index + 0x9c:id_block_index + 0xa4]).replace('/', '').strip()

						self.debug_print('Reconstructed string:', repr(self.string))

						# Invalidate string if the identification block doesn't
						# appear to be valid. (Intel AMI post-Color without string)
						if self.string[:10] in ('????-0000-', '????-0166-'):
							self.string = ''
							return True
				elif check_match.group(1): # 8088-BIOS header
					# Extract version.
					self.version = check_match.group(1).decode('cp437', 'ignore')
					self.debug_print('Version (8088):', self.string)

					# Locate the encoded string.
					match = self._8088_string_pattern.search(file_data)
					if match:
						# Extract string.
						buf = []
						for c in match.group(1):
							c = -c & 0xff
							c = (c << 1) | (c >> 7)
							buf.append(c & 0x7f)
						self.string = bytes(buf).decode('cp437', 'ignore')

						self.debug_print('Base string:', repr(self.string))
					else:
						# Fallback if we can't find the encoded string.
						self.string = '????-' + self.version.replace('/', '')

						self.debug_print('Reconstructed string:', repr(self.string))

				# Extract additional information after the copyright as a sign-on.
				# (Shuttle 386SX, CDTEK 286, Flying Triumph Access Methods)
				match = self._precolor_signon_pattern.search(file_data)
				if match:
					self.signon = match.group(1).decode('cp437', 'ignore')
					self.debug_print('Raw sign-on:', repr(self.signon))

					# Split sign-on lines. (Video Technology Info-Tech 286-BIOS)
					self.signon = '\n'.join(x.strip() for x in self.signon.split('\n') if x.strip()).strip('\n')

				# Extract BIOS type as an add-on.
				for match in self._precolor_type_pattern.finditer(file_data):
					self.metadata.append(('ID', match.group(1).decode('cp437', 'ignore') + '-BIOS'))
			else:
				# Assume this is not an AMI BIOS, unless we found Intel data above.
				if is_intel:
					self.debug_print('No AMI data found but Intel data found')
				return is_intel

		return True

	def _string_pcchips(self, line, match):
		'''ADVANCED SYSTEM SETUP UTILITY VERSION.+PC CHIPS INC'''

		# This is an early PC Chips BIOS.
		if not self.string:
			self.string = 'PC Chips'

		return True

	def _string_setupheader(self, line, match):
		'''[a-z][0-9/]+([^\(]*(SETUP PROGRAM FOR | SETUP UTILITY)[^\(]*)\(C\)19'''

		# Extract the setup header as a string if none was already found.
		if not self.string:
			self.string = match.group(1).replace(match.group(2), '')

		return True

	def _signon_intel(self, line, match):
		'''^(?:(?:BIOS (?:Release|Version) )?([0-9]\\.[0-9]{2}\\.[0-9]{2}\\.[A-Z][0-9A-Z]{1,})|(?:\\$IBIOSI\\$)?([0-9A-Z]{8}\\.([0-9A-Z]{3})\\.[0-9A-Z]{3,4}\\.[0-9A-Z]{1,4}\\.[0-9]{10}|(?:\\.[0-9]{4}){3}))'''

		# If this is Intel's second AMI run, check if this is not a generic
		# (86x) version string overwriting an OEM version string.
		oem = match.group(3)
		intel_version = match.group(1) or match.group(2)
		if (not oem or oem[:2] != '86' or not self._intel_86_pattern.match(self.signon)) and intel_version not in self.signon:
			# Extract the version string as a sign-on.
			self.signon = intel_version

		return True

	def _addons_color(self, line, match):
		'''Improper Use of Setup may Cause Problems !!'''

		# Add setup type to add-ons.
		self.metadata.append(('Setup', 'Color'))

		return True

	def _addons_easy(self, line, match):
		'''AMIBIOS EASY SETUP UTILIT'''

		# Add setup type to add-ons.
		self.metadata.append(('Setup', 'EasySetup'))

		return True

	def _addons_hiflex(self, line, match):
		'''\\HAMIBIOS HIFLEX SETUP UTILIT'''

		# Add setup type to add-ons.
		self.metadata.append(('Setup', 'HiFlex'))

		return True

	def _addons_intel(self, line, match):
		'''Advanced Chipset Configuration  \\QPress'''

		# Add setup type to add-ons.
		self.metadata.append(('Setup', 'IntelSetup'))

		return True

	def _addons_new(self, line, match):
		'''AMIBIOS NEW SETUP UTILIT'''

		# Add setup type to add-ons.
		self.metadata.append(('Setup', 'NewSetup'))

		return True

	def _addons_simple(self, line, match):
		'''\\HAMIBIOS SIMPLE SETUP UTILIT'''

		# Add setup type to add-ons.
		self.metadata.append(('Setup', 'SimpleSetup'))

		return True

	def _addons_winbios(self, line, match):
		''' Wait----'''

		# Add setup type to add-ons.
		self.metadata.append(('Setup', 'WinBIOS'))

		return True


class AMIDellAnalyzer(AMIAnalyzer):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.vendor_id = 'AMIDell'

		self.register_check_list([
			(self._version_dell,	RegexChecker),
		])

	def reset(self):
		super().reset()
		self._trap_signon_lines = 0

	def can_handle(self, file_path, file_data, header_data):
		if file_data[:9] == b'DELLBIOS\x00':
			# DELLBIOS header contains the Dell version.
			self.version = '11/11/92'
			self.debug_print('DELLBIOS header present')

			# Extract the version as a sign-on.
			terminator_index = file_data.find(b'\x00', 10)
			if terminator_index > -1:
				self.signon = file_data[10:terminator_index].decode('ascii', 'ignore').strip()
				if self.signon:
					self.signon = 'BIOS Version ' + self.signon

			return True
		elif b'DELLXBIOS' in file_data and not re.search(
				b'''att6300plus|'''
				b'''Flash BIOS Update Program - Version |'''
				b'''Technologies Ltd|'''
				b'''Western Digital 32-bit disk driver \(WDCDRV\)''',
			file_data):
			# "att6300plus" (HIMEM.SYS)
			# "Flash BIOS Update Program - Version " (FLASH.EXE)
			# Substring of "Phoenix Technologies Ltd" (4xxT/M/L)
			# "Western Digital 32-bit disk driver (WDCDRV)" (WDCDRV.386)

			# The Dell version will be in the BIOS body.
			self.version = '11/11/92'
			self.debug_print('DELLXBIOS string present')

			return True

		return False

	def _version_dell(self, line, match):
		'''^BIOS Version (.+)'''

		# Extract both Dell and Intel version numbers as a sign-on.
		version = match.group(1).strip()
		if version[1:2] == '.':
			# Intel version on second line.
			linebreak_index = self.signon.find('\n')
			if linebreak_index > -1:
				self.signon = self.signon[:linebreak_index]
			self.signon = self.signon.rstrip() + '\n' + version
		else:
			# Dell version.
			self.signon = match.group(0).rstrip() + '\n' + self.signon.lstrip()

		return True

	def _string_main(self, line, match):
		# Prevent the AMI string detector from working here.
		return False

	def _signon_trigger(self, line, match):
		'''^DELLXBIOS$'''

		# Read sign-on on the next few lines.
		self._trap_signon_lines = 1

		return True

	def _signon_line(self, line, match):
		self._trap_signon_lines += 1
		if self._trap_signon_lines == 4:
			# Extract the sign-on as a string, and disarm the trap.
			self.string = line.strip()
			if self.string[:5] == 'Dell ':
				self.string = self.string[5:]
			self._trap_signon_lines = 0

		return True


class AMIIntelAnalyzer(Analyzer):
	_ami_pattern = re.compile(b'''AMIBIOS''')
	_ami_version_pattern = re.compile(b'''AMIBIOSC(0[1-9][0-9]{2})''')
	_phoenix_pattern = re.compile(b'''PhoenixBIOS(?:\\(TM\\))? ''')

	def __init__(self, *args, **kwargs):
		super().__init__('Intel', *args, **kwargs)

	def can_handle(self, file_path, file_data, header_data):
		# Handle Intel AMI BIOSes that could not be decompressed.

		# Stop if there is no header data or if this file is just the header data.
		# Note that headers with a 512-byte offset are converted by the extractor.
		if not header_data:
			return False

		# Stop if this is an User Data Area file.
		if header_data[112:126] == b'User Data Area':
			return False

		# Extract the Intel version from the flash header.
		if header_data[90:95] == b'FLASH':
			# Start by assuming this is an unknown BIOS.
			if self.vendor_id == 'Intel':
				self.vendor = 'Intel'
			self.version = 'Unknown Intel'

			# Extract AMI version from compressed data.
			# (0632 fork which bios_extract can't handle)
			match = AMIIntelAnalyzer._ami_pattern.search(file_data)
			if match:
				match = AMIIntelAnalyzer._ami_version_pattern.search(file_data[match.start(0):])
				if match:
					if self.vendor_id == 'Intel':
						self.vendor = 'AMI'
					self.version = match.group(1).decode('cp437', 'ignore') + '00'
			elif self.vendor_id == 'Intel' and AMIIntelAnalyzer._phoenix_pattern.search(file_data):
				self.vendor = 'Phoenix'

			# Apply the version as a sign-on.
			self.signon = util.read_string(header_data[112:])

			return True

		return False


class AMIUEFIAnalyzer(AMIAnalyzer):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.vendor_id = 'AMIUEFI'

		self._identifier_pattern = re.compile(b'''\\$SGN\\$|ALASKAA M I|[Xx]-UEFI-AMI''')
		self._signon_asus_pattern = re.compile(b''' ACPI BIOS Rev''')
		self._signon_intel_msi_pattern = re.compile(b'''\\$((?:IBIOSI|MSESGN)\\$|UBI)([\\x20-\\x7E]{4,})''')
		self._signon_sgn_pattern = re.compile(b'''\\$SGN\\$[\\x01-\\xFF][\\x00-\\xFF]{2}''')

	def can_handle(self, file_path, file_data, header_data):
		# Only handle files sent through UEFIExtractor.
		if header_data != b'\x00\xFFUEFIExtract\xFF\x00':
			return False

		# Check for one of the identifiers.
		if not self._identifier_pattern.search(file_data):
			return False

		# Get CSM string from AMIAnalyzer.
		super().can_handle(file_path, file_data, header_data)
		self.signon = ''

		# Would be nice to easily know the difference between Aptio IV, V and such...
		self.version = 'UEFI'

		# Locate and extract different types of sign-on.
		match = self._signon_intel_msi_pattern.search(file_data)
		if match: # Intel (4D84F7CA-37D8-42DB-87F0-5F43A0469F3B 12D58591-E491-4E89-A081-3A3CE413181C) and MSI (GUID varies)
			self.debug_print('$' + match.group(1).decode('cp437', 'ignore'), 'sign-on:', match.group(2))

			# Extract text as a sign-on.
			self.signon = match.group(2).decode('cp437', 'ignore')

			return True

		match = self._signon_asus_pattern.search(file_data)
		if match: # ASUSPostMessage (177B2C74-9674-45F4-AAEB-43F5506AE0FE)
			# Locate the string's actual beginning.
			string_index = match.start(0)
			string_index = file_data.rfind(b'\x00', string_index - 256, string_index) + 1

			if string_index > 0:
				# Extract sign-on.
				self.signon = util.read_string(file_data[string_index:string_index + 256])
				self.debug_print('ASUS sign-on at', hex(string_index) + ':', repr(self.signon))

				return True

		match = self._signon_sgn_pattern.search(file_data)
		if match: # standard AMI (2EBE0275-6458-4AF9-91ED-D3F4EDB100AA A59A0056-3341-44B5-9C9C-6D76F7673817)
			# Skip first string (version/copyright format string)
			string_index = match.end(0)
			first_string = util.read_string(file_data[string_index:string_index + 256])
			string_index += len(first_string) + 1
			self.debug_print('AMI $SGN$ first line:', repr(first_string))

			# Extract sign-on from the second string.
			self.signon = util.read_string(file_data[string_index:string_index + 256]).replace('\r', '')
			self.debug_print('AMI $SGN$ sign-on:', repr(self.signon))

		return True


class AmproAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('AMPRO', *args, **kwargs)

		self._version_pattern = re.compile(b'''AMPRO (.+) Rom-Bios[^\\n]+\\nVersion ([^ ]+)''')

	def can_handle(self, file_path, file_data, header_data):
		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Extract version.
		self.version = match.group(2).decode('cp437', 'ignore')

		# Extract board type as a sign-on.
		self.signon = match.group(1).decode('cp437', 'ignore')

		return True


class AmstradAnalyzer(NoInfoAnalyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Amstrad', *args, **kwargs)

		self._plc_pattern = re.compile(b'''A(?:MSTRAD|mstrad(?: Consumer Electronics)?) plc''')
		self._bios_pattern = re.compile(b'''IBMUS NON CARBORUNDUM|fit new batteries|Veuillez mettre des piles neuves|Batterie da sostituire|ponga piles nuevas|neue Batterien einsetzen''')

	def has_strings(self, file_data):
		return self._plc_pattern.search(file_data) and self._bios_pattern.search(file_data)


class AwardAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Award', *args, **kwargs)

		# "COPYRIGHT AWARD SOFTWARE INC." (early XT/286)
		self._award_pattern = re.compile(b'''(?:Award|A w a r d) Software Inc\\.|COPYRIGHT AWARD SOFTWARE INC\\.|Award Decompression Bios''')
		self._ast_pattern = re.compile(b'''\\(c\\) COPYRIGHT 1984,[0-9]{4}(?:A w a r d|Award) Software Inc\\.|IBM COMPATIBLE A(S)T BIOS''')
		self._early_pattern = re.compile(b'''([0-9A-Z][\\x21-\\x7E]+) BIOS V([0-9.]+)[\\x21-\\x7E]* COPYRIGHT''')
		self._early_modular_prefix_pattern = re.compile('''(.+) Modular BIOS ''')
		self._gigabyte_bif_pattern = re.compile(b'''\\$BIF[\\x00-\\xFF]{5}([\\x20-\\x7E]+)\\x00.([\\x20-\\x7E]+)\\x00''')
		self._gigabyte_eval_pattern = re.compile('''\\([a-zA-Z0-9]{1,8}\\) EVALUATION ROM - NOT FOR SALE$''')
		self._gigabyte_hefi_pattern = re.compile(b'''EFI CD/DVD Boot Option''')
		self._id_block_pattern = re.compile( # whatever has "Phoenix" instead of "Award" was lost to time
			b'''(?:''' + util.rotate_pattern(b'Award Software Inc. ', 6) + b'''|''' + util.rotate_pattern(b'Phoenix Technologies, Ltd ', 6) + b''')[\\x00-\\xFF]{8}IBM COMPATIBLE|'''
			b'''[0-9]{2}/[0-9]{2}/[0-9]{4} {4}IBM COMPATIBLE (?:[0-9]+ )?BIOS COPYRIGHT Award Software Inc\\.'''
		)
		self._ignore_pattern = re.compile(b'search=f000,0,ffff,S,"|VGA BIOS Version (?:[^\r]+)\r\n(?:Copyright \\(c\\) (?:[^\r]+)\r\n)?Copyright \\(c\\) (?:NCR \\& )?Award', re.M)
		self._romby_date_pattern = re.compile(b'''N((?:[0-9]{2})/(?:[0-9]{2})/)([0-9]{2})([0-9]{2})(\\1\\3)''')
		self._string_date_pattern = re.compile('''(?:[0-9]{2})/(?:[0-9]{2})/([0-9]{2,4})-''')
		# "V" instead of "v" (286 Modular BIOS V3.03 NFS 11/10/87)
		self._version_pattern = re.compile(''' (?:v([^-\\s]+)|V(?:ersion )?[^0-9]*([0-9]\\.[0-9][0-9A-Z]?))(?:[. ]([\\x20-\\x7E]+))?''')

	def can_handle(self, file_path, file_data, header_data):
		if not self._award_pattern.search(file_data):
			return False

		# Skip:
		# - Windows 95 INF updates
		# - Award VBIOS
		if self._ignore_pattern.search(file_data):
			self.debug_print('Skipping INF or VBIOS', self.version)
			return False

		# The bulk of Award identification data has remained in one place for the longest time.
		found = False
		for match in self._id_block_pattern.finditer(file_data):
			# Determine location of the identification block.
			id_block_index = match.start(0)
			self.debug_print('ID block starts at', hex(id_block_index), match.group(0))

			# Extract version.
			version_string = util.read_string(file_data[id_block_index + 0x61:id_block_index + 0xa1])
			self.debug_print('Raw version string:', repr(version_string))
			self.signon = ''
			version_match = self._version_pattern.search(version_string)
			if version_match:
				self.version = 'v' + (version_match.group(1) or version_match.group(2))
			elif version_string == 'Award Modular BIOS Version ': # Award version removed (Intel YM430TX)
				self.version = 'Intel'
			elif version_string[:19] == 'Award Modular BIOS/': # Award version removed (Packard Bell PB810)
				self.version = 'Packard Bell'
				self.signon = version_string[19:] + '\n'

			# Add Phoenix-Award and WorkstationBIOS indicators.
			if 'Phoenix' in version_string:
				self.version += ' (Phoenix)'
			elif 'WorkstationBIOS' in version_string:
				self.version += ' (Workstation)'

			# Extract sign-on.
			signon = util.read_string(file_data[id_block_index + 0xc1:id_block_index + 0x10f])
			if ' BUSINESS MACHINES CORP.' in signon: # alternative location (Acer 01/01/1988, Commodore PC 40)
				self.debug_print('Using alternate sign-on location')
				signon = util.read_string(file_data[id_block_index + 0x71a:id_block_index + 0x81a])
			self.debug_print('Raw sign-on:', repr(signon))
			self.signon += signon

			# Extract string, unless the version is known to be too old to have a string.
			if self.version[:3] not in ('v2.', 'v3.'):
				self.string = util.read_string(file_data[id_block_index + 0xc71:id_block_index + 0xce0])
				self.debug_print('Raw string:', repr(self.string))

				# Check if no string was inserted where it should
				# have been. (Gateway/Swan Anigma Award v4.28/4.32)
				if ' Award Software Inc. ' in self.string:
					# Extrapolate a string with just the ID a bit further down.
					self.string = '??/??/??-??????-' + util.read_string(file_data[id_block_index + 0xce0:id_block_index + 0xcf0])
				else:
					# bp/rom.by patches may include a new date in the "modul.tmp"
					# patch code. If one is present, apply it to the string.
					match = self._romby_date_pattern.search(file_data)
					if match:
						date_match = self._string_date_pattern.match(self.string)
						if date_match:
							# Apply the correct date (2-digit or 4-digit year).
							if len(date_match.group(1)) == 2:
								date = match.group(4)
							else:
								date = match.group(1) + match.group(2) + match.group(3)
							date = date.decode('cp437', 'ignore')
							self.string = date + self.string[len(date):]

				# Move on to the next block if the string is too short.
				# (PC Partner 440BX with remains of 1992 BIOS in Y segment)
				if len(self.string) <= 11 and self.string[-1:] == '-':
					self.debug_print('Bogus string, trying another ID block')
					self.signon = ''
					continue

				# Flag Gigabyte Hybrid EFI as UEFI.
				if self._gigabyte_hefi_pattern.search(file_data):
					self.metadata.append('UEFI', 'Gigabyte Hybrid')

			if self.version == 'v6.00PG' and self._gigabyte_eval_pattern.match(self.signon):
				# Reconstruct actual sign-on of a Gigabyte fork BIOS through
				# the data in the $BIF area (presumably BIOS update data).
				match = self._gigabyte_bif_pattern.search(file_data)
				if match:
					self.debug_print('Sign-on reconstructed from Gigabyte data')
					self.signon = (match.group(1) + b' ' + match.group(2)).decode('cp437', 'ignore')
			elif 'Award' not in version_string.split('\n')[0] or '8088 Modular' in version_string: # "386SX Modular BIOS v3.15", "i-8088 Modular BIOS Version 3.0F"
				# Extract early Modular type as the string.
				match = self._early_modular_prefix_pattern.match(version_string)
				if match:
					self.string = match.group(1)
					self.debug_print('Using early Modular type:', repr(self.string))

				# Append post-version data to the string.
				if version_match:
					post_version = version_match.group(3)
					if post_version:
						post_version = post_version.strip()
					if post_version:
						self.debug_print('Raw post-version data:', repr(post_version))
						if match:
							self.string += '\n' + post_version
						else:
							self.string = post_version

			found = True
			break

		if not found:
			# Handle AST modified Award.
			match = self._ast_pattern.search(file_data)
			if match:
				id_block_index = match.group(1) and match.start(1) or match.start(0)
				self.debug_print('AST ID block found at', hex(id_block_index))

				# Set static version.
				self.version = 'AST'

				# Extract AST string as a sign-on.
				self.signon = util.read_string(file_data[id_block_index + 0x44:id_block_index + 0x144])
				if self.signon[:1] != 'A':
					self.debug_print('Using alternate sign-on location')
					self.signon = util.read_string(file_data[id_block_index + 0x80:id_block_index + 0x180])

				# Remove extraneous AST copyright from the sign-on.
				lines = self.signon.split('\n')
				self.signon = ''
				for line in lines:
					if line[:10] == 'Copyright ' or line[:19] == 'All Rights Reserved':
						continue
					self.signon += line + '\n'
			else:
				# Handle early XT/286 BIOS.
				match = self._early_pattern.search(file_data)
				if match:
					id_block_index = match.start(0)
					self.debug_print('Early ID block found at', hex(id_block_index))

					# Extract version.
					self.version = 'v' + match.group(2).decode('cp437', 'ignore')

					# Extract BIOS type as a string.
					self.string = match.group(1).decode('cp437', 'ignore')

					# Extract sign-on.
					self.signon = util.read_string(file_data[id_block_index + 0x3c:id_block_index + 0x8c])
				else:
					return False

		# Split sign-on lines.
		# Vertical tab characters may be employed. (??? reported by BurnedPinguin)
		self.signon = '\n'.join(x.strip() for x in self.signon.replace('\r', '\n').replace('\v', '\n').split('\n') if x.strip()).strip('\n')

		return True


class AwardPowerAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('AwardPower', *args, **kwargs)
		self.vendor = 'Award'

		self.register_check_list([
			(self._version,	RegexChecker),
			(self._string,	RegexChecker)
		])

	def can_handle(self, file_path, file_data, header_data):
		if b'PowerBIOS Setup' not in file_data or b'Award Software International, Inc.' not in file_data:
			return False

		# Identify as PowerBIOS.
		self.version = 'PowerBIOS'

		return True

	def _version(self, line, match):
		'''PowerBIOS  Version (.+)'''

		# Add version number if there isn't one already.
		if ' ' not in self.version:
			self.version += ' ' + match.group(1).lstrip()
			return True

		return False

	def _string(self, line, match):
		'''-3[12357ABCDE][A-Z0-9]{6}'''

		# PowerBIOS has an Award identification block similar to v4.xx,
		# but it doesn't always contain the string. (SIMATIC M7-400 MOV450)
		# Just detect the string heuristically and take the whole line.
		self.string = line.strip(' -')


class BonusAnalyzer(Analyzer):
	"""Special analyzer for ACPI tables and option ROMs."""

	def __init__(self, *args, **kwargs):
		super().__init__('', *args, **kwargs)
		self._pci_ids = {}

		self._acpi_table_pattern = re.compile(b'''(DSDT|FACP|PSDT|RSDT|SBST|SSDT)([\\x00-\\xFF]{4})[\\x00-\\xFF]{24}[\\x00\\x20-\\x7E]{4}''')
		self._adaptec_pattern = re.compile(b'''Adaptec (?:BIOS:|([\\x20-\\x7E]+?)(?: SCSI)? BIOS )''')
		self._ncr_pattern = re.compile(b''' SDMS \\(TM\\) V([0-9\\.]+)''')
		self._orom_pattern = re.compile(b'''\\x55\\xAA[\\x01-\\xFF][\\x00-\\xFF]{21}([\\x00-\\xFF]{4})([\\x00-\\xFF]{2}IBM)?''')
		self._phoenixnet_patterns = (
			re.compile(b'''CPLRESELLERID'''),
			re.compile(b'''BINCPUTBL'''),
			re.compile(b'''BINIDETBL'''),
		)
		self._pxe_patterns = (
			re.compile(b'''PXE-M0F: Exiting '''),
			re.compile(b'''PXE-EC6: UNDI driver image is invalid\\.'''),
		)
		self._rpl_pattern = re.compile(b'''NetWare Ready ROM''')
		self._sli_pattern = re.compile(b'''[0-9]{12}Genuine NVIDIA Certified SLI Ready Motherboard for ([\\x20-\\x7E]*)''')

	def _enumerate_metadata(self, key, entries):
		if len(entries) > 0:
			# De-duplicate and sort before enumerating.
			entries = list(set(entries))
			entries.sort()
			self.metadata.append((key, ' '.join(entries)))

	def can_handle(self, file_path, file_data, header_data):
		# PhoenixNet
		if util.all_match(self._phoenixnet_patterns, file_data):
			self.metadata.append(('Add-on', 'PhoenixNet'))

		# ACPI tables
		acpi_tables = []
		for match in self._acpi_table_pattern.finditer(file_data):
			if struct.unpack('<I', match.group(2))[0] > 36: # length includes header, header is 36 bytes
				acpi_tables.append(util.read_string(match.group(1)))
		self._enumerate_metadata('ACPI', acpi_tables)

		# Adaptec and NCR SCSI
		scsi_roms = []
		for match in self._adaptec_pattern.finditer(file_data):
			model = match.group(1)
			if model:
				model = ' ' + util.read_string(model)
			else:
				model = ''
			self.metadata.append(('SCSI', 'Adaptec' + model))
		for match in self._ncr_pattern.finditer(file_data):
			self.metadata.append(('SCSI', 'NCR ' + util.read_string(match.group(1))))

		# PXE and RPL boot
		lan_roms = []
		if util.all_match(self._pxe_patterns, file_data):
			lan_roms.append('PXE')
		if self._rpl_pattern.search(file_data):
			lan_roms.append('RPL')
		self._enumerate_metadata('LAN', lan_roms)

		# SLI certificate
		match = self._sli_pattern.search(file_data)
		if match:
			self.metadata.append(('SLI', match.group(1)))

		# UEFI
		if header_data == b'\x00\xFFUEFIExtract\xFF\x00':
			self.metadata.append(('UEFI', 'Filesystem'))

		# Look for PCI/PnP option ROMs.
		for match in self._orom_pattern.finditer(file_data):
			# Check for the VGA BIOS compatibility marker string and add it as metadata.
			vga_marker = match.group(2)
			if vga_marker:
				# Find ASCII strings around the marker. There must be a space before/after
				# the marker to avoid parsing of non-text bytes as ASCII characters.
				vga_start = match.start(2) + 2
				if file_data[vga_start - 1:vga_start] == b' ':
					while vga_start > 0 and file_data[vga_start - 1] >= 0x20 and file_data[vga_start - 1] <= 0x7e:
						vga_start -= 1
				vga_end = match.end(2)
				if file_data[vga_end:vga_end + 1] == b' ':
					while vga_end < len(file_data) and file_data[vga_end] >= 0x20 and file_data[vga_end] <= 0x7e:
						vga_end += 1
				self.metadata.append(('Video', file_data[vga_start:vga_end].decode('cp437', 'ignore')))

			# Extract PCI and PnP data structure pointers.
			pci_header_ptr, pnp_header_ptr = struct.unpack('<HH', match.group(1))

			# Check for a valid PCI data structure.
			if pci_header_ptr >= 26:
				pci_header_ptr += match.start()
				pci_magic = file_data[pci_header_ptr:pci_header_ptr + 4]
				if pci_magic == b'PCIR':
					pci_header_data = file_data[pci_header_ptr + 4:pci_header_ptr + 16]
					if len(pci_header_data) == 12:
						# Read PCI header data.
						vendor_id, device_id, device_list_ptr, _, revision, progif, subclass, class_code = struct.unpack('<HHHHBBBB', pci_header_data)
						self.debug_print('PCI header: vendor', hex(vendor_id), 'device', hex(device_id), 'class', class_code, 'subclass', subclass, 'progif', progif)

						# Make sure the vendor ID is not bogus.
						if vendor_id not in (0x0000, 0xffff):
							# Flag VGA option ROMs if the compatibility marker didn't already do so.
							if not vga_marker and ((class_code == 0 and subclass == 1) or (class_code == 3 and subclass in (0, 1))):
								self.metadata.append(('Video', 'PCI VGA'))

							# Add IDs to the option ROM list.
							self.oroms.append((vendor_id, device_id))

							# Read additional IDs only if this ROM is PCI 3.0 compliant and has a valid device list pointer.
							# The revision code is a tough one: 0 is known to be PCI <= 2.3, and 3 is known to be PCI Firmware
							# Specification 3.1. There could be other values, but only the PCI-SIG specs ($$$) can tell.
							if revision < 3 or device_list_ptr < 10:
								continue

							# The device list pointer is relative to the PCI header.
							device_list_ptr += pci_header_ptr

							# Read device IDs.
							while len(file_data[device_list_ptr:device_list_ptr + 2]) == 2:
								# Read ID and stop if this is a terminator.
								device_id, = struct.unpack('<H', file_data[device_list_ptr:device_list_ptr + 2])
								self.debug_print('PCI header: additional device', hex(device_id))
								if device_id == 0x0000:
									break

								# Add the device ID and existing vendor ID to the option ROM list.
								self.oroms.append((vendor_id, device_id))

								# Move on to the next ID.
								device_list_ptr += 2

							# Don't process the PnP data structure.
							continue

			# Check for a valid PnP data structure.
			if pnp_header_ptr >= 26:
				pnp_header_ptr += match.start()
				if file_data[pnp_header_ptr:pnp_header_ptr + 4] == b'$PnP':
					pnp_header_data = file_data[pnp_header_ptr + 4:pnp_header_ptr + 18]
					if len(pnp_header_data) == 14:
						# Read PnP header data.
						_, _, _, _, _, device_id, vendor_ptr, device_ptr = struct.unpack('<BBHBB4sHH', pnp_header_data)

						# Extract vendor/device name strings if they're valid.
						if vendor_ptr >= 26:
							vendor = util.read_string(file_data[match.start() + vendor_ptr:])
						else:
							vendor = None
						if device_ptr >= 26:
							device = util.read_string(file_data[match.start() + device_ptr:])
						else:
							device = None
						self.debug_print('PnP header: vendor', repr(vendor), 'device', repr(device))

						# Take valid data only.
						if device_id[:2] != b'\x00\x00' and (vendor or device):
							# Add PnP ID (endianness swapped to help the front-end in
							# processing it), vendor name and device name to the list.
							self.oroms.append((struct.unpack('>I', device_id)[0], vendor, device))

		# This analyzer should never return True.
		return False


class CDIAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('CDI', *args, **kwargs)

	def can_handle(self, file_path, file_data, header_data):
		if b' COMPUTER DEVICES INC. ' not in file_data:
			return False

		# No version information, outside of NCR.
		if b'NCR\'S VERSION IBM CORP. AT ROM' in file_data:
			self.version = 'NCR'
		else:
			self.version = '?'

		return True


class CentralPointAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('CPS', *args, **kwargs)

		self.register_check_list([
			(self._version,	RegexChecker)
		])

	def can_handle(self, file_path, file_data, header_data):
		return b'Central Point Software, Inc.' in file_data

	def _version(self, line, match):
		'''^BIOS ([^\s]+) (?:.+) Central Point Software, Inc\.'''

		# Extract version.
		self.version = match.group(1).rstrip('.')

		# Lowercase v for consistency.
		if self.version[0] == 'V':
			self.version = 'v' + self.version[1:]

		return True


class ChipsAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('C&T', *args, **kwargs)

		self.register_check_list([
			(self._version,	RegexChecker),
		])

	def can_handle(self, file_path, file_data, header_data):
		return b'Chips & Technologies, Inc.' in file_data and b'BIOS Version ' in file_data

	def _version(self, line, match): # TODO: remove prefix, because teknor "TEK701 BIOS Version 2.2\r\nsign-on..."
		'''(?:^|(?:CHIPS (.+)|Chips & Technologies (.+) ROM|(Reply Corporation(?: .+)?)) )BIOS Version ([^\(]+)(?:\(([^\)]+)\)( .+)?)?'''

		# Stop if this is a VBIOS.
		string = match.group(1) or match.group(2) or match.group(3) or ''
		if string[-4:] == ' VGA' or '/' in match.group(4):
			return True

		# Extract version.
		self.version = match.group(4).rstrip(', ')

		# Extract string.
		self.string = string

		# Extract sign-on.
		self.signon = (match.group(5) or '') + (match.group(6) or '')

		return True


class CommodoreAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Commodore', *args, **kwargs)

		self.register_check_list([
			(self._version,	RegexChecker),
		])

	def can_handle(self, file_path, file_data, header_data):
		return b'Commodore Business Machines' in file_data

	def _version(self, line, match):
		'''Commodore (.+) BIOS(?:\s+)(?:V|Rev\. )([^\s]+)'''

		# Extract version.
		self.version = 'V' + match.group(2)

		# Extract string.
		self.string = match.group(1)

		return True


class CompaqAnalyzer(NoInfoAnalyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Compaq', *args, **kwargs)

		self._copyright_pattern = re.compile(b'''Copyright ([0-9]+ by )?COMPAQ Computer Corporation''')
		self._error_pattern = re.compile(b'''Insert (?:DIAGNOSTIC diskette in Drive |COMPAQ DOS diskette)|You must load COMPAQ BASIC|[0-9]{2}/[0-9]{2}/[0-9]{2} +[^ ]+ +Copyright [0-9]+ by COMPAQ Computer Corporation''')

	def has_strings(self, file_data):
		return self._copyright_pattern.search(file_data) and self._error_pattern.search(file_data)


class CopamAnalyzer(NoInfoAnalyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Copam', *args, **kwargs)

		self._pattern = re.compile(b'''THIS IS NOT IBM BIOS COPAM\\(C\\) [0-9]{4}''')

	def has_strings(self, file_data):
		return self._pattern.search(file_data)


class CorebootAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('coreboot', *args, **kwargs)

		self._identifier_pattern = re.compile(b'''coreboot-%s%s |Sage_coreboot-|Jumping to LinuxBIOS\\.''')
		self._version_coreboot_pattern = re.compile(b'''#(?: This image was built using coreboot|define COREBOOT_VERSION ")([^"]+)''')
		self._version_linuxbios_pattern = re.compile(b'''(LinuxBIOS|coreboot)-([^_ ]+)[_ ](?:Normal |Fallback )?(.* )?starting\\.\\.\\.''')
		self._string_build_pattern = re.compile(b'''#define COREBOOT_BUILD "([^"]+)"''')

	def can_handle(self, file_path, file_data, header_data):
		if not self._identifier_pattern.search(file_data):
			return False

		# Locate and extract version.
		match = self._version_coreboot_pattern.search(file_data)
		if match: # coreboot
			self.debug_print('coreboot tag:', match.group(0))

			# Reset vendor to coreboot.
			self.vendor = self.vendor_id

			# Extract version.
			self.version = match.group(1).decode('cp437', 'ignore')

			# Extract any additional information after the version as a string.
			dash_index = self.version.find('-')
			if dash_index > -1:
				self.string = self.version[dash_index + 1:]
				self.version = self.version[:dash_index]

			# Locate build tag.
			match = self._string_build_pattern.search(file_data)
			if match:
				self.debug_print('coreboot build:', match.group(0))

				# Add build tag to string.
				if self.string:
					self.string += '\n'
				self.string += match.group(1).decode('cp437', 'ignore')

			return True
		else:
			match = self._version_linuxbios_pattern.search(file_data)
			if match: # LinuxBIOS
				self.debug_print('LinuxBIOS banner:', match.group(0))

				# Set vendor to LinuxBIOS if required.
				self.vendor = match.group(1).decode('cp437', 'ignore')

				# Extract version.
				self.version = match.group(2).decode('cp437', 'ignore')

				# Extract any additional information after the version as a string.
				additional_info = match.group(3)
				if additional_info:
					self.string = additional_info.decode('cp437', 'ignore')

				return True

		return False


class DTKGoldStarAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('DTKGoldStar', *args, **kwargs)

		self._dtk_pattern = re.compile(b'''Datatech Enterprises Co\\., Ltd\\.|DATATECH ENTERPRISES CO\\., LTD\\.|\\x0ADTK Corp\\.|\\(C\\) Copyright by GoldStar Co\\.,Ltd\\.|GOLDSTAR  SYSTEM  SETUP''')
		self._version_pattern = re.compile(b'''(?:(DTK|GoldStar) ([\\x20-\\x7E]+) BIOS Ver(?:sion)? |(DTK)/([^/]+)/BIOS )([^\s]+)(?: ([^\s]+))?''')

	def reset(self):
		super().reset()
		self._dtk = False

	def can_handle(self, file_path, file_data, header_data):
		if not self._dtk_pattern.search(file_data):
			return False

		# Locate version string.
		match = self._version_pattern.search(file_data)
		if match:
			self.debug_print('DTK version:', match.group(0))

			# Extract vendor.
			self.vendor = (match.group(1) or match.group(3) or b'GoldStar').decode('cp437', 'ignore')

			# Extract version.
			self.version = match.group(5).decode('cp437', 'ignore')

			# Extract string.
			self.string = (match.group(2) or match.group(4) or b'').decode('cp437', 'ignore')
			if self.string[-4:] == ' ROM':
				self.string = self.string[:-4]

			# Add revision to string.
			revision = (match.group(6) or b'').decode('cp437', 'ignore')
			if revision and revision != '(C)':
				self.string += '\n' + revision

			return True

		return False

class GeneralSoftwareAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('General', *args, **kwargs)

		self._string_pattern = re.compile(b'''([0-9]{2}/[0-9]{2}/[0-9]{2})\(C\) [0-9]+ General Software, Inc\. ''')
		self._version_pattern = re.compile(b'''General Software (?:\\x00 )?([^\\\\\\x0D\\x0A]+)(?:rel\.|Revision)''')

	def can_handle(self, file_path, file_data, header_data):
		# Extract version.
		match = self._version_pattern.search(file_data)
		if match:
			self.version = match.group(1).decode('cp437', 'ignore').replace('(R)', '').replace('(tm)', '').replace(' BIOS ', ' ').strip()
		else:
			self.version = '?'

		# Extract date and revision as a string.
		match = self._string_pattern.search(file_data)
		if match:
			end = match.end(0)
			self.string = util.read_string(file_data[end:end + 256]) + '\n' + match.group(1).decode('cp437', 'ignore')

		# Take this analyzer if we found a version and a string.
		return self.version != '?' and self.string


class IBMAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('IBM', *args, **kwargs)

		self._header_pattern = re.compile(b'''([0-9]{2}[A-Z0-9][0-9]{4})  ?(COPR\\. IBM|\\(C\\) COPYRIGHT IBM CORPORATION) 19[89][0-9]''')
		self._interleaved_header_pattern = re.compile(b'''(([0-9])\\2([0-9])\\3([A-Z0-9])\\4(?:[0-9]{8}))  (CCOOPPRR\\.\\.  IIBBMM|\\(\\(CC\\)\\)  CCOOPPYYRRIIGGHHTT  IIBBMM  CCOORRPPOORRAATTIIOONN)  1199([89])\\6([0-9])\\7''')

	def can_handle(self, file_path, file_data, header_data):
		# Extract IBM part number/copyright headers.
		part_numbers = []
		copyrights = []
		for part_number, copyright in self._header_pattern.findall(file_data):
			part_numbers.append(part_number)
			copyrights.append(copyright)

		# Deinterleave interleaved headers.
		for part_number, _, _, _, copyright, _, _ in self._interleaved_header_pattern.findall(file_data):
			part_numbers.append(part_number[::2])
			part_numbers.append(part_number[1::2])
			copyrights.append(copyright[::2])
			copyrights.append(copyright[1::2])

		# Do we have any part numbers?
		if part_numbers:
			# Assume long-form copyright indicates a PS/2.
			if b'(C) COPYRIGHT IBM CORPORATION' in copyrights:
				self.version = 'PS/2 or PS/1'
			else:
				self.version = 'PC series'

			# Sort FRU codes and remove duplicates.
			part_numbers = list(set(part_number.decode('ascii', 'ignore') for part_number in part_numbers))
			part_numbers.sort()

			# Extract FRU codes as a string.
			self.string = '\n'.join(part_numbers)		

			return True
		else:
			return False


class IBMSurePathAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('IBM', *args, **kwargs)
		self.vendor_id = 'IBMSurePath'

		self._ibm_pattern = re.compile(
			b'''\\(\\(CC\\)\\)  CCOOPPYYRRIIGGHHTT  (?:IIBBMM  CCOORRPPOORRAATTIIOONN  11998811,,  ([0-9])\\1([0-9])\\2([0-9])\\3([0-9])\\4|11998811,,  ([0-9])\\5([0-9])\\6([0-9])\\7([0-9])\\8  IIBBMM  CCOORRPPOORRAATTIIOONN)  (?:--  )?AALLLL  RRIIGGHHTTSS  RREESSEERRVVEEDD|'''
			b'''\\(C\\) COPYRIGHT (?:IBM CORPORATION 1981, [0-9]{4}|1981, [0-9]{4} IBM CORPORATION) (?:- )?ALL RIGHTS RESERVED[ \\x0D\\x0A]*(?:[\\x00\\xFF]|US Government Users)'''
		)
		self._vpd_pattern = re.compile(b'''\\xAA\\x55VPD0RESERVE([0-9A-Z]{7})''')
		self._surepath_pattern = re.compile(b'''SurePath BIOS Version ([\\x20-\\x7E]+)(?:[\\x0D\\x0A\\x00]+([\\x20-\\x7E]+)?)?''')
		self._apricot_pattern = re.compile(b'''@\\(#\\)(?:Apricot .*|XEN-PC) BIOS [\\x20-\\x7E]+''')
		self._apricot_version_pattern = re.compile(b'''@\\(#\\)Version [\\x20-\\x7E]+''')

	def can_handle(self, file_path, file_data, header_data):
		if not self._ibm_pattern.search(file_data):
			return False

		# Determine location of the version.
		match = self._surepath_pattern.search(file_data)
		if match:
			# Extract version.
			self.version = match.group(1)
			self.debug_print('Uncompressed version:', self.version)
			self.version = 'SurePath ' + self.version.decode('cp437', 'ignore').strip()

			# Extract customization as a sign-on if found. (AT&T Globalyst)
			customization = match.group(2)
			if customization:
				self.debug_print('AT&T customization:', customization)
				self.signon = customization.decode('cp437', 'ignore')
		else:
			# Special case for Apricot-licensed SurePath.
			match = self._apricot_pattern.search(file_data)
			if match:
				# There appears to be a real SurePath version number hidden
				# in there (2.0) but it must be inside a compressed body.
				self.version = 'SurePath'

				# Extract Apricot customization as a sign-on.
				customization = match.group(0)
				self.debug_print('Apricot customization:', customization)
				self.signon = customization.decode('cp437', 'ignore')[4:]
				match = self._apricot_version_pattern.search(file_data)
				if match:
					self.signon = self.signon.strip() + '\n' + match.group(0).decode('cp437', 'ignore')[4:].strip()

		# Extract BIOS ID string from the VPD area if present.
		match = self._vpd_pattern.search(file_data)
		if match:
			# Later compressed SurePath provides no version clues.
			if not self.version:
				self.version = 'SurePath'

			# Extract string.
			id_string = match.group(1)
			self.debug_print('VPD ID string:', id_string)
			self.string = id_string.decode('cp437', 'ignore')

		# Stop if nothing was found.
		if not self.version:
			return False

		# Look for entrypoint dates.
		old_string = self.string
		self.string = ''
		NoInfoAnalyzer.get_entrypoint_dates(self, file_data)
		if old_string:
			if self.string:
				self.debug_print('entry point date:', self.string)
				self.string = old_string + '\n' + self.string
			else:
				self.string = old_string

		return True


class ICLAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('ICL', *args, **kwargs)

		self._version_pattern = re.compile(b'''(?:ROM|System) BIOS (#[\\x20-\\x7E]+) Version ([\\x20-\\x7E]+)\\x0D\\x0A\\(c\\) Copyright [\\x20-\\x7E]+(?:\\x0D\\x0A\\x0A\\x00([\\x20-\\x7E]+))?''')

	def can_handle(self, file_path, file_data, header_data):
		# Update files use unknown compression.
		if file_data[:8] == b'OKICL1\x01\x00':
			self.version = '?'
			return True

		# Determine location of the identification block.
		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Extract version.
		self.version = match.group(2).decode('cp437', 'ignore')

		# Extract identifier as a string.
		self.string = match.group(1).decode('cp437', 'ignore')

		# Extract sign-on if present.
		self.signon = (match.group(3) or b'').decode('cp437', 'ignore')

		return True


class InsydeAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Insyde', *args, **kwargs)

		self._version_pattern = re.compile(b'''InsydeH2O Version ''')

	def can_handle(self, file_path, file_data, header_data):
		# Only handle files sent through UEFIExtractor.
		if header_data != b'\x00\xFFUEFIExtract\xFF\x00':
			return False

		# Check for InsydeH2O version string.
		if not self._version_pattern.search(file_data):
			return False

		self.version = '?'

		return True


class IntelUEFIAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Intel', *args, **kwargs)
		self.vendor_id = 'IntelUEFI'

		# The Intel version's location is not super consistent throughout the
		# years. The second path helps here by providing a second opinion,
		# though one that might fail if a weird version string is somehow found.
		self._identifier_pattern = re.compile(b'''(?:\\$(?:IBIOSI\\$|FID|UBI)|Load Error\\x00{2}Success\\x00|S\\x00l\\x00o\\x00t\\x00 \\x00\\x30\\x00:\\x00 \\x00+)([0-9A-Z]{8}\\.[0-9A-Z]{3}(?:\\.[0-9]{4}){4})|'''
											  b'''([A-Z]{2}[0-9A-Z]{3}[0-9]{2}[A-Z]\\.[0-9]{2}[A-Z](?:\\.[0-9]{4}){4})''')

	def can_handle(self, file_path, file_data, header_data):
		# Only handle files sent through UEFIExtractor.
		if header_data != b'\x00\xFFUEFIExtract\xFF\x00':
			return False

		# Check for any Intel version code identifiers.
		match = self._identifier_pattern.search(file_data)
		if not match:
			return False

		self.version = 'UEFI'

		# Extract Intel version as a sign-on.
		self.signon = (match.group(1) or match.group(2)).decode('cp437', 'ignore')

		return True


class JukoAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Juko', *args, **kwargs)

		self._version_pattern = re.compile(b'''Juko (.+) BIOS ver (.+)''')

	def can_handle(self, file_path, file_data, header_data):
		if b'Juko Electronics Industrial Co.,Ltd.' not in file_data:
			return False

		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Extract version.
		self.version = match.group(2).decode('cp437', 'ignore')

		# Extract string.
		self.string = match.group(1).decode('cp437', 'ignore')

		return True


class MRAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('MR', *args, **kwargs)

		self._check_pattern = re.compile(b'''[A-Z ]{7} \\((?:r|tm)\\)  V''')
		self._signon_pattern = re.compile(b'''OEM SIGNON >>-->([\\x20-\\x7E]+)''')

		self.register_check_list([
			(self._version_newer,	RegexChecker),
			(self._version_older,	RegexChecker),
		])

	def can_handle(self, file_path, file_data, header_data):
		# Skip readme false positives.
		if len(file_data) < 2048 or not self._check_pattern.search(file_data):
			return False

		# Extract custom OEM sign-on.
		match = self._signon_pattern.search(file_data)
		if match:
			self.signon = match.group(1).decode('cp437', 'ignore')
			if len(self.signon) == 1: # single character when not set
				self.signon = ''
			self.signon = self.signon.strip()

		return True

	def _version_newer(self, line, match):
		'''[A-Z ]{7} \\((?:r|tm)\\)  (V[^ ']+)(?: (.+))?$'''

		# Extract version.
		self.version = match.group(1)

		# Extract part number as a string if one was found.
		part_number = match.group(2)
		if part_number:
			self.string = part_number.strip()

		return True

	def _version_older(self, line, match):
		'''Ver:? (V[^-]+)(?:-| +Port )(.+)'''

		# Extract version.
		self.version = match.group(1)

		# Extract part number(?)
		self.string = match.group(2)

		return True


class MylexAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Mylex', *args, **kwargs)

		self._version_pattern = re.compile(b'''MYLEX ([\\x20-\\x7E]+) BIOS Version ([\\x20-\\x7E]+) ([0-9]{2}/[0-9]{2}/[0-9]{2})''')

	def can_handle(self, file_path, file_data, header_data):
		# Determine location of the identification block.
		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Extract version.
		self.version = match.group(2).decode('cp437', 'ignore')

		# Extract date as a string.
		self.string = match.group(3).decode('cp437', 'ignore')

		# Extract board name as a sign-on.
		self.signon = match.group(1).decode('cp437', 'ignore')

		return True


class OlivettiAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Olivetti', *args, **kwargs)

		self._version_pattern = re.compile('''Version ([^\s]+)''')

		self.register_check_list([
			((self._version_precheck, self._version),		AlwaysRunChecker),
			(self._string_date,								RegexChecker),
		])

	def reset(self):
		super().reset()
		self._trap_version = False

	def can_handle(self, file_path, file_data, header_data):
		if b'COPYRIGHT (C)   OLIVETTI' not in file_data or (b'No ROM BASIC available - RESET' not in file_data and b'ROM BASIC Not Available,' not in file_data):
			return False

		# Start by assuming this is an unversioned BIOS.
		self.version = '?'

		return True

	def _version_precheck(self, line):
		return self._trap_version

	def _version(self, line, match):
		# Extract version if valid.
		match = self._version_pattern.match(line)
		if match:
			self.version = match.group(1)

		# Disarm trap.
		self._trap_version = False

		return True

	def _string_date(self, line, match):
		'''^(?:COPYRIGHT \(C\) OLIVETTI )?([0-9]{2}/[0-9]{2}/[0-9]{2})$'''

		# Extract the date as a string if newer than any previously-found date.
		date = match.group(1)
		if not self.string or util.date_gt(date, self.string, util.date_pattern_mmddyy):
			self.string = date

		# Read version on the next line.
		self._trap_version = True

		return True


class PhoenixAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Phoenix', *args, **kwargs)

		# "Phoenix ROM BIOS" (Dell Latitude CP/CPI)
		# No Phoenix copyrights, fallback to NuBIOS (Gateway? 1009.bin)
		self._phoenix_pattern = re.compile(b'''Phoenix (?:Technologies Ltd|Software Associates|Compatibility Corp|ROM BIOS)|PPhhooeenniixx  TTeecchhnnoollooggiieess|\\x00IBM AT Compatible Phoenix NuBIOS\\x00''')
		self._ignore_pattern = re.compile(b'''search=f000,0,ffff,S,"|\\x00\\xC3\\x82as Ltd. de Phoenix del \\xC2\\x83 de Tecnolog\\xC3\\x83\\x00''')
		self._bcpsegment_pattern = re.compile(b'''BCPSEGMENT''')

		self._rombios_version_pattern = re.compile(
			b'''(?:Phoenix )?''' # Phoenix brand (not always present)
			b'''((?:8086|8088|V20 |(?:80)?[0-9]{3})(?:/EISA)? )?ROM BIOS\\xF0? (PLUS )?''' # branch (F0 byte sidesteps Dell compression (Latitude CP/CPI))
			b'''Ver(?:sion)? ?([0-9]\\.[A-Z]?[0-9]{2})''' # actual version (can have short "Ver" with (JE1000) or without (BXM-8) space on small BIOSes, or letter before version (Dell fork "1.P10"))
			b'''[\\x20-\\x7E]*''' # added patch levels
		)
		# Covers the Xx86 and for Pentium family.
		self._xx86_version_pattern = re.compile(
			b'''(PhoenixBIOS\\(TM\\) )''' # Phoenix brand
			b'''[\\x00-\\xFF]{0,512}?''' # variable amount of code inbetween (not observed on DEC)
			b'''([A-Z][0-9]86|for ([\\x20-\\x7E]+?) (?:CPU )?- ([^ ]+))''' # branch
			b'''( Version )([0-9]\\.[0-9]{2})''' # actual version
			b'''-?([\\x20-\\x7E]*)''' # sign-on (Micronics M5PE)
		)
		# Additional space before version (some Siemens Nixdorf stuff)
		# "PhoenixMB" 4.03 (4alp001) but what has "PhoenixMB BIOS" was lost to time
		# "Developmental" 4.05 (HP Vectra 56x-57x and DEC Multia)
		# "Plug and Play" (ALR Sequel series)
		# Release can be single digit (ServerBIOS 2/3 Release 6.0)
		self._40x_version_pattern = re.compile(
			b'''(Phoenix(?:MB(?: BIOS)?|(?: [A-Za-z]*?)?BIOS) +(?:Developmental +)?(?:Plug and Play +)?''' # branch
			b'''(?:Version +)?(?:[0-9]+(?:\\.[0-9]+)? Release )?[0-9]+\\.[\\x21-\\x2D\\x2F-\\x7E]+''' # actual version
			b'''(?:[\\x21-\\x7E]|\\x20\\x08)*)''' # added patch levels (HP "4.02. " <ASCII backspace> "18", 4.05".Z.00", 6.0".I", ALR "5.10.3")
			b'''([\\x20-\\x7E]*)''' # sign-on (Micronics M55Hi-Plus 6.12)
		)
		# Backup location used as a last resort.
		self._40x_version_alt_pattern = re.compile(b'''v([0-9]\\.[0-9]{2}) Copyright 1985-[0-9]+ Phoenix Technologies Ltd''')
		# Some are cME, some are not, cME was the product name.
		self._core_version_pattern = re.compile(b'''Phoenix (?:cME )?[A-Za-z]+Core|FirstBIOS[\\x20-\\x7E]+''')

		# Some files may be compressed...
		self._dell_system_pattern = re.compile(b'''Dell System [\\x20-\\x7E]+''')
		# More attempts to sidestep compression.
		self._dell_version_pattern = re.compile(b'''(?:BIOS [Vv]ers[\\x00-\\xFF]{3}(?!  =):?|(?:80[0-9]{2,3}|Phoenix) ROM BIOS PLUS Version [^\\s]+) ([A-Z0-9.]+)''')
		self._dell_version_code_pattern = re.compile(b'''([A-Z][0-9]{2})''')
		self._hp_pattern = re.compile(b'''([\\x21-\\x7E]+ [\\x21-\\x7E]+) \\(C\\)Copyright 1985-.... Hewlett-Packard Company, All Rights Reserved''')
		self._hp_signon_pattern = re.compile(b'''Version +[\\x21-\\x7E]+ +HP [\\x20-\\x7E]+''')
		# "All Rights Reserved\r\n\n\x00\xF4\x01" (Ax86)
		# "All Rights Reserved\r\n\n\x00" (Commodore 386LT, Tandy 1000RSX)
		# "All Rights Reserved\r\n\n" (ROM BIOS)
		# "All Rights Reserved\r\n\r\n\r\n" (Gateway 4DX2-50V)
		self._rombios_signon_pattern = re.compile(b'''\\x0D\\x0AAll Rights Reserved\\x0D\\x0A(?:\\x0A(?:\\x00(?:[\\x90\\xF4]\\x01)?)?|\\x0D\\x0A\\x0D\\x0A)''')
		# No "All Rights Reserved" (Yangtech 2.27 / pxxt)
		self._rombios_signon_alt_pattern = re.compile(b'''\\(R\\)eboot, other keys to continue\\x00\\xFF+''')
		self._rombios_signon_dec_pattern = re.compile(b'''Copyright \\(C\\) [0-9]{4} Digital Equipment Corporation''')
		self._segment_pattern = re.compile('''segment_([0-9A-F]{4})\\.rom$''')
		self._strings_pattern = re.compile('''strings_[0-9A-F_]+\\.rom$''')
		self._intel_86_pattern = re.compile('''[0-9A-Z]{8}\\.86[0-9A-Z]\\.[0-9A-Z]{3,4}\\.[0-9A-Z]{1,4}\\.[0-9]{10}$''')
		self._date_pattern = re.compile(b'''((?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/[0-9]{2}|(?:0{2}[1-9]{2}|1{2}[0-2]{2})/(?:0{2}[1-9]{2}|[12]{2}[0-9]{2}|3{2}[01]{2})/[0-9]{4})[^0-9]''')

		self.register_check_list([
			((self._signon_fujitsu_precheck, self._signon_fujitsu),	AlwaysRunChecker),
			((self._signon_nec_precheck, self._signon_nec),			AlwaysRunChecker),
			(self._version_grid,									SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
			(self._version_sct,										RegexChecker),
			(self._version_sct_preboot,								SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
			(self._version_tandy,									SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
			(self._signon_ast,										SubstringChecker, SUBSTRING_BEGINNING | SUBSTRING_CASE_SENSITIVE),
			(self._signon_commodore,								RegexChecker),
			(self._signon_fujitsu_trigger,							SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
			(self._signon_hp,										RegexChecker),
			(self._signon_intel,									RegexChecker),
			(self._signon_nec_trigger,								RegexChecker),
			(self._signon_surepath,									RegexChecker),
			(self._signon_tandy,									RegexChecker),
		])

	def reset(self):
		super().reset()
		self._trap_signon_fujitsu_lines = 0
		self._trap_signon_nec = False
		self._found_signon_tandy = ''

	class BCP:
		def __init__(self, signature, version_maj, version_min, data):
			self.signature = signature
			self.version_maj = version_maj
			self.version_min = version_min
			self.data = data

		def __repr__(self):
			return '<{0} version {1}.{2} datalen {3}>'.format(self.signature, self.version_maj, self.version_min, len(self.data))

	def can_handle(self, file_path, file_data, header_data):
		if not self._phoenix_pattern.search(file_data):
			return False

		# Skip:
		# - Windows 95 INF updates
		# - Intel UEFI with PCI device list (UTF-8 encoded)
		if self._ignore_pattern.search(file_data):
			return False

		# Skip BCP parsing if this is not 4.0x or newer.
		raw_data = b''
		bios_maj = bios_min = code_segment = None
		if self._bcpsegment_pattern.search(file_data):
			# Load raw BIOS data.
			compressed = os.path.isdir(file_path)
			if compressed:
				self.debug_print('Loading raw data for compressed BIOS')
				try:
					f = open(os.path.join(file_path, 'remainder.rom'), 'rb')
					raw_data = f.read()
					f.close()
				except:
					self.debug_print('Could not load raw data, falling back to existing data')
					raw_data = file_data
			else:
				raw_data = file_data

			# Create a virtual memory space with the file loaded to its end.
			virtual_mem = bytearray(0x100000)
			target_len = min(len(raw_data), len(virtual_mem))
			virtual_mem[-target_len:] = raw_data[-target_len:]

			# Look for the BCPSEGMENT.
			bcp = {}
			for match in self._bcpsegment_pattern.finditer(virtual_mem):
				# Parse BCP entries.
				valid_bcp = True
				bcpsegment_offset = match.start(0)
				self.debug_print('Probing BCPSEGMENT at', hex(bcpsegment_offset))
				offset = bcpsegment_offset + 0x0a
				while virtual_mem[offset:offset + 3] == b'BCP':
					# Parse header while skipping bogus ones.
					header = virtual_mem[offset:offset + 0x0a]
					if len(header) != 0xa or header[0x06:0x09] == b'BCP': # invalid: chain of signatures in ACFG (Micronics M54Li 07)
						valid_bcp = False
						break
					signature, version_maj, version_min, size = struct.unpack('<6sBBH', header)
					if size < 0x0a: # invalid: "BCPSYS" followed by 0x00 bytes (DEC Venturis 466, other DEC 4.0x)
						valid_bcp = False
						break

					# Add BCP to map.
					signature = signature.decode('cp437', 'ignore')
					if signature not in bcp:
						bcp[signature] = []
					bcp[signature].append(PhoenixAnalyzer.BCP(signature, version_maj, version_min, virtual_mem[offset:offset + size]))

					# Move on to the next BCP entry.
					offset += size
					if virtual_mem[offset:offset + 3] != b'BCP':
						# Sometimes the sizes don't line up (BCPDMI on NEC Powermate V, other cases where it's off by one)
						next_bcp_offset = virtual_mem[offset:offset + 256].find(b'BCP')
						if next_bcp_offset > -1:
							offset += next_bcp_offset
						else:
							break

				# Stop looking if this appears to be a valid BCPSEGMENT.
				if valid_bcp:
					# Set initial code segment.
					code_segment = (bcpsegment_offset & -0x10000) >> 4
					break

			self.debug_print('Found BCPs:', bcp)

			# Extract information from BCPSYS.
			bcpsys = bcp.get('BCPSYS', [None])[0]
			if bcpsys:
				# BCPSYS versions observed:
				# - 0.3 (4.01)
				# - 1.4 (4.02-4.03) changed date/time format and moved build code
				# - 1.5 (4.04) added register table pointers
				# - 1.7 (4.05)
				# - 3.1 (4.05-4.0R6)
				# - 3.2 (4.0R6) added register table segment
				# - 3.3 (SecureCore)
				self.debug_print('BCPSYS version:', bcpsys.version_maj, bcpsys.version_min)

				# Extract core version. This is preliminary and may be overridden by string checks.
				bios_maj, bios_min, bios_patch = bcpsys.data[0x0a:0x0d]
				if bios_maj > 4: # (ALR "4.0 Release 5.10.3" reports 05 0A 03)
					self.version = '4.{0:02}'
				else:
					if bios_maj == 4 and bios_min >= 6:
						self.version = '{0}.0 Release {1}.0' # 4.0R6 is way more common than 4.06
					else:
						self.version = '{0}.{1:02}'
				if self.version:
					self.debug_print('BCPSYS core version:', bios_maj, bios_min, bios_patch)
					self.version = self.version.format(bios_maj, bios_min, bios_patch)

				# Extract the build code as metadata.
				# Size checks are sanity checks not observed in the real world.
				data_size = len(bcpsys.data)
				if bcpsys.version_maj == 0 and data_size > 0x33:
					build_code = bcpsys.data[0x33:min(0x3b, data_size)]
				elif data_size > 0x37:
					build_code = bcpsys.data[0x37:min(0x3f, data_size)]
				else:
					build_code = b''
				build_code = util.read_string(build_code.replace(b'\x00', b'\x20')).strip()
				if build_code:
					self.debug_print('BCPSYS build code:', build_code)
					self.metadata.append(('BCP', build_code))

				# Extract the build dates and times as metadata.
				dates_times = (b'', b'')
				if data_size > 0x0f:
					if bcpsys.version_maj == 0:
						dates_times = (
							bcpsys.data[0x0f:min(0x17, data_size)] + b' ' + bcpsys.data[min(0x17, data_size):min(0x1f, data_size)],
							bcpsys.data[min(0x1f, data_size):min(0x27, data_size)] + b' ' + bcpsys.data[min(0x27, data_size):min(0x2f, data_size)]
						)
					else:
						dates_times = (
							bcpsys.data[0x0f:min(0x20, data_size)],
							bcpsys.data[min(0x21, data_size):min(0x32, data_size)]
						)
				dates_times = tuple(util.read_string(date_time.replace(b'\x00', b'\x20')).strip() for date_time in dates_times)
				self.debug_print('BCPSYS build dates/times:', dates_times)
				dates_times = ' - '.join(date_time for date_time in dates_times if date_time[:8] != '00/00/00')
				if dates_times:
					self.metadata.append(('BCP', dates_times))

				# Extract register table pointer segment and offsets.
				if bcpsys.version_maj >= 3 and data_size >= 0x6a:
					regtable_start, regtable_end, regtable_segment = struct.unpack('<HHH', bcpsys.data[0x65:0x6b])
					if bcpsys.version_maj == 3 and bcpsys.version_min <= 1:
						regtable_segment = code_segment
					elif regtable_segment == 0x7000: # (Intel)
						self.debug_print('Remapping Intel register table segment', hex(regtable_segment))
						regtable_segment = code_segment = 0xe000
					elif regtable_segment <= 0xe31f: # (DE35 on HP Pavilion 2200, E31F on HP Brio 80xx)
						self.debug_print('Register table segment', hex(regtable_segment), 'too low, resetting to', hex(code_segment))
						regtable_segment = code_segment
					else:
						code_segment = regtable_segment
				elif bcpsys.version_maj == 1 and bcpsys.version_min >= 5 and data_size >= 0x6d:
					regtable_start, regtable_end, regtable_segment = struct.unpack('<HHH', bcpsys.data[0x67:0x6d])
					code_segment = regtable_segment
				else:
					regtable_segment = None

				if regtable_segment:
					self.debug_print('Register table at', hex(regtable_segment), ':', hex(regtable_start), 'to', hex(regtable_end))

		# Locate main 4.0x version.
		match = self._40x_version_pattern.search(file_data)
		if match:
			# Extract full version string as metadata.
			version_string = util.read_string(match.group(1))
			self.metadata.append(('ID', version_string))
			self.debug_print('Raw 4.0x version:', repr(version_string))

			# Extract sign-on.
			signon = match.group(2)
			if signon:
				self.signon = util.read_string(signon)
				self.debug_print('Raw 4.0x post-version sign-on:', repr(signon))
		else:
			# Locate backup 4.0x version, but only if we don't have a better one from BCPSYS.
			if not self.version:
				match = self._40x_version_alt_pattern.search(file_data)
			if match:
				# Extract base core version.
				self.version = util.read_string(match.group(1))
				self.debug_print('Backup 4.0x version:', repr(match.group(0)))
			else:
				# Locate SecureCore/TrustedCore/FirstBIOS version.
				match = self._core_version_pattern.search(file_data)
				if match:
					# Assume base core version if we don't have a better one from BCPSYS.
					if not self.version:
						self.version = '4.0 Release 6.0'

					# Extract full version as metadata.
					version_string = util.read_string(match.group(0))
					self.metadata.append(('ID', version_string.replace('(tm)', '')))
					self.debug_print('Raw Core version:', repr(version_string))
				else:
					# Locate Xx86 version.
					match = self._xx86_version_pattern.search(file_data)
					if match:
						# Extract version.
						branch = match.group(3)
						if branch: # for Pentium
							branch = (branch.replace(b'(TM)', b'').strip().split(b'/')[-1] + b' ' + match.group(4))
						else: # Xx86
							branch = match.group(2)
						self.version = util.read_string(branch + b' ' + match.group(6))

						# Extract full version string as metadata.
						version_string = util.read_string(match.group(1) + match.group(2) + match.group(5) + match.group(6))
						self.metadata.append(('ID', version_string.replace(' (TM)', '').replace('(TM)', '')))
						self.debug_print('Raw Xx86 version:', repr(version_string))

						# Extract sign-on.
						self.signon = util.read_string(match.group(7))
					else:
						# Locate ROM BIOS version.
						match = self._rombios_version_pattern.search(file_data)
						if match:
							# Extract version.
							self.version = util.read_string(match.group(3))

							# Add PLUS prefix if present.
							pre_version = match.group(2)
							if pre_version:
								self.version = util.read_string(pre_version) + self.version

							# Extract version prefix if present.
							pre_version = match.group(1)
							if pre_version:
								# Shorten 80286/80386(/80486?)
								if len(pre_version) >= 5 and pre_version[:2] == b'80':
									pre_version = pre_version[2:]

								self.version = util.read_string(pre_version) + self.version

							# Extract full version string as metadata.
							version_string = util.read_string(match.group(0).replace(b'\xF0', b''))
							self.metadata.append(('ID', version_string))
							self.debug_print('Raw ROM BIOS version:', repr(version_string))
						else:
							self.debug_print('No version found!')

		# Save post-version sign-on to be restored later.
		post_version = self.signon

		# Extract sign-on from BCPOST on 4.0x and newer BIOSes.
		if bios_maj != None and bios_min != None and code_segment != None:
			bcpost = bcp.get('BCPOST', [None])[0]
		else:
			bcpost = None
		if bcpost and len(bcpost.data) >= 0x25:
			# BCPOST versions observed:
			# - 0.1 (4.01)
			# - 0.3 (4.02-4.05)
			# - 0.4 (4.04-4.05)
			# - 1.3 (4.0R6)
			# - 1.4 (SecureCore)
			self.debug_print('BCPOST version:', bcpost.version_maj, bcpost.version_min)

			# If this is a compressed BIOS, load decompressed segments.
			segment_ranges = []
			strings_files = []
			if compressed:
				# Go through extracted files.
				for file_in_dir in os.listdir(file_path):
					match = self._segment_pattern.match(file_in_dir)
					if match:
						# Read segment data.
						try:
							f = open(os.path.join(file_path, file_in_dir), 'rb')
							data = f.read()
							f.close()
						except:
							self.debug_print('Could not load segment file:', file_in_dir)
							continue

						# Load segment data into the virtual memory space.
						self.debug_print('Loaded segment file:', file_in_dir)
						offset = int(match.group(1), 16) << 4
						target_len = min(len(virtual_mem) - offset, len(data))
						if target_len >= 0:
							virtual_mem[offset:offset + target_len] = data[:target_len]
							segment_ranges.append((offset, offset + target_len))
					elif self._strings_pattern.match(file_in_dir):
						# Read string data.
						try:
							f = open(os.path.join(file_path, file_in_dir), 'rb')
							data = f.read()
							f.close()
						except:
							self.debug_print('Could not load strings file:', file_in_dir)
							continue

						# SecureCore may have 4 bytes before the STRPACK header.
						offset = data.find(b'STRPACK-BIOS')
						if offset > -1:
							strings_files.append(data[offset:])
							self.debug_print('Loaded strings file:', file_in_dir)
						else:
							# Try to ascertain the string table location from the language code
							# and next 2 bytes if no STRPACK header is present. (HP B013300I)
							offset = data.find(b'us\x14\x00')
							if offset > -1:
								header = data[offset - 0x20:offset]
								if len(header) < 0x20:
									header = (b'\x00' * (0x20 - len(header))) + header
								strings_files.append(header + data[offset:])
							else:
								self.debug_print('Bad strings file:', file_in_dir)

			# Sort strings files, prioritizing the "us" (English) language.
			strings_files.sort(key=lambda x: x[0x20:0x22] == b'us' and b'\x00\x00' or x[0x20:0x22])

			# Read sign-on string pointer.
			signon_segment = code_segment
			signon_offset, = struct.unpack('<H', bcpost.data[0x23:0x25])

			# Handle 4.04+ where the string pointer points to a string table pointer instead of a string.
			signon = None
			if bios_maj >= 6 or (bios_maj == 4 and bios_min >= 6):
				# 4.0R6+: string table pointer is relative to string table file minus header.
				signon_offset += 0x1c
				self.debug_print('BCPOST sign-on points to string table file offset', hex(signon_offset))

				# Make sure we have a strings file first.
				if len(strings_files) > 0:
					string_table_offset = strings_files[0][signon_offset:signon_offset + 2]
					if len(string_table_offset) == 2:
						signon_offset, = struct.unpack('<H', string_table_offset)
						signon_offset += 0x1c
						self.debug_print('BCPOST sign-on string table entry points to file offset', hex(signon_offset))

						# Phoenix allowed for some line drawing that is not quite CP437.
						# The actual characters used haven't been confirmed in hardware.
						signon = strings_files[0][signon_offset:signon_offset + 256]
						for args in ((b'\x91', b'\xDA'), (b'\x92', b'\xC4'), (b'\x87', b'\xBF'), (b'\x86', b'\xB3'), (b'\x90', b'\xC0'), (b'\x88', b'\xD9')):
							signon = signon.replace(*args)
					else:
						self.debug_print('BCPOST sign-on string table short read')
				else:
					self.debug_print('BCPOST missing strings file')
			else:
				self.debug_print('BCPOST sign-on points to', hex(signon_segment), ':', hex(signon_offset))

				if bios_maj >= 5 or (bios_maj == 4 and bios_min >= 4):
					# 4.04-4.05: string table pointer is relative to string table segment.
					signon_offset = (signon_segment << 4) + signon_offset
					string_table_offset = virtual_mem[signon_offset:signon_offset + 2]
					if len(string_table_offset) == 2:
						# Look for a string table segment overlapping the string pointer's segment and offset.
						for start, end in segment_ranges:
							if signon_offset >= start and signon_offset < end:
								signon_segment = start >> 4
								break

						# Now we should have a pointer to the actual string.
						signon_offset, = struct.unpack('<H', string_table_offset)
						self.debug_print('BCPOST sign-on string table entry points to', hex(signon_segment), ':', hex(signon_offset))
					else:
						self.debug_print('BCPOST sign-on string table short read')

				# Add segment to pointer.
				signon_offset += signon_segment << 4
				signon = virtual_mem[signon_offset:signon_offset + 256]

			# Read string if one was found.
			if signon:
				self.signon = util.read_string(signon)
				self.debug_print('Raw BCPOST sign-on:', repr(self.signon))
		else:
			# Determine if this is a Dell BIOS.
			match = self._dell_system_pattern.search(file_data)
			if match:
				# Backup in case no Phoenix version is found, which is possible given compression.
				if not self.version:
					self.version = 'Dell'

				# Extract the model as a sign-on.
				self.signon = match.group(0).decode('cp437', 'ignore')
				self.debug_print('Dell model:', self.signon)

				# Add version information to the sign-on, looking at the data after the model first...
				version_index = match.start(0) + 0x20
				match = self._dell_version_code_pattern.match(file_data[version_index:version_index + 3])
				if not match:
					# ...then the version strings...
					match = self._dell_version_pattern.search(file_data)
					if not match:
						# ...then on byte 48 of some files.
						match = self._dell_version_code_pattern.match(file_data[0x30:0x33])
				if match:
					version_string = match.group(1)
					self.signon += '\nBIOS Version: ' + version_string.decode('cp437', 'ignore')
					self.debug_print('Dell version:', version_string)
			else:
				# Determine if this is some sort of HP Vectra BIOS.
				match = self._hp_pattern.search(file_data)
				if match:
					self.version = 'HP'

					# Extract code as a string.
					self.string = match.group(1).decode('cp437', 'ignore')

					# Extract the version number as a sign-on.
					match = self._hp_signon_pattern.search(file_data)
					if match:
						self.signon = match.group(0).decode('cp437', 'ignore')
						self.debug_print('HP version:', self.signon)
				else:
					# Extract sign-on from Ax86 and older BIOSes.
					match = self._rombios_signon_pattern.search(file_data)
					if match:
						copyright_index = match.start(0)
						if self._rombios_signon_dec_pattern.match(file_data[copyright_index - 48:copyright_index]):
							self.debug_print('Ignored bogus sign-on on DEC BIOS')
							match = None
						else:
							signon_log = 'std'
					else:
						match = self._rombios_signon_alt_pattern.search(file_data)
						signon_log = 'alt'
					if match:
						end = match.end(0)
						if file_data[end] != 0xfa: # (unknown 8088 PLUS 2.52)
							signon = util.read_string(file_data[end:end + 256])
							if len(signon) <= 3: # Phoenix video BIOS (Commodore SL386SX25), bogus data (NEC Powermate V)
								match = None
								self.debug_print('Ignored bogus sign-on (too short)')
							else:
								self.signon = signon
								self.debug_print('Raw old', signon_log, 'sign-on:', repr(self.signon))
						else:
							self.debug_print('Ignored bogus sign-on, first bytes:', repr(file_data[end:end + 8]))
							match = None

		# Restore post-version sign-on.
		if post_version != self.signon:
			if self.signon:
				self.signon = post_version + '\n' + self.signon
			else:
				self.signon = post_version

		# Split sign-on lines.
		if self.signon:
			self.signon = self.signon.replace('\r', '\n').replace('\x00', ' ')
			self.signon = '\n'.join(x.strip() for x in self.signon.split('\n') if x.strip()).strip('\n')

		return True

	def _signon_fujitsu_precheck(self, line):
		return self._trap_signon_fujitsu_lines > 0

	def _signon_nec_precheck(self, line):
		return self._trap_signon_nec

	def _version_grid(self, line, match):
		'''Copyright (C) [0-9-]+, GRiD Systems Corp.All Rights Reserved'''

		# This is a GRiD BIOS.
		if not self.version:
			self.version = 'GRiD'

		return False

	def _version_sct(self, line, match):
		'''Phoenix BIOS SC-T (v[^\\s#]+)'''
		# (SecureCore Tiano)
		# "SC-T v2.2#AcerSystem" (unknown Acer)

		# Extract version.
		self.version = 'SecureCore Tiano ' + match.group(1)

		# This is UEFI.
		self.metadata.append(('UEFI', 'SC-T'))

		return True

	def _version_sct_preboot(self, line, match):
		'''SecureCore Tiano (TM) Preboot Agent '''

		# Extract version if a more specific one wasn't already found.
		if not self.version:
			self.version = 'SecureCore Tiano'

		# This is UEFI.
		self.metadata.append(('UEFI', 'SC-T'))

		return True

	def _version_tandy(self, line, match):
		'''$ Tandy Corporation '''

		# This is a Tandy BIOS with Phoenix Compatibility Software.
		if not self.version:
			self.version = 'Tandy'

		# Set Tandy sign-on if we already found one.
		self.signon = self._found_signon_tandy

		return True

	def _signon_ast(self, line, match):
		'''AST System BIOS Version '''

		# This is an AST BIOS.
		self.version = 'AST'

		# Extract version as a sign-on.
		self.signon = line

		return True

	def _signon_commodore(self, line, match):
		'''^ *(Commodore [^\s]+ BIOS Rev\. [^\s]+)'''

		# Extract the version string as a sign-on.
		self.signon = match.group(1)

		return True

	def _signon_fujitsu_trigger(self, line, match):
		'''Phoenix/FUJITSU'''

		# Read sign-on on the next 2 lines.
		self._trap_signon_fujitsu_lines = 1

		return True

	def _signon_fujitsu(self, line, match):
		if self._trap_signon_fujitsu_lines == 1:
			# Extract the version on the first line.
			self.signon = ' '.join(line.split())

			# Move on to the next line.
			self._trap_signon_fujitsu_lines = 2
		else:
			# Extract the model number on the second line.
			self.signon = self.signon + ' (' + line.lstrip() + ')'

			# Disarm the trap.
			self._trap_signon_fujitsu_lines = 0

		return True

	def _signon_hp(self, line, match):
		'''^(?:[A-Z]{2,3})\.(?:[0-9]{2})\.(?:[0-9]{2})(?: \((?:[A-Z]{2,3})\.(?:[0-9]{2})\.(?:[0-9]{2})\)|$)'''

		# This is an HP BIOS.
		if not self.version:
			self.version = 'HP'

		# Extract the version string as a sign-on.
		self.signon = match.group(0)

		return True

	def _signon_intel(self, line, match):
		'''^(?:\\$IBIOSI\\$)?([0-9]\\.[0-9]{2}\\.[0-9]{2}\\.[0-9A-Z]{2,}|[0-9A-Z]{8}\\.([0-9A-Z]{3})\\.[0-9A-Z]{3,4}\\.[0-9A-Z]{1,4}\\.([0-9]{10}))'''

		# This is an Intel BIOS.
		if not self.version:
			self.version = 'Intel'

		# If this is Intel's second Phoenix run, check if this is not a generic
		# (86x) version string overwriting an OEM version string.
		oem = match.group(2)
		if not oem or oem[:2] != '86' or not self._intel_86_pattern.match(self.signon):
			# Extract the version string as a sign-on.
			self.signon = match.group(1)

		return True

	def _signon_nec_trigger(self, line, match):
		'''^..(NEC Corporation)$'''

		# This is an NEC BIOS.
		if not self.version:
			self.version = 'NEC'

		# Discard any bogus sign-on extracted earlier.
		self.signon = match.group(1)

		# Read sign-on on the next line or two.
		self._trap_signon_nec = True

		return True

	def _signon_nec(self, line, match):
		# Disarm trap once we reach the end.
		if line == '@((PP((PP,(-)*.':
			self._trap_signon_nec = False
			return False

		# Add line to the sign-on, skipping duplicates.
		signon = line.strip()
		if signon not in self.signon:
			self.signon += '\n' + signon

		return True

	def _signon_surepath(self, line, match):
		'''^SurePath\(tm\) BIOS Version (.+)'''

		# This is an IBM BIOS.
		if not self.version:
			self.version = 'IBM'

		# Extract the version string as a sign-on.
		self.signon = match.group(0)

		return True

	def _signon_tandy(self, line, match):
		'''^\!BIOS ROM version ([^\s]+)'''

		# Extract the Tandy version as a sign-on.
		self._found_signon_tandy = line[1:]

		# Set sign-on if we already determined this is a Tandy BIOS.
		if self.version == 'Tandy':
			self.signon = self._found_signon_tandy


class PromagAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Promag', *args, **kwargs)

		self._version_pattern = re.compile(b'''\\(C\\) PROMAG SYSTEM BOARD VER\\. ([^ ]+) [^\\n]+\\n([\\r\\n\\x20-\\x7E]+)''')

	def can_handle(self, file_path, file_data, header_data):
		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Extract version.
		self.version = match.group(1).decode('cp437', 'ignore')

		# Extract sign-on.
		self.signon = match.group(2).decode('cp437', 'ignore').replace('\r', '')

		return True


class QuadtelAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Quadtel', *args, **kwargs)

		self._id_block_pattern = re.compile(b'''Copyright 19..-.... Quadtel Corp\\. Version''')
		self._version_pattern = re.compile('''(?:(?:Quadtel|QUADTEL|PhoenixBIOS) )?(.+) BIOS Version ([^\\r\\n]+)''')
		self._date_pattern = re.compile(b'''([0-9]{2}/[0-9]{2}/[0-9]{2})[^0-9]''')

	def can_handle(self, file_path, file_data, header_data):
		if b' Quadtel Corp. Version ' not in file_data:
			return False

		# Quadtel appears to have a consistent identification block.
		match = self._id_block_pattern.search(file_data)
		if match:
			# Determine location of the identification block.
			id_block_index = match.start(0)

			# Extract version.
			version_string = util.read_string(file_data[id_block_index + 0xc8:id_block_index + 0x190]) # may contain space followed by backspace (ZEOS Marlin)
			version_match = self._version_pattern.search(version_string) # may start with a linebreak (Phoenix-Quadtel)
			if version_match:
				self.version = version_match.group(2).rstrip('.').strip().rstrip('.') # remove trailing "." (first for quadt286, second for Quadtel GC113)
				if self.version[0:1] == 'Q': # flag Phoenix-Quadtel
					self.version = self.version[1:] + ' (Phoenix)'

				# Extract BIOS type as the string.
				self.string = version_match.group(1).strip()

			# Extract sign-on.
			self.signon = util.read_string(file_data[id_block_index + 0x190:id_block_index + 0x290]).strip()

			# Split sign-on lines.
			self.signon = '\n'.join(x.rstrip('\r').strip() for x in self.signon.split('\n') if x != '\r').strip('\n')

		# Add newest date found to the string.
		for match in self._date_pattern.finditer(file_data):
			date = match.group(1).decode('cp437', 'ignore')
			linebreak_index = self.string.find('\n')
			if linebreak_index > -1:
				if util.date_gt(date, self.string[linebreak_index + 1:], util.date_pattern_mmddyy):
					self.string = self.string[:linebreak_index + 1] + match.group(0).decode('cp437', 'ignore')
			else:
				if self.string:
					self.string += '\n'
				self.string += date

		return True


class SchneiderAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Schneider', *args, **kwargs)

		self._version_pattern = re.compile(b'''EURO PC\s+BIOS (V[\\x20-\\x7E]+)''')

	def can_handle(self, file_path, file_data, header_data):
		if b'Schneider Rundfunkwerke AG' not in file_data:
			return False

		# Locate version.
		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Extract version.
		self.version = match.group(1).decode('cp437', 'ignore')

		return True


class SystemSoftAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('SystemSoft', *args, **kwargs)

		self._systemsoft_pattern = re.compile(b'''(?:SystemSoft|Insyde Software Presto) BIOS ''')
		self._version_pattern = re.compile(b''' BIOS [Ff]or ([\\x20-\\x7E]+) (?:Vers(?:\\.|ion) 0?([^ \\x0D\\x0A]+)(?: ([\\x20-\\x7E]+))?| *\\(c\\))''')
		self._version_mobilepro_pattern = re.compile(b'''(Insyde Software Presto|SystemSoft MobilePRO) BIOS Version ([^ \\x0D\\x0A]+)(?: ([\\x20-\\x7E]+))?''')
		self._string_for_pattern = re.compile(b''' BIOS [Ff]or ([\\x20-\\x27\\x29-\\x7E]+)\\(''')
		self._string_scu_pattern = re.compile(b''' SCU [Ff]or ([\\x20-\\x7E]+) [Cc]hipset''')
		self._signon_pattern = re.compile(b'''(?:\\x0D\\x0A){1,}\\x00\\x08\\x00([\\x20-\\x7E]+)''')
		self._signon_old_pattern = re.compile(b'''(?:[\\x0D\\x0A\\x20-\\x7E]+\\x00){1,}\\x00+([\\x0D\\x0A\\x20-\\x7E]+)''')

	def can_handle(self, file_path, file_data, header_data):
		if not self._systemsoft_pattern.search(file_data):
			return False

		# Look for the all-in-one version + chipset string.
		aio_match = self._version_pattern.search(file_data)
		if aio_match:
			self.debug_print('All-in-one version string:', aio_match.group(0))

			# Extract version, which may or may not exist. (HP OmniBook XE2)
			self.version = (aio_match.group(2) or b'?').decode('cp437', 'ignore')

			# Unknown version. (NCR Notepad 3130)
			if len(self.version) <= 2:
				self.version = '?'

			# Extract chipset as a string.
			self.string = aio_match.group(1).decode('cp437', 'ignore')

			# Extract any additional information after the version into the string.
			additional_info = aio_match.group(3)
			if additional_info:
				self.string = self.string.strip() + ' ' + additional_info.decode('cp437', 'ignore').strip()

		# Look for the MobilePRO/Presto version string.
		mp_match = self._version_mobilepro_pattern.search(file_data)
		if mp_match:
			self.debug_print('MobilePRO version string:', mp_match.group(0))

			# Extract version.
			self.version = (mp_match.group(1).split(b' ')[-1] + b' ' + mp_match.group(2)).decode('cp437', 'ignore')

			# Extract any additional information after the version into the string.
			additional_info = mp_match.group(3)
			if additional_info:
				self.string = self.string.strip() + ' ' + additional_info.decode('cp437', 'ignore').strip()

		# Stop if we haven't found a version.
		if not self.version:
			return False

		# Look for the BIOS and SCU chipset strings if no chipset identifiers have been found.
		if not aio_match:
			# The SCU string is more precise; a bunch of chipsets including
			# 440BX/ZX and SiS 630 identify as "430TX" on the other one.
			match = self._string_scu_pattern.search(file_data)
			if not match:
				match = self._string_for_pattern.search(file_data)
			if match:
				self.debug_print('SCU/chipset string:', match.group(0))

				# Prepend chipset into the string if not already found.
				chipset = match.group(1).decode('cp437', 'ignore')
				if self.string[:len(chipset)] != chipset:
					self.string = chipset.strip() + ' ' + self.string.strip()

		# Extract sign-on after the version string.
		match = mp_match or aio_match
		while match:
			end = match.end(0)
			file_data = file_data[end:]
			match = self._signon_pattern.search(file_data)
			if match:
				signon_line = match.group(1)
				if signon_line[:9] == b'Copyright' and (b'SystemSoft' in signon_line or b'Insyde' in signon_line):
					# Skip SystemSoft copyright line.
					pass
				elif signon_line:
					self.signon += '\n' + signon_line.decode('cp437', 'ignore')

		# Special sign-on case for very old BIOSes. (NCR Notepad 3130)
		if not self.signon and aio_match:
			match = self._signon_old_pattern.match(file_data)
			if match:
				self.signon = match.group(1).decode('cp437', 'ignore').replace('\r', '\n')

				# Split sign-on lines.
				self.signon = '\n'.join(x.strip() for x in self.signon.split('\n') if x.strip() and (x[:9] != 'Copyright' or 'SystemSoft' not in x)).strip('\n')

		return True


class TandonAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Tandon', *args, **kwargs)

		self._version_pattern = re.compile(b'''NOT COPR. IBM 1984 BIOS VERSION ([\\x20-\\x7E]+)''')

	def can_handle(self, file_path, file_data, header_data):
		# Locate version.
		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Extract version.
		self.version = match.group(1).decode('cp437', 'ignore')

		return True


class TinyBIOSAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('tinyBIOS', *args, **kwargs)

		self._version_pattern = re.compile(b'''tinyBIOS (V(?:[^\\s]+))''')

	def can_handle(self, file_path, file_data, header_data):
		if b' PC Engines' not in file_data:
			return False

		# Locate version.
		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Extract version.
		self.version = match.group(1).decode('cp437', 'ignore')

		# Locate sign-on, the last string before the version.
		version_index = match.start(0)
		signon_index = version_index - 1
		if signon_index > -1 and file_data[signon_index:version_index] == b'"':
			# Ignore MESSAGE.8 in the source code.
			return False
		while signon_index > -1 and file_data[signon_index] in (0x00, 0x0a, 0x0d):
			signon_index -= 1
		while signon_index > -1 and file_data[signon_index] >= 0x0a and file_data[signon_index] <= 0x7e:
			signon_index -= 1
		signon_index += 1
		if version_index - signon_index <= 256:
			# Extract sign-on.
			self.signon = util.read_string(file_data[signon_index:version_index])
			self.debug_print('Sign-on at', hex(signon_index) + ':', repr(self.signon))

		return True

class ToshibaAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Toshiba', *args, **kwargs)
		self.vendor = 'Award'

		self._string_pattern = re.compile(b'''(?:([\\x21-\\x7F]+\s*V[\\x21-\\x7F]{1,16}\s*)TOSHIBA |\\x00{3}BIOS[\\x00-\\xFF]{4}([\\x20-\\x7E]{16}))''')

	def can_handle(self, file_path, file_data, header_data):
		if not (b' TOSHIBA ' in file_data and b'Use Toshiba\'s BASIC.' in file_data) and b'Toshiba Corporation. & Award Software Inc.' not in file_data:
			return False

		# Identify as Toshiba-customized Award.
		self.version = 'Toshiba'

		# Extract string.
		match = self._string_pattern.search(file_data)
		if match:
			# Extract 16 characters from the end to avoid preceding characters. (T3100e)
			self.string = (match.group(1) or match.group(2))[-16:].decode('cp437', 'ignore')

		return True

class WhizproAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Whizpro', *args, **kwargs)

	def can_handle(self, file_path, file_data, header_data):
		if b'$PREPOST' not in file_data or b'$BOOTBLK' not in file_data:
			return False

		# Extract build date as version, as there's no actual
		# version information to be found anywhere. (compressed?)
		date_index = len(file_data) - 0x0b
		self.version = util.read_string(file_data[date_index:date_index + 8])

		# Determine location of the identification block. I've only ever
		# seen 512K BIOSes; other sizes are assumed to work the same way.
		id_block_index = len(file_data) - 0x20110

		# Extract string.
		self.string = util.read_string(file_data[id_block_index + 0xe0:id_block_index + 0x100])

		# Extract sign-on.
		self.signon = util.read_string(file_data[id_block_index:id_block_index + 0x20])

		return True

	def _signon_precheck(self, line):
		return self._trap_signon

	def _signon(self, line, match):
		# The sign-on is one line before the string, so we must store all
		# lines, then act upon the last stored line when the string is found.
		self._found_signon = line

		return True

	def _string(self, line, match):
		'''^[A-Z]-.+-[0-9]+$'''

		# Extract string.
		self.string = match.group(0)

		# Extract sign-on.
		self.signon = self._found_signon

		# Disarm sign-on trap.
		self._trap_signon = False


class ZenithAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Zenith', *args, **kwargs)

		self._date_pattern = re.compile(b'''([0-9]{2}/[0-9]{2}/[0-9]{2}) \(C\)ZDS CORP''')
		self._monitor_pattern = re.compile(b'''[\\x20-\\x7E]+ Monitor, Version [\\x20-\\x7E]+''')

	def can_handle(self, file_path, file_data, header_data):
		# Locate date.
		match = self._date_pattern.search(file_data)
		if not match:
			return False

		# Extract date as a version.
		self.version = match.group(1).decode('cp437', 'ignore')

		# Extract monitor banner as a sign-on.
		match = self._monitor_pattern.search(file_data)
		if match:
			self.signon = match.group(0).decode('cp437', 'ignore')

		return True
