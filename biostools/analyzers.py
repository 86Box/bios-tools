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
import codecs, re, struct, sys
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
	def __init__(self, vendor, debug=False):
		self.vendor_id = self.vendor = vendor
		self.debug = debug

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
					self.debug_print(callback_func.__name__, line)
					return callback_result

	def can_handle(self, file_data, header_data):
		"""Returns True if this analyzer can handle the given file data.
		   header_data contains data from the :header: flag file, or
		   None if no such file exists."""
		return True

	def debug_print(self, key, line=None):
		"""Print a line containing analyzer state if debugging is enabled."""
		if self.debug:
			print(self._file_path, '=> found', self.vendor_id, key, '=', (line == None) and 'no line' or repr(line), '\n', end='', file=sys.stderr)

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
		self.addons = []
		self.oroms = []

		self._file_path = '?'

class NoInfoAnalyzer(Analyzer):
	"""Special analyzer for BIOSes which can be identified,
	   but contain no information to be extracted."""
	def __init__(self, vendor, *args, **kwargs):
		super().__init__(vendor, *args, **kwargs)

	def can_handle(self, file_data, header_data):
		if not self.has_strings(file_data):
			return False

		self.version = '?'

		return True

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

	def can_handle(self, file_data, header_data):
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
		'''([A-Z]{3}[A-Z0-9]{3}00-[A-Z0-9]{3}-[0-9]{6}-[^\s]+)(?:\s+(.+))?'''

		# Extract string.
		self.string = match.group(1)

		# Extract sign-on if present.
		signon = match.group(2)
		if signon:
			if self.signon:
				self.signon += '\n'
			self.signon = signon

		# Read version on the next line.
		self._trap_version = True

		return True


class AMIAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('AMI', *args, **kwargs)

		self._date_pattern = re.compile(b'''([0-9]{2}/[0-9]{2}/[0-9]{2})[^0-9]''')
		self._uefi_csm_pattern = re.compile('''63-0100-000001-00101111-......-Chipset$''')
		self._intel_86_pattern = re.compile('''(?:[0-9A-Z]{8})\.86(?:[0-9A-Z])\.(?:[0-9A-Z]{4})\.(?:[0-9A-Z]{3})\.(?:[0-9]{10})$''')
		# The "All Rights Reserved" is important to not catch the same header on other files.
		# AMIBIOS 6+ version corner cases:
		# - Second digit not 0 (I forget which one had 000000)
		# - Can be 4-digit instead of 6-digit (Biostar)
		self._id_block_pattern = re.compile(b'''(?:AMIBIOS (?:(0[1-9][0-9]{2}[\\x00-\\xFF]{2})[\\x00-\\xFF]{2}|W ([0-9]{2}) ([0-9]{2})[\\x00-\\xFF])|0123AAAAMMMMIIII|\(AAMMIIBBIIOOSS\))([0-9]{2}/[0-9]{2}/[0-9]{2})\(C\)[0-9]{4} American Megatrends,? Inc(?:\.,? All Rights Reserved|/Hewlett-Packard Company)''')
		# Weird TGem identifier (TriGem 486-BIOS)
		self._precolor_block_pattern = re.compile(b'''\(C\)[0-9]{4}(?:AMI,404-263-8181|TGem-HCS,PSC,JGS)''')
		# "Date:-" might not have a space after it (Intel AMI)
		self._precolor_date_pattern = re.compile(b'''(?: Date:- ?|AMI- )[0-9]{2}/[0-9]{2}/[0-9]{2}''')
		self._precolor_chipset_pattern = re.compile(b'''(SETUP PROGRAM FOR [\\x20-\\x7F]+)|(EMI 386 CHIPSET SETUP UTILITY)|(VLSI BIOS, 286 CHIPSET)|(CHIP & TECH SETUP PROGRAM)|( 286 BIOS)|(386 BIOS, NO CHIPSET)|([234]86-BIOS \(C\))''')
		self._precolor_signon_pattern = re.compile(b'''BIOS \(C\).*(?:AMI|American Megatrends Inc), for ([\\x0D\\x0A\\x20-\\x7E]+)''')

		self.register_check_list([
			(self._string_pcchips,			RegexChecker),
			(self._string_setupheader,		RegexChecker),
			(self._signon_intel,			RegexChecker),
			(self._addons_color,			SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_easy,				SubstringChecker, SUBSTRING_BEGINNING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_hiflex,			SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_new,				SubstringChecker, SUBSTRING_BEGINNING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_simple,			SubstringChecker, SUBSTRING_BEGINNING | SUBSTRING_CASE_SENSITIVE),
			(self._addons_winbios,			SubstringChecker, SUBSTRING_CASE_SENSITIVE),
		])

	def can_handle(self, file_data, header_data):
		if b'American Megatrends Inc' not in file_data and b'AMIBIOSC' not in file_data and b'All Rights Reserved, (C)AMI (C)AMI (C)AMI ' not in file_data and b'(C) Access Methods Inc.' not in file_data:
			return False

		# The decompressed body for some BIOSes on Intel's first AMI run lacks the Intel version number, so we
		# can't determine this is an Intel first AMI run BIOS (which needs a classic date version) solely through
		# that. Use AMIIntelAnalyzer to determine if this is an Intel BIOS, and enable classic dates in that case.
		if header_data and AMIIntelAnalyzer.can_handle(self, file_data, header_data):
			self._can_version_classic = True

		# Check post-Color identification block.
		match = self._id_block_pattern.search(file_data)
		if match:
			# Determine location of the identification block.
			id_block_index = match.start(0)

			# Extract version.
			version_6plus = match.group(1)
			if version_6plus:
				# AMIBIOS 6 onwards.
				self.version = version_6plus.decode('cp437', 'ignore')

				# Pad 4-digit versions. (Biostar)
				if self.version[-1] not in '0123456789':
					self.version = self.version[:4] + '00'
			else:
				# WinBIOS (AMIBIOS 4/5)
				version_winbios_maj = match.group(2)
				version_winbios_min = match.group(3)
				if version_winbios_maj and version_winbios_min:
					self.version = (version_winbios_maj + version_winbios_min).decode('cp437', 'ignore') + '00'
					self.addons.append('WinBIOS')
				else:
					# AMI Color date.
					self.version = match.group(4).decode('cp437', 'ignore')

			# Extract string.
			self.string = util.read_string(file_data[id_block_index + 0x78:id_block_index + 0xa0]).strip()

			# Stop if this BIOS is actually Aptio UEFI CSM.
			if self._uefi_csm_pattern.match(self.string):
				return False

			# Extract sign-on, while removing carriage returns.
			self.signon = util.read_string(file_data[id_block_index + 0x100:id_block_index + 0x200])

			# The actual sign-on starts on the second line.
			self.signon = '\n'.join(x.rstrip('\r').strip() for x in self.signon.split('\n')[1:] if x != '\r').strip('\n')
		elif len(file_data) < 1024:
			# Ignore false positives from sannata readmes.
			return False
		elif self._precolor_date_pattern.search(file_data):
			# Check date, using a different pattern to differentiate core date from build date.
			match = self._date_pattern.search(file_data)
			if match:
				# Extract date as the version.
				self.version = match.group(1).decode('cp437', 'ignore')

				# Check pre-Color identification block.
				match = self._precolor_block_pattern.search(file_data)
				if match:
					# Determine location of the identification block.
					id_block_index = match.start(0)

					# Reconstruct string, starting with the setup type.
					if b'ROM DIAGNOSTICS.(C)' in file_data:
						self.string = 'D'
					elif b'EXTENDED CMOS SETUP PROGRAM Ver - ' in file_data:
						self.string = 'E'
					else:
						self.string = 'S'

					# Add chipset. Known undetectable codes due
					# to a lack of BIOS images or marker strings:
					# - 307 (C&T CS8236)
					# - GS2 (GoldStar)
					# - INT (Intel 82335)
					# - PAQ (Compaq)
					# - S24 (??? Morse KP286)
					# - SUN (Suntac)
					# - VLX (VLSI 386?)
					chipset = '???'
					match = self._precolor_chipset_pattern.search(file_data)
					if match:
						setup_program_for = match.group(1) # "SETUP PROGRAM FOR"
						if setup_program_for:
							#if b' C&T ' in setup_program_for: # not necessary with fallback below
							#	chipset = 'C&T'
							if b' INTEL 386 ' in setup_program_for:
								chipset = '343'
							elif b' NEAT ' in setup_program_for:
								if b'NEATsx Memory Controller Identifier' in file_data:
									chipset = 'NSX'
								else:
									chipset = 'NET'
							elif b' OPTI ' in setup_program_for:
								chipset = 'OPB'
							elif b' SCAT ' in setup_program_for:
								chipset = 'SC2'
							elif b' SIS ' in setup_program_for:
								chipset = 'SIS'
							else:
								# Your guess is as good as mine.
								chipset = setup_program_for[18:21].decode('cp437', 'ignore')
								if chipset != 'C&T':
									self.signon = 'DEBUG:UnknownSetup:' + setup_program_for.decode('cp437', 'ignore')
						else:
							bios_id_index = match.start(5) # " 286 BIOS"
							if bios_id_index > -1:
								bios_id = file_data[bios_id_index - 10:bios_id_index + 1]
								if b'ACER 1207 ' in bios_id:
									chipset = 'AR2'
								elif b'HT-11 ' in bios_id:
									chipset = 'H12'
								elif b'HT-1X ' in bios_id:
									chipset = 'H1X'
								elif b'NEAT ' in bios_id: # assumed; not bootable on 86Box
									chipset = 'NET'
								elif b'WIN ' in bios_id: # Winbond; not bootable on 86Box, source is a MAME comment
									chipset = '286'
								else:
									self.signon = 'DEBUG:UnknownChipset:' + bios_id.decode('cp437', 'ignore')
							elif match.group(2): # "EMI 386 CHIPSET SETUP UTILITY"
								chipset = 'EMI'
							elif match.group(3): # "VLSI BIOS, 286 CHIPSET"
								chipset = 'VL2'
							elif match.group(4): # "CHIP & TECH SETUP PROGRAM"
								chipset = 'C&T'
							elif match.group(6): # "386 BIOS, NO CHIPSET"
								chipset = 'INT'
							else:
								x86_bios = match.group(7) # "[234]86-BIOS (C)"
								if x86_bios:
									chipset = x86_bios[:3].decode('cp437', 'ignore')
					self.string += chipset

					# Add vendor ID.
					self.string += '-' + codecs.encode(file_data[id_block_index - 0xbb:id_block_index - 0xb9], 'hex').decode('ascii', 'ignore').upper()

					# Add date. Use the entry point date instead of the identification block one, as it
					# appears the entry point one is displayed on screen. (Shuttle 386SX, TriGem 486-BIOS)
					self.string += '-' + util.read_string(file_data[id_block_index + 0x9c:id_block_index + 0xa4]).replace('/', '').strip()

					# Invalidate string if the identification block
					# doesn't appear to be valid. (Intel AMI post-Color)
					if self.string[:10] in ('S???-0000-', 'S???-0166-') and file_data[id_block_index - 0xb9:id_block_index - 0xb7] != b'\x00\x01':
						self.string = ''
					else:
						# Extract additional information after the copyright as a sign-on.
						# (Shuttle 386SX, CDTEK 286, Flying Triumph Access Methods)
						match = self._precolor_signon_pattern.search(file_data)
						if match:
							self.signon = match.group(1).decode('cp437', 'ignore')

							# Split sign-on lines. (Video Technology Info-Tech 286-BIOS)
							self.signon = '\n'.join(x.strip() for x in self.signon.split('\n') if x.strip()).strip('\n')
			else:
				# Assume this is not an AMI BIOS.
				return False

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
		'''^(?:(BIOS (?:Release|Version) )?([0-9]\.[0-9]{2}\.[0-9]{2}\.[A-Z][0-9A-Z]{1,})|(?:\$IBIOSI\$)?([0-9A-Z]{8}\.([0-9A-Z]{3})\.[0-9A-Z]{4}\.[0-9A-Z]{3}\.[0-9]{10}|(?:\.[0-9]{4}){3}))'''

		# If this is Intel's second AMI run, check if this is not a generic
		# (86x) version string overwriting an OEM version string.
		oem = match.group(4)
		if not oem or oem[:2] != '86' or not self._intel_86_pattern.match(self.signon):
			# Extract the version string as a sign-on.
			prefix_idx = self.signon.rfind(' ')
			if prefix_idx > -1:
				prefix = self.signon[:prefix_idx + 1]
			else:
				prefix = match.group(1) or ''
			self.signon = prefix + (match.group(2) or match.group(3))

		return True

	def _addons_color(self, line, match):
		'''Improper Use of Setup may Cause Problems !!'''

		# Add setup type to add-ons.
		self.addons.append('Color')

		return True

	def _addons_easy(self, line, match):
		'''AMIBIOS EASY SETUP UTILIT'''

		# Add setup type to add-ons.
		self.addons.append('EasySetup')

		return True

	def _addons_hiflex(self, line, match):
		'''\\HAMIBIOS HIFLEX SETUP UTILIT'''

		# Add setup type to add-ons.
		self.addons.append('HiFlex')

		return True

	def _addons_new(self, line, match):
		'''AMIBIOS NEW SETUP UTILIT'''

		# Add setup type to add-ons.
		self.addons.append('NewSetup')

		return True

	def _addons_simple(self, line, match):
		'''\\HAMIBIOS SIMPLE SETUP UTILIT'''

		# Add setup type to add-ons.
		self.addons.append('SimpleSetup')

		return True

	def _addons_winbios(self, line, match):
		'''Keystroke/Mouse Convention'''

		# Add setup type to add-ons.
		self.addons.append('WinBIOS')

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

	def can_handle(self, file_data, header_data):
		if file_data[:9] == b'DELLBIOS\x00':
			# DELLBIOS header contains the Dell version.
			self.version = '11/11/92'
			self.debug_print('DELLBIOS header')

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
			self.debug_print('DELLXBIOS string')

			return True

		return False

	def _version_intel(self, line, match):
		# Prevent the Intel version detector from working here.
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
	def __init__(self, *args, **kwargs):
		super().__init__('AMI', *args, **kwargs)
		self.vendor_id = 'AMIIntel'

	def can_handle(self, file_data, header_data):
		# Handle Intel AMI BIOSes that could not be decompressed.

		# Stop if there is no header data.
		if not header_data:
			return False

		# Stop if this is an User Data Area file.
		if header_data[112:126] == b'User Data Area':
			return False

		# Extract the Intel version from the multi-part header.
		if header_data[90:95] == b'FLASH':
			version = header_data[112:header_data.find(b'\x00', 112)]
		elif header_data[602:607] == b'FLASH':
			version = header_data[624:header_data.find(b'\x00', 624)]
		else:
			version = None

		# Apply the version as a sign-on if one was extracted.
		if version:
			self.version = 'Unknown Intel'
			self.signon = version.decode('cp437', 'ignore').strip()
			return True

		return False


class AMIUEFIAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('AMI', *args, **kwargs)
		self.vendor_id = 'AMIUEFI'

		self._identifier_regex = re.compile(b'''Version %x\.%02x\.%04x\.|ALASKAA M I''')

		self.register_check_list([
			(self._string_csm,						RegexChecker),
			((self._signon_precheck, self._signon),	AlwaysRunChecker),
			(self._signon_trigger,					RegexChecker),
			(self._signon_asus,						RegexChecker),
			(self._signon_prefixed,					RegexChecker),
		])

	def reset(self):
		super().reset()
		self._trap_signon = False

	def _signon_precheck(self, line):
		return self._trap_signon

	def can_handle(self, file_data, header_data):
		# Only handle files sent through UEFIExtractor.
		if header_data != b'\x00\xFFUEFIExtract\xFF\x00':
			return False

		# Check for version format string or "ALASKA" ACPI table identifier.
		if not self._identifier_regex.search(file_data):
			return False

		self.version = 'UEFI'

		return True

	def _string_csm(self, line, match):
		'''^63-0100-000001-00101111-......-Chipset$'''

		# Extract string from the AMIBIOS 8-based CSM, just because.
		self.string = line

		return True

	def _signon_trigger(self, line, match):
		'''^Version %x\.%02x\.%04x. Copyright \(C\)'''

		# Read sign-on on the next line if one wasn't already found.
		if not self.signon:
			self._trap_signon = True

		return True

	def _signon(self, line, match):
		# Extract sign-on.
		self.signon = line

		# Disarm trap.
		self._trap_signon = False

		return True

	def _signon_asus(self, line, match):
		'''. ACPI BIOS Revision .'''

		# Extract sign-on.
		self.signon = line

		return True

	def _signon_prefixed(self, line, match):
		'''^\$(?:(?:IBIOSI\$|UBI)([0-9A-Z]{8}\.[0-9A-Z]{3}(?:\.[0-9]{4}){4})|MSESGN\$(.+))'''
		# "$IBIOSI$", "$UBI" (Intel)
		# "$MSESGN$" (MSI)

		# Extract sign-on.
		self.signon = match.group(1) or match.group(2)

		return True


class AmstradAnalyzer(NoInfoAnalyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Amstrad', *args, **kwargs)

	def has_strings(self, file_data):
		return (b'AMSTRAD plc' in file_data or b'Amstrad Consumer Electronics plc' in file_data) and ((b'Veuillez mettre des piles neuves' in file_data and b'Batterie da sostituire' in file_data and b'ponga piles nuevas' in file_data and b'neue Batterien einsetzen' in file_data) or b'IBMUS NON CARBORUNDUM' in file_data)


class AwardAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Award', *args, **kwargs)

		self._early_modular_prefix_pattern = re.compile('''(.+) Modular BIOS ''')
		self._gigabyte_bif_pattern = re.compile(b'''\$BIF[\\x00-\\xFF]{5}([\\x20-\\x7F]+)\\x00.([\\x20-\\x7F]+)\\x00''')
		self._gigabyte_eval_pattern = re.compile('''\([a-z0-9]{1,8}\) EVALUATION ROM - NOT FOR SALE$''')
		self._id_block_pattern = re.compile(b'''(?:Award |Phoeni)[\\x00-\\xFF]{8}IBM COMPATIBLE ''')
		self._ignore_pattern = re.compile(b'search=f000,0,ffff,S,"|VGA BIOS Version (?:[^\r]+)\r\n(?:Copyright \(c\) (?:[^\r]+)\r\n)?Copyright \(c\) (?:NCR \& )?Award', re.M)
		self._romby_date_pattern = re.compile(b'''N((?:[0-9]{2})/(?:[0-9]{2})/)([0-9]{2})([0-9]{2})(\\1\\3)''')
		self._string_date_pattern = re.compile('''(?:[0-9]{2})/(?:[0-9]{2})/([0-9]{2,4})-''')
		self._version_pattern = re.compile(''' (?:v([^\s]+)|Version [^0-9]*([0-9]\.[0-9]{2}))(?:[. ]([\\x20-\\x7F]+))?''')

		self.register_check_list([
			(self._version_ast,		RegexChecker),
			(self._version_pcxt,	RegexChecker),
			(self._addons_uefi,		SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
		])

	def can_handle(self, file_data, header_data):
		if b'Award Software Inc.' not in file_data and b'Award Decompression Bios' not in file_data:
			return False

		# Skip Windows 95 INF updates and Award VBIOS.
		if self._ignore_pattern.search(file_data):
			return False

		# The bulk of Award identification data has remained in one place for the longest time.
		match = self._id_block_pattern.search(file_data)
		if match:
			# Determine location of the identification block.
			id_block_index = match.start(0)

			# Extract version.
			version_string = util.read_string(file_data[id_block_index + 0x61:id_block_index + 0xa1])
			version_match = self._version_pattern.search(version_string)
			if version_match:
				self.version = 'v' + (version_match.group(1) or version_match.group(2))
			elif version_string == 'Award Modular BIOS Version ': # Award version removed (Intel YM430TX)
				self.version = 'Intel'

			# Add Phoenix-Award and WorkstationBIOS indicators.
			if 'Phoenix' in version_string:
				self.version += ' (Phoenix)'
			elif 'WorkstationBIOS' in version_string:
				self.version += ' (Workstation)'

			# Extract sign-on.
			# Vertical tab characters may be employed (??? reported by BurnedPinguin)
			self.signon = util.read_string(file_data[id_block_index + 0xc1:id_block_index + 0x10f]).replace('\r', '').replace('\v', '\n')

			# Split sign-on lines.
			self.signon = '\n'.join(x.strip() for x in self.signon.split('\n') if x.strip()).strip('\n')

			# Extract string, unless the version is known to be too old to have a string.
			if self.version[:3] not in ('v2.', 'v3.'):
				self.string = util.read_string(file_data[id_block_index + 0xc71:id_block_index + 0xce0])

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

			if self.version == 'v6.00PG' and self._gigabyte_eval_pattern.match(self.signon):
				# Reconstruct actual sign-on of a Gigabyte fork BIOS through
				# the data in the $BIF area (presumably BIOS update data).
				match = self._gigabyte_bif_pattern.search(file_data)
				if match:
					self.signon = (match.group(1) + b' ' + match.group(2)).decode('cp437', 'ignore').strip()
			elif 'Award' not in version_string.split('\n')[0]: # "386SX Modular BIOS v3.15"
				# Extract early Modular type as the string.
				match = self._early_modular_prefix_pattern.match(version_string)
				if match:
					self.string = match.group(1)

				# Append post-version data to the string.
				if version_match:
					post_version = version_match.group(3)
					if post_version:
						post_version = post_version.strip()
					if post_version:
						if match:
							self.string += '\n' + post_version
						else:
							self.string = post_version

			# Perform final clean-up.
			self.version = self.version.strip()
			self.string = self.string.strip()
			self.signon = self.signon.strip()

		return True

	def _version_ast(self, line, match):
		'''^.AST ((?:.+) BIOS Rel\. (?:.+))'''

		# This is an AST BIOS.
		self.version = 'AST'

		# Extract model and version as a sign-on.
		self.signon = match.group(1)

		return True

	def _version_pcxt(self, line, match):
		'''(PC|XT) BIOS V([^\s]+)'''

		# Extract version if one wasn't already found.
		if not self.version:
			self.version = 'v' + match.group(2)

			# Extract BIOS type as a string.
			self.string = match.group(1)

		return True

	def _addons_uefi(self, line, match):
		'''EFI CD/DVD Boot Option'''

		# Flag Gigabyte Hybrid EFI as UEFI.
		self.addons.append('UEFI')

		return True


class AwardPowerAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('AwardPower', *args, **kwargs)
		self.vendor = 'Award'

		self.register_check_list([
			(self._version,	RegexChecker),
			(self._string,	RegexChecker)
		])

	def can_handle(self, file_data, header_data):
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

		self._acpi_table_pattern = re.compile(b'''(?:APIC|DSDT|FACP|PSDT|RSDT|SBST|SSDT)(.{4}).{24}[\\x00\\x20-\\x7E]{4}''')
		self._adaptec_pattern = re.compile(b'''Adaptec (?:BIOS:|([\\x20-\\x7E]+) BIOS )''')
		self._ncr_pattern = re.compile(b''' SDMS \(TM\) V([0-9])''')
		self._pci_rom_pattern = re.compile(b'''\\x55\\xAA[^\\x00].{21}(.{2})''')
		self._phoenixnet_patterns = (
			re.compile(b'''CPLRESELLERID'''),
			re.compile(b'''BINCPUTBL'''),
			re.compile(b'''BINIDETBL'''),
		)
		self._pxe_patterns = (
			re.compile(b'''PXE-M0F: Exiting '''),
			re.compile(b'''PXE-EC6: UNDI driver image is invalid\.'''),
		)
		self._rpl_pattern = re.compile(b'''NetWare Ready ROM''')
		self._sli_pattern = re.compile(b'''[0-9]{12}Genuine NVIDIA Certified SLI Ready Motherboard for ''')
		self._vbios_pattern = re.compile(b'''IBM (?:VGA C(?:OMPATIBLE|ompatible)|COMPATIBLE PARADISE)|ATI Technologies Inc\.|SiS super VGA chip''')

	def can_handle(self, file_data, header_data):
		# PhoenixNet
		if util.all_match(self._phoenixnet_patterns, file_data):
			self.addons.append('PhoenixNet')

		# ACPI tables
		match = self._acpi_table_pattern.search(file_data)
		if match and struct.unpack('<I', match.group(1))[0] > 36: # length includes header, header is 36 bytes
			self.addons.append('ACPI')

		# Adaptec SCSI
		if self._adaptec_pattern.search(file_data):
			self.addons.append('Adaptec')

		# NCR SCSI
		match = self._ncr_pattern.search(file_data)
		if match:
			self.addons.append('NCR' + match.group(1).decode('ascii', 'ignore'))

		# PXE boot
		if util.all_match(self._pxe_patterns, file_data):
			self.addons.append('PXE')

		# RPL boot
		if self._rpl_pattern.search(file_data):
			self.addons.append('RPL')

		# SLI certificate
		if self._sli_pattern.search(file_data):
			self.addons.append('SLI')

		# UEFI
		if header_data == b'\x00\xFFUEFIExtract\xFF\x00':
			self.addons.append('UEFI')

		# VGA BIOS
		if self._vbios_pattern.search(file_data):
			self.addons.append('VGA')

		# Look for PCI option ROMs.
		for match in self._pci_rom_pattern.finditer(file_data):
			# Move on to the next ROM if we don't have a valid PCI data structure.
			pci_header_ptr, = struct.unpack('<H', match.group(1))
			if pci_header_ptr < 26:
				continue
			pci_header_ptr += match.start()
			if file_data[pci_header_ptr:pci_header_ptr + 4] != b'PCIR':
				continue
			pci_header_data = file_data[pci_header_ptr + 4:pci_header_ptr + 16]
			if len(pci_header_data) != 12:
				continue

			# Read PCI header data, and move on to the next ROM if we have a bogus vendor ID.
			vendor_id, device_id, device_list_ptr, _, revision, progif, subclass, class_code = struct.unpack('<HHHHBBBB', pci_header_data)
			if vendor_id in (0x0000, 0xffff):
				continue

			# Flag VGA option ROMs.
			if (class_code == 0 and subclass == 1) or (class_code == 3 and subclass in (0, 1)):
				self.addons.append('VGA')

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
				if device_id == 0x0000:
					break

				# Add the device ID and existing vendor ID to the option ROM list.
				self.oroms.append((vendor_id, device_id))

				# Move on to the next ID.
				device_list_ptr += 2

		# This analyzer should never return True.
		return False


class CDIAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('CDI', *args, **kwargs)

	def can_handle(self, file_data, header_data):
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

	def can_handle(self, file_data, header_data):
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

	def can_handle(self, file_data, header_data):
		return b'Chips & Technologies, Inc.' in file_data and b'BIOS Version ' in file_data

	def _version(self, line, match):
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

	def can_handle(self, file_data, header_data):
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

	def has_strings(self, file_data):
		return b'Copyright COMPAQ Computer Corporation' in file_data and (b'Insert DIAGNOSTIC diskette in Drive ' in file_data or b'Insert COMPAQ DOS diskette' in file_data or b'You must load COMPAQ BASIC' in file_data)


class CorebootAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('coreboot', *args, **kwargs)

		self.register_check_list([
			(self._version_coreboot,	RegexChecker),
			(self._version_linuxbios,	RegexChecker),
			(self._string_coreboot,		RegexChecker),
		])

	def can_handle(self, file_data, header_data):
		return b'coreboot-%s%s ' in file_data or b'Jumping to LinuxBIOS.' in file_data

	def _version_coreboot(self, line, match):
		'''^#(?: This image was built using coreboot|define COREBOOT_VERSION ")([^"]+)'''

		# Extract version.
		self.version = match.group(1)

		# Extract any additional information after the version as a string.
		dash_index = self.version.find('-')
		if dash_index > -1:
			self.string = self.version[dash_index + 1:]
			self.version = self.version[:dash_index]

		return True

	def _version_linuxbios(self, line, match):
		'''^LinuxBIOS-([^_ ]+)[_ ](?:Normal |Fallback )(.+) starting\.\.\.$'''

		# Set vendor to LinuxBIOS instead.
		self.vendor = 'LinuxBIOS'

		# Extract version.
		self.version = match.group(1)

		# Extract any additional information after the version as a string.
		self.string = match.group(2)

		return True

	def _string_coreboot(self, line, match):
		'''^#define COREBOOT_BUILD "([^"]+)"'''

		# Add build date to string.
		if self.string:
			self.string += '\n'
		self.string += match.group(1)

		return True


class DTKGoldStarAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('DTKGoldStar', *args, **kwargs)

		self.register_check_list([
			(self._version,	RegexChecker),
		])

	def reset(self):
		super().reset()
		self._dtk = False

	def can_handle(self, file_data, header_data):
		return b'Datatech Enterprises Co., Ltd.' in file_data or b'(C) Copyright by GoldStar Co.,Ltd.' in file_data or b'GOLDSTAR  SYSTEM  SETUP' in file_data

	def _version(self, line, match):
		'''^(?:(DTK|GoldStar) (.+) ROM BIOS Version |VER )([^\s]+)(?: ([^\s]+))?'''

		# Extract vendor.
		self.vendor = match.group(1) or 'GoldStar'

		# Extract version.
		self.version = match.group(3)

		# Extract string.
		self.string = match.group(2) or ''

		# Add revision to string.
		revision = match.group(4)
		if revision:
			if self.string:
				self.string += '\n'
			self.string += revision

		return True


class GeneralSoftwareAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('General', *args, **kwargs)

		self._string_pattern = re.compile(b'''([0-9]{2}/[0-9]{2}/[0-9]{2})\(C\) [0-9]+ General Software, Inc\. ''')
		self._version_pattern = re.compile(b'''General Software (?:\\x00 )?([^\\\\]+)(?:rel\.|Revision)''')

	def can_handle(self, file_data, header_data):
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

		# Take this analyzer if we found a version or string.
		return self.version != '?' or self.string


class IBMAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('IBM', *args, **kwargs)

		self._header_pattern = re.compile(b'''([0-9]{2}[A-Z0-9][0-9]{4}) (COPR\. IBM|\(C\) COPYRIGHT IBM CORPORATION) 19[89][0-9]''')
		self._interleaved_header_pattern = re.compile(b'''(([0-9])\\2([0-9])\\3([A-Z0-9])\\4(?:[0-9]{8}))  (CCOOPPRR\.\.  IIBBMM|\(\(CC\)\)  CCOOPPYYRRIIGGHHTT  IIBBMM  CCOORRPPOORRAATTIIOONN)  1199([89])\\6([0-9])\\7''')

	def can_handle(self, file_data, header_data):
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


class InsydeAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Insyde', *args, **kwargs)

		self._identifier_regex = re.compile(b'''InsydeH2O Version ''')

	def can_handle(self, file_data, header_data):
		# Only handle files sent through UEFIExtractor.
		if header_data != b'\x00\xFFUEFIExtract\xFF\x00':
			return False

		# Check for InsydeH2O version string.
		if not self._identifier_regex.search(file_data):
			return False

		self.version = '?'

		return True


class IntelUEFIAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Intel', *args, **kwargs)
		self.vendor_id = 'IntelUEFI'

		self._identifier_regex = re.compile(b'''\$(?:IBIOSI\$|FID)[0-9A-Z]{8}\.''')

		self.register_check_list([
			(self._signon,	RegexChecker),
		])

	def can_handle(self, file_data, header_data):
		# Only handle files sent through UEFIExtractor.
		if header_data != b'\x00\xFFUEFIExtract\xFF\x00':
			return False

		# Check for any Intel version code identifiers.
		if not self._identifier_regex.search(file_data):
			return False

		self.version = 'UEFI'

		return True

	def _signon(self, line, match):
		'''^(?:\$(?:IBIOSI\$|FID))?([0-9A-Z]{8}\.([0-9A-Z]{3})(?:\.[0-9]{4}){4})'''

		# Extract sign-on.
		self.signon = match.group(1)

		return True


class JukoAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Juko', *args, **kwargs)

		self.register_check_list([
			(self._version,	RegexChecker),
		])

	def can_handle(self, file_data, header_data):
		return b'Juko Electronics Industrial Co.,Ltd.' in file_data

	def _version(self, line, match):
		'''Juko (.+) BIOS ver (.+)'''

		# Extract version.
		self.version = match.group(2)

		# Extract string.
		self.string = match.group(1)

		return True


class MRAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('MR', *args, **kwargs)

		self._signon_pattern = re.compile(b'''OEM SIGNON >>-->([\\x20-\\x7F]+)''')

		self.register_check_list([
			(self._version_newer,	RegexChecker),
			(self._version_older,	RegexChecker),
		])

	def can_handle(self, file_data, header_data):
		# Skip readme false positives.
		if len(file_data) < 2048 or b'MR BIOS (r)  V' not in file_data:
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
		'''^MR BIOS \(r\)  (V(?:[^\s]+))(?: (.+))?$'''

		# Extract version.
		self.version = match.group(1)

		# Extract part number as a string if one was found.
		part_number = match.group(2)
		if part_number:
			self.string = part_number

		return True

	def _version_older(self, line, match):
		'''^Ver: (V[^-]+)-(.+)'''

		# Extract version.
		self.version = match.group(1)

		# Extract part number(?)
		self.string = match.group(2)

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

	def can_handle(self, file_data, header_data):
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

		# "All Rights Reserved\r\n\n\x00\xF4\x01" (Ax86)
		# "All Rights Reserved\r\n\n\x00" (Commodore 386LT, Tandy 1000RSX)
		# "All Rights Reserved\r\n\n" (ROM BIOS)
		# "All Rights Reserved\r\n\r\n\r\n" (Gateway 4DX2-50V)
		self._rombios_signon_pattern = re.compile(b'''\\x0D\\x0AAll Rights Reserved\\x0D\\x0A(?:\\x0A(?:\\x00(?:\\xF4\\x01)?)?|\\x0D\\x0A\\x0D\\x0A)''')
		self._bcpsys_datetime_pattern = re.compile('''(?:[0-9]{2})/(?:[0-9]{2})/(?:[0-9]{2}) ''')
		self._core_signon_pattern = re.compile(b'''\\x00FOR EVALUATION ONLY\. NOT FOR RESALE\.\\x00([\\x00-\\xFF]+)\\x00Primary Master \\x00''')
		self._intel_86_pattern = re.compile('''(?:[0-9A-Z]{8})\.86(?:[0-9A-Z])\.(?:[0-9A-Z]{4})\.(?:[0-9A-Z]{3})\.(?:[0-9]{10})$''')

		self.register_check_list([
			((self._signon_fujitsu_precheck, self._signon_fujitsu),	AlwaysRunChecker),
			((self._signon_nec_precheck, self._signon_nec),			AlwaysRunChecker),
			(self._version_xx86,									RegexChecker), # "All Rights Reserved" => "A286 Version 1.01"
			(self._version_pentium,									RegexChecker),
			(self._version_40rel,									RegexChecker),
			(self._version_40x,										RegexChecker),
			(self._version_branch,									RegexChecker),
			(self._version_core,									RegexChecker),
			(self._version_grid,									SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
			(self._version_rombios,									RegexChecker),
			(self._version_tandy,									SubstringChecker, SUBSTRING_FULL_STRING | SUBSTRING_CASE_SENSITIVE),
			((self._date_precheck, self._string_date),				RegexChecker),
			(self._signon_ast,										SubstringChecker, SUBSTRING_BEGINNING | SUBSTRING_CASE_SENSITIVE),
			((self._dell_precheck, self._signon_dell),				RegexChecker),
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
		self._is_core = False
		self._trap_signon_fujitsu_lines = 0
		self._trap_signon_nec = False
		self._found_signon_tandy = ''

	def can_handle(self, file_data, header_data):
		# "Phoenix ROM BIOS" (Dell Latitude CP/CPI)
		if b'Phoenix Technologies Ltd' not in file_data and b'Phoenix ROM BIOS' not in file_data and b'PPhhooeenniixx  TTeecchhnnoollooggiieess' not in file_data:
			return False

		# Skip Windows 95 INF updates.
		if b'search=f000,0,ffff,S,"' in file_data:
			return False

		# Read build date and time from BCPSYS on 4.0 and newer BIOSes.
		offset = file_data.find(b'BCPSYS')
		if offset > -1:
			# Extract the build date and time as a string.
			self.string = file_data[offset + 15:offset + 32].replace(b'\x00', b'\x20').decode('ascii', 'ignore').strip()

			# Discard if this is an invalid date/time (PHLASH.EXE)
			if not self._bcpsys_datetime_pattern.match(self.string):
				self.string = ''
			else:
				self.debug_print('BCPSYS date/time', self.string)

		# Determine if this is a Dell BIOS (48-byte header).
		offset = file_data.find(b'Dell System ')
		if offset > -1:
			self.version = 'Dell'
			self.signon = '\n'

			# Extract Dell version.
			if file_data[offset + 0x20:offset + 0x21] == b'A':
				self.signon += 'BIOS Version: ' + file_data[offset + 0x20:offset + 0x30].decode('ascii', 'ignore').rstrip('^\x00')
		else:
			# Extract sign-on from Core and some 4.0 Release 6.0 BIOSes.
			match = self._core_signon_pattern.search(file_data)
			if match:
				self.signon = match.group(1).decode('cp437', 'ignore')
			else:
				# Extract sign-on from Ax86 and older BIOSes.
				match = self._rombios_signon_pattern.search(file_data)
				if match:
					end = match.end(0)
					if file_data[end] != 0xfa: # (unknown 8088 PLUS 2.52)
						self.signon = util.read_string(file_data[end:end + 256])

			# Split sign-on lines.
			if self.signon:
				self.signon = self.signon.replace('\r', '\n').replace('\x00', ' ')
				self.signon = '\n'.join(x.strip() for x in self.signon.split('\n') if x.strip()).strip('\n')

		return True

	def _core_precheck(self, line):
		return self._is_core

	def _date_precheck(self, line):
		return len(self.string) != 8 or util.date_pattern_mmddyy.match(line)

	def _dell_precheck(self, line):
		return self.version == 'Dell'

	def _signon_fujitsu_precheck(self, line):
		return self._trap_signon_fujitsu_lines > 0

	def _signon_nec_precheck(self, line):
		return self._trap_signon_nec

	def _version_40rel(self, line, match):
		'''Phoenix(MB)? ?BIOS ([0-9]\.[^\s]+ Release [0-9]\.[^\s]+)(?: (.+))?'''

		# Extract version with release.
		self.version = match.group(2)

		# Add version prefix if one was found.
		prefix = match.group(1)
		if prefix:
			self.version = prefix + ' ' + self.version

		# Extract any additional information after the version
		# as a sign-on, if one wasn't already found.
		additional_info = match.group(3)
		if additional_info and not self.signon:
			self.signon = additional_info.rstrip()

		return True

	def _version_40x(self, line, match):
		'''Phoenix(?:(MB)(?: BIOS)?| ?BIOS(?: (Developmental))?) Version +([0-9]\.[^\s.]+)(?:[\s\.](.+))?'''

		# Extract version.
		self.version = match.group(3)

		# Add version prefix if one was found.
		prefix = match.group(1) or match.group(2)
		if prefix:
			self.version = prefix + ' ' + self.version

		# Extract any additional information after the version
		# as a sign-on, if one wasn't already found.
		additional_info = match.group(4)
		if additional_info and not self.signon:
			self.signon = additional_info.rstrip()

		return True

	def _version_branch(self, line, match):
		'''Phoenix ([A-Za-z]+(?:BIOS|Bios)) (?:Version ([0-9]\.[^\s]+)|([0-9](?:\.[0-9.]+)? Release [0-9]\.[^\s]+))(?:[\s\.](.+))?'''

		# Extract version with branch and release.
		self.version = match.group(1) + ' ' + (match.group(2) or match.group(3))

		# Extract any additional information after the version
		# as a sign-on, if one wasn't already found.
		additional_info = match.group(4)
		if additional_info and not self.signon:
			self.signon = additional_info.rstrip()

		return True

	def _version_core(self, line, match):
		'''^Phoenix (cME|[A-Za-z]+Core)(?:\(tm\))? (?!Setup)([^\s]+)?'''

		# Extract the first word.
		self.version = match.group(1)

		# Extract the second word.
		second_word = match.group(2)
		if second_word:
			if second_word == 'SVR':
				second_word = 'Server'
			self.version += ' ' + second_word

		# Mark this as a Core BIOS for sign-on extraction.
		self._is_core = True

		return True

	def _version_grid(self, line, match):
		'''Copyright (C) 1987-1991, GRiD Systems Corp.All Rights Reserved'''

		# This is a GRiD BIOS.
		if not self.version:
			self.version = 'GRiD'

		return False

	def _version_pentium(self, line, match):
		'''^(?:PhoenixBIOS(?:\(TM\))? )?for ((?:486/)?Pentium)\s?\(TM\)(?: CPU)? - ([^\s]+) Version ([^-\s]+)(?:(?:-|\s)(.+))?'''

		# Add branch to version.
		self.version = match.group(1)

		# Add non-ISA bus types to version.
		bus_type = match.group(2)
		if bus_type != 'ISA':
			self.version += ' ' + bus_type

		# Add actual version.
		self.version += ' ' + match.group(3)

		# Extract any additional information after the version as a sign-on,
		# if one wasn't already found.
		post_version = match.group(4)
		if not self.signon and post_version:
			post_version = post_version.strip()
			if post_version:
				self.signon = post_version

		return True

	def _version_rombios(self, line, match):
		'''(?:(?:((?:8086|8088|V20 |(?:80)?(?:[0-9]{3}))(?:/EISA)?) )?ROM BIOS (PLUS )?|^ (PLUS) )Ver(?:sion)? ([0-9]\.[A-Z0-9]{2,})\.?([^\s]*)(\s+[0-9A-Z].+)?'''

		# Stop if this was already determined to be a Dell BIOS.
		if self.version == 'Dell':
			# Let _signon_dell handle this version line.
			return False

		# Extract version.
		self.version = match.group(4).rstrip('. ')

		# Extract version prefix if present.
		pre_version = match.group(1)
		if pre_version:
			# Shorten 80286/80386(/80486?)
			if len(pre_version) >= 5 and pre_version[:2] == '80':
				pre_version = pre_version[2:]

			self.version = pre_version.strip() + ' ' + self.version

		# Add PLUS prefix/suffix if present.
		if match.group(1) or match.group(2):
			space_index = self.version.find(' ')
			if space_index > -1:
				self.version = self.version[:space_index] + ' PLUS' + self.version[space_index:]
			else:
				self.version = 'PLUS ' + self.version

		# Extract any additional information after the version as a sign-on
		# if none was already found.
		if not self.signon.replace('\t', '').replace(' ', ''):
			additional_info = (match.group(5) or '') + (match.group(6) or '')
			if additional_info and (len(additional_info) > 3 or additional_info[0] != '.'):
				self.signon = additional_info

		return True

	def _version_tandy(self, line, match):
		'''$ Tandy Corporation '''

		# This is a Tandy BIOS with Phoenix Compatibility Software.
		if not self.version:
			self.version = 'Tandy'

		# Set Tandy sign-on if we already found one.
		self.signon = self._found_signon_tandy

		return True

	def _version_xx86(self, line, match):
		'''(?:Phoenix(?:(?:\s)?BIOS(?:\(TM\))?)? )?([ADE][23456]86) Version (?:([0-9]\.[0-9]{2})(.*))?$'''

		# Stop if this is A386 after A486 (Apricot LS Pro)
		branch = match.group(1)
		if branch == 'A386' and self.version[:5] == 'A486 ':
			return True

		# Add branch to the version.
		self.version = branch

		# Add actual version, if found.
		version = match.group(2)
		if version:
			self.version += ' ' + version

		# Abort analysis if this is a non-BIOS file. (ZEOS id.txt)
		if version == 'A486 1.0x"':
			self.version = ''
			raise AbortAnalysisError('Phoenix non-BIOS (_version_xx86)')

		# Extract any additional information after the version as a sign-on
		# if none was already found.
		if not self.signon:
			additional_info = match.group(3)
			if additional_info and (len(additional_info) > 3 or additional_info[0] != '.'):
				self.signon = additional_info

		return True

	def _string_date(self, line, match):
		'''^((?:[0-9]{2})/(?:[0-9]{2})/(?:[0-9]{2})|(?:[0-9]{4})//(?:[0-9]{4})//(?:[0-9]{4}))((?:[0-9]{2})/(?:[0-9]{2})/(?:[0-9]{2}))?'''

		# De-interleave date if interleaved.
		date = match.group(1)
		if len(date) > 8:
			date = date[::2]

		# If two dates were found, the newest one takes precedence.
		other_date = match.group(2)
		if other_date and util.date_gt(other_date, date, util.date_pattern_mmddyy):
			date = other_date

		# Skip known bad dates.
		if date == '00/00/00':
			return True

		# Extract the date as a string if newer than any previously-found date.
		if ' ' not in self.string and (not self.string or util.date_gt(date, self.string, util.date_pattern_mmddyy)):
			self.string = date

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

	def _signon_dell(self, line, match):
		'''^(?:(D)ell System |(?:BIOS Version(?!  =)|Phoenix ROM BIOS PLUS Version (?:[^\s]+)) )(.+)'''

		# Add model or BIOS version to the sign-on.
		linebreak_index = self.signon.find('\n')
		if match.group(1): # the single captured character is a flag
			self.signon = match.group(2) + self.signon[linebreak_index:]
		else:
			self.signon = self.signon[:linebreak_index + 1] + 'BIOS Version: ' + match.group(2)

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
		'''^(?:\$IBIOSI\$)?((?:[0-9])\.(?:[0-9]{2})\.(?:[0-9]{2})\.(?:[0-9A-Z]{2,})|(?:[0-9A-Z]{8})\.([0-9A-Z]{3})\.(?:[0-9A-Z]{4})\.(?:[0-9A-Z]{3})\.([0-9]{10}))'''

		# This is an Intel BIOS.
		if not self.version:
			self.version = 'Intel'

		# If this is Intel's second Phoenix run, check if this is not a generic
		# (86x) version string overwriting an OEM version string.
		oem = match.group(2)
		if not oem or oem[:2] != '86' or not self._intel_86_pattern.match(self.signon):
			# Extract the version string as a sign-on.
			self.signon = match.group(1)

		# The longer string on Intel's second Phoenix run has a build date and
		# time, which is more accurate than the build date and time in BCPSYS.
		build_date_time = match.group(3)
		if build_date_time:
			# Check if the date is newer than any existing date.
			build_date = '{0}/{1}/{2}'.format(build_date_time[2:4], build_date_time[4:6], build_date_time[:2])
			if len(self.string) >= 8 and util.date_gt(build_date, self.string[:8], util.date_pattern_mmddyy):
				# Extract the date as a string.
				self.string = '{0} {1}:{2}'.format(build_date, build_date_time[6:8], build_date_time[8:10])

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


class QuadtelAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Quadtel', *args, **kwargs)

		self._id_block_pattern = re.compile(b'''Copyright 19..-.... Quadtel Corp\. Version''')
		self._version_pattern = re.compile('''(?:(?:Quadtel|QUADTEL|PhoenixBIOS) )?(.+) BIOS Version ([^\\r\\n]+)''')

		self.register_check_list([
			(self._string_date,	RegexChecker),
		])

	def can_handle(self, file_data, header_data):
		if b' Quadtel Corp. Version ' not in file_data:
			return False

		# Quadtel appears to have a consistent identification block.
		match = self._id_block_pattern.search(file_data)
		if match:
			# Determine location of the identification block.
			id_block_index = match.start(0)

			# Extract version.
			version_string = util.read_string(file_data[id_block_index + 0xc8:id_block_index + 0x190])
			version_match = self._version_pattern.search(version_string) # may start with a linebreak (Phoenix-Quadtel)
			if version_match:
				self.version = version_match.group(2).replace(' \b', '').rstrip('.').strip() # remove trailing "." (quadt286) and space followed by backspace (ZEOS Marlin)
				if self.version[0:1] == 'Q': # flag Phoenix-Quadtel
					self.version = self.version[1:] + ' (Phoenix)'

				# Extract BIOS type as the string.
				self.string = version_match.group(1).strip()

			# Extract sign-on.
			self.signon = util.read_string(file_data[id_block_index + 0x190:id_block_index + 0x290]).strip()

			# Split sign-on lines.
			self.signon = '\n'.join(x.rstrip('\r').strip() for x in self.signon.split('\n') if x != '\r').strip('\n')

		return True

	def _string_date(self, line, match):
		'''^[0-9]{2}/[0-9]{2}/[0-9]{2}$'''

		# Add date to string, or replace any previously-found date with a newer one.
		linebreak_index = self.string.find('\n')
		if linebreak_index > -1:
			if util.date_gt(line, self.string[linebreak_index + 1:], util.date_pattern_mmddyy):
				self.string = self.string[:linebreak_index + 1] + match.group(0)
		else:
			if self.string:
				self.string += '\n'
			self.string += line

		# Disarm sign-on trap if armed.
		self._trap_signon = False

		return True


class SchneiderAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Schneider', *args, **kwargs)

		self.register_check_list([
			(self._version,	RegexChecker),
		])

	def can_handle(self, file_data, header_data):
		return b'Schneider Rundfunkwerke AG' in file_data

	def _version(self, line, match):
		'''EURO PC(?:\s+)BIOS (V.+)'''

		# Extract version.
		self.version = match.group(1)

		return True


class SystemSoftAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('SystemSoft', *args, **kwargs)

		self._lowbyte_pattern = re.compile(b'''[\x00-\x09\x0B-\x0F]''')
		self._branch_pattern = re.compile('''(?:^|\s)[Ff]or ([^\s]+)''')

		self.register_check_list([
			((self._signon_precheck, self._signon),	AlwaysRunChecker),
			(self._version,							RegexChecker),
			(self._version_mobilepro,				RegexChecker),
			(self._string_for,						RegexChecker),
			(self._string_scu,						RegexChecker),
			(self._string_440bx,					RegexChecker),
			(self._signon_trigger,					RegexChecker),
		])

	def reset(self):
		super().reset()

		self._version_prefix = ''
		self._version_number = ''
		self._string_branch = ''
		self._string_branch_decisive = ''
		self._string_additional = ''

		self._trap_signon = False

	def can_handle(self, file_data, header_data):
		return b'SystemSoft BIOS' in file_data

	def _update_version_string(self):
		self.version = (self._version_prefix.strip() + ' ' + self._version_number.strip()).strip()
		self.string = self._string_branch_decisive or self._string_branch
		if self._string_additional:
			self.string += ' (' + self._string_additional.lstrip(' (').rstrip(' )') + ')'

	def _signon_precheck(self, line):
		return self._trap_signon

	def _version(self, line, match):
		'''^SystemSoft BIOS for (.+) Vers(?:\.|ion) 0?([^\s]+)(?: (.+))?'''

		# Extract version number if valid.
		version = match.group(2)
		if '.' in version:
			self._version_number = version

		# Extract branch as the string.
		self._string_branch_decisive = (match.group(1) or '').rstrip(' .,') # strip dot and comma (NCR 3xxx series)

		# Extract model information after the branch (NCR 3315) as a sign-on.
		onthe_split = self._string_branch_decisive.split(' on the ')
		if len(onthe_split) == 2:
			self._string_branch_decisive, self.signon = onthe_split

		# Add any additional information after the version to the string.
		additional_info = match.group(3)
		if additional_info:
			self._string_additional = additional_info

		# Update version and string.
		self._update_version_string()

		return True

	def _version_mobilepro(self, line, match):
		'''^SystemSoft (MobilePRO) BIOS Version ([^\s]+)(?: (.+))?'''

		# Set prefix.
		self._version_prefix = match.group(1)

		# Set version number.
		self._version_number = match.group(2)

		# Add any additional information after the version to the string.
		additional_info = match.group(3)
		if additional_info:
			self._string_additional = additional_info

		# Update version and string.
		self._update_version_string()

		return True

	def _string_440bx(self, line, match):
		'''^(Intel )?(440BX(?:/ZX)?)'''

		# Extract branch as decisive, so it doesn't get overwritten by 430TX.
		self._string_branch_decisive = (match.group(1) or 'Intel ') + match.group(2)

		# Update string.
		self._update_version_string()

		return True

	def _string_for(self, line, match):
		'''SystemSoft BIOS [Ff]or ([^\(]+)'''
		
		# Extract branch.
		self._string_branch = match.group(1)

		# Update string.
		self._update_version_string()

		return True

	def _string_scu(self, line, match):
		'''SystemSoft SCU [Ff]or (.+) [Cc]hipset'''

		# Extract branch.
		self._string_branch = match.group(1)

		# Update string.
		self._update_version_string()

		return True

	def _signon_trigger(self, line, match):
		'''^Copyright (?:.+ SystemSoft Corp(?:oration|\.)?|SystemSoft Corp(?:oration|\.) .+\.)\s+All Rights Reserved'''

		# Read sign-on on the next line.
		self.signon = ''
		self._trap_signon = True

		return True

	def _signon(self, line, match):
		# Add line to sign-on if it's valid.
		if '. All Rights Reserved' not in line[-22:]:
			if line not in (' 9 9 9 9', 'ICICIC9CW') and line[:27] != 'OEM-CONFIGURABLE MESSAGE # ':
				# " 9 9 9 9" (Kapok 8x00C/P)
				# "ICICIC9CW" (Systemax sndbk105)
				# ". All Rights Reserved" (Dual/Smile mic6903/mic6907)
				if self.signon:
					self.signon += '\n'
				self.signon = line

			# Disarm trap if there's no additional sign-on line up next.
			if line != 'TriGem Computer, Inc.':
				self._trap_signon = False

		return True


class TandonAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Tandon', *args, **kwargs)

		self.register_check_list([
			(self._version,	RegexChecker),
		])

	def can_handle(self, file_data, header_data):
		return b'NOT COPR. IBM 1984 BIOS VERSION ' in file_data

	def _version(self, line, match):
		'''NOT COPR. IBM 1984 BIOS VERSION (.+)'''

		# Extract version.
		self.version = match.group(1)

		return True


class TinyBIOSAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('tinyBIOS', *args, **kwargs)

		self.register_check_list([
			(self._version,								RegexChecker),
			((self._noversion_precheck, self._signon),	AlwaysRunChecker),
		])

	def can_handle(self, file_data, header_data):
		return b'tinyBIOS V' in file_data and b' PC Engines' in file_data

	def _noversion_precheck(self, line):
		return not self.version

	def _version(self, line, match):
		'''^tinyBIOS (V(?:[^\s]+))'''

		# Extract version.
		self.version = match.group(1)

		return True

	def _signon(self, line, match):
		# Extract the last line before the version as a sign-on.
		self.signon = line

		return False


class ToshibaAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Toshiba', *args, **kwargs)
		self.vendor = 'Award'

		self._string_pattern = re.compile(b'''([\\x21-\\x7F]+\s*V[\\x21-\\x7F]{1,16}\s*)TOSHIBA ''')

	def can_handle(self, file_data, header_data):
		if not (b' TOSHIBA ' in file_data and b'Use Toshiba\'s BASIC.' in file_data) and b'Toshiba Corporation. & Award Software Inc.' not in file_data:
			return False

		# Identify as Toshiba-customized Award.
		self.version = 'Toshiba'

		# Extract string.
		match = self._string_pattern.search(file_data)
		if match:
			# Extract 16 characters from the end to avoid preceding characters. (T3100e)
			self.string = match.group(1)[-16:].decode('cp437', 'ignore').strip()

		return True

class WhizproAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Whizpro', *args, **kwargs)

	def can_handle(self, file_data, header_data):
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
		self.string = util.read_string(file_data[id_block_index + 0xe0:id_block_index + 0x100]).strip()

		# Extract sign-on.
		self.signon = util.read_string(file_data[id_block_index:id_block_index + 0x20]).strip()

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

		self.register_check_list([
			(self._version_date,	RegexChecker)
		])

	def can_handle(self, file_data, header_data):
		return b'(C)ZDS CORP' in file_data and b'+++ Wild Hardware Interrupt! +++' in file_data

	def _version_date(self, line, match):
		'''^([0-9]{2}/[0-9]{2}/[0-9]{2}) \(C\)ZDS CORP'''

		# Extract date as a version.
		self.version = match.group(1)