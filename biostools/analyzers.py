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

		self._check_pattern = re.compile(b'''Copyright \\(C\\) Acer Incorporated 1990|Acer Boot Block v1\\.0''')
		self._version_pattern = re.compile(
			b'''(?:ACER|\\x00{4})\\x00(V[0-9\\.]+)\\x00\\x00|''' # V2.x and V3.x - can be all NULs instead of ACER (AOpen DX2G Plus)
			b'''(V[0-9\\.]+)[\\x00 ][0-9]{2}/[0-9]{2}/[0-9]{2,4}\\x00|''' # V1.x and V2.x - observed: space + 2-digit year; NUL + 4-digit year
			b'''[\\x20-\\x7E]*ACER BIOS (V[\\x20-\\x7E]+)\\x00{2}''' # V1.0
		)
		# Project code may be 2 digits instead of 3 (AcerNote 350P)
		self._string_pattern = re.compile(b'''(?:([\\x20-\\x7E]{4,})\\x00)?([A-Z]{3}[0-9A-F]{2}[A-Z0-9]{2,3}-[A-Z0-9]{3}-[0-9]{6}-[\\x21-\\x7E]+)(?: +([\\x20-\\x7E]+))?''')
		# Multiple choices and dot before string (J3)
		# May have one (J3) or two (V10) NULs before string
		self._string_v1_pattern = re.compile(b'''((?:[\\x20-\\x7E]{4,}\\x00)+)([\\x20-\\x7E]{8})\\x00\\x00?\\.([\\x20-\\x7E]{5})\\x00''')

	def can_handle(self, file_path, file_data, header_data):
		if not self._check_pattern.search(file_data):
			return False

		# Extract version.
		match = self._version_pattern.search(file_data)
		if not match:
			return False
		version_string = match.group(1) or match.group(2) or match.group(3)
		self.debug_print('Raw version string:', version_string)
		self.version = util.read_string(version_string)

		# Extract V1.0 identification string as metadata.
		if match.group(3):
			id_string = match.group(0).rstrip(b'\x00')
			self.debug_print('Raw V1.0 ID string:', id_string)
			self.metadata.append(('ID', util.read_string(id_string)))

		match = self._string_pattern.search(file_data)
		if match:
			# Extract V2.0 identification string as metadata.
			id_string = match.group(1)
			if id_string:
				self.debug_print('Raw V2 ID string:', id_string)
				self.metadata.append(('ID', util.read_string(id_string)))

			# Extract string.
			string = match.group(2)
			self.debug_print('Raw V2 string:', string)
			self.string = util.read_string(string)

			# Extract sign-on.
			signon = match.group(3)
			if signon:
				self.debug_print('Raw V2 sign-on:', signon)
				self.signon = util.read_string(signon).strip()
		else:
			match = self._string_v1_pattern.search(file_data)
			if match:
				# Extract string.
				string = match.group(3)
				self.debug_print('Raw V1 string:', string)
				self.string = util.read_string(string)

				# Extract revision as a sign-on.
				signon = match.group(2)
				self.debug_print('Raw V1 revision:', signon)
				self.signon = util.read_string(signon)

				# Extract identification string as metadata.
				id_string = match.group(1)
				self.debug_print('Raw V1 ID strings:', id_string)
				id_string = id_string.replace(b' \x00', b'\n').replace(b'\x00', b'\n')
				self.metadata.append(('ID', util.read_string(id_string)))

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
		# Pre-Color entrypoint date can inexplicably have most significant bit set (two characters on arche_486_1989-1991), part 1
		self._date_pattern = re.compile(b'''([0-9\\xB0-\\xB9]{2}/[0-9\\xB0-\\xB9]{2}/[0-9\\xB0-\\xB9]{2})[^0-9]''')
		self._uefi_csm_pattern = re.compile('''63-0100-000001-00101111-[0-9]{6}-Chipset-0AAAA000$''')
		# The "All Rights Reserved" is important to not catch the same header on other files.
		# "All<Rights Reserved" (Tatung TCS-9850 9600x9, corrupted during production?)
		# AMIBIOS 6+ version corner cases:
		# - Second digit not 0 (I forget which one had 000000)
		# - Can be 4-digit instead of 6-digit (Biostar)
		# - Copyright string overwritten with "0$RAIDUAC0" structure (Iwill DJ800)
		# - "1.0\x00F\x00\x00\x00" (ECS RC410-M2)
		self._id_block_pattern = re.compile(
			b'''(?:AMIBIOS (?:(0[1-9][0-9]{2}[\\x00-\\xFF]{2})[\\x00-\\xFF]{2}|W ([0-9]{2}) ([0-9]{2})[\\x00-\\xFF]|[0-9]\\.[0-9]\\x00[A-Z]\\x00{3})|0123AAAAMMMMIIII|\\(AAMMIIBBIIOOSS\\))'''
			b'''(?:([\\x00-\\xFF]{2}/[0-9]{2}/[0-9]{2})\\(C\\)[0-9]{4} American Megatrends,? Inc(?:\\.,?.All.Rights.Reserved|/Hewlett-Packard Company)|[0-9]\\$RAIDUAC[0-9])'''
		)
		self._regtable_pattern = re.compile(b'''\\$\\$CT[\\x01\\x02]([\\x20-\\x7E]+)''')
		# Dash separator possible (TritonIDETimings on AMI Apollo and potentially others)
		self._regtable_split_pattern = re.compile('''[- ]''')
		# "Cfg" and "Config" (Acrosser AR-B1479 STPC Elite)
		self._regtable_trim_pattern = re.compile('''[- ]+(?:Table|B(?:oot[- ]?)?Block|BtBlk|POST(?: Init)?|Cfg|Config|Port)''', re.I)
		# TriGem weirdness: "TGem-HCS,PSC,JGS" (UMC 486-BIOS) and "TriGem Computer " (SiS 486-BIOS)
		self._precolor_block_pattern = re.compile(b'''\\(C\\)(?:[0-9]{4}(?:AMI,404-263-8181|TGem-HCS,PSC,JGS|TriGem Computer )|( Access Methods Inc\\.))''')
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
		# Text before "BIOS" cannot capture . due to AMI copyright prior to ID string.
		self._precolor_signon_pattern = re.compile(b'''([0-9A-Za-z- ]*BIOS \\(C\\).*(?:AMI|American Megatrends Inc\\.?))(?:, for ([\\x0D\\x0A\\x20-\\x7E]+))?''')
		self._precolor_setup_pattern = re.compile(b'''[A-Za-z][0-9/]+([\\x20-\\x27\\x29-\\x7E]*(SETUP PROGRAM FOR | SETUP UTILITY)[\\x20-\\x27\\x29-\\x7E]*)\\(C\\)19''')
		self._precolor_pcchips_pattern = re.compile(b'''ADVANCED SYSTEM SETUP UTILITY VERSION[\\x20-\\x7E]+?PC CHIPS INC''')
		# Decoded: "\(C\)AMI, \(([^\)]{11,64})\)" (the 64 is arbitrary)
		self._8088_string_pattern = re.compile(b'''\\xEC\\x5F\\x6C\\x60\\x5A\\x5C\\xEA\\xF0\\xEC([\\x00-\\x6B\\x6D-\\xFF]{11,64})\\x6C''')

		# I believe "UTILITIES" instead of "UTILITY" was only observed on New Setup, but check on all of them for safety.
		self._setup_patterns = {
			'Color': re.compile(b'''Improper Use of Setup may Cause Problems !!'''),
			'Easy': re.compile(b'''AMIBIOS EASY SETUP UTILIT'''),
			'HiFlex': re.compile(b'''\\\\HAMIBIOS HIFLEX SETUP UTILIT'''),
			'Intel': re.compile(b'''Advanced Chipset Configuration  \\\\QPress'''),
			'New': re.compile(b'''AMIBIOS NEW SETUP UTILIT'''),
			'Simple': re.compile(b'''\\\\HAMIBIOS SIMPLE SETUP UTILIT'''),
			'WinBIOS': re.compile(b''' Wait----''')
		}

	def can_handle(self, file_path, file_data, header_data):
		check_match = self._check_pattern.search(file_data)
		if not check_match:
			return False

		# Extract Intel data in a preliminary manner in case extraction failed.
		is_intel = AMIIntelAnalyzer.can_handle(self, file_path, file_data, header_data)
		if is_intel:
			self.debug_print('Intel data found')

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
			signon_terminator = b'''\\x00'''
			if file_data[id_block_index + 0x123:id_block_index + 0x12b] == b' Inc.,\x00 ':
				self.debug_print('Applying sign-on terminator hack')
				signon_terminator += b'''\\x00'''

			# Extract sign-on.
			signon = util.read_string(file_data[id_block_index + 0x100:id_block_index + 0x200], terminator=signon_terminator)
			self.debug_print('Raw sign-on:', repr(signon))
			if self.signon: # Intel may already have a sign-on here
				self.signon += '\n'
			self.signon += signon

			# Separate full copyright string from the sign-on and add it as metadata.
			# Copyright line may be terminated by a carriage return only (MSI MS-7522: line is blank)
			# Copyright might not be on the first line (Dell PowerVault 725N)
			stripped = [x.strip() for x in self.signon.replace('\r', '\n').split('\n')]
			if len(stripped) > 0:
				copyright = None
				for x in range(len(stripped)): # search through lines first...
					if 'American Megatrends' in stripped[x]:
						copyright = stripped[x]
						break
				if not copyright: # ...and assume first line if nothing is found
					copyright = stripped[0]
				if copyright:
					self.metadata.append(('ID', copyright))
					stripped.remove(copyright)
			self.signon = '\n'.join(x for x in stripped if x)

			# Add setup type(s) as metadata.
			# There can be multiple setup modules (PC Chips M559 with switchable Simple/WinBIOS)
			setup_types = []
			for setup_type in self._setup_patterns:
				if self._setup_patterns[setup_type].search(file_data):
					setup_types.append(setup_type)
			if len(setup_types) > 0:
				self.metadata.append(('Setup', ', '.join(setup_types)))

			# Add AMIBIOS 6+ register table names as metadata.
			regtables = {}
			for match in self._regtable_pattern.finditer(file_data):
				# Trim name to skip redundant words.
				regtable_name = util.read_string(match.group(1))
				regtable_name = self._regtable_trim_pattern.sub('', regtable_name).strip()

				# Split name for common prefix search, while applying cosmetic fixes.
				regtable_name = re.sub('''(^| )([A-Za-z]+)(Time)($| )''', '\\1\\2 \\3\\4', regtable_name) # (ITOX STAR)
				regtable_name = re.sub('''(^| )W(?:in|IN)([0-9]{3})''', '\\1Winbond \\2', regtable_name) # (MSI MS-5146)
				split = [x for x in self._regtable_split_pattern.split(regtable_name) if x]
				if len(split) == 2 and split[1] == 'Timing' and 'mhz' in split[0].lower(): # (Biostar MB-8500TUC)
					split.reverse()
				elif len(split) >= 4 and split[0] == 'System' and split[2] == 'to': # SMC FDC37C669 (PC Partner MB600N), NSC PC87306 (Supermicro P55T2S)
					split = split[3:] + split[0:2]
				regtables[regtable_name.lower()] = split

			# Sort table names by common prefixes.
			regtables = [regtables[regtable] for regtable in regtables]
			if len(regtables) > 0:
				self.debug_print('Clean register tables:', regtables)

				# Add grouped register tables to metadata.
				regtable_groups = util.common_prefixes(regtables)
				regtable_group_strings = []
				for regtable_group in sorted(regtable_groups):
					joined = ', '.join(' '.join(x) for x in regtable_groups[regtable_group] if x)
					if len(joined) > 0:
						joined = ': ' + joined
					regtable_group_strings.append(regtable_group + joined)
				self.metadata.append(('Table', '\n'.join(regtable_group_strings)))
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
				# Pre-Color entrypoint date can inexplicably have most significant bit set (two characters on arche_486_1989-1991), part 2
				self.version = bytes((c & 0x7f) for c in (match.group(1) or (match.group(2) + b'/' + match.group(3) + b'/' + match.group(4)))).decode('cp437', 'ignore')
				self.debug_print('Version (pre-Color):', self.version)

				# Check pre-Color identification block.
				invalid_id = False
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

				# Extract full version string as metadata, and also extract
				# additional information after the copyright as a sign-on
				# (Shuttle 386SX, CDTEK 286, Flying Triumph Access Methods)
				match = self._precolor_signon_pattern.search(file_data)
				if match:
					version_string = util.read_string(match.group(1), terminator=b'''[\\x00\\x0D\\x0A\\x80-\\xFF]''') # MSB termination on early 8088-BIOS
					self.debug_print('Raw version string:', repr(version_string))
					self.metadata.append(('ID', version_string))

					self.signon = util.read_string(match.group(2) or b'')
					self.debug_print('Raw sign-on:', repr(self.signon))

					# Split sign-on lines. (Video Technology Info-Tech 286-BIOS)
					stripped = (x for x in self.signon.split('\n'))
					self.signon = '\n'.join(x for x in stripped if x).strip('\n')

				# Add setup type as metadata.
				match = self._precolor_setup_pattern.search(file_data)
				if match:
					self.metadata.append(('Setup', util.read_string(match.group(1).replace(match.group(2), b''))))
				elif self._precolor_pcchips_pattern.search(file_data):
					self.metadata.append(('Setup', 'PC Chips'))
			else:
				# Assume this is not an AMI BIOS, unless we found Intel data above.
				if is_intel:
					self.debug_print('No AMI data found but Intel data found')
				return is_intel

		return True


class AMIIntelAnalyzer(Analyzer):
	_ami_pattern = re.compile(b'''AMIBIOS''')
	_ami_version_pattern = re.compile(b'''AMIBIOSC(0[1-9][0-9]{2})''')
	_phoenix_pattern = re.compile(b'''PhoenixBIOS(?:\\(TM\\))? ''')
	_version_pattern = re.compile(b'''(?:BIOS (?:Release|Version) )?([0-9]\\.[0-9]{2}\\.[0-9]{2}\\.[A-Z][0-9A-Z]{1,})|(?:\\$IBIOSI\\$)?([0-9A-Z]{8}\\.([0-9A-Z]{3})\\.[0-9A-Z]{3,4}(?:\\.[0-9A-Z]{1,4}\\.[0-9]{10}|(?:\\.[0-9]{4}){3}))''')
	_86_pattern = re.compile('''[0-9A-Z]{8}\\.86[0-9A-Z]\\.[0-9A-Z]{3,4}\\.[0-9A-Z]{1,4}\\.[0-9]{10}$''')

	def __init__(self, *args, **kwargs):
		super().__init__('Intel', *args, **kwargs)

	def can_handle(self, file_path, file_data, header_data):
		# Handle header on Intel AMI (and sometimes Phoenix) BIOSes that could not be decompressed.
		ret = header_data and header_data[90:95] == b'FLASH' and header_data[112:126] != b'User Data Area'
		if ret:
			# Start by assuming this is an unknown BIOS.
			if self.vendor_id == 'Intel':
				self.vendor = 'Intel'
				self.version = '?'

			# Apply the version string as a sign-on.
			self.signon = util.read_string(header_data[112:])
		elif self.vendor_id != 'Intel': # run this part only when delegated
			# No header found, attempt to manually extract version string from data.
			for match in AMIIntelAnalyzer._version_pattern.finditer(file_data):
				self.debug_print('Raw Intel version:', match.group(0))

				# If this is Intel's second AMI run, check if this is not a generic
				# (86x) version string overwriting an OEM-customized version string.
				oem = util.read_string(match.group(3) or b'')
				intel_version = util.read_string(match.group(1) or match.group(2))
				if (not oem or oem[:2] != '86' or not AMIIntelAnalyzer._86_pattern.match(self.signon)) and intel_version not in self.signon:
					# Extract the version string as a sign-on.
					self.signon = intel_version
					ret = True

		if ret:
			# Extract AMI version from compressed data. (0632 fork which bios_extract can't handle)
			match = AMIIntelAnalyzer._ami_pattern.search(file_data)
			if match:
				match = AMIIntelAnalyzer._ami_version_pattern.search(file_data[match.start(0):])
				if match:
					if self.vendor_id == 'Intel':
						self.vendor = 'AMI'
					elif self.vendor != 'AMI':
						return False
					self.version = match.group(1).decode('cp437', 'ignore') + '00'
			elif AMIIntelAnalyzer._phoenix_pattern.search(file_data):
				if self.vendor_id == 'Intel':
					self.vendor = 'Phoenix'
				elif self.vendor_id != 'Phoenix':
					return False

		return ret


class AMIUEFIAnalyzer(AMIAnalyzer):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.vendor_id = 'AMIUEFI'

		# "AMITSESetup" (Pegatron H63ST)
		self._identifier_pattern = re.compile(b'''\\$SGN\\$|ALASKAA M I|[Xx]-UEFI-AMI|AMITSESetup''')
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

		# Interleaved "Award Software Inc." (AST)
		# "COPYRIGHT AWARD SOFTWARE INC." (early XT/286)
		self._award_pattern = re.compile(b'''(?:Award|A w a r d) Software Inc\\.|AAwwaarrdd SSooffttwwaarree IInncc\\.\\.|COPYRIGHT AWARD SOFTWARE INC\\.|Award Decompression Bios''')
		self._ast_pattern = re.compile(b'''\\(c\\) COPYRIGHT 1984,[0-9]{4}(?:A w a r d|Award) Software Inc\\.|IBM COMPATIBLE A(S)T BIOS''')
		self._early_pattern = re.compile(b'''([0-9A-Z][\\x21-\\x7E]+) BIOS V([0-9.]+)[\\x21-\\x7E]* COPYRIGHT''')
		self._gigabyte_bif_pattern = re.compile(b'''\\$BIF[\\x00-\\xFF]{5}([\\x20-\\x7E]+)\\x00.([\\x20-\\x7E]+)\\x00''')
		self._gigabyte_eval_pattern = re.compile('''\\([a-zA-Z0-9]{1,8}\\) EVALUATION ROM - NOT FOR SALE$''')
		self._gigabyte_flag_pattern = re.compile(b'''GIGABYTEFLAG\\x00''')
		self._gigabyte_hefi_pattern = re.compile(b'''EFI CD/DVD Boot Option''')
		self._id_block_pattern = re.compile(
			b'''(?:''' + util.rotate_pattern(b'Award Software Inc. ', 6) + b'''|''' + util.rotate_pattern(b'Phoenix Technologies, Ltd ', 6) + b''')[\\x00-\\xFF]{8}IBM COMPATIBLE|''' # whatever has "Phoenix" instead of "Award" was lost to time
			b'''[0-9]{2}/[0-9]{2}/[0-9]{4} {4}IBM COMPATIBLE (?:[0-9]+ )?BIOS COPYRIGHT Award Software Inc\\.|''' # whatever has this was lost to time
			b'''IBM COMPATIBLE (?:[0-9]+ )?BIOS COPYRIGHT Award Software Inc\\.''' # (Samsung Samtron 88S)
		)
		self._ignore_pattern = re.compile(b'search=f000,0,ffff,S,"|VGA BIOS Version (?:[^\r]+)\r\n(?:Copyright \\(c\\) (?:[^\r]+)\r\n)?Copyright \\(c\\) (?:NCR \\& )?Award', re.M)
		self._medallion_pattern = re.compile(b'''Award [\\x20-\\x7E]+\\x00Copyright \\(C\\) 1984-[0-9]{2,4}, Award Software, Inc\\.\\x00''') # older ones are preceded by HP(?!) copyright, but newer ones can be preceded by garbage, or not be the first string
		self._romby_date_pattern = re.compile(b'''N((?:[0-9]{2})/(?:[0-9]{2})/)([0-9]{2})([0-9]{2})(\\1\\3)''')
		self._string_date_pattern = re.compile('''(?:[0-9]{2})/(?:[0-9]{2})/([0-9]{2,4})-''')
		# "V" instead of "v" (286 Modular BIOS V3.03 NFS 11/10/87)
		self._version_pattern = re.compile(''' (?:v([^-\\s]+)|V(?:ersion )?[^0-9]*([0-9]\\.[0-9][0-9A-Z]?))(?:[. ]([\\x20-\\x7E]+))?''')
		self._phoenixnet_patterns = (
			re.compile(b'''CPLRESELLERID'''),
			re.compile(b'''BINCPUTBL'''),
			re.compile(b'''BINIDETBL'''),
		)
		self._phoenixnet_signon_pattern = re.compile('''MB(?:LOGO|TEXT)[0-9]?\\.TPL$''')

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

			# Extract full version string as metadata.
			version_match = self._medallion_pattern.search(file_data)
			if version_match:
				# Handle Medallion version string.
				self.debug_print('Raw Medallion string table entries:', version_match.group(0))
				version_string = util.read_string(version_match.group(0))
			else:
				version_string = util.read_string(file_data[id_block_index + 0x61:id_block_index + 0xc1])
				linebreak_index = version_string.find('\r')
				if linebreak_index > -1: # trim to linebreak (Samsung Samtron 88S)
					version_string = version_string[:linebreak_index]
			self.metadata.append(('ID', version_string))
			self.debug_print('Raw version string:', repr(version_string))

			# Extract version.
			self.signon = ''
			is_gigabyte = False
			version_match = self._version_pattern.search(version_string)
			if version_match:
				self.version = 'v' + (version_match.group(1) or version_match.group(2))
				is_gigabyte = self.version == 'v6.00PG'
			elif version_string == 'Award Modular BIOS Version ': # Award version removed (Intel YM430TX)
				self.version = 'Intel'
			elif version_string[:19] == 'Award Modular BIOS/': # Award version removed (Packard Bell PB810)
				self.version = 'Packard Bell'
				self.signon = version_string[19:] + '\n'
			elif self._gigabyte_flag_pattern.search(file_data): # Award version removed (Itautec ST 4271)
				self.version = '?'
				is_gigabyte = True

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

				# Check if this version is not too old to have a string.
				# (ASUS v4.00, Gateway/Swan Anigma Award v4.28/4.32)
				if ' Award Software Inc. ' in self.string:
					# Use the BIOS ID further down.
					self.string = util.read_string(file_data[id_block_index + 0xce0:id_block_index + 0xcf0])
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
					self.metadata.append(('UEFI', 'Gigabyte Hybrid EFI'))

				# Detect PhoenixNet.
				if util.all_match(self._phoenixnet_patterns, file_data):
					# Extract PhoenixNet sign-on from ROS filesystem.
					phoenixnet_signon = ''
					if os.path.isdir(file_path):
						# Look for ROS filesystem directory in the extracted payload.
						for file_in_dir in os.listdir(file_path):
							file_in_dir_path = os.path.join(file_path, file_in_dir)
							if os.path.isdir(file_in_dir_path):
								# Look for sign-on file in the ROS filesystem.
								for file_in_ros in os.listdir(file_in_dir_path):
									if self._phoenixnet_signon_pattern.match(file_in_ros):
										# Check if the sign-on file is valid.
										file_in_ros_path = os.path.join(file_in_dir_path, file_in_ros)
										if os.path.isfile(file_in_ros_path) and os.path.getsize(file_in_ros_path) >= 0xa:
											# Read the sign-on file.
											self.debug_print('Reading PhoenixNet sign-on from ROS', repr(file_in_dir), 'file', repr(file_in_ros))
											try:
												f = open(file_in_ros_path, 'rb')
												f.seek(9)
												this_phoenixnet_signon = util.read_string(f.read(4096))
												f.close()
												if this_phoenixnet_signon:
													phoenixnet_signon = this_phoenixnet_signon.strip()
													self.debug_print('Raw PhoenixNet sign-on:', repr(this_phoenixnet_signon))
													break
											except:
												pass

								# Stop if a sign-on file was found.
								if phoenixnet_signon:
									break

					# TODO: PhoenixNet-specific sign-ons
					self.metadata.append(('PhoenixNet', phoenixnet_signon))

			if is_gigabyte and self._gigabyte_eval_pattern.match(self.signon):
				# Reconstruct actual sign-on of a Gigabyte fork BIOS through
				# the data in the $BIF area (presumably BIOS update data).
				match = self._gigabyte_bif_pattern.search(file_data)
				if match:
					self.debug_print('Sign-on reconstructed from Gigabyte data')
					self.signon = (match.group(1) + b' ' + match.group(2)).decode('cp437', 'ignore') # actual sign-on may be a longer one located in a hard spot (Itautec ST 4271)

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
					elif 'IBM IS A TRADEMARK OF INTERNATIONAL BUSINESS MACHINES CORP.' in line:
						break
					self.signon += line + '\n'
			else:
				# Handle early XT/286 BIOS.
				match = self._early_pattern.search(file_data)
				if match:
					id_block_index = match.start(0)
					self.debug_print('Early ID block found at', hex(id_block_index))

					# Extract version.
					self.version = 'v' + match.group(2).decode('cp437', 'ignore')

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

		self._check_pattern = re.compile(b'''PowerBIOS Setup''')
		self._id_block_pattern = re.compile(b'''IBM COMPATIBLE BIOS COPYRIGHT AWARD SOFTWARE INC\\.''')
		self._strings_pattern = re.compile(b'''[\\x01-\\xFF]+\\x00''')
		self._version_pattern = re.compile('''Version ([\\x21-\\x7E]+)''')
		self._siemens_string_pattern = re.compile(b'''- [\\x20-\\x7E]+\\x0D\\x0A\\x00''')

	def can_handle(self, file_path, file_data, header_data):
		if not self._check_pattern.search(file_data):
			return False

		# Determine location of the identification block.
		match = self._id_block_pattern.search(file_data)
		if not match:
			return False
		id_block_index = match.start(0)
		self.debug_print('ID block starts at', hex(id_block_index))

		# Extract string list.
		strings = []
		for match in self._strings_pattern.finditer(file_data[id_block_index + 0x82:id_block_index + 0x102]):
			entry = match.group(0)
			self.debug_print('String list entry:', entry)
			if len(entry) <= 2: # skip empty strings (Siemens FM456-2 after serial)
				continue
			strings.append(util.read_string(entry))

		# Parse string list.
		self.version = 'PowerBIOS'
		if len(strings) > 0:
			# Extract ID string.
			if len(strings) > 1:
				self.string = strings.pop()

				# Extraneous "m" on some strings (Siemens FM356/456-4)
				if self.string[0:1] == 'm':
					self.string = self.string[1:]

				# Modified string display routine (Siemens FM456-2)
				if self.string.strip() == 'Serial No.':
					# This modified string begins with the entry point date.
					match = NoInfoAnalyzer._entrypoint_date_pattern.search(file_data)
					if match:
						self.string = util.read_string(match.group(1))

					# It continues on at a different point in the image.
					match = self._siemens_string_pattern.search(file_data)
					if match:
						self.string += ' ' + util.read_string(match.group(0)).strip()

			# Extract full version string as metadata.
			# Copyright line not always present (Siemens FM456-2)
			stripped = (x.strip() for x in strings)
			version_string = '\n'.join(x for x in stripped if x)
			self.debug_print('Raw version string:', repr(version_string))
			self.metadata.append(('ID', version_string))

			# Extract version.
			match = self._version_pattern.search(version_string)
			if match:
				self.version += ' ' + match.group(1)

		# Extract sign-on.
		self.signon = util.read_string(file_data[id_block_index - 0xe00e:id_block_index - 0xdf0e])
		self.debug_print('Raw sign-on:', repr(self.signon))

		return True


class BonusAnalyzer(Analyzer):
	"""Special analyzer for ACPI tables and option ROMs."""

	def __init__(self, *args, **kwargs):
		super().__init__('', *args, **kwargs)
		self._pci_ids = {}

		self._acpi_table_pattern = re.compile(b'''(DSDT|FACP|PSDT|RSDT|SBST|SSDT)([\\x00-\\xFF]{4})(?:[\\x00-\\xFF]{20}|[\\x00-\\xFF]{24})[\\x00\\x20-\\x7E]{4}''')
		self._adaptec_pattern = re.compile(b'''Adaptec (?:BIOS:([\\x20-\\x7E]+)|([\\x20-\\x7E]+?)(?: SCSI)? BIOS )''')
		self._dmi_bios_pattern = re.compile(b'''\\x00([\\x12-\\xFF])''')
		self._dmi_system_pattern = re.compile(b'''\\x01([\\x08\\x19\\x1B])''')
		self._dmi_baseboard_pattern = re.compile(b'''\\x02([\\x08-\\xFF])''')
		self._dmi_processor_pattern = re.compile(b'''\\x04([\\x1A-\\x30])''') # non-standard length 0x20 (ASUS CUV4X-LS, Supermicro S2DGE)
		self._dmi_strings_pattern = re.compile(b'''(?:[\\x20-\\x7E]{1,255}\\x00){1,255}\\x00''')
		self._dmi_date_pattern = re.compile('''[0-9]{2}/[0-9]{2}/[0-9]{2}(?:[0-9]{2})?$''')
		self._ncr_pattern = re.compile(b''' SDMS \\(TM\\) V([0-9\\.]+)''')
		self._orom_pattern = re.compile(b'''\\x55\\xAA([\\x01-\\xFF])([\\x00-\\xFF])[\\x00-\\xFF]{20}([\\x00-\\xFF]{4})([\\x00-\\xFF]{2}IBM)?''')
		self._orom_string_pattern = re.compile(b'''[\\x0D\\x0A\\x20-\\x7E]{9,}''')
		self._pxe_patterns = (
			re.compile(b'''PXE-M0F: Exiting '''),
			re.compile(b'''PXE-EC6: UNDI driver image is invalid\\.'''),
		)
		self._rpl_pattern = re.compile(b'''NetWare Ready ROM''')
		self._sli_pattern = re.compile(b'''[0-9]{12}Genuine NVIDIA Certified SLI Ready Motherboard for ([\\x20-\\x7E]*)[\\x20-\\x7E]{4}-Copyright [0-9]{4} NVIDIA''')
		self._vga_string_pattern = re.compile(
			b'''[\\x0D\\x0A\\x20-\\x7E]{16,}''' # standard string
			b'''(?:\\x00[\\x0D\\x0A\\x20-\\x7E]{16,})?''' # PhoenixView
		)
		self._vga_trim_pattern = re.compile(
			'''(?:IBM (?:(?:VGA )?Compat[ia]ble(?: BIOS)?|''' # typical
			'''IS A TRADEMARK OF INTERNATIONAL BUSINESS MACHINES CORP(?:([\\x20-\\x7E]+?) Phone-\\([\\x21-\\x7E]+)?)|''' # AMI monologue
			'''\\*\\* +RESERVED FOR IBM COMPATIBILITY +\\*\\*|''' # Trident
			'''This is not a product of IBM|''' # Tseng
			'''NOT AN IBM BIOS\\!)''' # Radius
			'''[\\x20-\\x2F\\x3A-\\x40\\x5B-\\x60\\x7A-\\x7E]*''', # trim non-alphanumeric characters
			re.I)

		# Read BIOSSIG database.
		self._biossig_patterns = []
		if os.path.exists('BIOSSIG.DBA'):
			with open('BIOSSIG.DBA', 'rb') as f:
				column_pattern = re.compile(b'''"([^"]+)"(?:,|$)''')
				hex_pattern = re.compile(b'''(?:[0-9A-F]{2}){1,}$''')

				# Go through pattern declaration entries.
				for match in re.finditer(b'''known_bios\\(((?:"[^"]+",)+"[^"]+")\\)''', f.read()):
					columns = column_pattern.findall(match.group(1))

					# Decode patterns.
					byte_patterns = []
					for x in range(5, len(columns) - 3, 2): # last entry appears to be a CRC
						addr, pattern = columns[x:x + 2]
						addr = int(addr, 16) - 0x100000 # store offset from top of image
						if hex_pattern.match(pattern):
							pattern = codecs.decode(pattern, 'hex')
						else:
							# Nasty hack to get rid of UTF-8, as the file wasn't preserved properly.
							pattern = pattern.replace(b'\xc3\xba', b'\x00')
						byte_patterns.append((addr, pattern))

					pattern_key = b'\n'.join(columns[:2]).decode('cp437', 'ignore')
					self._biossig_patterns.append((pattern_key, byte_patterns))

	def _enumerate_metadata(self, key, entries, delimiter=' '):
		if len(entries) > 0:
			# De-duplicate and sort before enumerating.
			entries = list(set(entries))
			entries.sort()
			self.metadata.append((key, delimiter.join(entries)))

	def can_handle(self, file_path, file_data, header_data):
		# BIOSSIG patterns
		for pattern_key, pattern_list in self._biossig_patterns:
			# Go through patterns.
			found = True
			for pattern_addr, pattern_bytes in pattern_list:
				if file_data[pattern_addr:pattern_addr + len(pattern_bytes)] != pattern_bytes:
					# Not what we're looking for.
					found = False
					break
			if not found:
				continue

			# Successful match, report as metadata.
			self.metadata.append(('BIOSSIG', pattern_key))
			break

		# ACPI tables
		acpi_tables = []
		for match in self._acpi_table_pattern.finditer(file_data):
			if struct.unpack('<I', match.group(2))[0] > 36: # length includes header, header is 36 bytes
				acpi_tables.append(util.read_string(match.group(1)))
		self._enumerate_metadata('ACPI', acpi_tables)

		# DMI
		def _read_dmi_strings(header_match, string_value_offsets):
			header_offset = header_match.start(0)

			# Check if the structure header's handle value is valid.
			handle = file_data[header_offset + 2:header_offset + 4]
			if len(handle) != 2 or handle == b'\xFF\xFF\xFF\xFF':
				return None

			# Check if the structure doesn't go beyond the end of the file.
			table_length = header_match.group(1)[0]
			if (header_offset + table_length) > len(file_data):
				return None

			# Extract string index values from the structure.
			string_values = []
			found_any = False
			for rel_string_value_offset in string_value_offsets:
				# Extract index value.
				string_value_offset = header_offset + rel_string_value_offset
				string_value = file_data[string_value_offset:string_value_offset + 1]
				if len(string_value) != 1: # stop if we're past the end of the file
					return None
				string_values.append(string_value[0] - 1)

				# Mark that we found any string being referenced.
				if string_value[0] > 0:
					found_any = True

			# Stop if the structure references no string.
			if not found_any:
				return None

			# Extract string table from the end of the structure.
			header_len = header_match.group(0)[1]
			string_table_offset = header_offset + header_len
			strings_match = self._dmi_strings_pattern.match(file_data[string_table_offset:string_table_offset + 4096])
			if strings_match:
				string_table = strings_match.group(0).split(b'\x00')[:-2]

				# Extract strings from the referenced index values.
				found_any = False
				strings = []
				for string_value in string_values:
					# Stop if this index is out of bounds.
					if string_value >= len(string_table):
						return None

					# Add string to list.
					if string_value < 0: # empty if not set
						strings.append('')
					else:
						string_contents = string_table[string_value].decode('cp437', 'ignore').strip()
						strings.append(string_contents)
						if string_contents:
							found_any = True

				# Return strings only if non-empty ones were ever found.
				if found_any:
					return strings

		# Go through DMI table candidates.
		dmi_tables = []

		for match in self._dmi_bios_pattern.finditer(file_data): # SMBIOS Type 0: BIOS
			# Read strings for this candidate.
			candidate = _read_dmi_strings(match, (0x04, 0x05, 0x08))
			if not candidate:
				continue
			self.debug_print('DMI BIOS table header', codecs.encode(file_data[match.start(0):match.start(0) + 5], 'hex'))

			bios_vendor, bios_version, bios_date = candidate

			# Check date for validity.
			if not self._dmi_date_pattern.match(bios_date):
				continue

			dmi_tables.append('[BIOS] {0} {1} {2}'.format(bios_vendor, bios_version, bios_date))
			break

		for match in self._dmi_system_pattern.finditer(file_data): # SMBIOS Type 1: System
			# Read strings for this candidate.
			candidate = _read_dmi_strings(match, (0x04, 0x05, 0x06))
			if not candidate:
				continue
			self.debug_print('DMI System table header', codecs.encode(file_data[match.start(0):match.start(0) + 5], 'hex'))

			# Check wake-up type for validity if present.
			header_offset = match.start(0)
			if match.group(1)[0] > 0x18 and file_data[header_offset + 0x18] > 0x08:
				continue

			system_mfg, system_product, system_version = candidate
			dmi_tables.append('[System] {0} {1} {2}'.format(system_mfg, system_product, system_version))
			break

		for match in self._dmi_baseboard_pattern.finditer(file_data): # SMBIOS Type 2: Baseboard
			# Read strings for this candidate.
			candidate = _read_dmi_strings(match, (0x04, 0x05, 0x06))
			if not candidate:
				continue
			self.debug_print('DMI Baseboard table header', codecs.encode(file_data[match.start(0):match.start(0) + 5], 'hex'))

			# Check board type for validity if present.
			header_offset = match.start(0)
			if match.group(1)[0] > 0x0d and (file_data[header_offset + 0x0d] < 0x01 or file_data[header_offset + 0x0d] > 0x0d):
				continue

			board_mfg, board_product, board_version = candidate

			# Check for duplicate system and baseboard information.
			formatted = '{0} {1} {2}'.format(board_mfg, board_product, board_version)
			if len(dmi_tables) > 0 and dmi_tables[-1][:9] == '[System] ' and util.compare_alnum(dmi_tables[-1][9:], formatted):
				dmi_tables[-1] = '[Board/System] ' + formatted
			else:
				dmi_tables.append('[Board] ' + formatted)
			break

		for match in self._dmi_processor_pattern.finditer(file_data): # SMBIOS Type 4: Processor
			# Read strings for this candidate.
			candidate = _read_dmi_strings(match, (0x04, 0x07, 0x10))
			if not candidate:
				continue
			self.debug_print('DMI Processor table header', codecs.encode(file_data[match.start(0):match.start(0) + 5], 'hex'))

			# Check type for validity.
			# Type and family may be invalid 0x00 (Supermicro S2DGE)
			header_offset = match.start(0)
			if file_data[header_offset + 0x05] > 0x06:
				continue

			cpu_socket, cpu_mfg, cpu_version = candidate
			dmi_tables.append('[CPU] {0} {1} {2}'.format(cpu_socket, cpu_mfg, cpu_version))
			break

		self._enumerate_metadata('DMI', dmi_tables, delimiter='\n')

		# SLI certificate in DSDT SLIC
		match = self._sli_pattern.search(file_data)
		if match:
			self.metadata.append(('SLI', util.read_string(match.group(1))))

		# UEFI
		if header_data == b'\x00\xFFUEFIExtract\xFF\x00':
			self.metadata.append(('UEFI', 'Filesystem'))

		# Look for option ROMs.
		for match in self._orom_pattern.finditer(file_data):
			# Extract ROM data based on its size.
			rom_offset = match.start()
			rom_size = match.group(1)[0] * 512
			rom_data = file_data[rom_offset:rom_offset + rom_size]

			# Check for Adaptec and NCR SCSI.
			scsi_roms = []
			submatch = self._adaptec_pattern.search(rom_data)
			if submatch:
				model = submatch.group(1) or submatch.group(2)
				if model:
					model = ' ' + util.read_string(model)
				else:
					model = ''
				self.metadata.append(('SCSI', 'Adaptec' + model))
			submatch = self._ncr_pattern.search(rom_data)
			if submatch:
				self.metadata.append(('SCSI', 'NCR ' + util.read_string(submatch.group(1))))

			# Check for PXE and RPL boot.
			lan_roms = []
			if util.all_match(self._pxe_patterns, rom_data):
				lan_roms.append('PXE')
			if self._rpl_pattern.search(rom_data):
				lan_roms.append('RPL')
			self._enumerate_metadata('LAN', lan_roms)

			# Check for the VGA BIOS compatibility marker string and add it as metadata.
			orom_marker = match.group(4)
			orom_is_vga = False
			if orom_marker:
				orom_is_vga = True

				# Find ASCII strings around the marker. There must be a space before/after
				# the marker to avoid parsing of non-text bytes as ASCII characters.
				vga_start = match.start(4) + 2 - rom_offset
				if rom_data[vga_start - 1:vga_start] == b' ':
					while vga_start > 0 and rom_data[vga_start - 1] >= 0x20 and rom_data[vga_start - 1] <= 0x7e:
						vga_start -= 1
				vga_end = match.end(4) - rom_offset
				if rom_data[vga_end:vga_end + 1] == b' ':
					while vga_end < len(rom_data) and rom_data[vga_end] >= 0x20 and rom_data[vga_end] <= 0x7e:
						vga_end += 1
				orom_marker = util.read_string(rom_data[vga_start:vga_end]).strip()

				# Find an ASCII string after the IBM header, and if one is found, use it instead.
				additional_match = self._vga_string_pattern.search(rom_data[vga_end:])
				if additional_match:
					orom_marker = self._vga_trim_pattern.sub('', orom_marker).strip()
					if orom_marker:
						orom_marker += '\n'
					orom_marker += util.read_string(additional_match.group(0).replace(b'\x00', b' ')).strip()
			elif rom_size >= 4096 and not rom_size & 0x7ff and match.group(2) in b'\xe9\xeb':
				# Find ASCII strings near what appears to be a header.
				# Not much we can do to check the validity of a header,
				# outside of the size which is a >= 4K multiple of 2K
				# in most cases, and the entry point jump instruction.
				string_match = self._orom_string_pattern.search(rom_data[5:4096]) # spec says data starts at 6, but a short jump can make it start at 5
				if string_match and b'NetWare Ready ROM' in string_match.group(0): # ignore RPL signature
					string_match = self._orom_string_pattern.search(rom_data[string_match.end(0):4096])
				if string_match:
					orom_marker = util.read_string(string_match.group(0)).strip()
					if len(orom_marker) > 256: # ignore Adaptec's essay about 1 GB drives
						orom_marker = None
					elif orom_marker == 'Invalid Partition Table': # ignore Trend ChipAwayVirus MBR signatures(?)
						orom_marker = None

			# Extract PCI and PnP data structure pointers.
			pci_header_ptr, pnp_header_ptr = struct.unpack('<HH', match.group(3))

			# Check for a valid PCI data structure.
			if pci_header_ptr >= 26:
				pci_magic = rom_data[pci_header_ptr:pci_header_ptr + 4]
				if pci_magic == b'PCIR':
					pci_header_data = rom_data[pci_header_ptr + 4:pci_header_ptr + 16]
					if len(pci_header_data) == 12:
						# Read PCI header data.
						vendor_id, device_id, device_list_ptr, _, revision, progif, subclass, class_code = struct.unpack('<HHHHBBBB', pci_header_data)
						self.debug_print('PCI header: vendor', hex(vendor_id), 'device', hex(device_id), 'class', class_code, 'subclass', subclass, 'progif', progif)

						# Make sure the vendor ID is not bogus.
						if vendor_id not in (0x0000, 0xffff):
							# The extracted option ROM marker is no longer required.
							orom_marker = None

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
							while len(rom_data[device_list_ptr:device_list_ptr + 2]) == 2:
								# Read ID and stop if this is a terminator.
								device_id, = struct.unpack('<H', rom_data[device_list_ptr:device_list_ptr + 2])
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
				if rom_data[pnp_header_ptr:pnp_header_ptr + 4] == b'$PnP':
					pnp_header_data = rom_data[pnp_header_ptr + 4:pnp_header_ptr + 18]
					if len(pnp_header_data) == 14:
						# Read PnP header data.
						_, _, _, _, _, device_id, vendor_ptr, device_ptr = struct.unpack('<BBHBB4sHH', pnp_header_data)

						# Extract vendor/device name strings if they're valid.
						if vendor_ptr >= 26:
							vendor = util.read_string(rom_data[match.start() + vendor_ptr:])
						else:
							vendor = None
						if device_ptr >= 26:
							device = util.read_string(rom_data[match.start() + device_ptr:])
						else:
							device = None
						self.debug_print('PnP header: vendor', repr(vendor), 'device', repr(device))

						# Take valid data only.
						if device_id[:2] != b'\x00\x00' and (vendor or device):
							# The extracted option ROM marker is no longer required.
							orom_marker = None

							# Add PnP ID (endianness swapped to help the front-end in
							# processing it), vendor name and device name to the list.
							self.oroms.append((struct.unpack('>I', device_id)[0], vendor, device))

			# Add extracted option ROM marker if no PCI/PnP data was found.
			if orom_marker:
				# Strip lines that are too short or have a single repeated character.
				stripped = (x.strip() for x in orom_marker.replace('\r', '\n').split('\n'))
				orom_marker = '\n'.join(x for x in stripped if len(x) > 3 and x[:10] != (x[0] * min(len(x), 10))).strip('\n')
				self.oroms.append((-1, 'VGA' if orom_is_vga else 'OROM', orom_marker))

		# This analyzer should never return True.
		return False


class CDIAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('CDI', *args, **kwargs)

		self._ncr_pattern = re.compile(b'''NCR'S VERSION IBM(?: CORP\\.)? [AX]T ROM''')

	def can_handle(self, file_path, file_data, header_data):
		match = self._ncr_pattern.search(file_data)
		if not match and b' COMPUTER DEVICES INC. ' not in file_data:
			return False

		# No version information, outside of whether it's NCR.
		# Whether or not *only* CDI+NCR existed remains to be seen.
		if match:
			self.version = 'NCR'
		else:
			self.version = '?'

		# Look for entrypoint dates.
		NoInfoAnalyzer.get_entrypoint_dates(self, file_data)
		if self.string:
			self.debug_print('Entry point date:', self.string)

		return True


class CentralPointAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('CPS', *args, **kwargs)

		self._pattern = re.compile(b'''BIOS [Vv]([\\x21-\\x7E]+)[\\x00-\\xFF] Copyright [\\x21-\\x7E]+ +Central Point Software, Inc\\.''')

	def can_handle(self, file_path, file_data, header_data):
		# Extract version.
		match = self._pattern.search(file_data)
		if not match:
			return False
		self.version = 'v' + util.read_string(match.group(1))

		return True


class ChipsAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('C&T', *args, **kwargs)

		self._check_pattern = re.compile(b''' Chips & Technologies''')
		self._signon_pattern = re.compile(b'''\\x01\\xE4\\x00\\xF0\\x2F\\x00([\\x01-\\xFF]+)''') # (GW-286CT, Amstrad PC5286...)
		self._signon_alt_pattern = re.compile(b'''\\x0D\\x0A\\x00((?:[\\x01-\\xFF]+ )?BIOS Version [\\x01-\\xFF]+)''') # (Reply PS/2 stuff)

	def can_handle(self, file_path, file_data, header_data):
		if not self._check_pattern.search(file_data):
			return False

		# Locate sign-on.
		match = self._signon_pattern.search(file_data)
		if not match:
			match = self._signon_alt_pattern.search(file_data)
		if not match:
			return False

		# There seems to be no consistent core versioning scheme.
		# Not even the full version string is consistent...
		self.version = '?'

		# ...so we extract the full version string as a sign-on.
		self.signon = util.read_string(match.group(1))
		self.debug_print('Raw version string:', repr(self.signon))

		return True


class CommodoreAnalyzer(Analyzer):
	# Prefix decoded from CP437: "┌─+┐"
	# Reused by PhoenixAnalyzer.
	_signon_pattern = re.compile(b'''\\xDA\\xC4+\\xBF[\\x01-\\xFF]+''')

	def __init__(self, *args, **kwargs):
		super().__init__('Commodore', *args, **kwargs)

		self._version_pattern = re.compile(b'''Commodore [\\x20-\\x7E]+ Rom Bios Version ([\\x20-\\x7E]+)[\\x0D\\x0A\\x20-\\x7E]*''')

	def can_handle(self, file_path, file_data, header_data):
		# Extract version.
		match = self._version_pattern.search(file_data)
		if not match:
			return False
		self.version = util.read_string(match.group(1))

		# Extract full version string as metadata.
		version_string = util.read_string(match.group(0))
		self.debug_print('Raw version:', repr(version_string))

		# Extract sign-on.
		match = CommodoreAnalyzer._signon_pattern.search(file_data)
		if match:
			self.signon = util.read_string(match.group(0))
			self.debug_print('Raw sign-on:', repr(self.signon))

			# Trim sign-on to the first, bigger box.
			# The smaller box and some BIOS strings follow. (Commodore PC30)
			linebreak_index = self.signon.find('\r\n\r\n')
			if linebreak_index > -1:
				self.signon = self.signon[:linebreak_index]

		return True


class CompaqAnalyzer(NoInfoAnalyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Compaq', *args, **kwargs)

		self._copyright_pattern = re.compile(b'''Copyright ([0-9]+ by )?COMPAQ Computer Corporation''')
		self._error_pattern = re.compile(b'''Insert (?:DIAGNOSTIC diskette in Drive |COMPAQ DOS diskette)|You must load COMPAQ BASIC|[0-9]{2}/[0-9]{2}/[0-9]{2} +[^ ]+ +Copyright [0-9]+ by COMPAQ Computer Corporation''')
		self._entrypoint_pattern = re.compile(b'''[0-9]{2}COMPAQ\\xEA[\\x00-\\xFF]{2}\\x00\\xF0(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/[0-9]{2} ''')

	def has_strings(self, file_data):
		return (self._copyright_pattern.search(file_data) and self._error_pattern.search(file_data)) or self._entrypoint_pattern.search(file_data)


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
		self._version_coreboot_pattern = re.compile(b'''(?:#(?: This image was built using coreboot |define COREBOOT_VERSION ")|COREBOOT_VERSION: )([\\x20-\\x21\\x23-\\x7E]+)''')
		self._version_linuxbios_pattern = re.compile(b'''((LinuxBIOS|coreboot)-([^_ ]+)[_ ](?:Normal |Fallback )?(?:.* )?)starting\\.\\.\\.''')
		self._build_pattern = re.compile(b'''#define COREBOOT_BUILD "([^"]+?)"''')

	def can_handle(self, file_path, file_data, header_data):
		if not self._identifier_pattern.search(file_data):
			return False

		# Locate and extract version.
		match = self._version_coreboot_pattern.search(file_data)
		if match: # coreboot
			# Reset vendor to coreboot.
			self.vendor = self.vendor_id

			# Extract full version string as metadata.
			self.version = util.read_string(match.group(1))
			self.metadata.append(('ID', 'coreboot ' + self.version))
			self.debug_print('Raw coreboot version:', self.version)

			# Separate main version number.
			dash_index = self.version.find('-')
			if dash_index > -1:
				self.version = self.version[:dash_index]

			# Locate build tag.
			match = self._build_pattern.search(file_data)
			if match:
				# Extract build tag as metadata.
				build_code = util.read_string(match.group(1))
				self.debug_print('Raw coreboot build:', build_code)
				self.metadata.append(('Build', build_code))

			return True
		else:
			match = self._version_linuxbios_pattern.search(file_data)
			if match: # LinuxBIOS
				# Set vendor to LinuxBIOS if required.
				self.vendor = util.read_string(match.group(2))

				# Extract full version string as metadata.
				version_string = util.read_string(match.group(1))
				self.metadata.append(('ID', version_string))
				self.debug_print('Raw LinuxBIOS version:', version_string)

				# Extract version.
				self.version = util.read_string(match.group(3))

				return True

		return False


class DTKAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('DTK', *args, **kwargs)

		self._dtk_pattern = re.compile(b'''Datatech Enterprises Co\\., Ltd\\.|DATATECH ENTERPRISES CO\\., LTD\\.|\\x0ADTK Corp\\.|\\(C\\) Copyright by GoldStar Co\\.,Ltd\\.|GOLDSTAR  SYSTEM  SETUP''')
		self._version_pattern = re.compile(b'''(?:(?:DTK|GoldStar) [\\x20-\\x7E]+ BIOS Ver(?:sion)? |(?:DTK)/[\\x21-\\x2E\\x30-\\x7E]+/BIOS )([\\x21-\\x7E]+)(?: [\\x20-\\x7E]+)?''')

	def reset(self):
		super().reset()
		self._dtk = False

	def can_handle(self, file_path, file_data, header_data):
		if not self._dtk_pattern.search(file_data):
			return False

		# Locate version string.
		match = self._version_pattern.search(file_data)
		if match:
			# Extract version string as metadata.
			dtk_ver = match.group(0)
			self.debug_print('DTK version:', dtk_ver)
			self.metadata.append(('ID', dtk_ver.decode('cp437', 'ignore')))

			# Extract version.
			self.version = match.group(1).decode('cp437', 'ignore')

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
				self.debug_print('Entry point date:', self.string)
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

		self._version_older_pattern = re.compile(b'''Ver:? (V[\\x21-\\x2C\\x2E-\\x7E]+)(?:-| +Port )([\\x21-\\x7E]+)''')
		self._version_newer_pattern = re.compile(b'''[A-Z ]{7} \\((?:r|tm)\\)  (V[\\x21-\\x26\\x28-\\x7E]+) \\x09 ([\\x21-\\x7E]+)''')
		self._signon_pattern = re.compile(
			b'''OEM SIGNON >>-->''' # start marker
			b'''(?:[\\x20-\\x7E][\\x00-\\x1F\\x7F-\\xFF][\\x00-\\xFF]{14})?''' # code inbetween (on older BIOSes)
			b'''([\\x20-\\x7E]*?)''' # actual sign-on
			b'''\\x00?''' # null terminator (not always present)
			b'''<--<< OEM SIGNON''' # end marker
		)

	def can_handle(self, file_path, file_data, header_data):
		# Skip readme false positives.
		if len(file_data) < 2048:
			return False

		# Extract older format version.
		match = self._version_older_pattern.search(file_data)
		if match:
			self.debug_print('Raw older version:', match.group(0))

			# Extract version.
			self.version = util.read_string(match.group(1))

			# Extract part number as a string.
			self.string = util.read_string(match.group(2))
		else:
			# Extract newer format version.
			match = self._version_newer_pattern.search(file_data)
			if match:
				self.debug_print('Raw newer version:', match.group(0))

				# Extract version.
				self.version = util.read_string(match.group(1))

				# Extract part number as a string if one was found.
				self.string = util.read_string(match.group(2) or b'')
			else:
				# No version information found.
				return False

		# Extract custom OEM sign-on.
		match = self._signon_pattern.search(file_data)
		if match:
			signon = util.read_string(match.group(1))
			if len(signon) > 1: # sign-on contains a single ASCII character when not set
				self.signon = signon.strip()

		return True


class MylexAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Mylex', *args, **kwargs)

		self._version_pattern = re.compile(b'''MYLEX [\\x20-\\x7E]+ BIOS Version ([\\x20-\\x7E]+) ([0-9]{2}/[0-9]{2}/[0-9]{2})''')

	def can_handle(self, file_path, file_data, header_data):
		# Determine location of the identification block.
		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Extract version.
		self.version = match.group(1).decode('cp437', 'ignore')

		# Extract date as a string.
		self.string = match.group(2).decode('cp437', 'ignore')

		# Extract full version string as metadata.
		self.metadata.append(('ID', match.group(0).decode('cp437', 'ignore')))

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


class PhilipsAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Philips', *args, **kwargs)

		self._version_pattern = re.compile(b'''\\x0DPhilips ROM BIOS Version ([\\x21-\\x7E]+) ''')

	def can_handle(self, file_path, file_data, header_data):
		# Locate version.
		match = self._version_pattern.search(file_data)
		if not match:
			return False

		# Extract version.
		self.version = match.group(1).decode('cp437', 'ignore')

		return True


class PhoenixAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Phoenix', *args, **kwargs)

		# "Phoenix ROM BIOS" (Dell Latitude CP/CPI)
		# No Phoenix copyrights, fallback to NuBIOS (Gateway Solo 2500, AST Advantage! 4075P)
		self._phoenix_pattern = re.compile(b'''Phoenix (?:Technologies Ltd|Software Associates|Compatibility Corp|ROM BIOS)|PPhhooeenniixx  TTeecchhnnoollooggiieess|\\x00IBM AT Compatible Phoenix NuBIOS''')
		self._ignore_pattern = re.compile(b'''search=f000,0,ffff,S,"|\\x00\\xC3\\x82as Ltd. de Phoenix del \\xC2\\x83 de Tecnolog\\xC3\\x83\\x00''')
		self._bcpsegment_pattern = re.compile(b'''BCPSEGMENT''')
		self._valid_id_pattern = re.compile(b'''[\\x20-\\x7E][\\x00\\x20-\\x7E]{7,}''')

		self._rombios_version_pattern = re.compile(
			b'''(?:Phoenix )?''' # Phoenix brand (not always present)
			b'''((?:80[0-9a-zA-Z]+|V[1-4]0 |[0-9]{3})(?:/EISA)? )?ROM BIOS (PLUS )?''' # branch (whatever lacked the "80" was lost to time)
			b'''Ver(?:sion|s\\.)? ?([0-9]\\.[A-Z]?[0-9]{2})''' # actual version (can have short "Ver" with (JE1000) or without (BXM-8) space on small BIOSes, or "Vers." (NEC 80286 3.05T), or letter before version (Dell fork "1.P10"))
			b'''[\\x20-\\x7E]*''' # added patch levels and OEM info
		)
		# Covers the Xx86 and for Pentium family.
		self._xx86_version_pattern = re.compile(
			b'''(PhoenixBIOS\\(TM\\) )''' # Phoenix brand
			b'''[\\x00-\\xFF]{0,512}?''' # variable amount of code inbetween (or nothing at all (DEC))
			b'''(([A-Z][0-9]86|for ([\\x20-\\x7E]+?)(?: ?\\(TM\\))? (?:CPU )?- ([^ ]+))''' # branch (can be missing entirely (Wearnes LPX))
			b''' Version )?([0-9]\\.[0-9]{2})''' # actual version
			b'''([\\x20-\\x7E]*)''' # added patch levels (Samsung SPC-6033P) and OEM info (Micronics M5PE)
		)
		# Customized Xx86 used in GRiDPad products.
		self._xx86_grid_version_pattern = re.compile(
			b'''\\xBE[\\x00-\\xFF]{2}\\xE8[\\x00-\\xFF]{2}\\x5E\\xC3''' # code before string
			b'''(([\\x20-\\x7E]*?)''' # branch (LAP386SL or nothing observed so far)
			b''' Version ''' # text inbetween
			b'''[\\x20-\\x7E]*?''' # added OEM info (2360 "for 224")
			b'''([0-9]\\.[0-9]{2})''' # actual version
			b'''[\\x20-\\x7E]*)''' # more added OEM info (2260 and 2270 date)
			b'''[\\x00-\\xFF]+''' # metric ton of code inbetween
			b'''(PhoenixBIOS\\(TM\\) )\\x00''' # Phoenix brand
		)
		# Not all SecureCore Tiano have this version string...
		self._sct_version_pattern = re.compile(b'''Phoenix BIOS SC-T (v[0-9\\.]+)[\\x20-\\x7E]*''')
		# ...in which case we use this.
		self._sct_marker_pattern = re.compile(b'''SecureCore Tiano \\(TM\\) Preboot Agent |CSM_Egroup Code Ending''')
		# "BIOS ROM" (Tandy) and "ROM BIOS" (HP)
		self._compat_pattern = re.compile(b'''(?:BIOS ROM|ROM BIOS)[\\x0D\\x0A\\x20-\\x7E]+Compatibility Software[\\x0D\\x0A\\x20-\\x7E]+Phoenix[\\x0D\\x0A\\x20-\\x7E]+''')
		self._dell_system_pattern = re.compile(b'''Dell System [\\x20-\\x7E]+''')
		self._dell_version_pattern = re.compile(b'''(?:BIOS [Vv]ersion(?!  =):?|(?:80[0-9]{2,3}|Phoenix) ROM BIOS PLUS Version [^\\s]+) ([A-Z0-9\\.]+)''')
		self._dell_version_code_pattern = re.compile(b'''([A-Z][0-9]{2})''')
		self._hp_pattern = re.compile(b'''([\\x21-\\x7E]+ [\\x21-\\x7E]+) \\(C\\)Copyright 1985-.... Hewlett-Packard Company, All Rights Reserved[\\x20-\\x7E]+''')
		# Versa 2000
		self._nec_signon_pattern = re.compile(b'''\\xE9[\\x00-\\xFF]{2}(NEC Corporation\\x0D\\x0A[\\x0D\\x0A\\x20-\\x7E]*)''')
		# "All Rights Reserved\r\n\n\x00\xF4\x01" (Xx86)
		# "All Rights Reserved\r\n\n\x00" (Commodore 386LT, Tandy 1000RSX)
		# "All Rights Reserved\r\n\n" (ROM BIOS)
		# "All Rights Reserved\r\n\r\n\r\n" (Gateway 4DX2-50V)
		self._rombios_signon_pattern = re.compile(b'''\\x0D\\x0AAll Rights Reserved\\x0D\\x0A(?:\\x0A(?:\\x00(?:[\\x90\\xF4]\\x01)?)?|\\x0D\\x0A\\x0D\\x0A)''')
		# No "All Rights Reserved" (Yangtech 2.27 / pxxt)
		self._rombios_signon_alt_pattern = re.compile(b'''\\(R\\)eboot, other keys to continue\\x00\\xFF+''')
		self._rombios_signon_dec_pattern = re.compile(b'''Copyright \\(C\\) [0-9]{4} Digital Equipment Corporation''')
		self._segment_pattern = re.compile('''(?:segment_([0-9A-F]{4})|bioscode_[0-9]+_[0-9A-F]{5,}_000F_([0-9A-F]{4}))\\.rom$''')
		self._strings_pattern = re.compile('''strings_[0-9A-F_]+\\.rom$''')
		self._date_pattern = re.compile(b'''((?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/[0-9]{2}|(?:0{2}[1-9]{2}|1{2}[0-2]{2})/(?:0{2}[1-9]{2}|[12]{2}[0-9]{2}|3{2}[01]{2})/[0-9]{4})[^0-9]''')

		# Reverse engineered from Phoenix BIOS Editor Pro.
		self._regtable_categories = {
			0: 'System',
			1: 'Cache',
			2: 'CPU',
			3: 'I/O',
			4: 'PM',
			5: 'Bridge',
			6: 'MCD',
			7: 'Other'
		}
		self._regtable_entries = {
			1: {
				1: 'OPTI 82C391',
				2: 'OPTI 82C493',
				3: 'OPTI 82C495',
				4: 'OPTI 82C596',
				5: 'SIS 85C460',
				6: 'SIS 85C401',
				7: 'ALD 93C305A',
				8: 'SIS 85C461',
				9: 'SYMPHONY 82C461',
				10: 'OPTI 82C801',
				11: 'OPTI 82C496',
				12: 'WD 8110LV',
				13: 'VLSI 82C481',
				14: 'SIS 85C411',
				15: 'OPTI 82C682',
				16: 'INTEL 82C420',
				17: 'HT HTK340',
				18: 'CT CS4031',
				19: 'ETEQ ET9000',
				20: 'VLSI 82C483',
				21: 'SIS 85C471',
				22: 'SYMPHONY 82C491',
				23: 'OPTI 82C802',
				24: 'SAND 93101',
				25: 'ACC 2168GT',
				26: 'OPTI 82C499',
				27: 'VLSI 82C486',
				28: 'CYRIX PAM',
				29: 'INTEL 82C430LX', # was "INTEL 82C430"
				30: 'FOREX 58C602',
				31: 'INTEL 82C425',
				32: 'INTEL 82C430NX',
				33: 'PICO 86C268',
				34: 'PICO 86C368',
				35: 'VLSI 82C590',
				36: 'CONTAQ 82C596',
				37: 'OPTI 82C546',
				38: 'EFAR EC802G',
				39: 'CT CS4041',
				40: 'ACC 2278',
				41: 'SAM 388',
				42: 'INTEL 82C430FX',
				43: 'PICO 86C668',
				44: 'OPTI 82C557',
				45: 'OPTI 82C558',
				46: 'HYDRA HT35X',
				47: 'OPTI 82C465',
				48: 'GRNLOGIC GL488',
				49: 'STD TTL',
				50: 'CI CBUS2 CBC2',
				51: 'OPTI 82C558N',
				52: 'ETEQ ET5001',
				53: 'UNI U5800',
				54: 'INTEL EX',
				55: 'INTEL ORION',
				56: 'INTEL P60',
				57: 'VIA 82C425',
				58: 'INTEL 82C430MX',
				59: 'ACC 2178A',
				60: 'SIS 5501',
				61: 'STDNOTEB',
				62: 'TI MERC3',
				63: 'MEC 5520',
				64: 'VLSI 82C594',
				65: 'ACC 2178',
				66: 'VLSI 82C535',
				67: 'ALI M1609',
				68: 'PICO 86C378',
				69: 'FTD 82C4591',
				70: 'INTEL 82C440FX',
				71: 'PICO 86C521',
				72: 'INTEL 82C430HX',
				73: 'OPTI 82C895',
				74: 'INTEL 82C430VX',
				75: 'VLSI 82C540',
				76: 'CYPRESS 82C691',
				77: 'OPTI 82C567',
				78: 'OPTI 82C568',

				80: 'ALI M1601',
				81: 'ACC 2058',
				82: 'SEC F4S',
				83: 'ACC 2051',
				84: 'AMD ELAN',
				85: 'ACC 2057',
				86: 'RADISYS R380',
				87: 'INTEL 82C430TX',
				88: 'INTEL 82C440LX',
				89: 'OKI PM1',
				90: 'EFAR EC92X',
				91: 'SMC 90E32',
				92: 'OPTI 82C650',
				93: 'RADISYS R400',
				94: 'RCC CHAMPION',
				95: 'S3 PLATO 86551',
				96: 'NEC uPD72170',
				97: 'AMD H2',
				98: 'INTEL E3G',
				99: 'INTEL 440BX',
				100: 'UMC 82C480',
				101: 'UMC 82C491',
				102: 'ACER M1219',
				103: 'ACER M1419',
				104: 'ACER M1429',
				105: 'VCTRONIX 92C5806',
				106: 'EFAR EC798',
				107: 'WINBOND 82C410',
				108: 'VIA 82C495',
				109: 'UMC 82C880',
				110: 'UMC 82C498',
				111: 'SIS 85C4967',
				112: 'SIS 85C50X',
				113: 'ALI 1445',
				114: 'ALI 1451',
				115: 'ALI 1461',
				116: 'UMC 82C890',
				117: 'VIA 82C486F',
				118: 'VIA 82C486',
				119: 'VIA 82C496',
				120: 'VIA 82C570',
				121: 'ALI 1489',
				122: 'SIS 5571',
				123: 'VIA 82C590VP',
				124: 'SIS 5597',



				128: 'SIS 551X',
				129: 'VTECH GW',
				130: 'ALI 1511',
				131: 'ACC 2056',
				132: 'ALI 1521',
				133: 'VIA 82C580VP',
				134: 'SIS 5596',
				135: 'SIS 510X',
				136: 'VIA 82C680',
				137: 'CYRIX GX',
				138: 'ITE 8330GN',
				139: 'ALI 1531',
				140: 'WEITEK 564ST',
				141: 'INTEL 82C450NX',
				142: 'VIA 82C597',
				143: 'ALI 1541',
				144: 'ALI 1621',
				145: 'VIA 82C598',
				146: 'INTEL 82C440EX',
				147: 'INTEL CAMINO',
				148: 'SIS 530',
				149: 'INTEL 82C460GX',
				150: 'WHITNEY GMCH',
				151: 'VIA 82C691',
				152: 'SIS 620',
				153: 'VIA VT8501',
				154: 'AMD IRONGATE',
				155: 'CYRIX MXI',
				156: 'INTEL CARMEL',
				157: 'VIA 82C694',
				158: 'TMETA TM100VNB',
				159: 'VIA VT8601',
				160: 'VIA 82C694X',
				161: 'SIS 540',
				162: 'SIS 630',
				163: 'INTEL GREENDALE',
				164: 'VIA VT8371',
				165: 'ALI 1631',
				166: 'VIA 82C8605',
				167: 'INTEL TIMNA',
				168: 'VIA 82C694Z',
				169: 'SOLANO GMCH',
				170: 'ALI 1632',
				171: 'ALI 1641',
				172: 'ALI 1561',
				173: 'VIA VT8363',
				174: 'AMD ELANSC520',
				175: 'VIA SAMUEL',
				176: 'INTEL ALMADOR',
				177: 'RCC GRAND CHAMP',
				178: 'ZFLINUX MACHZ',
				179: 'ALI 1647',
				180: 'VIA VT8603',
				181: 'VIA VT8365',
				182: 'SIS 730',
				183: 'RADISYS 82600',
				184: 'VIA VT8633',
				185: 'SIS 635',
				186: 'SIS 735',
				187: 'ALI 1651',
				188: 'ALI 1644',
				189: 'ALI 1646',
				190: 'VIA VT8366',
				191: 'INTEL BROOKDALE',
				192: 'ATI_CABO',
				193: 'VIA_P4X266',
				194: 'SIS_645',
				195: 'NVIDIA CRUSH11 NB',
				196: 'AMD 761',
				197: 'AMD 762',
				198: 'ALI 1671',
				199: 'ST ATLAS',
				200: 'AMD HAMMER',
				201: 'SIS 648',
				202: 'SIS 740',
				203: 'INTEL PLUMAS',
				204: 'VIA VT8372',
				205: 'VIA VT8367',
				206: 'VIA P4X333',
				207: 'INTEL ODEM',
				208: 'ATI RS200',
				209: 'SIS 746',
				210: 'INTEL MONTARA',
				211: 'VIA VT8377',
				212: 'ALI 1681',
				213: 'SIS 655',
				214: 'INTEL PLUMAS533',
				215: 'VIA VT8383',
				216: 'SIS 755'
			},
			2: {
				0|0: '386 Class - 386DX',
				0|1: '386 Class - 386SX',
				0|2: '386 Class - 386SL',
				0|3: '386 Class - 386CX',
				64|0: '486 Class - 486DX',
				64|1: '486 Class - 486SX',
				64|2: '486 Class - 486DX2',
				64|3: '486 Class - P24C',
				64|4: '486 Class - 487SX',
				64|5: '486 Class - 386486',
				64|6: '486 Class - CX486SLC',
				64|7: '486 Class - CX486DLC',
				64|8: '486 Class - IBM386SLC',
				64|9: '486 Class - IBM486SLC2',
				64|10: '486 Class - IBM486SLBL',
				64|11: '486 Class - CX486S',
				64|12: '486 Class - CX486S2',
				64|13: '486 Class - CX486M7',
				64|14: '486 Class - CX486M72',
				64|15: '486 Class - TI486SXL',
				64|16: '486 Class - 486SX2',
				64|17: '486 Class - AM486PLDX2',
				64|18: '486 Class - AM486PLDX2WB',
				64|19: '486 Class - AM486PLDX4',
				64|20: '486 Class - AM486PLDX4WB',
				64|21: '486 Class - TI486DX2',
				64|22: '486 Class - 486DX2WB',
				64|23: '486 Class - 486DXL',
				64|24: '486 Class - CX486DX4',
				64|25: '486 Class - P24CWB',
				64|32: '486 Class - TI486DX4',
				64|33: '486 Class - AMDX5',
				64|34: '486 Class - AMDX5WB',
				64|35: '486 Class - AM486SLE',
				64|36: '486 Class - STPCCLIENT',
				64|37: '486 Class - STPCCONSUMER',
				64|38: '486 Class - STPCINDUSTRIAL',
				64|63: '486 Class - 486 OD',
				128|0: '586 Class - P24T',
				128|1: '586 Class - PENTIUM',
				128|2: '586 Class - P54C',
				128|3: '586 Class - CYRIX M1',
				128|4: '586 Class - CYRIX M1sc',
				128|5: '586 Class - AMD K5',
				128|6: '586 Class - P55C',
				128|7: '586 Class - AMD K6',
				128|8: '586 Class - P55C OVER DRIVE',
				128|9: '586 Class - CYRIX M2',
				128|10: '586 Class - CYRIX CX/GX',
				128|11: '586 Class - TILLAMOOK',
				128|12: '586 Class - IDT C6',
				128|13: '586 Class - IDT C6 No MMX',
				128|14: '586 Class - IDT',
				128|(15+0): '586 Class - CYRIX GXM',
				128|(15+1): '586 Class - AMDK6-2',
				128|(15+2): '586 Class - AMDK6-3',
				128|(15+3): '586 Class - RISE MP6',
				128|(15+4): '586 Class - RISE MP6II',
				128|(15+5): '586 Class - CXMXI',
				128|(15+6): '586 Class - TMETA TM100',
				128|(15+7): '586 Class - TMETA TM120',
				128|(15+8): '586 Class - TMETA TM160',
				128|(15+9): '586 Class - CXJOSHUA',
				128|(15+10): '586 Class - AMDK6-2E Plus',
				128|(15+11): '586 Class - AMDK6-3E Plus',
				128|63: '586 Class - PENTIUM OVER DRIVE',
				192|(1+0): '686 Class - 686',
				192|(1+1): '686 Class - KLAMATH',
				192|(1+2): '686 Class - DESCHUTES',
				192|(1+3): '686 Class - PENTIUM II',
				192|(1+4): '686 Class - CELERON',
				192|(1+5): '686 Class - XEON',
				192|(1+6): '686 Class - COPPERMINE',
				192|(1+7): '686 Class - TANNER',
				192|(1+8): '686 Class - CASCADE',
				192|(1+9): '686 Class - KATMAI',
				192|(1+10): '686 Class - AMD K7',
				192|(1+11): '686 Class - TIMNA',
				192|(1+12): '686 Class - AMD DURON',
				192|(1+13): '686 Class - SAMUEL',
				192|(1+14): '686 Class - P8',
				192|(1+15): '686 Class - TUALATIN',
				192|(1+16): '686 Class - AMDK7 ATHLON',
				192|(1+17): '686 Class - AMDK7 DURON',
				192|(1+18): '686 Class - AMDK7 PALOMINO',
				192|63: '686 Class - 686 OVER DRIVE'
			},
			3: {
				0: 'STANDARD IO',
				1: 'NS 311',
				2: 'SMC 661',
				3: 'NS 310',
				4: 'CHIPS 711',
				5: 'SMC 665',
				6: 'NS 332',
				7: 'NS 322',
				8: 'NS 323',
				9: 'ACC 3221SP',
				10: 'SMC 653',
				11: 'INTEL 091AA',
				12: 'CHIPS 735',
				13: 'UMC 863',
				14: 'ACC 3223',
				15: 'NS 303',
				16: 'NS 334',
				17: 'NS 306',
				18: 'SMC 93X',
				19: 'SMC 922',
				20: 'VLSI VL82C532',
				21: 'WINBOND 787',
				22: 'NS 307',
				23: 'NS 308',
				24: 'SMC 669',
				25: 'UMC 8669',
				26: 'NS 336',
				27: 'NS 338',
				28: 'ALI 5113',
				29: 'UMC ITE 8680F',
				30: 'ALI 512X',
				31: 'SMC 957',
				32: 'SMC 669FR',
				33: 'NS PC87420',
				34: 'NC PC87317',
				35: 'SMC FDC37C67X',
				36: 'SMC FDC37C68X',
				37: 'SMC 77X',
				38: 'SMC FDC37B78X',
				39: 'SMC FDC37C60X',
				40: 'SMC FDC37M70X',
				41: 'SMC LPC47B17X',
				42: 'SMC LPC47B27X',
				43: 'NS PC87360',
				44: 'NS PC87364',
				45: 'SMC FDC 37B72X',
				46: 'ITE (UMC) 8693F',
				47: 'ITE (UMC) 8712F',
				48: 'SMC FDC 37N97X',
				49: 'SMC FDC 86X',
				50: 'SMC FDC 33X',
				51: 'NS PC87363',
				52: 'NS PC87366',
				53: 'SMSC LPC 47S42x',
				54: 'NS PC87560',
				55: 'ITE8761E',
				56: 'ALI M513X',
				57: 'SMSC 81X',
				58: 'SMC LPC47B227',
				59: 'ITE (UMC) 8702F',
				60: 'SMC FDC 10X',
				61: 'SMC FDC 37X',
				62: 'SMC FDC 14X',
				63: 'NS PC87391',
				64: 'SMC LPC 267',
				65: 'SMC LPC 45X',
				66: 'SMSC 254 Chivas',
				67: 'STM ATLAS',
				68: 'SMSC 192',
				69: 'ITE 8711F',
				70: 'SMSC 172',
				71: 'NS PC87372',
				72: 'SMSC 350',
				73: 'ITE 8711F'
			},
			4: {
				0: 'ACC 2051',
				1: 'ACC 2056',
				2: 'ACC 2057',
				3: 'ACC 2058',
				4: 'ACC 2066NT',
				5: 'ACC 2178A',
				6: 'ALI 1429',
				7: 'ALI 1513',
				8: 'ALI M1489',
				9: 'ALI M1523',
				10: 'ALI M6377',
				11: 'AMD ELAN',
				12: 'AMD H2',
				13: 'AMD SC400',
				14: 'CHIPS 4041',
				15: 'CYPRESS 693',
				16: 'CT CS4041',
				17: 'FUJITSU AQUARIUS',
				18: 'GRNLOGIC 488',
				19: 'INTEL GENERIC',
				20: 'INTEL 82371AB',
				21: 'INTEL 82371FB',
				22: 'INTEL 82371MX',
				23: 'INTEL 82374COM',
				24: 'INTEL 82374EB',
				25: 'INTEL 82375EB',
				26: 'INTEL 82378IBG',
				27: 'INTEL 82426EX',
				28: 'INTEL 82430MX',
				29: 'INTEL 82437MX',
				30: 'ITE PLATINUM',
				31: 'MEC MN5520',
				32: 'MEC MN5523',
				33: 'NEC PHX',
				34: 'OPTI GENERIC',
				35: 'OPTI 465MVB',
				36: 'OPTI 802G',
				37: 'OPTI 82C558',
				38: 'OPTI 82C558N',
				39: 'OPTI 82C568',
				40: 'OPTI 82C700',
				41: 'PICO 368',
				42: 'PICO 378',
				43: 'PICO 521',
				44: 'PICO 521NS420',
				45: 'PICO 668',
				46: 'PICO SEQUOIA',
				47: 'PICO VESUVIUS',
				48: 'SEC FALCONER',
				49: 'SIS 471',
				50: 'SIS 510X',
				51: 'SIS 551X',
				52: 'SIS 5571',
				53: 'SIS 5596',
				54: 'SMC 90E32',
				55: 'STDNOTEB',
				56: 'TI MERC3',
				57: 'UMC 82C498',
				58: 'UMC 890BN',
				59: 'UMC 890N',
				60: 'UNICHIP U5800',
				61: 'VIA 82C425MV',
				62: 'VIA 570M',
				63: 'VIA 570MV',
				64: 'VIA 580VP',
				65: 'VIA 82C586',
				66: 'VLSI 483',
				67: 'VLSI 541',
				68: 'VLSI 590',
				69: 'VLSI EAGLE',
				70: 'INTEL 82371AB IO',
				71: 'INTEL 82372FB IO',
				72: 'INTEL 82372FB',
				73: 'INTEL ICH',
				74: 'SIS 5595',
				75: 'AMD COBRA',
				76: 'ST STPC',
				77: 'VIA 8231',
				78: 'ZF MACHZ',
				79: 'VIA 8233',
				80: 'SMC 90E66 IO',
				81: 'SMC 90E66',
				82: 'NV MCP1',
				83: 'AMD 8111',
				84: 'VIA 8235',
				85: 'ATI SB200'
			},
			5: {
				1: 'INTEL 82378IB',
				2: 'INTEL 82374EB',
				3: 'INTEL 82375EB',
				4: 'INTEL 82426EX',
				5: 'INTEL 82371FB',
				6: 'OPTI 822',
				7: 'VLSI 590',
				8: 'ACC 2188',
				9: 'ALI M1435',
				10: 'UMC 82C8880',
				11: 'UMC 82C8890',
				12: 'OPTI 82C557',
				13: 'OPTI 82C558',
				14: 'OPTI 832',
				15: 'CHIPS 4049',
				16: 'INTEL 82371MX',
				17: 'SIS 5503',
				18: 'UMC 8890N',
				19: 'ALI M1513',
				20: 'ALI 1451',
				21: 'INTEL 82372SB',
				22: 'ALI M1523',
				23: 'CYPRESS 82C693',
				24: 'OPTI 82C567',
				25: 'OPTI 82C568',
				26: 'VLSI 543',
				27: 'OPTI 82C700',
				28: 'INTEL 82371AB',
				29: 'SMC E36',
				30: 'RCC OSB2',
				31: 'CYRIX 5500',
				32: 'INTEL 82372FB',
				33: 'INTEL ICH LPC',
				34: 'SIS 5595',
				35: 'VIA 82C686A',
				36: 'AMD COBRA',
				37: 'SIS 960',
				38: 'VIA VT8231',
				39: 'VIA VT8233',
				40: 'SIS 961',
				41: 'SMC 90E66',
				42: 'NVIDIA MCP1',
				43: 'AMD 766',
				44: 'AMD 768',
				45: 'AMD 8111',
				46: 'SIS 962',
				47: 'VIA VT8235',
				48: 'ATI SB200'
			},
			6: {
				0: 'Winbond 877F Super IO',
				1: 'Intel 091AA Super I/O',
				2: 'NS 306 Super I/O',
				3: 'NS 307 Super I/O',
				4: 'NS 308 Super I/O',
				5: 'NS 317 Super I/O',
				6: 'NS 334 Super I/O',
				7: 'NS 338 Super I/O',
				8: 'SMC 665 Super I/O',
				9: 'SMC 669 Super I/O',
				10: 'SMC 669FR Super I/O',
				11: 'SMC 93X Super I/O',
				12: 'SMC 957 Super I/O',
				13: 'Winbond 787 Super I/O',
				14: 'CT 2504 Audio',
				15: 'YAMAHA YMF715 Audio',
				16: 'TI 1131 Cardbus',
				17: 'NS 336 Super I/O',
				18: 'Crystal 423X Audio Chip',
				19: 'ITE 8669 Super I/O',
				20: 'Motorola 1673 Modem',
				21: 'Winbond 967 Super I/O',
				22: 'ITE 8680RF Super I/O',
				23: 'CL-PD6832 Cardbus',
				24: 'SMC 93XFR Super I/O',
				25: 'NS 309 Super I/O',
				26: 'ALI 512X Super I/O',
				27: 'NS LM78 Hardware Monitor',
				28: 'O2Micro Cardbus -OZ6832-',
				29: 'Winbond 977 Super I/O',
				30: 'VIA VT83C669 Super I/O',
				31: 'SMC FDC37N69 Super I/O',
				32: 'SMC 958 Super I/O',
				33: 'SMC 77X Super I/O',
				34: 'ITE 8671F Super I/O',
				35: 'ITE 8661F Super I/O',
				36: 'NS PC87360 Super I/O',
				37: 'NS PC87364 Super I/O',
				38: 'ITE 8693F Super I/O',
				39: 'VIA VT82C686A Super I/O',
				40: 'NS PC87363 Super I/O',
				41: 'Winbond 627 Super I/O',
				42: 'NS PC87366 Super I/O',
				43: 'NS PC87560 Super I/O',
				44: 'SIS 950 Super I/O',
				45: 'NSPC87365 Super I/O',
				46: 'Yamaha YMF744 Audio Chip',
				47: 'ALI M513X Super IO',
				48: 'NS PC87393 Super I/O',
				49: 'VIA VT8231 Super I/O',
				50: 'NS PC87364 Super I/O',
				51: 'AMD SC520 Super I/O',
				52: 'Winbond 697HF Super I/O',
				53: 'NS PC87351 Super I/O',
				54: 'AMD SC520 FDISK',
				55: 'SMC 14X Super I/O',
				56: 'NSPC87391 Super I/O',
				57: 'NSPC87414 Super I/O',
				58: 'VIA VT1211 LPC Super I/O',
				59: 'Winbond 517D Super I/O',
				60: 'SMC 172 Super I/O'
			}
		}
		self._regtable_entries[0] = self._regtable_entries[1]

	def reset(self):
		super().reset()
		self._regtables = {}

	class BCP:
		def __init__(self, signature, version_maj, version_min, offset, data):
			self.signature = signature
			self.version_maj = version_maj
			self.version_min = version_min
			self.offset = offset
			self.data = data

		def __repr__(self):
			return '<{0} version {1}.{2} datalen {3}>'.format(self.signature, self.version_maj, self.version_min, len(self.data))

	def _add_regtable(self, category, model):
		# Identify register table category and model names.
		entry = self._regtable_entries.get(category, {}).get(model, None)
		if entry:
			# Add this category and model to the register table list.
			category_name = self._regtable_categories.get(category, str(category))
			if entry not in self._regtables:
				self._regtables[entry] = [category_name]
			elif category_name not in self._regtables[entry]:
				self._regtables[entry].append(category_name)

	def can_handle(self, file_path, file_data, header_data):
		if not self._phoenix_pattern.search(file_data):
			return False

		# Skip:
		# - Windows 95 INF updates
		# - Intel UEFI with PCI device list (UTF-8 encoded)
		if self._ignore_pattern.search(file_data):
			return False

		# Extract Intel data in a preliminary manner in case extraction failed.
		is_intel = AMIIntelAnalyzer.can_handle(self, file_path, file_data, header_data)
		if is_intel:
			self.debug_print('Intel data found')

		# Skip BCP parsing if this is not 4.0x or newer.
		raw_data = b''
		bios_maj = bios_min = code_segment = regtable_segment = None
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

			# Remove footer.
			if len(raw_data) & 0xffff:
				last_block = len(raw_data) & ~0xffff
				if (raw_data[last_block:last_block + 2] == b'BC' or # platform.bin? (Tyan Tiger MP)
					(len(raw_data) & 0xffff) <= 16 # 11-byte footer consisting of ASCII text + CRLF (NEC)
					):
					raw_data = raw_data[:last_block]

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
				# Sometimes there's no BCP immediately after BCPSEGMENT (Micronics M54Li)
				# BCP can be way ahead (366 bytes on DEC Venturis FX) - old 256-byte check didn't cut it
				if virtual_mem[offset:offset + 3] != b'BCP':
					next_bcp_offset = virtual_mem[offset:offset + 1024].find(b'BCP')
					if next_bcp_offset > -1:
						offset += next_bcp_offset
					else:
						break
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
					bcp[signature].append(PhoenixAnalyzer.BCP(signature, version_maj, version_min, offset, virtual_mem[offset:offset + size]))

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
					code_segment = regtable_segment = (bcpsegment_offset & ~0xffff) >> 4
					break

			self.debug_print('Found BCPs:', bcp)

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
						try:
							offset = int(match.group(1), 16) << 4 # segment
						except:
							offset = int(match.group(2), 16) # bioscode 000F (DMI offsets only make sense if this is loaded to segment 0000 instead)
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
							# Load each string table.
							offset += 0x1c
							languages = []
							while True:
								# Parse string table header.
								lang_header = data[offset:offset + 6]
								if len(lang_header) != 6: # end reached
									break
								lang_size, _, lang_code = struct.unpack('<HH2s', lang_header)
								if lang_size == 0:
									break

								# Add string table data, prioritizing the English language.
								if lang_code == b'us':
									strings_files.insert(0, data[offset:offset + lang_size])
								else:
									strings_files.append(data[offset:offset + lang_size])
								languages.append(lang_code)

								# Move on to the next table.
								offset += lang_size

							strings_files.append(data[offset:])
							self.debug_print('Loaded strings file:', file_in_dir, '=>', languages)
						else:
							self.debug_print('Bad strings file:', file_in_dir)

			# Extract information from BCPSYS.
			dmi_segment = code_segment
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

				# Extract the build dates and times as further metadata.
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
				dates_times = '\n'.join(date_time for date_time in dates_times if date_time[:8] != '00/00/00')
				if dates_times:
					if build_code:
						build_code += '\n'
					build_code += dates_times

				# Add build code and dates/times as a single metadata entry.
				if build_code:
					self.metadata.append(('Build', build_code))

				# Extract register table pointer segment and offsets.
				if bcpsys.version_maj >= 3 and data_size >= 0x6a:
					regtable_start, regtable_end, regtable_segment = struct.unpack('<HHH', bcpsys.data[0x65:0x6b])
					if bcpsys.version_maj == 3 and bcpsys.version_min <= 1:
						regtable_segment = code_segment
					else:
						# Cut ahead of the BCPOST reading further down to check if the ID string is valid,
						# so we can detect if this image is being honest about its register table segment.
						bcpost = bcp.get('BCPOST', [None])[0]
						dmi_segment = regtable_segment
						if bcpost and len(bcpost.data) >= 0x1d:
							prev_version_offset, = struct.unpack('<H', bcpost.data[0x1b:0x1d])
							version_offset = prev_version_offset + (regtable_segment << 4)
							version_string = virtual_mem[version_offset:version_offset + 4096]
							if not self._valid_id_pattern.match(version_string):
								prev_regtable_segment = regtable_segment
								if regtable_segment > 0x0000 and regtable_segment < 0x8000:
									# Some images report a bogus table segment such as
									# 0x5000 (DEC 440LX DEVEL61F). This can probably be
									# made to check for segments beyond the image size.
									regtable_segment |= 0x8000
								else:
									# DMI at 0000 is valid (Siemens Nixdorf 4.06)
									if regtable_segment == 0x0000:
										dmi_segment = regtable_segment
									else:
										dmi_segment = 0xf000
									regtable_segment = 0xf000
								self.debug_print('Potentially bogus ID string at', hex(prev_regtable_segment), ':', hex(prev_version_offset), ', changing register table segment to', hex(regtable_segment))
							else:
								version_string = util.read_string(version_string)
						elif regtable_segment <= 0xe31f:
							# Old strategy (set by HP Brio 80xx) as a backup.
							self.debug_print('No BCPOST and register table segment', hex(regtable_segment), 'appears low, changing to 0xf000')
							dmi_segment = regtable_segment = 0xf000
						code_segment = regtable_segment
				elif bcpsys.version_maj == 1 and bcpsys.version_min >= 5 and data_size >= 0x6b:
					regtable_start, regtable_end = struct.unpack('<HH', bcpsys.data[0x67:0x6b])
					if data_size >= 0x6d: # data can end without this value (BCPSYS 1.5 on Micronics M54Li 07)
						code_segment, = struct.unpack('<H', bcpsys.data[0x6b:0x6d])
					regtable_segment = (bcpsys.offset >> 4) & 0xf000 # not always F000 due to inverted BIOSes
				else:
					regtable_segment = None

				if regtable_segment:
					self.debug_print('Register table pointer array at', hex(regtable_segment), ':', hex(regtable_start), 'to', hex(regtable_end))

					# Do some sanity checking on the values.
					if regtable_start >= 0 and (regtable_end - regtable_start) <= 128:
						# Add segment to offsets.
						regtable_start += regtable_segment << 4
						regtable_end += regtable_segment << 4

						# Go through table pointers.
						regtable_entry = regtable_start
						while regtable_entry < regtable_end:
							# Read pointer.
							regtable_ptr = virtual_mem[regtable_entry:regtable_entry + 2]
							if len(regtable_ptr) != 2:
								self.debug_print('Register table pointer short read at', hex(regtable_entry))
								break
							regtable_ptr, = struct.unpack('<H', regtable_ptr)
							regtable_entry += 2

							# Read data from table header.
							regtable_ptr += regtable_segment << 4
							regtable_header = virtual_mem[regtable_ptr + 0x01:regtable_ptr + 0x03]
							if len(regtable_header) != 2:
								self.debug_print('Register table header short read at', hex(regtable_ptr))
								break
							regtable_model, regtable_type = regtable_header
							self.debug_print('Register table at', hex(regtable_ptr), 'identifying as', regtable_type >> 4, ':', regtable_model)

							# Add to register table list.
							self._add_regtable(regtable_type >> 4, regtable_model)
					else:
						self.debug_print('Potentially bogus register table pointer array with', int((regtable_end - regtable_start) / 2), 'entries')
				else:
					# Restore code segment for BCPOST version string extraction.
					regtable_segment = code_segment

			# Extract chipset information from BCPCHP.
			for bcpchp in bcp.get('BCPCHP', []):
				# BCPCHP versions observed:
				# - 0.0 (4.01-4.04)
				# - 1.0 (4.04) removed chipset ID
				# - 1.1 (4.04-4.05)
				# - 2.0 (4.0R6-SecureCore)
				self.debug_print('BCPCHP version:', bcpchp.version_maj, bcpchp.version_min)

				# Extract model if possible.
				if bcpchp.version_maj == 0 and len(bcpchp.data) >= 0x0b:
					model = bcpchp.data[0x0a]
					self.debug_print('BCPCHP chipset identifying as', model)

					# Add to register table list.
					self._add_regtable(0, model)

			# Extract Super I/O information from BCPIO.
			for bcpio in bcp.get('BCPIO ', []):
				# BCPIO versions observed:
				# - 1.0 (4.01-4.04)
				# - 1.1 (4.04-4.05)
				# - 1.2 (4.05)
				self.debug_print('BCPIO version:', bcpio.version_maj, bcpio.version_min)

				# Extract model if possible.
				if len(bcpio.data) >= 0x0b:
					model = bcpio.data[0x0a]
					self.debug_print('BCPIO chip identifying as', model)

					# Add to register table list.
					self._add_regtable(3, model)

			# Extract Super I/O (and rarely onboard device) information from BCPMCD.
			for bcpmcd in bcp.get('BCPMCD', []):
				# BCPMCD versions observed:
				# - 0.0 (4.0R6)
				# - 0.1 (4.0R6-SecureCore)
				self.debug_print('BCPMCD version:', bcpmcd.version_maj, bcpmcd.version_min)

				# Extract model if possible.
				if len(bcpmcd.data) >= 0x0b:
					model = bcpmcd.data[0x0a]
					self.debug_print('BCPMCD chip identifying as', model)

					# Add to register table list.
					self._add_regtable(6, model)

			# Extract DMI information from BCPDMI if required.
			if not self._bonus_dmi:
				def _read_dmi_string(offset):
					if offset in (0x0000, 0xffff):
						return ''
					else:
						string_offset = (dmi_segment << 4) + offset
						return util.read_string(virtual_mem[string_offset:string_offset + 256]).strip()

				for bcpdmi in bcp.get('BCPDMI', []):
					# BCPDMI versions observed:
					# - 2.10 (4.05-4.0R6)
					# - 2.11 (4.0R6-SecureCore)
					self.debug_print('BCPDMI version:', bcpdmi.version_maj, bcpdmi.version_min)
					self.debug_print('DMI table segment:', hex(dmi_segment))

					dmi_tables = []

					if len(bcpdmi.data) >= 0x1c:
						offsets = struct.unpack('<HHH', bcpdmi.data[0x16:0x1c])
						self.debug_print('DMI System offsets:', *(hex(x) for x in offsets))
						system_mfg, system_product, system_version = (_read_dmi_string(offset) for offset in offsets)

						if system_mfg or system_product or system_version:
							dmi_tables.append('[System] {0} {1} {2}'.format(system_mfg, system_product, system_version))

					if len(bcpdmi.data) >= 0x10:
						offsets = struct.unpack('<HHH', bcpdmi.data[0x0a:0x10])
						self.debug_print('DMI Board offsets:', *(hex(x) for x in offsets))
						board_mfg, board_product, board_version = (_read_dmi_string(offset) for offset in offsets)

						if board_mfg or board_product or board_version:
							# Check for duplicate system and baseboard information.
							formatted = '{0} {1} {2}'.format(board_mfg, board_product, board_version)
							if len(dmi_tables) > 0 and dmi_tables[-1][:9] == '[System] ' and util.compare_alnum(dmi_tables[-1][9:], formatted):
								dmi_tables[-1] = '[Board/System] ' + formatted
							else:
								dmi_tables.append('[Board] ' + formatted)

					BonusAnalyzer._enumerate_metadata(self, 'DMI', dmi_tables, delimiter='\n')

			# Add all found register table information as metadata.
			regtable_metadata = ''
			for table in sorted(self._regtables):
				regtable_metadata += '\n{0} ({1})'.format(table, ', '.join(sorted(self._regtables[table])))
			if regtable_metadata:
				self.metadata.append(('Table', regtable_metadata[1:]))

		# Check version manually if this is a non-BCP BIOS.
		if not self.version:
			# Locate SecureCore Tiano version.
			match = self._sct_version_pattern.search(file_data)
			if match:
				# Extract version.
				self.version = 'SecureCore Tiano ' + util.read_string(match.group(1))

				# Extract full version as metadata.
				version_string = util.read_string(match.group(0))
				self.metadata.append(('ID', version_string))
				self.debug_print('Raw SecureCore Tiano version:', repr(version_string))
			else:
				# Locate Xx86 version.
				match = self._xx86_version_pattern.search(file_data)
				if match:
					# Extract version.
					branch = match.group(4)
					if branch: # for Pentium
						branch = (branch.strip().split(b'/')[-1] + b' ' + match.group(5))
					else: # Xx86
						branch = match.group(3) or b'??86'
					self.version = util.read_string(branch + b' ' + match.group(6))

					# Extract full version string as metadata.
					version_string = util.read_string(match.group(1) + (match.group(2) or b'') + match.group(6) + (match.group(7) or b''))
					self.metadata.append(('ID', version_string))
					self.debug_print('Raw Xx86 version:', repr(version_string))
				else:
					# Locate GRiD-customized Xx86 version.
					match = self._xx86_grid_version_pattern.search(file_data)
					if match:
						# Extract version.
						branch = match.group(2) or b'??86'
						self.version = util.read_string(branch + b' ' + match.group(3))

						# Extract full version string as metadata.
						version_string = util.read_string(match.group(4) + match.group(1))
						self.metadata.append(('ID', version_string))
						self.debug_print('Raw GRiD Xx86 version:', repr(version_string))
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
								pre_version = util.read_string(pre_version).replace('  ', ' ').strip()
								if len(pre_version) >= 5 and pre_version[:2] == '80':
									pre_version = pre_version[2:]

								self.version = pre_version + ' ' + self.version # double space on V20

							# Extract full version string as metadata.
							version_string = util.read_string(match.group(0).replace(b'\xF0', b''))
							self.metadata.append(('ID', version_string))
							self.debug_print('Raw ROM BIOS version:', repr(version_string))
						else:
							# Locate Compatibility Software version.
							match = self._compat_pattern.search(file_data)
							if match:
								# Extract full version string.
								version_string = util.read_string(match.group(0))
								self.debug_print('Raw Compatibility Software version:', repr(version_string))

								# Determine if this is HP, and if so, extract the identifier/date as a string.
								match = self._hp_pattern.search(file_data)
								if match:
									self.version = 'HP'
									self.string = util.read_string(match.group(1))
									self.debug_print('HP string:', repr(self.string))

									# Extract version/model from the version string as a sign-on.
									version_index = version_string.rfind('\n\rVersion')
									if version_index > -1:
										self.signon = version_string[version_index:].strip()
										version_string = version_string[:version_index]
								else:
									# Assume Tandy as a catch-all.
									self.version = 'Tandy'
									self.debug_print('Looks like Tandy')

								# Add full version string as metadata.
								self.metadata.append(('ID', version_string.strip()))
							else:
								# Locate SecureCore Tiano marker strings, in case no version string was found.
								if header_data == b'\x00\xFFUEFIExtract\xFF\x00':
									match = self._sct_marker_pattern.search(file_data)
								if match:
									self.debug_print('SecureCore Tiano marker:', match.group(0))
									self.version = 'SecureCore Tiano'
								else:
									self.debug_print('No version found!')

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

			# Read version string pointer.
			version_offset, = struct.unpack('<H', bcpost.data[0x1b:0x1d])

			# Extract full version string as metadata.
			if regtable_segment:
				self.debug_print('Version string pointer:', hex(regtable_segment), ':', hex(version_offset))
				version_offset += regtable_segment << 4
				if virtual_mem[version_offset:version_offset + 1] == b'\x00': # pointer may be off by one (Gateway Solo 2500)
					version_offset += 1
				version_string = util.read_string(virtual_mem[version_offset:version_offset + 4096])
				self.debug_print('Raw 4.0x version:', repr(version_string))
				self.metadata.append(('ID', version_string.strip()))

			# Read sign-on string pointer.
			signon_segment = code_segment
			signon_offset, = struct.unpack('<H', bcpost.data[0x23:0x25])

			# Handle 4.04+ where the string pointer points to a string table pointer instead of a string.
			signon = None
			if bios_maj >= 6 or (bios_maj == 4 and bios_min >= 6):
				# 4.0R6+: string table pointer is relative to string table file minus header.
				self.debug_print('BCPOST sign-on points to string table file offset', hex(signon_offset))

				# Make sure we have a strings file first.
				if len(strings_files) > 0:
					string_table_offset = strings_files[0][signon_offset:signon_offset + 2]
					if len(string_table_offset) == 2:
						signon_offset, = struct.unpack('<H', string_table_offset)
						self.debug_print('BCPOST sign-on string table entry points to file offset', hex(signon_offset))

						# Phoenix allowed for some line drawing that is not quite CP437.
						# The actual characters used haven't been confirmed in hardware.
						signon = strings_files[0][signon_offset:]
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
				signon = virtual_mem[signon_offset:signon_offset + 4096]

			# Read string if one was found.
			if signon:
				self.signon = util.read_string(signon)
				self.debug_print('Raw BCPOST sign-on:', repr(self.signon))
		else:
			# Determine if this is a customized Dell BIOS.
			match = self._dell_system_pattern.search(file_data)
			if match:
				# Backup in case no Phoenix version is found, which is possible given compression.
				if not self.version:
					self.version = 'Dell'

				# Extract the model as a sign-on.
				self.signon = util.read_string(match.group(0))
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
					version_string = util.read_string(match.group(1))
					self.signon += '\nBIOS Version: ' + version_string
					self.debug_print('Dell version:', repr(version_string))
			else:
				# Determine if this a customized Commodore BIOS.
				match = CommodoreAnalyzer._signon_pattern.search(file_data)
				if match:
					self.signon = util.read_string(match.group(0))
					self.debug_print('Raw Commodore sign-on:', repr(self.signon))
				else:
					# Determine if this is a customized NEC BIOS.
					match = self._nec_signon_pattern.search(file_data)
					if match:
						# Extract the model as a sign-on.
						self.signon = util.read_string(match.group(1))
						self.debug_print('NEC model:', repr(self.signon))
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

		# Split sign-on lines.
		if self.signon:
			self.signon = self.signon.replace('\r', '\n').replace('\x00', ' ')
			self.signon = '\n'.join(x.strip() for x in self.signon.split('\n') if x.strip()).strip('\n')

		return True


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
		self._version_pattern = re.compile('''(?:(?:Quadtel|QUADTEL|PhoenixBIOS) )?.+ BIOS Version ([^\\r\\n]+)''')
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
				self.version = version_match.group(1).rstrip('.').strip().rstrip('.') # remove trailing "." (first for quadt286, second for Quadtel GC113)
				if self.version[0:1] == 'Q': # flag Phoenix-Quadtel
					self.version = self.version[1:] + ' (Phoenix)'

				# Extract full version string as metadata.
				self.metadata.append(('ID', version_match.group(0)))

			# Extract sign-on.
			self.signon = util.read_string(file_data[id_block_index + 0x190:id_block_index + 0x290]).strip()

			# Split sign-on lines.
			self.signon = '\n'.join(x.rstrip('\r').strip() for x in self.signon.split('\n') if x != '\r').strip('\n')

		# Add newest date found to the string.
		for match in self._date_pattern.finditer(file_data):
			date = match.group(1).decode('cp437', 'ignore')
			if self.string:
				linebreak_index = self.string.find('\n')
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

		self._schneider_pattern = re.compile(b'''Schneider (?:Rundfunkwerke|Rdf\\.) AG''')
		self._version_pattern = re.compile(b'''EURO PC\\s+BIOS (V[\\x20-\\x7E]+)''')

	def can_handle(self, file_path, file_data, header_data):
		if not self._schneider_pattern.search(file_data):
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

		self._systemsoft_pattern = re.compile(b'''(?:SystemSoft|Insyde Software(?: Presto)?) BIOS |SystemSoft SCU\\. Copr 1983-''')
		self._version_pattern = re.compile(b'''(?:[\\x20-\\x7E]+ BIOS [Ff]or [\\x20-\\x7E]+|SystemSoft [\\x20-\\x7E]+ BIOS) (?:Vers(?:\\.|ion) 0?([^ \\x0D\\x0A]+)(?: ([\\x20-\\x7E]+))?| *\\(c\\))''')
		self._version_mobilepro_pattern = re.compile(b'''(Insyde Software Presto|SystemSoft MobilePRO) BIOS Version ([^ \\x0D\\x0A]+)(?: ([\\x20-\\x7E]+))?''')
		self._string_for_pattern = re.compile(b'''([\\x20-\\x7E]+ BIOS [Ff]or [\\x20-\\x27\\x29-\\x7E]+)\\(''')
		self._string_scu_pattern = re.compile(b'''([\\x20-\\x7E]+ SCU [Ff]or [\\x20-\\x7E]+ [Cc]hipset)''')
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
			self.version = (aio_match.group(1) or b'?').decode('cp437', 'ignore')

			# Unknown version. (NCR Notepad 3130)
			if len(self.version) <= 2:
				self.version = '?'

			# Extract version string as metadata.
			aio_version = aio_match.group(0).decode('cp437', 'ignore')
			if aio_version[:4] == 'IBM ':
				aio_version = aio_version[4:]
			if aio_version[-4:] == ' (c)':
				aio_version = aio_version[:-4]
			self.metadata.append(('ID', aio_version))

		# Look for the MobilePRO/Presto version string.
		mp_match = self._version_mobilepro_pattern.search(file_data)
		if mp_match:
			self.debug_print('MobilePRO version string:', mp_match.group(0))

			# Extract version.
			self.version = (mp_match.group(1).split(b' ')[-1] + b' ' + mp_match.group(2)).decode('cp437', 'ignore')

			# Extract version string as metadata.
			self.metadata.append(('ID', mp_match.group(0).decode('cp437', 'ignore')))

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
				self.debug_print('SCU/chipset string:', match.group(1))

				# Extract SCU string as metadata.
				self.metadata.append(('ID', match.group(1).decode('cp437', 'ignore')))

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

		self._check_pattern = re.compile(
			b'''This BASIC was aborted,\\x0Dbecause this machine has\\x0Dno ROM BASIC\\.\\x0D\\x0D Use Toshiba's BASIC\\.\\x0D|''' # (T1000/T1200/T3100e)
			b'''Toshiba Corporation\\.( & Award Software Inc|ALL RIGHTS RESERVED)\\.''' # with Award = lost to time; without Award = newer ones (320CDS V8.00)
		)
		self._string_pattern = re.compile(b'''(?:([\\x21-\\x7F]+\\s*V[\\x21-\\x7F]{1,16}\\s*)TOSHIBA |\\x00{3}BIOS[\\x00-\\xFF]{4}([\\x20-\\x7E]{16}))''')

	def can_handle(self, file_path, file_data, header_data):
		if not self._check_pattern.search(file_data):
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

		self._check_pattern = re.compile(b'''\\$[A-Z]{7}''')

	def can_handle(self, file_path, file_data, header_data):
		found_segments = []
		for match in self._check_pattern.finditer(file_data):
			found_segments.append(match.group(0))
		if b'$PREPOST' not in found_segments or b'$BOOTBLK' not in found_segments:
			return False

		# Extract build date as version, as there's no actual
		# version information to be found anywhere. (compressed?)
		date_index = len(file_data) - 0x0b
		self.version = util.read_string(file_data[date_index:date_index + 8])

		# Determine location of the identification block.
		# 256K BIOS = end - 0x10110
		# 512K BIOS = end - 0x20110
		id_block_index = len(file_data) - ((len(file_data) >> 2) + 0x110)

		# Extract string.
		self.string = util.read_string(file_data[id_block_index + 0xe0:id_block_index + 0x100])

		# Extract sign-on.
		self.signon = util.read_string(file_data[id_block_index:id_block_index + 0x20])

		return True


class ZenithAnalyzer(Analyzer):
	def __init__(self, *args, **kwargs):
		super().__init__('Zenith', *args, **kwargs)

		self._date_pattern = re.compile(b'''([0-9]{2}/[0-9]{2}/[0-9]{2}) \\(C\\)ZDS CORP''')
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
