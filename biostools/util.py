#!/usr/bin/python3
#
# 86Box          A hypervisor and IBM PC system emulator that specializes in
#                running old operating systems and software designed for IBM
#                PC systems and compatibles from 1981 through fairly recent
#                system designs based on the PCI bus.
#
#                This file is part of the 86Box BIOS Tools distribution.
#
#                Utility functions.
#
#
#
# Authors:       RichardG, <richardg867@gmail.com>
#
#                Copyright 2021 RichardG.
#
import errno, multiprocessing, os, math, random, re, shutil, traceback, urllib.request
from biostools.pciutil import *

date_pattern_mmddyy = re.compile('''(?P<month>[0-9]{2})/(?P<day>[0-9]{2})/(?P<year>[0-9]{2,4})''')
number_pattern = re.compile('''[0-9]+''')

digits = '0123456789'
lowercase = 'abcdefghijklmnopqrstuvwxyz'
uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
fn_symbols = '$%\'-_@~`!(){}^#&.+,;=[]'
base62 = digits + lowercase + uppercase
random_name_symbols = lowercase + digits + fn_symbols + uppercase
random_name_nosymbols = lowercase + digits + uppercase

raise_enospc = False

_error_log_lock = multiprocessing.Lock()


def all_match(patterns, data):
	"""Returns True if all re patterns can be found in data."""
	# Python is smart enough to stop generation when a None is found.
	return None not in (pattern.search(data) for pattern in patterns)

def alnum_key(s, difference=0):
	"""Key function which takes any number at the start of the string into
	   consideration, similarly to the Windows filename sorting algorithm.
	   The optional difference transforms any found number such that
	   returned = abs(num - difference)."""
	if type(s) == str:
		match = number_pattern.match(s)
		if match:
			return (abs(int(match.group(0)) - difference), s[match.end():])
	return (math.inf, s)

def closest_prefix(base, candidates, candidate_key=lambda x: x):
	"""Finds the closest prefix counterpart to base in candidates.
	   Returns None if no good match was found."""

	# Apply key function to the base.
	base = candidate_key(base)

	# Narrow down by removing one letter at a time.
	limit = len(base)
	candidates_copy = candidates # not a copy, but if we have one candidate already, this will do
	while len(candidates_copy) != 1 and limit > 0:
		# Copy the candidates list.
		candidates_copy = candidates[::]

		# Compare all candidates.
		for candidate in candidates:
			# Remove candidate if the file name (applying the key function, up to the limit) doesn't match.
			candidate_base = candidate_key(candidate)
			if candidate_base[:limit] != base[:limit]:
				candidates_copy.remove(candidate)

		# Remove next letter.
		limit -= 1

	# Try a backup number-distance comparison strategy if multiple
	# candidates were found, or stop if none were found at all.
	if len(candidates_copy) > 1:
		difference, _ = alnum_key(candidate_key(base))
		if difference == math.inf:
			difference = 0
		candidates_copy.sort(key=lambda x: alnum_key(candidate_key(x), difference))
	elif len(candidates_copy) < 1:
		return None

	# Return the first/only candidate.
	return candidates_copy[0]

def date_cmp(date1, date2, pattern):
	"""Returns the comparison difference between date1 and date2.
	   Date format set by the given pattern."""

	# Run date regex.
	date1_match = pattern.match(date1 or '')
	date2_match = pattern.match(date2 or '')
	if date1_match and not date2_match:
		return 1
	elif not date1_match and date2_match:
		return -1
	elif not date1_match and not date2_match:
		return 0

	# Extract year, month and day.
	date1_year  = int(date1_match.group('year'))
	date1_month = int(date1_match.group('month'))
	date1_day   = int(date1_match.group('day'))
	date2_year  = int(date2_match.group('year'))
	date2_month = int(date2_match.group('month'))
	date2_day   = int(date2_match.group('day'))

	# Add century to two-digit years.
	if date1_year < 100:
		if date1_year < 80:
			date1_year += 2000
		else:
			date1_year += 1900
	if date2_year < 100:
		if date2_year < 80:
			date2_year += 2000
		else:
			date2_year += 1900

	# Perform the comparisons.
	if date1_year != date2_year:
		return date1_year - date2_year
	elif date1_month != date2_month:
		return date1_month - date2_month
	elif date1_day != date2_day:
		return date1_day - date2_day
	else:
		return 0

def date_gt(date1, date2, pattern):
	"""Returns True if date1 is greater than date2.
	   Date format set by the given pattern."""
	return date_cmp(date1, date2, pattern) > 0

def date_lt(date1, date2, pattern):
	"""Returns True if date1 is lesser than date2.
	   Date format set by the given pattern."""
	return date_cmp(date1, date2, pattern) < 0

def hardlink_or_copy(src, dest):
	"""Attempt to hardlink or copy src to dest.
	   Returns True if either operation was successful."""
	try:
		os.link(src, dest)
	except:
		try:
			shutil.copy2(src, dest)
		except Exception as e:
			if raise_enospc and getattr(e, 'errno', None) == errno.ENOSPC:
				raise
			return False
	return True

def log_traceback(*args):
	"""Log to biostools_error.log, including any outstanding traceback."""

	elems = ['===[ While']
	for elem in args:
		elems.append(str(elem))
	elems.append(']===\n')
	output = ' '.join(elems)

	with _error_log_lock:
		f = open('biostools_error.log', 'a')
		f.write(output)
		traceback.print_exc(file=f)
		f.close()

def random_name(chars=16, charset=random_name_symbols):
	"""Generate a random filename using the given charset."""
	return ''.join(random.choice(charset) for x in range(chars))

def read_complement(file_path, file_header=None, max_size=16777216):
	"""Read up to max_size from file_path starting at the end of file_header.
	   Usage: file_header += read_complement(file_path, file_header)"""
	if not file_header or len(file_header) < max_size:
		try:
			f = open(file_path, 'rb')
			if file_header:
				f.seek(len(file_header))
				ret = f.read(max_size - len(file_header))
			else:
				ret = f.read(max_size)
			f.close()
			return ret
		except:
			pass
	return b''

def read_string(data, terminator=b'\x00'):
	"""Read a terminated string (by NUL by default) from a bytes."""
	terminator_index = data.find(terminator)
	if terminator_index > -1:
		data = data[:terminator_index]
	return data.decode('cp437', 'ignore')

def rmdirs(dir_path):
	"""Remove empty dir_path, also removing any parent directory which ends up empty."""
	removed_count = 0
	while True:
		try:
			os.rmdir(dir_path)
			removed_count += 1
			dir_path = os.path.dirname(dir_path)
		except OSError:
			break
		except Exception as e:
			if raise_enospc and getattr(e, 'errno', None) == errno.ENOSPC:
				raise
			continue
	return removed_count

def remove_all(files, func=lambda x: x):
	"""Remove all specified files, applying func to the paths.
	   func can return a string or iterable object."""
	for file in files:
		file = func(file)
		if type(file) == str:
			file = [file]
		for subfile in file:
			try:
				os.remove(subfile)
			except Exception as e:
				if raise_enospc and getattr(e, 'errno', None) == errno.ENOSPC:
					raise

def remove_extension(file_name):
	"""Remove file_name's extension, if one is present."""
	extension_index = file_name.rfind('.')
	if extension_index > -1:
		return file_name[:extension_index]
	else:
		return file_name

def try_makedirs(dir_path):
	"""Try to create dir_path. Returns True if successful, False if not."""
	try:
		os.makedirs(dir_path)
	except Exception as e:
		if raise_enospc and getattr(e, 'errno', None) == errno.ENOSPC:
			raise
	return os.path.isdir(dir_path)
