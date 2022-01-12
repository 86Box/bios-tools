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
import multiprocessing, os, re, traceback, urllib.request
from biostools.pciutil import *

date_pattern_mmddyy = re.compile('''(?P<month>[0-9]{2})/(?P<day>[0-9]{2})/(?P<year>[0-9]{2,4})''')

_error_log_lock = multiprocessing.Lock()


def all_match(patterns, data):
	"""Returns True if all re patterns can be found in data."""
	# Python is smart enough to stop generation when a None is found.
	return None not in (pattern.search(data) for pattern in patterns)

def date_cmp(date1, date2, pattern):
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

def read_complement(file_path, file_header=None, max_size=16777216):
	"""Read up to max_size from file_path starting at the end of file_header.
	   Usage: file_header += read_complement(file_path, file_header)"""
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
		except:
			continue
	return removed_count

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
	except:
		pass
	return os.path.isdir(dir_path)
