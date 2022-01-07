#!/usr/bin/python3 -u
#
# 86Box          A hypervisor and IBM PC system emulator that specializes in
#                running old operating systems and software designed for IBM
#                PC systems and compatibles from 1981 through fairly recent
#                system designs based on the PCI bus.
#
#                This file is part of the 86Box BIOS Tools distribution.
#
#                Main BIOS extractor and analyzer program.
#
#
#
# Authors:       RichardG, <richardg867@gmail.com>
#
#                Copyright 2021 RichardG.
#

import getopt, os, multiprocessing, re, subprocess, sys
from . import analyzers, extractors, formatters, util

# Constants.
MP_PROCESS_COUNT = 4
ANALYZER_MAX_CACHE_MB = 512


# Extraction module.

def extract_dir(file_extractors, dir_number_path, next_dir_number_path, scan_dir_path, scan_file_names):
	"""Process a given directory for extraction."""

	# Determine the destination subdirectory.
	dest_subdir = scan_dir_path[len(dir_number_path):]
	while dest_subdir[:len(os.sep)] == os.sep:
		dest_subdir = dest_subdir[len(os.sep):]

	# Iterate through files.
	for scan_file_name in scan_file_names:
		file_path = os.path.join(scan_dir_path, scan_file_name)

		# Remove links.
		if os.path.islink(file_path):
			try:
				os.remove(file_path)
			except:
				try:
					os.rmdir(file_path)
				except:
					pass
			continue

		# Read header.
		try:
			f = open(file_path, 'rb')
			file_data = f.read(32775) # upper limit set by ISOExtractor
			f.close()
		except:
			# Permission issues or after-the-fact removal of other files by
			# extractors can cause this. Give up.
			continue

		# Come up with a destination directory for this file.
		dest_file_path = os.path.join(dest_subdir, scan_file_name + ':')
		dest_dir = os.path.join(next_dir_number_path, dest_file_path)
		dest_dir_0 = os.path.join(os.path.dirname(next_dir_number_path), '0', dest_file_path)

		# Run through file extractors until one succeeds.
		for extractor in file_extractors:
			# Run the extractor.
			try:
				extractor_result = extractor.extract(file_path, file_data, dest_dir, dest_dir_0)
			except:
				# Log an error.
				util.log_traceback('extracting', file_path)
				continue

			# Check if the extractor produced any results.
			if extractor_result:
				# Handle the line break ourselves, since Python prints the main
				# body and line break separately, causing issues when multiple
				# threads/processes are printing simultaneously.
				print('{0} => {1}{2}\n'.format(file_path, extractor.__class__.__name__, (extractor_result == True) and ' (skipped)' or ''), end='')
				break

		# Remove destination directories if they were created but are empty.
		for to_remove in (dest_dir, dest_dir_0):
			util.rmdirs(to_remove)

	# Remove this directory if it ends up empty.
	util.rmdirs(scan_dir_path)


def extract_process(queue, dir_number_path, next_dir_number_path):
	"""Main loop for the extraction multiprocessing pool."""

	# Set up extractors.
	file_extractors = [
		extractors.DiscardExtractor(),
		extractors.ISOExtractor(),
		extractors.PEExtractor(),
		extractors.FATExtractor(),
		extractors.TarExtractor(),
		extractors.ArchiveExtractor(),
		extractors.HexExtractor(),
		extractors.ImageExtractor(),
		extractors.DellExtractor(),
		extractors.IntelExtractor(),
		extractors.OMFExtractor(),
		extractors.InterleaveExtractor(),
		extractors.BIOSExtractor(),
		extractors.UEFIExtractor(),
	]

	# Receive work from the queue.
	while True:
		item = queue.get()
		if item == None: # special item to stop the loop
			break
		extract_dir(file_extractors, dir_number_path, next_dir_number_path, *item)

def extract(dir_path, _, options):
	"""Main function for extraction."""

	# Check if the structure is correct.
	if not os.path.exists(os.path.join(dir_path, '1')):
		print('Incorrect directory structure. All data to unpack should be located inside', file=sys.stderr)
		print('a directory named 1 in turn located inside the given directory.', file=sys.stderr)
		return 2

	# Check if bios_extract is there.
	if not os.path.exists(os.path.abspath(os.path.join('bios_extract', 'bios_extract'))):
		print('bios_extract binary not found, did you compile it?', file=sys.stderr)
		return 3

	# Open devnull file for shell command output.
	devnull = open(os.devnull, 'wb')

	# Recurse through directory numbers.
	dir_number = 1
	while True:
		dir_number_path = os.path.join(dir_path, str(dir_number))
		next_dir_number_path = os.path.join(dir_path, str(dir_number + 1))

		# Fix permissions on extracted archives.
		print('Fixing up directory {0}:'.format(dir_number), end=' ', flush=True)
		try:
			print('chown', end=' ', flush=True)
			subprocess.run(['chown', '-hR', '--reference=' + dir_path, '--', dir_number_path], stdout=devnull, stderr=subprocess.STDOUT)
			print('chmod', end=' ', flush=True)
			subprocess.run(['chmod', '-R', 'u+rwx', '--', dir_number_path], stdout=devnull, stderr=subprocess.STDOUT) # execute for listing directories
		except:
			pass
		print()

		# Start multiprocessing pool.
		print('Starting extraction on directory {0}'.format(dir_number), end='', flush=True)
		queue = multiprocessing.Queue(maxsize=MP_PROCESS_COUNT)
		mp_pool = multiprocessing.Pool(MP_PROCESS_COUNT, initializer=extract_process, initargs=(queue, dir_number_path, next_dir_number_path))

		# Create next directory.
		if not os.path.isdir(next_dir_number_path):
			os.makedirs(next_dir_number_path)

		# Scan directory structure. I really wanted this to have file-level
		# granularity, but IntelExtractor and InterleaveBIOSExtractor
		# both require directory-level granularity for inspecting other files.
		print(flush=True)
		found_any_files = False
		for scan_dir_path, scan_dir_names, scan_file_names in os.walk(dir_number_path):
			if len(scan_file_names) > 0:
				found_any_files = True
				queue.put((scan_dir_path, scan_file_names))

		# Stop if no files are left.
		if not found_any_files:
			# Remove this directory and the directory if they're empty.
			try:
				os.rmdir(dir_number_path)
				dir_number -= 1
			except:
				pass
			try:
				os.rmdir(next_dir_number_path)
			except:
				pass
			break

		# Increase number.
		dir_number += 1

		# Stop multiprocessing pool and wait for its workers to finish.
		for _ in range(MP_PROCESS_COUNT):
			queue.put(None)
		mp_pool.close()
		mp_pool.join()

	# Create 0 directory if it doesn't exist.
	print('Merging directories:', end=' ')
	merge_dest_path = os.path.join(dir_path, '0')
	if not os.path.isdir(merge_dest_path):
		os.makedirs(merge_dest_path)

	# Merge all directories into the 0 directory.
	for merge_dir_name in range(1, dir_number + 1):
		merge_dir_path = os.path.join(dir_path, str(merge_dir_name))
		if not os.path.isdir(merge_dir_path):
			continue
		print(merge_dir_name, end=' ')

		subprocess.run(['cp', '-rlaT', merge_dir_path, merge_dest_path], stdout=devnull, stderr=subprocess.STDOUT)
		subprocess.Popen(['rm', '-rf', merge_dir_path], stdout=devnull, stderr=subprocess.STDOUT)

	# Clean up.
	devnull.close()
	print()
	return 0


# Analysis module.

def analyze_dir(formatter, scan_base, file_analyzers, scan_dir_path, scan_file_names):
	"""Process a given directory for analysis."""

	# Sort file names for better predictability. The key= function forces
	# "original.tm1" to be combined after "original.tmp" for if the Award
	# identification data spans across both files (AOpen AX6B(+) R2.00)
	scan_file_names.sort(key=lambda fn: (fn == 'original.tm1') and 'original.tmq' or fn)

	# Set up caches.
	files_flags = {}
	files_data = {}
	combined_oroms = []
	header_data = None
	
	# In combined mode (enabled by InterleaveExtractor and BIOSExtractor), we
	# handle all files in the directory as a single large blob, to avoid any doubts.
	combined = ':combined:' in scan_file_names
	if combined:
		files_data[''] = b''

	# Read files into the cache.
	cache_quota = ANALYZER_MAX_CACHE_MB * 1073741824
	for scan_file_name in scan_file_names:
		# Skip known red herrings. This check is legacy code with an unknown impact.
		scan_file_name_lower = scan_file_name.lower()
		if 'post.string' in scan_file_name_lower or 'poststr.rom' in scan_file_name_lower:
			continue

		# Read up to 16 MB as a safety net.
		file_data = util.read_complement(os.path.join(scan_dir_path, scan_file_name))

		# Write data to cache.
		if scan_file_name == ':header:':
			header_data = file_data
		elif combined:
			files_data[''] += file_data

			# Add PCI option ROM IDs extracted from AMI BIOSes by bios_extract, since the ROM might not
			# contain a valid PCI header to begin with. (Apple PC Card with OPTi Viper and AMIBIOS 6)
			match = re.match('''amipci_([0-9a-f]{4})_([0-9a-f]{4})\.rom$''', scan_file_name_lower)
			if match:
				combined_oroms.append((int(match.group(1), 16), int(match.group(2), 16)))
		else:
			files_data[scan_file_name] = file_data

		# Stop reading if the cache has gotten too big.
		cache_quota -= len(file_data)
		if cache_quota <= 0:
			break

	# Prepare combined-mode analysis.
	if combined:
		# Set interleaved flag on de-interleaved blobs.
		if scan_file_names == [':combined:', 'deinterleaved_a.bin', 'deinterleaved_b.bin', 'interleaved_a.bin', 'interleaved_b.bin']:
			combined = 'interleaved'

		# Commit to only analyzing the large blob.
		scan_file_names = ['']
	elif header_data:
		# Remove header flag file from list.
		scan_file_names.remove(':header:')

	# Analyze each file.
	for scan_file_name in scan_file_names:
		# Read file from cache if possible.
		scan_file_path = os.path.join(scan_dir_path, scan_file_name)
		file_data = files_data.get(scan_file_name, None)
		if file_data == None:
			# Read up to 16 MB as a safety net.
			file_data = util.read_complement(scan_file_path)

		# Check for an analyzer which can handle this file.
		bonus_analyzer_addons = bonus_analyzer_oroms = None
		file_analyzer = None
		strings = None
		for analyzer in file_analyzers:
			# Reset this analyzer.
			analyzer.reset()
			analyzer._file_path = scan_file_path

			# Check if the analyzer can handle this file.
			try:
				analyzer_result = analyzer.can_handle(file_data, header_data)
			except:
				# Log an error.
				util.log_traceback('searching for analyzers for', os.path.join(scan_dir_path, scan_file_name))
				continue

			# Move on if the analyzer responded negatively.
			if not analyzer_result:
				# Extract add-ons and option ROMs from the bonus analyzer.
				if bonus_analyzer_addons == None:
					bonus_analyzer_addons = analyzer.addons
					bonus_analyzer_oroms = analyzer.oroms
				continue

			# Run strings on the file data if required (only once).
			if not strings:
				try:
					strings = subprocess.run(['strings', '-n8'], input=file_data, stdout=subprocess.PIPE).stdout.decode('ascii', 'ignore').split('\n')
				except:
					util.log_traceback('running strings on', os.path.join(scan_dir_path, scan_file_name))
					continue

			# Analyze each string.
			try:
				for string in strings:
					analyzer.analyze_line(string)
			except analyzers.AbortAnalysisError:
				# Analysis aborted.
				pass
			except:
				# Log an error.
				util.log_traceback('analyzing', os.path.join(scan_dir_path, scan_file_name))
				continue

			# Take this analyzer if it produced a version.
			if analyzer.version:
				# Clean up version field if an unknown version was returned.
				if analyzer.version == '?':
					analyzer.version = ''

				# Stop looking for analyzers.
				file_analyzer = analyzer
				break

		# Did any analyzer successfully handle this file?
		if not file_analyzer:
			# Treat this as a standalone PCI option ROM file if BonusAnalyzer found any.
			if bonus_analyzer_oroms:
				bonus_analyzer_addons = []
				file_analyzer = file_analyzers[0]
			else:
				# Move on to the next file if nothing else.
				continue

		# Add interleaved flag to add-ons.
		if combined == 'interleaved':
			bonus_analyzer_addons.append('Interleaved')

		# Clean up the file path.
		scan_file_path_full = os.path.join(scan_dir_path, scan_file_name)

		# Remove combined directories.
		found_flag_file = True
		while found_flag_file:
			# Find archive indicator.
			archive_idx = scan_file_path_full.rfind(':' + os.sep)
			if archive_idx == -1:
				break

			# Check if a combined or header flag file exists.
			found_flag_file = False
			for flag_file in (':combined:', ':header:'):
				if os.path.exists(os.path.join(scan_file_path_full[:archive_idx] + ':', flag_file)):
					# Trim the directory off.
					scan_file_path_full = scan_file_path_full[:archive_idx]
					found_flag_file = True
					break

		scan_file_path = scan_file_path_full[len(scan_base) + len(os.sep):]

		# Remove root extraction directory.
		slash_index = scan_file_path.find(os.sep)
		if slash_index == 1 and scan_file_path[0] == '0':
			scan_file_path = scan_file_path[2:]

		# De-duplicate and sort add-ons and option ROMs.
		addons = list(set(addon.strip() for addon in (analyzer.addons + bonus_analyzer_addons)))
		addons.sort()
		oroms = list(set(combined_oroms + analyzer.oroms + bonus_analyzer_oroms))
		oroms.sort()

		# Add names to option ROMs.
		previous_vendor = previous_device = None
		for x in range(len(oroms)):
			# Get vendor and device IDs and names.
			vendor_id, device_id = oroms[x]
			vendor, device = util.get_pci_id(vendor_id, device_id)

			# Skip valid vendor IDs associated to a bogus device ID.
			if device == '[Unknown]' and device_id == 0x0000:
				oroms[x] = None
				continue

			# Clean up IDs.
			vendor = util.clean_vendor(vendor).strip()
			device = util.clean_device(device, vendor).strip()

			# De-duplicate vendor names.
			if vendor == previous_vendor and vendor != '[Unknown]':
				if device == previous_device:
					previous_device, device = device, ''
					previous_vendor, vendor = vendor, '\u2196' # up-left arrow
				else:
					previous_device = device
					previous_vendor, vendor = vendor, ' ' * len(vendor)
			else:
				previous_device = device
				previous_vendor = vendor

			# Format string.
			oroms[x] = '[{0:04x}:{1:04x}] {2} {3}'.format(vendor_id, device_id, vendor, device)

		# Remove bogus option ROM device ID entries.
		while None in oroms:
			oroms.remove(None)

		# Collect the analyzer's results.
		fields = [((type(field) == str) and field.replace('\t', ' ').strip() or field) for field in [
			scan_file_path,
			file_analyzer.vendor,
			file_analyzer.version,
			formatter.split_if_required('\n', file_analyzer.string),
			formatter.split_if_required('\n', file_analyzer.signon),
			formatter.join_if_required(' ', addons),
			formatter.join_if_required('\n', oroms),
		]]

		# Output the results.
		formatter.output_row(fields)

def analyze_process(queue, formatter, scan_base):
	"""Main loop for the analysis multiprocessing pool."""

	# Set up analyzers.
	file_analyzers = [
		analyzers.BonusAnalyzer(), # must be the first one
		analyzers.AwardPowerAnalyzer(), # must run before AwardAnalyzer
		analyzers.ToshibaAnalyzer(), # must run before AwardAnalyzer
		analyzers.AwardAnalyzer(), # must run before PhoenixAnalyzer
		analyzers.QuadtelAnalyzer(), # must run before PhoenixAnalyzer
		analyzers.PhoenixAnalyzer(), # must run before AMIDellAnalyzer and AMIIntelAnalyzer
		#analyzers.AMIDellAnalyzer(), # must run before AMIAnalyzer
		analyzers.AMIUEFIAnalyzer(), # must run before AMIAnalyzer
		analyzers.AMIAnalyzer(), # must run before AMIIntelAnalyzer
		analyzers.AMIIntelAnalyzer(),
		analyzers.MRAnalyzer(),
		# less common BIOSes with no dependencies on the common part begin here #
		analyzers.AcerAnalyzer(),
		analyzers.AcerMultitechAnalyzer(),
		analyzers.AmstradAnalyzer(),
		analyzers.CDIAnalyzer(),
		analyzers.CentralPointAnalyzer(),
		analyzers.ChipsAnalyzer(),
		analyzers.CommodoreAnalyzer(),
		analyzers.CompaqAnalyzer(),
		analyzers.CorebootAnalyzer(),
		analyzers.DTKGoldStarAnalyzer(),
		analyzers.GeneralSoftwareAnalyzer(),
		analyzers.IBMAnalyzer(),
		analyzers.ICLAnalyzer(),
		analyzers.InsydeAnalyzer(),
		analyzers.IntelUEFIAnalyzer(),
		analyzers.JukoAnalyzer(),
		analyzers.MRAnalyzer(),
		analyzers.MylexAnalyzer(),
		analyzers.OlivettiAnalyzer(),
		analyzers.SchneiderAnalyzer(),
		analyzers.SystemSoftAnalyzer(),
		analyzers.TandonAnalyzer(),
		analyzers.TinyBIOSAnalyzer(),
		analyzers.WhizproAnalyzer(),
		analyzers.ZenithAnalyzer(),
	]

	# Receive work from the queue.
	while True:
		item = queue.get()
		if item == None: # special item to stop the loop
			break
		analyze_dir(formatter, scan_base, file_analyzers, *item)

def analyze(dir_path, formatter_args, options):
	"""Main function for analysis."""

	# Initialize output formatter.
	output_formats = {
		'csv': (formatters.XSVFormatter, ','),
		'scsv': (formatters.XSVFormatter, ';'),
		'json': formatters.JSONObjectFormatter,
		'jsontable': formatters.JSONTableFormatter,
	}
	formatter = output_formats.get(options['format'], None)
	if not formatter:	
		raise Exception('unknown output format ' + options['format'])
	if type(formatter) == tuple:
		formatter = formatter[0](*formatter[1:], sys.stdout, options, formatter_args)
	else:
		formatter = formatter(sys.stdout, options, formatter_args)

	# Begin output.
	formatter.begin()
	formatter.output_headers(['File', 'Vendor', 'Version', 'String', 'Sign-on', 'Add-ons', 'PCI ROMs'], options.get('headers'))

	# Remove any trailing slash from the root path, as the output path cleanup
	# functions rely on it not being present.
	if dir_path[-len(os.sep):] == os.sep:
		dir_path = dir_path[:-len(os.sep)]
	elif dir_path[-1:] == '/':
		dir_path = dir_path[:-1]

	# Start multiprocessing pool.
	queue = multiprocessing.Queue(maxsize=MP_PROCESS_COUNT)
	mp_pool = multiprocessing.Pool(MP_PROCESS_COUNT, initializer=analyze_process, initargs=(queue, formatter, dir_path))

	# Scan directory structure.
	for scan_dir_path, scan_dir_names, scan_file_names in os.walk(dir_path):
		queue.put((scan_dir_path, scan_file_names))

	# Stop multiprocessing pool and wait for its workers to finish.
	for _ in range(MP_PROCESS_COUNT):
		queue.put(None)
	mp_pool.close()
	mp_pool.join()

	# End output.
	formatter.end()

	return 0


def main():
	mode = None
	options = {
		'array': False,
		'format': 'csv',
		'headers': True,
		'hyperlink': False,
		'docker-usage': False,
	}

	args, remainder = getopt.gnu_getopt(sys.argv[1:], 'xaf:hnr', ['extract', 'analyze', 'format=', 'hyperlink', 'no-headers', 'array', 'docker-usage'])
	for opt, arg in args:
		if opt in ('-x', '--extract'):
			mode = 'extract'
		elif opt in ('-a', '--analyze'):
			mode = 'analyze'
		elif opt in ('-f', '--format'):
			options['format'] = arg.lower()
		elif opt in ('-h', '--hyperlink'):
			options['hyperlink'] = True
		elif opt in ('-n', '--no-headers'):
			options['headers'] = False
		elif opt in ('-r', '--array'):
			options['array'] = True
		elif opt == '--docker-usage':
			options['docker-usage'] = True

	if len(remainder) > 0:
		if mode == 'extract':
			return extract(remainder[0], remainder[1:], options)
		elif mode == 'analyze':
			return analyze(remainder[0], remainder[1:], options)

	if options['docker-usage']:
		usage = '''
Usage: docker run -v directory:/bios biostools [-f output_format] [-h] [-n] [-r] [formatter_options]

       Archives and BIOS images in the directory mounted to /bios will be
       extracted and analyzed.
'''
	else:
		usage = '''
Usage: python3 -m biostools -x directory
       python3 -m biostools [-f output_format] [-h] [-n] [-r] -a directory [formatter_options]

       -x    Extract archives and BIOS images recursively in the given directory

       -a    Analyze extracted BIOS images in the given directory'''
	usage += '''
       -f    Output format:
                 csv		Comma-separated values with quotes (default)
                 scsv		Semicolon-separated values with quotes
                 json		JSON object array
                 jsontable	JSON table
       -h    Generate download links for file paths representing HTTP URLs.
             csv/scsv: The Excel HYPERLINK formula is used; if you have
                       non-English Excel, you must provide your language's
                       HYPERLINK formula name in formatter_options.
       -n    csv/scsv/jsontable: Don't output column headers.
       -r    json/jsontable: Output multi-value cells as arrays.
'''
	print(usage, file=sys.stderr)
	return 1

if __name__ == '__main__':
	sys.exit(main())
