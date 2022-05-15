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

import errno, getopt, os, pickle, multiprocessing, re, socket, subprocess, sys, threading
from . import analyzers, extractors, formatters, util

# Constants.
ANALYZER_MAX_CACHE_MB = 512
DEFAULT_REMOTE_PORT = 8620


# Extraction module.

def extract_dir(file_extractors, subdir_trim_index, path_trim_index, next_dir_number_path, scan_dir_path, scan_file_names):
	"""Process a given directory for extraction."""

	# Determine the destination subdirectory.
	dest_subdir = scan_dir_path[subdir_trim_index:]
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
			file_data = f.read(32782) # upper limit set by ISOExtractor
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
			except Exception as e:
				if util.raise_enospc and getattr(e, 'errno', None) == errno.ENOSPC:
					# Abort on no space if requested.
					print('{0} => aborting extraction due to disk space\n'.format(file_path[path_trim_index:]), end='')
					raise

				# Log an error.
				util.log_traceback('extracting', file_path)
				continue

			# Check if the extractor produced any results.
			if extractor_result:
				# Handle the line break ourselves, since Python prints the main
				# body and line break separately, causing issues when multiple
				# threads/processes are printing simultaneously.
				print('{0} => {1}{2}\n'.format(file_path[path_trim_index:], extractor.__class__.__name__, (extractor_result == True) and ' (skipped)' or ''), end='')
				break

		# Remove destination directories if they were created but are empty.
		for to_remove in (dest_dir, dest_dir_0):
			util.rmdirs(to_remove)

	# Remove this directory if it ends up empty.
	util.rmdirs(scan_dir_path)

def extract_process(queue, abort_flag, dir_number_path, next_dir_number_path, options):
	"""Main loop for the extraction multiprocessing pool."""

	# Set up extractors.
	file_extractors = [
		extractors.DiscardExtractor(),
		extractors.ISOExtractor(),
		extractors.VMExtractor(),
		extractors.PEExtractor(),
		extractors.FATExtractor(),
		extractors.MBRSafeExtractor(),
		extractors.TarExtractor(),
		extractors.ArchiveExtractor(),
		extractors.CPUZExtractor(),
		extractors.HexExtractor(),
		extractors.ImageExtractor(),
		extractors.ApricotExtractor(),
		extractors.IntelNewExtractor(),
		# extractors from here on down may read more than the header during detection
		extractors.DellExtractor(),
		extractors.IntelExtractor(),
		extractors.OMFExtractor(),
		extractors.TrimondExtractor(),
		extractors.InterleaveExtractor(),
		extractors.BIOSExtractor(),
		extractors.UEFIExtractor(),
		extractors.MBRUnsafeExtractor(),
	]

	# Disable debug mode on extractors.
	if not options['debug']:
		dummy_func = lambda self, *args: None
		for extractor in file_extractors:
			extractor.debug_print = dummy_func

	# Raise exceptions on no space if requested.
	util.raise_enospc = options['enospc']

	# Cache trim index values for determining a file's relative paths.
	dir_number_path = dir_number_path.rstrip(os.sep)
	subdir_trim_index = len(dir_number_path)
	path_trim_index = len(os.path.dirname(dir_number_path)) + len(os.sep)

	# Receive work from the queue.
	while True:
		item = queue.get()
		if item == None: # special item to stop the loop
			break
		elif abort_flag.value:
			continue
		try:
			extract_dir(file_extractors, subdir_trim_index, path_trim_index, next_dir_number_path, *item)
		except Exception as e:
			if util.raise_enospc and getattr(e, 'errno', None) == errno.ENOSPC:
				# Abort all threads if ENOSPC was raised.
				abort_flag.value = 1
				continue
			raise

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
		queue_size = options['threads'] + len(options['remote_servers'])
		queue = multiprocessing.Queue(maxsize=queue_size * 8)
		abort_flag = multiprocessing.Value('B', 0)
		initargs = (queue, abort_flag, dir_number_path, next_dir_number_path, options)
		mp_pool = multiprocessing.Pool(options['threads'], initializer=extract_process, initargs=initargs)
		print(flush=True)

		# Start remote clients.
		remote_clients = []
		for remote_server in options['remote_servers']:
			remote_clients.append(RemoteClient(remote_server, 'x', initargs))

		# Create next directory.
		if not os.path.isdir(next_dir_number_path):
			os.makedirs(next_dir_number_path)

		# Scan directory structure. I really wanted this to have file-level
		# granularity, but IntelExtractor and InterleaveBIOSExtractor
		# both require directory-level granularity for inspecting other files.
		found_any_files = False
		for scan_dir_path, scan_dir_names, scan_file_names in os.walk(dir_number_path):
			if len(scan_file_names) > 0:
				found_any_files = True
				queue.put((scan_dir_path, scan_file_names))
				if abort_flag.value: # stop feeding queue if a thread abort was requested
					break

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
		for _ in range(queue_size):
			queue.put(None)
		mp_pool.close()
		mp_pool.join()

		# Wait for remote clients to finish.
		for client in remote_clients:
			client.join()

		# Abort extraction if a thread abort was requested.
		if abort_flag.value:
			return 1

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
		flag_size = os.path.getsize(os.path.join(scan_dir_path, ':combined:'))
		if flag_size >= 2:
			combined = 'Interleaved'
			if flag_size > 2:
				combined += str(flag_size)

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

			# Run strings on the file data if required (only once if requested by analyzer).
			if analyzer.can_analyze():
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
		if type(combined) == str:
			bonus_analyzer_addons.append(combined)

		# Clean up the file path.
		scan_file_path_full = os.path.join(scan_dir_path, scan_file_name)

		# Remove combined directories.
		found_flag_file = True
		while found_flag_file:
			# Find archive indicator.
			archive_index = scan_file_path_full.rfind(':' + os.sep)
			if archive_index == -1:
				break

			# Check if a combined or header flag file exists.
			found_flag_file = False
			for flag_file in (':combined:', ':header:'):
				if os.path.exists(os.path.join(scan_file_path_full[:archive_index] + ':', flag_file)):
					# Trim the directory off.
					scan_file_path_full = scan_file_path_full[:archive_index]
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
			if len(oroms[x]) == 2: # PCI ROM
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
			else: # PnP ROM
				# Get PnP ID, vendor name and device name.
				device_id, vendor, device = oroms[x]

				# Extract ASCII letters from the PnP ID.
				pnp_id = ''.join(chr(0x40 + (letter & 0x1f)) for letter in (device_id >> 26, device_id >> 21, device_id >> 16))

				# Add the numeric part of the PnP ID.
				pnp_id += format(device_id & 0xffff, '04x').upper()

				# Clean up vendor and device names.
				vendor_device = ((vendor or '') + '\n' + (device or '')).replace('\r', '')
				vendor_device = '\n'.join(x.strip() for x in vendor_device.split('\n') if x.strip())

				# Format string.
				oroms[x] = '[{0}] {1}'.format(pnp_id, vendor_device.replace('\n', '\n' + (' ' * (len(pnp_id) + 3))))

		# Remove bogus option ROM device ID entries.
		while None in oroms:
			oroms.remove(None)

		# Add file name in single-file analysis.
		if not scan_dir_path and not scan_file_path:
			scan_file_path = os.path.basename(scan_base)

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

def analyze_process(queue, formatter, scan_base, options):
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
		analyzers.AmproAnalyzer(),
		analyzers.AmstradAnalyzer(),
		analyzers.CDIAnalyzer(),
		analyzers.CentralPointAnalyzer(),
		analyzers.ChipsAnalyzer(),
		analyzers.CommodoreAnalyzer(),
		analyzers.CompaqAnalyzer(),
		analyzers.CopamAnalyzer(),
		analyzers.CorebootAnalyzer(),
		analyzers.DTKGoldStarAnalyzer(),
		analyzers.GeneralSoftwareAnalyzer(),
		analyzers.IBMSurePathAnalyzer(),
		analyzers.IBMAnalyzer(),
		analyzers.ICLAnalyzer(),
		analyzers.InsydeAnalyzer(),
		analyzers.IntelUEFIAnalyzer(),
		analyzers.JukoAnalyzer(),
		analyzers.MRAnalyzer(),
		analyzers.MylexAnalyzer(),
		analyzers.OlivettiAnalyzer(),
		analyzers.PromagAnalyzer(),
		analyzers.SchneiderAnalyzer(),
		analyzers.SystemSoftAnalyzer(),
		analyzers.TandonAnalyzer(),
		analyzers.TinyBIOSAnalyzer(),
		analyzers.WhizproAnalyzer(),
		analyzers.ZenithAnalyzer(),
	]

	# Disable debug mode on analyzers.
	if not options['debug']:
		dummy_func = lambda self, *args: None
		for analyzer in file_analyzers:
			analyzer.debug_print = dummy_func
			analyzer.debug = False

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
	formatter.output_headers(['File', 'Vendor', 'Version', 'String', 'Sign-on', 'Add-ons', 'ROMs'], options.get('headers'))

	# Remove any trailing slash from the root path, as the output path cleanup
	# functions rely on it not being present.
	if dir_path[-len(os.sep):] == os.sep:
		dir_path = dir_path[:-len(os.sep)]
	elif dir_path[-1:] == '/':
		dir_path = dir_path[:-1]

	# Start multiprocessing pool.
	queue = multiprocessing.Queue(maxsize=options['threads'] * 8)
	mp_pool = multiprocessing.Pool(options['threads'], initializer=analyze_process, initargs=(queue, formatter, dir_path, options))

	if os.path.isdir(dir_path):
		# Scan directory structure.
		for scan_dir_path, scan_dir_names, scan_file_names in os.walk(dir_path):
			queue.put((scan_dir_path, scan_file_names))
	else:
		# Scan single file.
		queue.put(('', [dir_path]))

	# Stop multiprocessing pool and wait for its workers to finish.
	for _ in range(options['threads']):
		queue.put(None)
	mp_pool.close()
	mp_pool.join()

	# End output.
	formatter.end()

	return 0


# Remote server module.

class DummyAbortFlag:
	def __init__(self):
		self.value = False

class RemoteClient:
	"""State and functions for communicating with a remote server."""

	def __init__(self, addr, action, initargs):
		# Initialize state.
		self.action = action
		if isinstance(initargs[0], multiprocessing.Value):
			self.initargs = (DummyAbortFlag(),) + initargs[2:]
			self.abort_flag = initargs[0]
		else:
			self.initargs = initargs[1:]
			self.abort_flag = DummyAbortFlag()
		self.queue = initargs[0]

		self.sock = self.f = None
		self.queue_lock = threading.Lock()
		self.write_lock = threading.Lock()
		self.close_event = threading.Event()
		self.close_event.clear()

		# Parse address:port.
		addr_split = addr.split(':')
		self.port = DEFAULT_REMOTE_PORT
		if len(addr_split) == 0:
			return
		elif len(addr_split) == 1:
			self.addr = addr_split[0]
		else:
			self.port = int(addr_split[1])
			self.addr = addr_split[0]

		# Start client thread.
		self.queue_thread = None
		self.client_thread = threading.Thread(target=self.client_thread_func)
		self.client_thread.daemon = True
		self.client_thread.start()

	def client_thread_func(self):
		"""Thread function for a remote client."""

		# Connect to server.
		print('Connecting to {0}:{1}\n'.format(self.addr, self.port), end='')
		self.sock = socket.create_connection((self.addr, self.port))
		self.f = self.sock.makefile('rwb')
		print('Connected to {0}:{1}\n'.format(self.addr, self.port), end='')

		# Start multiprocessing pool.
		self.f.write((self.action + '\n').encode('utf8', 'ignore'))
		self.f.write(pickle.dumps(self.initargs))
		self.f.flush()

		# Read responses from server.
		while True:
			try:
				line = self.f.readline().rstrip(b'\r\n')
			except:
				break
			if not line:
				break

			if line[0:1] in b'xa':
				# Multiprocessing pool started, now start the queue thread.
				self.queue_thread = threading.Thread(target=self.queue_thread_func)
				self.queue_thread.daemon = True
				self.queue_thread.start()
			elif line[0:1] == b'q':
				# Allow queue thread to proceed.
				try:
					self.queue_lock.release()
				except:
					pass
			elif line[0:1] == b'j':
				# We're done.
				self.close_event.set()
				break

		# Close connection.
		try:
			self.f.close()
		except:
			pass
		try:
			self.sock.close()
		except:
			pass
		print('Disconnected from {0}:{1}\n'.format(self.addr, self.port), end='')

	def queue_thread_func(self):
		"""Thread function to remove items from the local
		   queue and push them to the remote server's queue."""

		while True:
			# Wait for the queue to be available.
			self.queue_lock.acquire()

			# Read queue item.
			item = self.queue.get()
			if item == None or self.abort_flag.value: # special item to stop the loop
				self.close()
				break

			# Send queue item to server.
			scan_dir_path, scan_file_names = item
			with self.write_lock:
				self.f.write(b'q' + scan_dir_path.encode('utf8', 'ignore'))
				for scan_file_name in scan_file_names:
					self.f.write(b'\x00' + scan_file_name.encode('utf8', 'ignore'))
				self.f.write(b'\n')
				self.f.flush()

	def close(self):
		"""Close connection to the server."""

		# Write stop message.
		with self.write_lock:
			try:
				self.f.write(b'j\n')
				self.f.flush()
			except:
				return

	def join(self):
		"""Wait for the server connection to be closed."""
		self.close_event.wait()

class RemoteServerClient:
	"""State and functions for communicating with remote clients."""

	def __init__(self, accept, options):
		# Initialize state.
		self.sock, self.addr = accept
		self.options = options
		self.queue = self.mp_pool = None
		self.write_lock = threading.Lock()
		self.queue_lock = threading.Lock()

		self.f = self.sock.makefile('rwb')

		# Start client thread.
		self.client_thread = threading.Thread(target=self.client_thread_func)
		self.client_thread.daemon = True
		self.client_thread.start()

	def client_thread_func(self):
		"""Thread function for a remote client."""

		print(self.addr, 'New connection')

		# Parse commands.		
		while True:
			try:
				line = self.f.readline().rstrip(b'\r\n')
			except:
				break
			if not line:
				break

			if line[0:1] in b'xa':
				# Start multiprocessing pool.
				print(self.addr, 'Starting pool for', (line[0] == b'x') and 'extraction' or 'analysis')
				self.queue = multiprocessing.Queue(maxsize=self.options['threads'] * 8)
				if line[0:1] == b'x':
					func = extract_process
				else:
					func = analyze_process
				self.mp_pool = multiprocessing.Pool(self.options['threads'], initializer=func, initargs=(self.queue,) + pickle.load(self.f))
			elif line[0:1] == b'q':
				# Add directory to queue.
				file_list = [item.decode('utf8', 'ignore') for item in line[1:].split(b'\x00')]
				if self.options['debug']:
					print(self.addr, 'Queuing', file_list[0], 'with', len(file_list) - 1, 'files')
				if self.queue:
					self.queue.put((file_list[0], file_list[1:]))
				else:
					print(self.addr, 'Attempted queuing with no queue')
			elif line[0:1] == b'j':
				# Stop multiprocessing pool and wait for its workers to finish.
				print(self.addr, 'Waiting for pool')
				if self.mp_pool and self.queue:
					for _ in range(self.options['threads']):
						self.queue.put(None)
					self.mp_pool.close()
					self.mp_pool.join()
					self.mp_pool = None
				else:
					print(self.addr, 'Attempted pool wait with no pool/queue')

			# Write acknowledgement.
			with self.write_lock:
				self.f.write(line[0:1] + b'\n')
				self.f.flush()

			# Stop if requested by the client.
			if line[0:1] == b'j':
				break

		# Close connection.
		print(self.addr, 'Closing connection')
		try:
			self.f.close()
		except:
			pass
		try:
			self.sock.close()
		except:
			pass
		if self.mp_pool:
			self.mp_pool.close()
			self.mp_pool.join()

def remote_server(dir_path, formatter_args, options):
	# Create server and listen for connections.
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind(('', options['remote_port']))
	server.listen(5)

	print('Listening on port', options['remote_port'])

	# Receive connections.
	try:
		while True:
			RemoteServerClient(server.accept(), options)
	except KeyboardInterrupt:
		pass

	# Close server.
	print('Closing server')
	server.close()

	return 0


def main():
	# Set default options.
	mode = None
	options = {
		'array': False,
		'debug': False,
		'enospc': False,
		'format': 'csv',
		'headers': True,
		'hyperlink': False,
		'threads': 0,
		'docker-usage': False,
		'remote_servers': [],
		'remote_port': 0,
	}

	# Parse arguments.
	args, remainder = getopt.gnu_getopt(sys.argv[1:], 'xadf:hnrt', ['extract', 'analyze', 'debug', 'format=', 'hyperlink', 'no-headers', 'array', 'threads', 'remote=', 'remote-server', 'docker-usage'])
	for opt, arg in args:
		if opt in ('-x', '--extract'):
			mode = extract
		elif opt in ('-a', '--analyze'):
			mode = analyze
		elif opt in ('-d', '--debug'):
			options['debug'] = True
		elif opt in ('-f', '--format'):
			options['format'] = arg.lower()
		elif opt in ('-h', '--hyperlink'):
			options['hyperlink'] = True
		elif opt in ('-n', '--no-headers'):
			options['headers'] = False
			options['enospc'] = True
		elif opt in ('-r', '--array'):
			options['array'] = True
		elif opt in ('-t', '--threads'):
			try:
				options['threads'] = int(arg)
			except:
				pass
		elif opt == '--remote':
			options['remote_servers'].append(arg)
		elif opt == '--remote-server':
			mode = remote_server
			try:
				options['remote_port'] = int(remainder[0])
			except:
				pass
			remainder.append(None) # dummy
		elif opt == '--docker-usage':
			options['docker-usage'] = True

	if len(remainder) > 0:
		# Set default numeric options.
		if options['threads'] <= 0:
			options['threads'] = options['debug'] and 1 or (os.cpu_count() or 4)
		if options['remote_port'] <= 0:
			options['remote_port'] = DEFAULT_REMOTE_PORT

		# Run mode handler.
		if mode:
			return mode(remainder[0], remainder[1:], options)

	# Print usage.
	if options['docker-usage']:
		usage = '''
Usage: docker run -v directory:/bios biostools [-d] [-f output_format] [-h] [-n] [-r] [formatter_options]

       Archives and BIOS images in the directory mounted to /bios will be
       extracted and analyzed.
'''
	else:
		usage = '''
Usage: python3 -m biostools [-d] [-n] [-t threads] -x directory
       python3 -m biostools [-d] [-f output_format] [-h] [-n] [-r] [-t threads]
                            -a directory|single_file [formatter_options]

       -x    Extract archives and BIOS images recursively in the given directory
       -n    Abort extraction if disk space runs out.

       -a    Analyze extracted BIOS images in the given directory, or a single
             extracted file (extracting with -x first is recommended)'''
	usage += '''
       -f    Output format:
                 csv        Comma-separated values with quotes (default)
                 scsv       Semicolon-separated values with quotes
                 json       JSON object array
                 jsontable  JSON table
       -h    Generate download links for file paths representing HTTP URLs.
             csv/scsv: The Excel HYPERLINK formula is used; if you have
                       non-English Excel, you must provide your language's
                       HYPERLINK formula name in formatter_options.
       -n    csv/scsv/jsontable: Don't output column headers.
       -r    json/jsontable: Output multi-value cells as arrays.

       Common options (applicable to both -x and -a modes):
       -d    Enable debug output.
       -t    Set number of threads to use.
'''
	print(usage, file=sys.stderr)
	return 1

if __name__ == '__main__':
	sys.exit(main())
