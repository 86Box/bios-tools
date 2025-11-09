import getopt, itertools, os, queue, subprocess, sys, threading, time, zlib

algos = ['lh5', 'lzari', 'lzh', 'notlzss', 'notlzari', 'notlzh'] + ['zl' + str(x) for x in itertools.chain(range(8, 16), [0], range(-15, -7), range(24, 32), range(40, 48))]
longest_algo = 0
thread_status = []
term_size = os.get_terminal_size()
result_line = 1
max_result_line = 1
longest_result_line = 0
info_offset = 0
info_offset_found = 0

print_lock = threading.Lock()
def print_(s):
	with print_lock:
		sys.stdout.write(s)
		sys.stdout.flush()

def print_thread():
	global info_offset
	global thread_status

	# Initialize thread status display.
	for thread_id in range(len(thread_status)):
		sys.stdout.write('\033[{0};1H{0}'.format(thread_id + 1))

	# Print thread status in a loop.
	while True:
		with print_lock:
			for thread_id in range(len(thread_status)):
				sys.stdout.write('\033[{0};{1}H{2}'.format(thread_id + 1, info_offset, thread_status[thread_id]))
			sys.stdout.flush()
		time.sleep(0.1)

def work_thread(thread_id, options, q):
	global longest_algo
	global info_offset
	global info_offset_found
	global thread_status
	global result_line
	global max_result_line
	global longest_result_line

	# Save some useful stuff for later.
	#exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bruteforce')
	exe_path = '/home/richard/bruteforce'
	process_args = [exe_path, '[magic]']
	output_base = os.path.join('bruteforce_out', os.path.basename(options['file_path']))

	while True:
		# Start process.
		proc = subprocess.Popen(process_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

		# Initialize thread status.
		thread_status[thread_id] = 'init'

		# Read file into buffer 0.
		with open(options['file_path'], 'rb') as f:
			data = f.read()
		proc.stdin.write('0;0\n{0}\n'.format(options['file_path']).encode('utf8', 'ignore'))
		proc.stdin.flush()

		# Read size of buffer 0.
		file_size = int(proc.stdout.readline().strip())
		if info_offset_found <= 0:
			info_offset_found = info_offset + longest_algo + (len(hex(file_size - 1)) - 2) + 3

		# Initialize buffer 1.
		proc.stdin.write('1;1;{0}\n'.format(options['decomp_buf_size']).encode('utf8', 'ignore'))
		proc.stdin.flush()

		# Read size of buffer 1.
		buf_size = int(proc.stdout.readline().strip())
		if buf_size < options['decomp_size']:
			options['decomp_size'] = buf_size

		# Work until the process dies.
		while True:
			# Receive work from the queue.
			item = q.get()
			if item == None: # special item to stop the loop
				proc.stdin.close()
				return

			offset, algo = item
			is_zl = algos[algo][:2] == 'zl'

			# Request decompression.
			if not is_zl:
				proc.stdin.write('3;0;{0};{1};1;0;{2};{3}\n'.format(offset, file_size - offset, options['decomp_size'], algo).encode('utf8', 'ignore'))
				proc.stdin.flush()

			# Set thread status.
			thread_status[thread_id] = algos[algo].ljust(longest_algo) + ' ' + hex(offset)[2:]

			# Read result.
			if is_zl:
				try:
					decompressed_data = zlib.decompress(data[offset:], wbits=int(algos[algo][2:]))
					decompressed = len(decompressed_data)
				except:
					decompressed_data = b''
					decompressed = 0
			else:
				try:
					decompressed = proc.stdout.readline()
				except:
					decompressed = b''
				if decompressed:
					decompressed = int(decompressed.strip())
				else:
					try:
						proc.kill()
					except:
						pass
					break

			# Check for success.
			found = None
			if options['byte_search']:
				if is_zl:
					found_offset = decompressed_data[:options['check_length']].find(options['byte_search'])
				else:
					# Request byte search.
					proc.stdin.write('4;1;0;{0};{1}\n'.format(options['check_length'], len(options['byte_search'])).encode('utf8', 'ignore'))
					proc.stdin.write(options['byte_search'])
					proc.stdin.flush()

					# Read result.
					found_offset = int(proc.stdout.readline().strip())

				# Print result.
				if found_offset > -1:
					found = '{0}+{1}'.format(hex(offset)[2:], hex(found_offset)[2:])
			elif decompressed >= options['check_length']:
				found = hex(offset)[2:]

			if found:
				with open(output_base + '.' + found, 'wb') as f:
					if is_zl:
						f.write(decompressed_data)
					else:
						# Request buffer read.
						if decompressed > 0:
							request_size = decompressed
						else:
							request_size = buf_size
						proc.stdin.write('2;1;0;{0}\n'.format(request_size).encode('utf8', 'ignore'))
						proc.stdin.flush()

						# Read data length.
						data_length = int(proc.stdout.readline().strip())

						# Write buffer data to file.
						f.write(proc.stdout.read(data_length))

				with print_lock:
					s = algos[algo] + ' ' + found
					if len(s) > longest_result_line:
						longest_result_line = len(s)
					if info_offset_found + len(s) < term_size.columns:
						sys.stdout.write('\033[{0};{1}H{2}'.format(result_line, info_offset_found, s))
						sys.stdout.flush()
						result_line += 1
						if result_line >= term_size.lines:
							result_line = 1
							info_offset_found += longest_result_line + 2
						elif result_line > max_result_line:
							max_result_line = result_line

def main():
	global longest_algo
	global info_offset
	global thread_status

	# Set default options.
	options = {
		'byte_search': None,
		'check_length': 0,
		'decomp_size': 0,
		'decomp_buf_size': 0,
		'offset': 0,
		'threads': 0
	}

	# Parse arguments.
	args, remainder = getopt.gnu_getopt(sys.argv[1:], 'b:l:d:s:o:t:', ['byte-search', 'byte-search-length', 'decomp-size', 'decomp-buf-size', 'offset', 'threads'])
	for opt, arg in args:
		if opt in ('-b', '--byte-search'):
			try:
				options['byte_search'] = eval('b\'' + arg.replace('\'', '\\\'') + '\'')
			except:
				pass
		elif opt in ('-l', '--check-length'):
			try:
				options['check_length'] = int(arg, 0)
			except:
				pass
		elif opt in ('-d', '--decomp-size'):
			try:
				options['decomp_size'] = int(arg, 0)
			except:
				pass
		elif opt in ('-s', '--decomp-buf-size'):
			try:
				options['decomp_buf_size'] = int(arg, 0)
			except:
				pass
		elif opt in ('-o', '--offset'):
			try:
				options['offset'] = int(arg, 0)
			except:
				pass
		elif opt in ('-t', '--threads'):
			try:
				options['threads'] = int(arg, 0)
			except:
				pass

	if len(remainder) < 1:
		print('Usage: python3 bruteforce.py [-b byte_search_escaped] [-l check_length] [-d decomp_size] [-s decomp_buf_size] [-o start_offset] [-t threads] file_path')
		return 1
	options['file_path'] = remainder[0]

	# Set more default options.
	if options['decomp_buf_size'] <= 0:
		options['decomp_buf_size'] = 16777216
	if options['decomp_size'] <= 0 or options['decomp_size'] > options['decomp_buf_size']:
		options['decomp_size'] = options['decomp_buf_size']
	if options['check_length'] <= 0:
		options['check_length'] = options['decomp_size']
	if options['offset'] <= 0:
		options['offset'] = 0
	if options['threads'] <= 0:
		options['threads'] = os.cpu_count() or 4

	# Clear screen.
	print_('\033c')

	# Create output directory.
	try:
		os.makedirs('bruteforce_out')
	except:
		pass

	# Prepare queue.
	q = queue.Queue(maxsize=options['threads'])

	# Start work threads.
	threads = []
	for thread_id in range(options['threads']):
		thread_status.append('')
		thread = threading.Thread(target=work_thread, args=(thread_id, options, q))
		thread.daemon = False
		thread.start()
		threads.append(thread)

	# Determine algorithms to use.
	for algo in range(len(algos)):
		if not options['byte_search'] and algo != 0: # only lh5 is complex enough to have return values
			algos[algo] = None

	# Start print thread.
	longest_algo = max(len(algo) for algo in algos if algo)
	info_offset = len(str(options['threads'])) + 2
	thread = threading.Thread(target=print_thread)
	thread.daemon = True
	thread.start()

	try:
		# Add every offset-algorithm combination.
		file_size = os.path.getsize(options['file_path'])
		for offset in range(options['offset'], file_size):
			for algo in range(len(algos)):
				if algos[algo]:
					q.put((offset, algo))

		# Stop threads.
		for _ in range(options['threads']):
			q.put(None)

		# Wait for threads.
		for thread in threads:
			thread.join()
	except KeyboardInterrupt:
		pass

	# Stop threads again.
	for _ in range(options['threads']):
		q.put(None)

	# Move cursor to a sane position.
	global result_line
	print_('\033[{0};1H'.format(max(options['threads'], max_result_line) + 1))

	return 0

if __name__ == '__main__':
	sys.exit(main())
