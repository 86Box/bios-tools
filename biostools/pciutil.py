#!/usr/bin/python3
#
# 86Box          A hypervisor and IBM PC system emulator that specializes in
#                running old operating systems and software designed for IBM
#                PC systems and compatibles from 1981 through fairly recent
#                system designs based on the PCI bus.
#
#                This file is part of the 86Box BIOS Tools distribution.
#
#                Utility library for identifying PCI device/vendor IDs.
#
#
#
# Authors:       RichardG, <richardg867@gmail.com>
#
#                Copyright 2021 RichardG.
#
import io, re, urllib.request

clean_device_abbr = [
	# Generic patterns to catch extended abbreviations: "Abbreviated Terms (AT)"
	(r'([A-Z])[^- ]+[- ]([A-Z])[^ ]+ (?:\(|\[|\{|/)\\2\\3(?:$|\)|\]|\})', '\\2\\3'),
	(r'([A-Z])[^- ]+[- ]([A-Z])[^- ]+[- ]([A-Z])[^ ]+ (?:\(|\[|\{|/)\\2\\3\\4(?:$|\)|\]|\})', '\\2\\3\\4'),
	(r'([A-Z])[^- ]+[- ]([A-Z])[^- ]+[- ]([A-Z])[^- ]+[- ]([A-Z])[^ ]+ (?:\(|\[|\{|/)\\2\\3\\4\\5(?:$|\)|\]|\})', '\\2\\3\\4\\5'),

	# Manual patterns
	('100Base-TX?', 'FE'),
	('1000Base-T', 'GbE'),
	('Accelerat(?:ion|or)', 'Accel.'),
	('Alert on LAN', 'AoL'),
	(r'\((.+) applications?\)', '(\\2)'), # 8086:105e
	('Chipset Family', 'Chipset'),
	('Chipset Graphics', 'iGPU'),
	('Connection', 'Conn.'),
	('DECchip', ''),
	('Dual (Lane|Port)', '2-\\2'),
	('Fast Ethernet', 'FE'),
	('Fibre Channel', 'FC'),
	('Function', 'Func.'),
	('([0-9]{1,3})G Ethernet', '\\2GbE'),
	('(?:([0-9]{1,3}) ?)?(?:G(?:bit|ig) Ethernet|GbE)', '\\2GbE'),
	('Graphics Processor', 'GPU'),
	('High Definition Audio', 'HDA'),
	('Host Adapter', 'HBA'),
	('Host Bus Adapter', 'HBA'),
	('Host[- ]Controller', 'HC'), # dash = 1106:3104
	('Input/Output', 'I/O'),
	(r'Integrated ([^\s]+) (?:Graphics|GPU)', '\\2 iGPU'), # VIA CLE266
	('Integrated (?:Graphics|GPU)', 'iGPU'),
	('([0-9]) (lane|port)', '\\2-\\3'),
	('Local Area Network', 'LAN'),
	('Low Pin Count', 'LPC'),
	('Memory Controller Hub', 'MCH'),
	('Network (?:Interface )?(?:Adapter|Card|Controller)', 'NIC'),
	('NVM Express', 'NVMe'),
	('Parallel ATA', 'PATA'),
	('PCI(?:-E|[- ]Express)', 'PCIe'),
	('([^- ]+)[- ]to[- ]([^- ]+)', '\\2-\\3'),
	('Platform Controller Hub', 'PCH'),
	('Processor Graphics', 'iGPU'),
	('Quad (Lane|Port)', '4-\\2'),
	('Serial ATA', 'SATA'),
	('Serial Attached SCSI', 'SAS'),
	('Single (Lane|Port)', '1-\\2'),
	('USB ?([0-9])\\.0', 'USB\\2'),
	('USB ?([0-9])\\.[0-9] ?Gen([0-9x]+)', 'USB\\2.\\3'),
	('USB ?([0-9]\\.[0-9])', 'USB\\2'),
	('Virtual Machine', 'VM'),
	('Wake on LAN', 'WoL'),
	('Wireless LAN', 'WLAN'),

	# Generic pattern to remove duplicate abbreviations: "AT (AT)"
	(r'([^ \(\[\{/]+) (?: |\(|\[|\{|/)\\2(?: |\)|\]|\})', '\\2'),
]
clean_device_bit_pattern = re.compile(r'''( |^|\(|\[|\{|/)(?:([0-9]{1,4}) )?(?:(K)(?:ilo)?|(M)(?:ega)?|(G)(?:iga)?)bit( |$|\)|\]|\})''', re.I)
clean_device_suffix_pattern = re.compile(r''' (?:Adapter|Card|Device|(?:Host )?Controller)( (?: [0-9#]+)?|$|\)|\]|\})''', re.I)
clean_vendor_abbr_pattern = re.compile(r''' \[([^\]]+)\]''')
clean_vendor_suffix_pattern = re.compile(r'''[ ,.](?:Semiconductors?|(?:Micro)?electronics?|Interactive|Technolog(?:y|ies)|(?:Micro)?systems|Computer(?: works)?|Products|Group|and subsidiaries|of(?: America)?|Co(?:rp(?:oration)?|mpany)?|Inc|LLC|Ltd|GmbH(?: & .+)?|AB|AG|SA|(?:\(|\[|\{).*)$''', re.I)
clean_vendor_force = {
	'National Semiconductor Corporation': 'NSC',
}
clean_vendor_final = {
	'Chips and': 'C&T',
	'Digital Equipment': 'DEC',
	'Integrated Technology Express': 'ITE',
	'Microchip Technology/SMSC': 'Microchip/SMSC',
	'NVidia/SGS Thomson': 'NVIDIA/ST',
	'S3 Graphics': 'S3',
	'Silicon Integrated': 'SiS',
	'Silicon Motion': 'SMI',
	'STMicroelectronics': 'ST',
	'Texas Instruments': 'TI',
	'VMWare': 'VMware',
}

_clean_device_abbr_cache = []
_pci_vendors = {}
_pci_devices = {}
_pci_subdevices = {}
_pci_classes = {}
_pci_subclasses = {}
_pci_progifs = {}

def clean_device(device, vendor=None):
	"""Make a device name more compact if possible."""

	# Generate pattern cache if required.
	if not _clean_device_abbr_cache:
		for pattern, replace in clean_device_abbr:
			_clean_device_abbr_cache.append((
				re.compile(r'''(?P<prefix> |^|\(|\[|\{|/)''' + pattern + r'''(?P<suffix> |$|\)|\]|\})''', re.I),
				'\\g<prefix>' + replace + '\\g<suffix>',
			))

	# Apply patterns.
	device = clean_device_bit_pattern.sub('\\1\\2\\3\\4\\5bit\\6', device)
	for pattern, replace in _clean_device_abbr_cache:
		device = pattern.sub(replace, device)
	device = clean_device_suffix_pattern.sub('\\1', device)

	# Remove duplicate vendor ID.
	if vendor and device[:len(vendor)] == vendor:
		device = device[len(vendor):]

	# Remove duplicate spaces.
	return ' '.join(device.split())

def clean_vendor(vendor):
	"""Make a vendor name more compact if possible."""

	# Apply force table.
	vendor_force = clean_vendor_force.get(vendor, None)
	if vendor_force:
		return vendor_force

	# Use an abbreviation if the name already includes it.
	vendor = vendor.replace(' / ', '/')
	match = clean_vendor_abbr_pattern.search(vendor)
	if match:
		return match.group(1)

	# Apply patterns.
	match = True
	while match:
		vendor = vendor.rstrip(' ,.')
		match = clean_vendor_suffix_pattern.search(vendor)
		if match:
			vendor = vendor[:match.start()]

	# Apply final cleanup table.
	vendor = clean_vendor_final.get(vendor, vendor)

	# Remove duplicate spaces.
	return ' '.join(vendor.split())

def download_compressed(url, skip_exts=[]):
	"""Downloads a file which may be available in compressed versions."""

	# Try all files.
	for ext, module_name in (('.xz', 'lzma'), ('.bz2', 'bz2'), ('.gz', 'gzip'), (None, None)):
		# Skip extension if requested.
		if ext in skip_exts:
			continue

		# Import decompression module if required.
		if module_name:
			try:
				module = __import__(module_name)
			except:
				continue

		# Connect to URL.
		try:
			f = urllib.request.urlopen(url + (ext or ''), timeout=30)
		except:
			# Move on to the next file if the connection failed.
			continue

		# If this is uncompressed, return the file handle as is.
		if not module_name:
			return f

		# Decompress data into a BytesIO object.
		try:
			return io.BytesIO(module.decompress(f.read()))
		except:
			# Move on to the next file if decompression failed.
			continue

	# No success with any files.
	raise FileNotFoundError('All attempts to download "{0}" and variants thereof have failed'.format(url))

def get_pci_id(vendor_id, device_id):
	"""Get the PCI device vendor and name for vendor_id and device_id."""

	# Load PCI ID database if required.
	if not _pci_vendors:
		load_pci_db()

	# Get identification.
	vendor = _pci_vendors.get(vendor_id, '').strip()
	return vendor or '[Unknown]', _pci_devices.get((vendor_id << 16) | device_id, vendor and '[Unknown]' or '').strip()

def load_pci_db():
	"""Loads PCI ID database from disk or the website."""

	# Try loading from disk or the website.
	try:
		f = open('/usr/share/misc/pci.ids', 'rb')
	except:
		try:
			f = download_compressed('https://pci-ids.ucw.cz/v2.2/pci.ids', ['.xz'])
		except:
			# No sources available.
			return

	vendor = 0
	class_num = subclass_num = None
	for line in f:
		if len(line) < 2 or line[0] == 35:
			continue
		elif line[0] == 67: # class
			class_num = int(line[2:4], 16)
			_pci_classes[class_num] = line[6:-1].decode('utf8', 'ignore')
		elif class_num != None: # subclass/progif
			if line[1] != 9: # subclass
				subclass_num = (class_num << 8) | int(line[1:3], 16)
				_pci_subclasses[subclass_num] = line[5:-1].decode('utf8', 'ignore')
			else: # progif
				progif_num = (subclass_num << 8) | int(line[2:4], 16)
				_pci_progifs[progif_num] = line[6:-1].decode('utf8', 'ignore')
		elif line[0] != 9: # vendor
			vendor = int(line[:4], 16)
			_pci_vendors[vendor] = line[6:-1].decode('utf8', 'ignore')
		elif line[1] != 9: # device
			device = (vendor << 16) | int(line[1:5], 16)
			_pci_devices[device] = line[7:-1].decode('utf8', 'ignore')
		else: # subdevice
			subdevice = (int(line[2:6], 16) << 16) | int(line[7:11], 16)
			if device not in _pci_subdevices:
				_pci_subdevices[device] = {}
			_pci_subdevices[device][subdevice] = line[13:-1].decode('utf8', 'ignore')

	f.close()

# Debugging feature.
if __name__ == '__main__':
	s = input()
	try:
		if len(s) in (8, 9):
			vendor, device = get_pci_id(int(s[:4], 16), int(s[-4:], 16))
			vendor = clean_vendor(vendor)
			print(vendor)
			print(clean_device(device, vendor))
		else:
			raise Exception('not id')
	except:
		print(clean_device(s))
