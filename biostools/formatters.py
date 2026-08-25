#!/usr/bin/python3
#
# 86Box          A hypervisor and IBM PC system emulator that specializes in
#                running old operating systems and software designed for IBM
#                PC systems and compatibles from 1981 through fairly recent
#                system designs based on the PCI bus.
#
#                This file is part of the 86Box BIOS Tools distribution.
#
#                Data output formatting classes.
#
#
#
# Authors:       RichardG, <richardg867@gmail.com>
#
#                Copyright 2021 RichardG.
#
import json, os, re

class Formatter:
	def __init__(self, out_file, options, args):
		"""Initialize a formatter with the given output file and options."""

		self.out_file = out_file
		self.options = options
		self.args = args

		self.array = options.get('array')

	def begin(self):
		"""Begin the formatter's output."""
		pass

	def end(self):
		"""End the formatter's output."""
		pass

	def get_url(self, columns):
		"""Returns the download URL for a given row."""

		# Start building the URL.
		link_url = columns[0]

		# Remove www from original path.
		if columns[0][:4] == 'www.':
			columns[0] = columns[0][4:]
		
		# Make sure the components are slash-separated.
		if os.sep != '/':
			link_url = link_url.replace(os.sep, '/')

		# Stop at the first decompression layer.
		archive_index = link_url.find(':/')
		if archive_index > -1:
			link_url = link_url[:archive_index]

		# Encode the URL.
		link_url = link_url.replace('#', '%23')
		link_url = re.sub(r'''\?(^[/]*)/''', '%3F\\1/', link_url)

		# Stop if the URL is not valid.
		slash_index = link_url.find('/')
		if slash_index == -1 or '.' not in link_url[:slash_index]:
			return ''
		
		return 'http://' + link_url

	def join_if_required(self, c, l):
		"""Returns just l if array mode is enabled, or l joined by c otherwise."""
		if self.array:
			return l
		else:
			return c.join(l)

	def output_headers(self, columns, do_output):
		"""Output column headers."""
		if do_output:
			self.output_row(columns)

	def output_row(self, columns):
		"""Output an item."""
		raise NotImplementedError()

	def split_if_required(self, c, s):
		"""Returns s split by c if array mode is enabled, or just s otherwise."""
		if self.array:
			return s.split(c)
		else:
			return s


class XSVFormatter(Formatter):
	def __init__(self, delimiter, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Not supported here.
		self.array = False

		self.delimiter = delimiter
		self.query = True

		if self.options.get('hyperlink'):
			# Get the localized HYPERLINK formula name if specified.
			if self.args:
				self.hyperlink = self.args[0]
			else:
				self.hyperlink = 'HYPERLINK'
		else:
			self.hyperlink = None

	def output_row(self, columns):
		# Add hyperlink if requested.
		output = ''
		if self.hyperlink:
			link_url = self.get_url(columns)
			if link_url:
				link_prefix = '=' + self.hyperlink + '(""'
				link_suffix = '""' + ';' + '""\U0001F53D"")' # down arrow emoji

				# Build and output the final link, accounting for Excel's column size limit in connection (not query) mode.
				if self.query:
					link = link_prefix + link_url + link_suffix
				else:
					link = link_prefix + link_url[:256 - len(link_prefix) - len(link_suffix)] + link_suffix
				output += '"' + link + '"'
			else:
				output += '""'

		# Add fields.
		for field in columns:
			if output:
				output += self.delimiter
			output += '"'
			if self.query:
				output += field.replace('"', '""')
			else:
				# Account for Excel's column size limit and lack of linebreak support in connection (not query) mode.
				output += field.replace('\n', ' - ').replace('"', '""')[:256]
			output += '"'

		# Add linebreak.
		output += '\n'

		# Write row.
		self.out_file.write(output)


class JSONFormatter(Formatter):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.hyperlink = self.options.get('hyperlink')

	def begin(self):
		# Start root list.
		self.out_file.write('[')
		self.first_row = True

	def end(self):
		# End root list.
		self.out_file.write(']\n')

	def get_json_object(self, columns):
		"""Returns the JSON object to be output for this row."""
		raise NotImplementedError()

	def output_headers(self, columns, do_output):
		# Insert URL column if requested.
		hyperlink = self.hyperlink
		if hyperlink:
			columns.insert(0, 'URL')

		# Prevent output_row from adding a null header.
		self.hyperlink = False
		super().output_headers(columns, do_output)
		self.hyperlink = hyperlink

	def output_row(self, columns):
		# Add URL if requested.
		if self.hyperlink:
			columns.insert(0, self.get_url(columns))

		# Write row.
		obj = self.get_json_object(columns)
		if obj:
			if self.first_row:
				self.first_row = False
			else:
				self.out_file.write('\n,')
			self.out_file.write(json.dumps(obj))

class JSONObjectFormatter(JSONFormatter):
	def get_json_object(self, columns):
		return {self.headers[column_index]: columns[column_index] for column_index in range(len(columns)) if columns[column_index]}

	def output_headers(self, columns, do_output):
		# Insert URL column if requested.
		if self.hyperlink:
			columns.insert(0, 'URL')

		# Save column headers for later.
		self.headers = [column.lower().replace(' ', '').replace('-', '') for column in columns]

class JSONTableFormatter(JSONFormatter):
	def get_json_object(self, columns):
		return columns
