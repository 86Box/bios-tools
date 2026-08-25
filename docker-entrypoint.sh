#!/bin/sh
#
# 86Box          A hypervisor and IBM PC system emulator that specializes in
#                running old operating systems and software designed for IBM
#                PC systems and compatibles from 1981 through fairly recent
#                system designs based on the PCI bus.
#
#                This file is part of the 86Box BIOS Tools distribution.
#
#                Docker container entrypoint for running the tools.
#
#
#
# Authors:       RichardG, <richardg867@gmail.com>
#
#                Copyright 2022 RichardG.
#

# Skip extractor if the 0 directory exists and there's no 1 directory to append.
if [ ! -d /bios/0 -o -d /bios/1 ]
then
	# Print usage if there's no 1 directory (nothing bound to /bios).
	[ ! -d /bios/1 ] && exec python3 -u -m biostools --docker-usage >&2

	# Run extractor.
	python3 -u -m biostools -x /bios $* >&2

	# Fail if there's no 0 directory.
	[ ! -d /bios/0 ] && exit 1
fi

# Run analyzer.
exec python3 -u -m biostools -a /bios/0 $*
