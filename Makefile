.PHONY: all

all:
	make -C bios_extract all
	make -C deark all

%:
	make -C bios_extract "$@"
	make -C deark "$@"
