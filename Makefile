.PHONY: all

all:
	make -C bios_extract all
	make -C deark all
	make -C fdimg all

%:
	make -C bios_extract "$@"
	make -C deark "$@"
	case "$@" in all|clean) make -C fdimg "$@";; esac
