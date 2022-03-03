#
# 86Box          A hypervisor and IBM PC system emulator that specializes in
#                running old operating systems and software designed for IBM
#                PC systems and compatibles from 1981 through fairly recent
#                system designs based on the PCI bus.
#
#                This file is part of the 86Box BIOS Tools distribution.
#
#                Dockerfile for running the tools in a container.
#
#
#
# Authors:       RichardG, <richardg867@gmail.com>
#
#                Copyright 2022 RichardG.
#

# Create intermediary builder image.
FROM debian:bullseye AS builder

# Install build dependencies.
RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential wget unzip && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists

# Download UEFIExtract.
RUN mkdir /biostools && cd /biostools && \
	wget -O uefiextract.zip https://github.com/LongSoft/UEFITool/releases/download/A59/UEFIExtract_NE_A59_linux_x86_64.zip && \
	unzip -o uefiextract.zip && \
	rm -f uefiextract.zip

# Insert repository contents.
COPY . /biostools

# Compile bios_extract.
RUN cd /biostools/bios_extract && \
	make

# Create final image.
FROM debian:bullseye

# Install runtime dependencies.
RUN sed -i -e 's/main/main contrib non-free/' /etc/apt/sources.list && \
	apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip p7zip-full p7zip-rar qemu-system-x86 && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists

# Copy repository contents from the intermediary image.
COPY --from=builder /biostools /biostools

# Install Python dependencies.
RUN pip install -r /biostools/requirements.txt

# Establish directories.
VOLUME /bios
WORKDIR /biostools

# Run our entry point script.
ENTRYPOINT ["/bin/sh", "/biostools/docker-entrypoint.sh"]
