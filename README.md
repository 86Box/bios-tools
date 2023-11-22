86Box BIOS Tools
================
A toolkit for extracting and analyzing x86 BIOS ROM images (mostly) within the context of the 86Box project.

## Test drive

**86Bot** on the [86Box Discord](https://86box.net/#social) has a BIOS analysis feature which uses BIOS Tools behind the scenes. Go to the `#bot-spam` channel and use the `!bios` command with an attached file or an URL. Other commands which work the same way and also leverage these tools are `!acpi` for extracting and decompiling ACPI tables, and `!epa` for extracting logo images.

## Quick usage through Docker

1. Build the Docker image from this repository:

```sudo docker build -t biostools "https://github.com/86Box/bios-tools.git#main"```

2. Create a destination directory, which will be called `roms` here.
3. Create a `1` directory within `roms`.
4. Place BIOS ROM images, archives, disk images, flasher executables and what have you in the `1` directory. Subdirectories will also be checked. **These files will be deleted during the extraction process.**
5. Run the container, binding `/bios` to the directory created in step 2:

```sudo docker run --rm -v /path/to/roms:/bios biostools | tee bioslist.csv```

6. Import the resulting `bioslist.csv` file to Excel, or do whatever else you want to do with it. Other output formats can be selected through arguments to the container (after `biostools`); run `sudo docker run --rm biostools` to see a full list of supported arguments.

## Manual usage

### System requirements

* **Linux**. Unfortunately, we rely on tools which contain non-portable code and generate filenames that are invalid for Windows, as well as GNU-specific extensions to shell commands. WSL should work for Windows users.
* **Python 3.5** or newer.
* **Standard gcc toolchain** for building the essential `bios_extract` tool.
* **7-Zip** command line utility installed as `7z`.
* **QEMU** (`qemu-system-i386`) for optionally extracting files which need to be executed.
* **Unshield** for optionally extracting InstallShield installers.

### Installation

1. Clone this repository.
2. Build the `bios_extract` and `deark` tools:

```
cd /path/to/bios-tools
make
```

3. Download the `UEFIExtract` tool from its [GitHub repository](https://github.com/LongSoft/UEFITool/releases) and place its executable on the repository's root directory. Prebuilt versions are only available for `x86_64`, but this tool is optional, and only required for UEFI extraction.
4. Optionally install a dependency required for BIOS logo extraction:

```
pip install -r requirements.txt
```

### Usage

1. Create a destination directory, which will be called `roms` here.
2. Create a `1` directory within `roms`.
3. Place BIOS ROM images, archives, disk images, flasher executables and what have you in the `1` directory. Subdirectories will also be checked. **These files will be deleted during the extraction process.**
4. Run the extractor, pointing it to the directory created in step 1:

```
python3 -m biostools -x roms
```

5. The extracted file structure will be located in `roms/0`. Individual files are extracted to directories named after the original file's name followed by `:`.
6. Run the analyzer, pointing it to the `0` directory and redirecting its output to a `bioslist.csv` file:

```
python3 -m biostools -a roms/0 | tee bioslist.csv
```

7. Import the resulting `bioslist.csv` file to Excel, or do whatever else you want to do with it. Other output formats can be selected through arguments to `-a`; run `python3 -m biostools` to see a full list of supported arguments.

## Extraction notes

* Many common file types known not to be useful, such as images, PDFs, Office documents and hardware information tool reports, are automatically discarded.
* Interleaved ROMs are merged through a heuristic filename and string detection, which may lead to incorrect merging if the chunks to different interleaved ROMs are present in the same directory.
* The FAT filesystem extractor relies on assumptions which may not hold true for all disk images.
* EPA (Award), PCX (AMI), PGX (Phoenix) and other image formats are automatically converted to PNG if the aforementioned optional dependency is installed.
* Extraction of the following BIOS distribution formats is **not implemented** due to the use of unknown compression methods:
  * ICL `.LDB`

## Analysis notes

### AMI

* The string on **UEFI** is a hidden string located within the AMIBIOS 8-based Compatibility Support Module (CSM). A missing string may indicate a missing CSM.
* Metadata tag **Setup** indicates the setup type for AMIBIOS Color through 7: **Color**, **Easy**, **HiFlex**, **Intel**, **New**, **Simple** or **WinBIOS**.

### Award

* OEM modifications which may interfere with detection: **Sukjung** (string)
* Metadata tag **PhoenixNet** indicates the presence of PhoenixNet features, even if those were disabled by the OEM, and contains its splash screen's sign-on text.
* Metadata tag **UEFI** indicates Gigabyte Hybrid EFI.

### IBM

* The FRU codes contained in PC or PS/2 ROMs are interpreted as the string.

### Phoenix

* Some OEMs have modified Phoenix to a point where detection may not be perfect.

### SystemSoft

* Insyde-compressed modules (identified by magic bytes `FF 88`) cannot be decompressed, limiting the analyzer's ability to identify Insyde-branded SystemSoft BIOSes.

## Metadata reference

Depending on the contents of each BIOS, the following tags may be displayed on the analyzer output's "Metadata" column:

* **ACPI**: Appears to contain the ACPI tables specified. Does not necessarily indicate ACPI actually works.
* **Build**: Build information contained within the BIOS.
* **ID**: How the BIOS identifies itself during POST.
* **LAN**: PXE or Novell NetWare RPL-compliant network boot ROM, usually associated with on-board Ethernet.
* **SCSI**: Adaptec or NCR/Symbios SCSI option ROM. Model (Adaptec) or SDMS version (NCR/Symbios) information is extracted from the ROM.
* **SLI**: NVIDIA SLI license for non-nForce motherboards. Model information is extracted from the license header.
* **Table**: Register table information contained within the BIOS. May help in identifying chipset and Super I/O devices.
* **UEFI**: Appears to contain traces of UEFI. Does not necessarily indicate UEFI support is available.
* **VGA**: Non-PCI video BIOS, usually associated with on-board video.
