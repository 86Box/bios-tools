86Box BIOS Tools
================
A full toolkit for analyzing and extracting x86 BIOS ROM images (mostly) within the context of the 86Box project.

## System requirements

* **Linux**. Unfortunately, we rely on tools which contain non-portable code and generate filenames that are invalid for Windows.
* **Python 3.5** or newer.
* **Standard gcc toolchain** for building the essential `bios_extract` tool.

## Installation

1. Clone this repository.
2. Build the `bios_extract` tool:

```
cd bios_extract
make
```

3. Download the `uefiextract` tool from its [GitHub repository](https://github.com/LongSoft/UEFITool/releases) and place its executable on the repository's root directory. Prebuilt versions are only available for `x86_64`, but this tool is optional; UEFI extraction will not work without it.
4. Optionally run this command to install a dependency required for BIOS logo extraction:

```
pip install -r requirements.txt
```

## Usage

1. Create a directory, which will be called `roms` here.
2. Create a `1` directory within `roms`.
3. Place BIOS ROM images, archives, disk images, flasher executables and what have you inside the `1` directory. Subdirectories will also be checked.
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
* PCX (AMI) and EPA (Award) images are automatically converted to PNG if the aforementioned optional dependency is installed.
* Some Intel motherboard BIOSes (particularly from the AMIBIOS 6 era) will not be extracted properly due to a different address line inversion mechanism. This is a known issue with the Intel update format concatenator which may eventually be solved.
* Extraction of the following BIOS distribution formats is **not implemented** due to the use of unknown compression methods:
  * Evergreen ETI (an ugly hack exists)
  * IBM Sydex floppy self-extractor (it looks like CopyQM RLE but isn't)

## Analysis notes

### AMI

* **Pre-Color** (1990 and older) BIOSes have a dynamically-generated string that is not easily extractable; the analyzer will attempt to reconstruct it around the limited data contained in the ROM in a best-effort basis.
* The string on **UEFI** is a hidden string located within the AMIBIOS 8-based Compatibility Support Module (CSM). A missing string may indicate a lack of CSM.

### Award

* The core version can be followed by `(Phoenix)` on BIOSes which identify as **Phoenix AwardBIOS**, or `(Workstation)` on ones which identify as **Award WorkstationBIOS**.
* OEM modifications which interfere with detection: **Sukjung** (string)

### IBM

* The FRU codes contained in PC or PS/2 ROMs are interpreted as the string.

### Phoenix

* Identification is **not perfect**, as the location of identification data varies from version to version, and a lot of OEMs mess with it.
* Phoenix has no concept of a string. Any date or time found in the BIOS is interpreted as the string.

## Add-on reference

Depending on the contents of each BIOS, the following tags may be displayed on the analyzer output's "Add-ons" column:

* **ACPI**: Appears to contain an ACPI table. Does not necessarily indicate ACPI actually works.
* **Adaptec**: Adaptec ISA or PCI SCSI option ROM.
* **NCR3/4**: NCR PCI SCSI option ROM with SDMS version 3 or 4 (respectively).
* **PXE**: PXE-compliant network boot ROM, usually associated with on-board Ethernet.
* **RPL**: Novell NetWare RPL-compliant network boot ROM, usually associated with on-board Ethernet.
* **SLI**: NVIDIA SLI license for non-nForce motherboards.
* **UEFI**: The BIOS core is UEFI-compliant. Does not necessarily indicate UEFI support is available.
* **VGA**: Video BIOS, usually associated with on-board video.

### BIOS-specific add-ons

* AMIBIOS (Color through 7) setup types: **Color**, **EasySetup**, **HiFlex**, **NewSetup**, **SimpleSetup**, **WinBIOS**.
* Award: **PhoenixNet** indicates the presence of PhoenixNet features, even if those were disabled by the OEM. **UEFI** indicates Gigabyte Hybrid EFI.
