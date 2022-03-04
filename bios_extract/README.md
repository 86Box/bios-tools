bios_extract
============
Fork of the [coreboot bios_extract tool](https://github.com/coreboot/bios_extract) modified for our needs.

## Modifications

* Added some sanity checks
* Improved AMI, Award and Phoenix BIOS detection
* Improved AMIBIOS extraction
* Improved Award extraction on semi-compressed v4.50 BIOSes
* Added AMIBIOS WinBIOS (12/15/93), 4 (07/25/94) and 5 (10/10/94) extraction
* Added AMIBIOS AFUDOS decompression
* Added LH5 extraction bruteforcing for Intel AMI Color fork
* Improved Phoenix extraction based on PHOEDECO
* Added SystemSoft extraction based on SYSODECO
