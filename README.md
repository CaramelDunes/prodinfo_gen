prodinfo_gen
============
Lockpick_RCM is a bare metal Nintendo Switch payload that derives encryption keys for use in Switch file handling software like hactool, hactoolnet/LibHac, ChoiDujour, etc. without booting Horizon OS.

Due to changes imposed by firmware 7.0.0, Lockpick homebrew can no longer derive the latest keys. In the boot-time environment however, there is no such limitation.

Usage
=
* It is highly recommended, but not required, to place Minerva on SD from the latest [Hekate](https://github.com/CTCaer/hekate/releases) for best performance, especially while dumping titlekeys - the file and path is `/bootloader/sys/libsys_minerva.bso`
* Launch Lockpick_RCM.bin using your favorite payload injector or chainloader
* Upon completion, keys will be saved to `/switch/prod.keys` and titlekeys to `/switch/title.keys` on SD
* If the console has Firmware 7.x or higher, the `/sept/` folder from [Atmosphère](https://github.com/Atmosphere-NX/Atmosphere/releases) or [Kosmos](https://github.com/AtlasNX/Kosmos/releases) release zip must be present on SD or else only keyblob master key derivation is possible (ie. up to `master_key_05` only)

Building
=
Install [devkitARM](https://devkitpro.org/) and run `make`.

Massive Thanks to CTCaer!
=
This software is heavily based on [Hekate](https://github.com/CTCaer/hekate). Beyond that, CTCaer was exceptionally helpful in the development of this project, lending loads of advice, expertise, and humor.

License
=
This project is under the GPLv2 license. The Save processing module is adapted from [hactool](https://github.com/SciresM/hactool) code under ISC.