prodinfo_gen
============
prodinfo_gen is a Nintendo Switch payload that can generate barely-working, console-unique, PRODINFO files.

It can either generate one from scratch or modify a donor PRODINFO.

It is primarily aimed at people without a backup of their PRODINFO or building a NAND from scratch.

Limitations
===========

Of course, as we do not have Nintendo's private keys, the generated files can't be perfect.

What *should* work with a **"from scratch"** PRODINFO:
 - Booting
 - Launching homebrews

What *won't* work with a **"from scratch"** PRODINFO:
 - Communicating with Nintendo's servers
 - Amiibos (not tested)
 - GameCards

What *should* work with a **"from donor"** PRODINFO:
 - Booting
 - Launching homebrews
 - Amiibos (not tested)
 - GameCards (not tested)
 - Communicating with Nintendo's servers (RISK OF BEING BANNED, not tested)

USE THIS TOOL AT YOUR OWN RISK, DO NOT OVERWRITE A FACTORY PRODINFO WITHOUT MAKING A BACKUP FIRST.

Usage
=====
* Make sure you have a `/switch/prod.keys` file on your microSD card with a valid `master_key_00` in it.
* If you want to use a donor PRODINFO, place it at `/switch/donor_prodinfo.bin`.
* Launch prodinfo_gen.bin using your favorite payload injector or chainloader.
* You should find `/switch/generated_prodinfo_from_scratch.bin` or `/switch/generated_prodinfo_from_donor.bin` depending on what you selected.
* You can now write that PRODINFO to your NAND using a tool such as HacDiskMount.

Building
========
Install [devkitARM](https://devkitpro.org/) and run `make`.

Credits
=======
 - This software is based on **shchmue**'s [**Lockpick_RCM**](https://github.com/shchmue/Lockpick_RCM).
 - GCM encryption primitives from [**Atmosphère**](https://github.com/Atmosphere-NX/Atmosphere)
 - Most of the reverse engineering work comes from [**shchmue**](https://github.com/shchmue), [**PabloZaiden**](https://github.com/PabloZaiden), [**SwitchBrew**](https://switchbrew.org/wiki/Calibration)

License
=======
This project is under the GPLv2 license.