prodinfo_gen [![Build Status](https://api.cirrus-ci.com/github/CaramelDunes/prodinfo_gen.svg)](https://cirrus-ci.com/github/CaramelDunes/prodinfo_gen)
============
prodinfo_gen is a Nintendo Switch payload that can generate barely-working, console-unique, PRODINFO files.

It can either generate one from scratch or import parts of a donor PRODINFO.

It is primarily aimed at people without a backup of their PRODINFO or building a NAND from scratch.

This tool is not meant to, and will not, unban a Switch console.

Limitations
===========

Of course, as we do not have Nintendo's private keys, the generated files can't be perfect.

What *should* work with a **"from scratch"** PRODINFO:
 - Booting
 - Launching homebrews

What *won't* work with a **"from scratch"** PRODINFO:
 - Communicating with Nintendo's servers
 - GameCards
 - Amiibos (not tested)

What *should* work with a **"from donor"** PRODINFO:
 - Booting
 - Launching homebrews
 - GameCards
 - Amiibos (not tested)

What *won't* work with a **"from donor"** PRODINFO:
 - Communicating with Nintendo's servers

 As such, a *"from scratch"* PRODINFO also acts as a more elaborate "Incognito". 

**USE THIS TOOL AT YOUR OWN RISK, DO NOT OVERWRITE A FACTORY PRODINFO WITHOUT MAKING A BACKUP FIRST.**

Usage
=====
* Make sure you have a `/switch/prod.keys` file on your microSD card with, at least, valid master keys in it.
* If you want to use a donor PRODINFO, place it at `/switch/donor_prodinfo.bin`. **Note:** If the donor is a patched or Mariko Switch, you will need to add the *donor's* `device_key_4x` key to the `prod.keys` file as `donor_device_key_4x`.
* Launch prodinfo_gen.bin using your favorite payload injector or chainloader.
* You should find `/switch/generated_prodinfo_from_scratch.bin` or `/switch/generated_prodinfo_from_donor.bin` depending on what you selected.
* You can now write that PRODINFO to your NAND using a tool such as HacDiskMount (*it is recommended to make a backup of the current PRODINFO first*).

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