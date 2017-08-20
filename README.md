Virtual Machine Introspection Library
=====================================

This library allows easy inspection of VM's state by exposing as much debug
information as possible. Debug information can come from the guest VM itself,
compiled binaries with debug information, etc.

libvmi relies on libelf and libdwarf to do the actual debug info parsing.

libvmi can be used by S2E plugins. Currently the following file formats are
supported:

* PE
* DECREE
* ELF
