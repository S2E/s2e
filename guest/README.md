# S2E Guest Tools #

This repository contains various tools to be installed and run in the guest OS
in order to improve symbolic execution performance. These tools are optional,
but simplify many of the common tasks such as transfering files between the host
and the guest while running in S2E mode, monitoring guest OS events (e.g.,
process loads, program crashes, etc.), and injecting symbolic values in programs.


Windows
-------

Contains Windows drivers and utilities to run symbolic execution. See README.md
in that subfolder for more information.

Linux
-----

Contains Linux-specifc guest tools. The most important is a shared library
called ```s2e.so``` that can be LD_PRELOADed in the program under analysis.
This library takes care of symbolic command line arguments, function models,
etc.

Common
------

These are tools that can be used both on Windows and Linux. CMake requires
MINGW64 in order to cross-compile for Windows. There are three important tools:

* ```s2eget```: downloads files from the host into the guest. It can be used
in scenarios where there is no real network, as is often the case during
symbolic execution. This is similar to the concept of "shared folders" in
other virtual machine environments.

* ```s2eput```: uploads files from the guest to the host. This is useful to
save per-path data, such as core dumps, bug reports, and other experimental
results.

* ```s2ecmd```: contains various commands that are useful in shell scripts.
Among them, creating symbolic files and fetching seeds from the host.

In addition to these tools, the ```include``` folder contains S2E header files
for use by guest testing infrastructure. These headers expose the S2E engine API
and plugin functionality to the guest.

S2E BIOS
--------

This contains basic infrastructure code to run pieces of code on bare metal, without
any operating system, programs, devices, or even BIOS interfering with execution. This is especially
useful when debugging and testing the execution engine. The S2E BIOS provides
a well-defined and reproducible starting environment where you can run your tests.

Building Guest Tools
====================

Create a directory, run cmake followed by make. By default, 64-bit versions of
the tools are built.

```
mkdir guest-tools64
cd guest-tools64
cmake ..
make
```

If you need 32-bit guest tools:

```
mkdir guest-tools32
cd guest-tools32
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/Toolchain-linux-i686.cmake ..
make
```

If you want to cross compile for Windows:

```
mkdir guest-tools64
cd guest-tools64
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/Toolchain-windows-x86_64.cmake
make
```

Likewise for 32-bit Windows use the `Toolchain-windows-i686.cmake` file.

Note: this will not build Windows-specific tools (such as the driver), which
require a Windows setup with Visual Studio 2015.
