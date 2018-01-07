S2E Tools for Windows Guests
============================


The guest tools for Windows are composed of a kernel mode driver and
several utilities that can be used to test Windows binaries.
The kernel mode driver communicates to WindowsMonitor information about
loaded modules, threads, processes, and other kernel events that can
be used by other S2E plugins.

Building Guest Tools
====================

- Download and install Visual Studio 2015

- Download and install the Windows Driver Kit. The driver is preconfigured
  to use the latest driver kit installed. Modify the driver project settings
  in Visual Studio if needed.

- Open ```s2e.sln```, select Release or Debug, x64 or Win32, then click Build.
  You should get ```s2e.sys```, ```drvctl.exe```,
  and ```pdbparser.exe```. You should select the Win32 build if your guest
  OS is 32-bit, and x64 if it is 64-bit. Note that 64-bit guests can also
  run 32-bit tools, but cannot load the 32-bit driver.

Using Guest Tools
=================

The S2E guest driver currently supports a dozen of different types of Windows
kernels, from Windows XP to Windows 10. Note that Windows updates usually
change the kernel version too, the driver supports RTM and various service
packs out of the box. It is possible to add support for other versions,
see later in this section.

You first need to install the guest OS. After it is done,
disable driver signature enforcement (or enable test signing
depending on your OS version). The S2E driver is automatically test signed
by Visual Studio during build and requires test mode to be enabled. Windows
will not load it otherwise.

Copy ```s2e.sys```, ```s2e.inf```, as well as the other binaries you need in your guest. You
can do this using the ```s2eget``` utility as part of the bootstrap file.

```
# Copy files
mkdir c:\s2e
cd c:\s2e
s2eget s2e.sys
s2eget s2e.inf

# Install and start the driver
%SystemRoot%\System32\rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 c:\s2e\s2e.inf
sc start s2e
```

Once the driver is started, you should see in ```s2e-last/debug.txt```
information about loaded modules and system events.

 ```drvctl.exe``` contains a number of useful commands to register it as a
system-wide JIT debugger and generate crash dumps. This way, you can easily
generate dumps if any of the programs or drivers that you are testing
crash.

 ```pdbparser.exe``` takes an ```exe``` and ```pdb``` file, and extracts various information.
This tool is used to add support for new kernels to the S2E driver.


Adding Support for new Kernels
==============================

Adding support for new kernels is straightforward. Please follow the following steps:

- Download the MSYS-GIT SDK from ```https://github.com/git-for-windows/build-extra/releases```

- Launch ```C:\git-sdk-32\msys2.exe``` and type the following commands.

Note: you must use Windows as these steps require parsing PDB files, which can only be done with Microsoft tools.

```
# Install the environment
pacman -Syy gcc python2-setuptools
easy_install-2.7 pip virtualenv

# Install guest tools requirements
cd $S2E_DIR/guest/windows
virtualenv venv
. venv/bin/activate
pip install -r requirements.txt

# Run the driver generation script
./scripts/gendriver.sh /path/to/Windows/ISOs
```

The ```gendriver.sh``` script takes as input a folder containing the ISOs of all Windows versions to support.
It extracts all kernel binaries from the ISOs, downloads corresponding symbol files (PDB), then generates
the ```driver/src/winmonitor_gen.c``` file.

Finally, rebuild the driver. Note that new OS versions may considerably change the kernel structure, requiring upgrading
the generation scripts.

Code Style
==========

The preferred code formatter is ReSharper. The solution contains ```s2e.sln.DotSettings```,
which is automatically picked up by ReSharper.

If you don't have ReSharper, you may also use the CodeMaid formatter, as follows. Note that CodeMaid
does not format the code in exactly the same way as ReSharper, but it should be sufficient to keep it clean.

1. Load the customized C++ formatting settings
   (Tools->Import and Export settings / Import settings from ```VS2015_cpp_formatting_settings.vssettings```)

2. Install CodeMaid (Tools/Extensions and Updates).
   CodeMaid uses VisualStudio Formatting, but adds its own set of formatting rules on top.
   Load CodeMaid settings from ```CodeMaid.config``` (CodeMaid->Options->Import)
