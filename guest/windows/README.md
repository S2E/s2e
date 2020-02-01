S2E Tools for Windows Guests
============================


The guest tools for Windows are composed of a kernel mode driver and
several utilities that can be used to test Windows binaries.
The kernel mode driver communicates to WindowsMonitor information about
loaded modules, threads, processes, and other kernel events that can
be used by other S2E plugins.

Building guest tools
====================

- Download and install Visual Studio 2015

- Download and install the Windows Driver Kit. The driver is preconfigured
  to use the latest driver kit installed. Modify the driver project settings
  in Visual Studio if needed.

- Open `s2e.sln`, select Release or Debug, x64 or Win32, then click Build.
  You should get `s2e.sys`, `drvctl.exe`,
  and `pdbparser.exe`. You should select the Win32 build if your guest
  OS is 32-bit, and x64 if it is 64-bit. Note that 64-bit guests can also
  run 32-bit tools, but cannot load the 32-bit driver.

Using guest tools
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

Copy `s2e.sys`, `s2e.inf`, as well as the other binaries you need in your guest. You
can do this using the `s2eget` utility as part of the bootstrap file.

```bash
# Copy files
mkdir c:\s2e
cd c:\s2e
s2eget s2e.sys
s2eget s2e.inf

# Install and start the driver
%SystemRoot%\System32\rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 c:\s2e\s2e.inf
sc start s2e
```

Once the driver is started, you should see in `s2e-last/debug.txt`
information about loaded modules and system events.

 `drvctl.exe` contains a number of useful commands to register it as a
system-wide JIT debugger and generate crash dumps. This way, you can easily
generate dumps if any of the programs or drivers that you are testing
crash.

 `pdbparser.exe` takes an `exe` and `pdb` file, and extracts various information.
This tool is used to add support for new kernels to the S2E driver.

Using `s2e.sys` in your projects
--------------------------------

Guest programs can open `s2e.sys` and communicate with it through an IOCTL interface. The `testctl.exe` tool
shows how to call `s2e.sys`. In order to communicate with it, user programs need to include the `s2ectl.h`
header file. This header provides an API to open the driver and send commands to it. It is particularly
useful when a user app wants to use S2E custom instructions but cannot easily include the S2E library,
because it would require extensive changes to the project (e.g., importing pre-compiled S2E library).
In this case, the `s2ectl.h` header provides a simple, self-contained way of using S2E custom
instructions through the S2E driver.


Adding support for new kernels
==============================

Adding support for new kernels is straightforward. Please follow the following steps:

- Download the 64-bit MSYS2 environment from [here](https://www.msys2.org/)

- Launch `C:\msys64\msys2.exe` and type the following commands.

Note: you must use Windows as these steps require parsing PDB files, which can only be done with Microsoft tools.

```bash
# Install the environment
pacman -Syy gcc python3-setuptools p7zip msys/libcrypt-devel
easy_install-3.7 pip

# Install guest tools requirements
cd $S2E_DIR/guest/windows
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt

# Run the driver generation script
./scripts/gendriver.sh /path/to/Windows/ISOs
```

The `gendriver.sh` script takes as input a folder containing the ISOs of all Windows versions to support.
It extracts all kernel binaries from the ISOs, downloads corresponding symbol files (PDB), then generates
the `driver/src/winmonitor_gen.c` file.

Finally, rebuild the driver. Note that new OS versions may considerably change the kernel structure, requiring upgrading
the generation scripts.


Code coverage for Windows binaries
==================================

Binaries produced by Microsoft tools contain line information in PDB files. These files have a proprietary
format and are not readable by Linux tools. This poses several challenges in order to covert program counters
produced by S2E's coverage plugin into say LCOV reports.

The following instructions explain how to get LCOV coverage reports for Windows binaries.

- Build the solution in Visual Studio

- Run `pdbparser.exe` as follows:

    ```
    ./x64/Release/pdbparser.exe -l my_binary.exe my_binary.pdb > my_binary.exe.lines
    ```

    The `*.lines` file contains line information in JSON format.

- Run your binary in S2E using `s2e-env`. At the end of the run, you should have `tb-coverage*.json`
  files in your `s2e-last` folder.

- Run `s2e coverage lcov my_binary`. Make sure that the `my_binary.exe.lines` is located in the same
  directory as `my_binary.exe`.  This should produce the `my_binary.exe.info` file, which contains
  LCOV coverage info.

- You must use LCOV on Windows in order to generate the report, because the LCOV files contain Windows path.
  You can also patch the files yourself to convert the paths inside to the Linux format. Run the following command in MSYS after
  installing LCOV from [here](https://github.com/linux-test-project/lcov):

  ```
  genhtml --ignore-errors source -p "c:/" -p "d:/" -o coverage_report my_binary.exe.info
  ```

  **Note:** it is important to strip all the drive prefixes (`-p` option) so that `genhtml` does not attempt
  to write HTML files all over the file system. The command also ignores sources files that cannot be opened, e.g.,
  those from the standard library, which are typically unavailable.

Options for pdbparser.exe
=========================

Getting pretty-printed callstacks
---------------------------------

`s2e.sys` outputs testcases containing underscore-separated address lists for each module.
You can use the following command in order to get a pretty-printed representation of these addresses.

```bash
pdbparser.exe -a "140035c76_1400355ed_140035a66_14003887e_1400090ca_14000afda_140059201_140001109" driver.sys driver.pdb
[0] 140035c76, user\driver\src\support\malloc.c:120
[1] 1400355ed, user\driver\src\support\callback.c:35
[2] 140035a66, user\driver\src\support\callback.c:93
[3] 14003887e, user\driver\src\support\periodic_task.c:137
[4] 1400090ca, user\driver\src\config\token_cache.c:80
[5] 14000afda, user\driver\src\driver.c:270
[6] 140059201, user\driver\src\driver.c:478
[7] 140001109, d:\5359\minkernel\wdf\framework\kmdf\src\dynamic\stub\stub.cpp:287
```

Code style
==========

The preferred code formatter is ReSharper. The solution contains `s2e.sln.DotSettings`,
which is automatically picked up by ReSharper.

If you don't have ReSharper, you may also use the CodeMaid formatter, as follows. Note that CodeMaid
does not format the code in exactly the same way as ReSharper, but it should be sufficient to keep it clean.

1. Load the customized C++ formatting settings
   (Tools->Import and Export settings / Import settings from VS2015_cpp_formatting_settings.vssettings`)

2. Install CodeMaid (Tools/Extensions and Updates).
   CodeMaid uses VisualStudio Formatting, but adds its own set of formatting rules on top.
   Load CodeMaid settings from `CodeMaid.config` (CodeMaid->Options->Import)
