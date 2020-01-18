============================================
Setting up a Windows development environment
============================================

This tutorial explains how to quickly set up a Windows development environment
in which you can build Windows applications and device drivers. This is useful
when you want to develop the S2E `guest tools <https://github.com/S2E/s2e/tree/master/guest/windows>`__
for Windows (e.g, the ``s2e.sys`` guest driver) or simply want to build and run various Windows applications in S2E.


.. note::

    This tutorial is not about how to compile and run S2E itself on a Windows machine.
    We do not support running S2E on Windows hosts yet, but we got reports
    that S2E builds and runs in the Windows 10 WSL environment or in a docker container.


Throughout this tutorial, you will use various scripts located in the
``~/s2e/env/source/s2e/scripts/windows`` `directory <https://github.com/S2E/s2e/tree/master/scripts/windows>`__.
This folder contains scripts that simplify the setup of Windows development VMs.
Most scripts assume you have a Linux host and want to setup a clean Windows VM
for development (e.g., building Windows-specific components of S2E, such as the
``s2e.sys`` guest driver).

Prerequisites:

    1. You have a working S2E environment on a Linux host machine
    2. You have a working hypervisor (VMware, Virtual Box, etc.)
    3. You have access to a 64-bit Windows 10 1803 ISO (e.g. through MSDN)
    4. You have an Internet connection (the installation will download several GBs)
    5. You have enough disk space and free memory (you will need at least 60 GB of disk and 4 GB of RAM for the VM).



1. Provisioning a Windows development VM
========================================

First, you need to build a Windows VM. At the end of this section, you will have a Windows 10 VM with Visual Studio 2017
Community Edition, the Windows Driver Kit, and an SSH server. Visual Studio will be installed with all C/C++ development
options (support for XP, 7, 8.1, 10). You will be able to SSH into this VM, rsync files, and do remote builds.

a. **Install a Windows 10 VM.** Use 60GB of disk and 4GB of RAM for the guest. Any 64-bit Windows 10 version should
   work, but it is recommended you use the latest one (the scripts were tested with version 1803).

   Preferably use ``s2e`` as login for the admin user. Most scripts assume ``s2e`` as default
   user name, so you will not have to override this user name later. Other than that, a vanilla installation will do.

   When you get to the Windows desktop, take a snapshot so that you can restore quickly in case of problems later.

b. **Provision the guest.** Open PowerShell with admin rights and run the ``Setup-DevHost.ps1`` script. You will need
   to access this script from the guest, e.g., by mapping your host directories to the guest
   using shared folders on VirtualBox/VMware.

   Wait until the script terminates. It is fully automated, no manual intervention is required.


   .. warning::

        Do **NOT** run the provisioning script on your host Windows environment. The script assumes a fresh Windows
        installation in a VM and may damage your existing Visual Studio environment if you already have one. If you
        still wish to run the script on your host (e.g., you do not have Visual Studio or want to set up SSH), carefully
        examine its content to make sure it will not interfere. Delete problematic sections if necessary.

   .. warning::

        The script requires Internet access to run successfully. It mainly uses the
        `Chocolatey <https://chocolatey.org/>`__ package manager in order to install software.

   .. note::

        You may install any additional packages that you want in the guest.
        Chocolatey comes with a vast list of supported Windows applications.
        Just add ``choco install -y package_name`` to the PowerShell script.

c. **Check installation correctness.** Open Visual Studio and try to build the S2E guest tools in x86/x64
   debug/release combinations. You should not get any errors.

d. **Check remote connection.** Check that you can SSH into the VM. You should get a Windows command prompt.

e. Finally, do not forget to take a snapshot.


2. Building Visual Studio projects remotely
===========================================

In this section, we explain how to build Visual Studio projects in the VM that you built in the previous section.

a. Copy your public SSH key into the guest VM. This is important, as the remote build script would ask you to type the
VM password several times, which is not convenient.

.. code-block:: bash

    $ cd ~/s2e/env/source/s2e/scripts/windows

    # This script resembles the normal ssh-copy-id but is designed to work for Windows remote machines.
    # Adapt the user name and address accordingly.
    $ ./ssh-copy-id-win.sh s2e@192.168.122.12

b. Checkout some Visual Studio projects to your Linux host. For example, like this:

.. code-block:: bash

    $ cd
    $ git clone https://github.com/Microsoft/Windows-driver-samples.git

c. Choose some project to build remotely, e.g., ``filesys/miniFilter/scanner``:

.. code-block:: bash

    $ REMOTE_HOST=192.126.122.12 REMOTE_FOLDER=myfolder ~/s2e/env/source/s2e/scripts/windows/remote-msbuild.sh \
       Windows-driver-samples/filesys/miniFilter/scanner

This command copies the contents of ``Windows-driver-samples/filesys/miniFilter/scanner`` to ``c:\users\s2e\myfolder``
on the remote machine, then launches ``msbuild`` in that folder. Finally, it rsyncs back the remote folder into the
local one. You can customize the target build directory, the host address, the user name, and other options using
environment variables (see the script header for details).

When this command completes, you should have all the build artifacts locally, in the
``Windows-driver-samples/filesys/miniFilter/scanner`` folder. Look for ``*.exe`` and ``*.sys`` files.


3. Use case: building and running a Windows device driver
=========================================================

This section assumes that you successfully built the ``Windows-driver-samples/filesys/miniFilter/scanner`` solution.
If no, go to the previous section.

First, we need to create a few symbolic links to the the project binaries, as follows. This is needed because
``s2e-env`` looks for the driver's binaries in the same directory as the driver's ``inf`` file.

.. code-block:: bash

    $ cd Windows-driver-samples/filesys/miniFilter/scanner
    $ ln -s filter/x64/Debug/scanner.sys
    $ ln -s filter/x64/Debug/scanner.sys.lines
    $ ln -s user/x64/Debug/scanuser.exe
    $ ln -s user/x64/Debug/scanuser.exe.lines

The ``*.lines`` files above contain debug information in JSON format. The S2E coverage tool expects them to have the
same name as the binary with ``.lines`` appended.

Then create the project, run it, and get code coverage. For more details, please refer to the Windows driver testing
`tutorial <Tutorials/WindowsDrivers/FaultInjection.rst>`__.

.. code-block:: bash

    $ cd ~/s2e/env
    $ s2e new_project ~/Windows-driver-samples/filesys/miniFilter/scanner/scanner.inf

    # ... edit projects/scanner/bootstrap.sh to start the driver ...
    $ cd projects/scanner
    $ ./launch-s2e.sh
    # ... wait for the analysis to complete ...

    $ cd ~/s2e/env
    $ s2e coverage --sympath ~/Windows-driver-samples/filesys/miniFilter/scanner/ lcov --html scanner

It is important to add the symbol search path to the coverage command, otherwise the driver's source will not be
found and the HTML coverage report will not be generated. In principle, the `*.lines` files already contain paths to the
source, however these paths are valid only on the build machine. The coverage command will therefore try to match these
paths against the given search paths.
