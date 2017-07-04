===========================
Preparing VM Images for S2E
===========================

.. contents::

To run S2E, you need a QEMU-compatible virtual machine disk image. S2E can run any x86 operating system inside the VM.
In this section, we describe how to build a Linux image and present general requirements and guidelines for various
operating systems.

Note that you only need to follow these steps if you are **not** using `s2e-env <s2e-env.rst>`_.

Preparing a Linux VM Image
==========================

In the following, we describe how to install a minimal version of Debian Linux in QEMU.

**Please make sure that you perform all the steps below using QEMU that ships with S2E.** There will be compatibility
problems if you use QEMU that comes with your system (especially when saving/restoring snapshots).

``$S2EDIR`` refers to the directory where S2E is located. The paths below assume you followed the `installation
tutorials <BuildingS2E.rst>`_. Note that ``i386`` can be replaced with ``x86_64`` to build a 64-bit image.

.. code-block:: console

    # Create an empty disk image
    $S2EDIR/build/qemu-release/qemu-img create -f raw s2e_disk.raw 2G

    # Download debian install CD
    wget http://cdimage.debian.org/debian-cd/current/i386/iso-cd/debian-8.7.1-i386-netinst.iso

    # Run QEMU and install the OS
    $S2EDIR/build/qemu-release/i386-softmmu/qemu-system-i386 s2e_disk.raw -cdrom debian-8.7.1-i386-netinst.iso
    # Follow the on-screen instructions to install Debian Linux inside VM
    # Select only the "Standard System" components to install

    # When you system is installed and rebooted, run the following command
    # inside the guest to install C and C++ compilers
    su -c "apt-get install build-essential"

It is also recommended to build and install a `Linux kernel <BuildingLinux.rst>`_ that works with the `LinuxMonitor
<Plugins/Linux/LinuxMonitor.rst>`_ plugin. Finally, the `guest tools <https://github.com/S2E/guest-tools>`_ should be
built and transferred to the image.

You have just set up a disk image in RAW format. You need to convert it to the S2E format for use with S2E (the reasons
for this are described in the next section).

The S2E image format is identical to the RAW format, except that the image file name has the ".s2e" extension.
Therefore, to convert from RAW to S2E, renaming the file is enough (a symlink is fine too).

.. code-block:: console

    mv s2e_disk.raw s2e_disk.raw.s2e

Taking Snapshots
================

Once the image has been prepared, a snapshot should be taken. This allows the boot and startup sequence to be skipped
when running an S2E analysis. To take a snapshot, you will need to build `libs2e <https://github.com/S2E/libs2e>`_ and
boot your image with the following command:

.. code-block:: console

    LD_PRELOAD=$S2EDIR/build/libs2e-release/i386-softmmu/libs2e.so              \
        $S2EDIR/build/qemu-release/i386-softmmu/qemu-system-i386 -enable-kvm    \
        -drive file=s2e_disk.raw.s2e,format=s2e,cache=writeback                 \
        -serial file:serial.txt -enable-serial-commands                         \
        -net none -net nic,model=e1000

Note that we load the **non-S2E** version of ``libs2e.so``. You can then run the ``launch.sh`` script from the `guest
tools <https://github.com/S2E/guest-tools/blob/master/linux/scripts/launch.sh>`_. This will send the snapshot command
over the serial port to QEMU and take a ``ready`` snapshot (note that this requires the ``-enable-serial-commands``
option). Note that if you would like to create a snapshot with a different name, modify the ``SECRET_MESSAGE_SAVEVM``
variable in ``launch.sh``. After the snaptshot is taken, QEMU will shutdown. You should see a
``s2e_disk.raw.s2e.ready`` file in the same directory as ``s2e_disk.raw.s2e``. To start your snapshot in S2E mode, do:

.. code-block:: console

    LD_PRELOAD=$S2EDIR/build/libs2e-release/i386-s2e-softmmu/libs2e.so          \
        $S2EDIR/build/qemu-release/i386-softmmu/qemu-system-i386 -enable-kvm    \
        -drive file=s2e_disk.raw.s2e,format=s2e,cache=writeback                 \
        -serial file:serial.txt -net none -net nic,model=e1000 -loadvm ready

Note that this time we use the **S2E** version of ``libs2e.so`` and we specify the snapshot name using the ``loadvm``
option. The VM should boot and wait for a ``bootstrap.sh`` script that bootstraps the S2E analysis process.

The S2E VM Image Format
=======================

Existing image formats are not suitable for multi-path execution, because they usually mutate internal bookkeeping
structures on read operations. Worse, they may write these mutations back to the disk image file, causing VM image
corruptions. QCOW2 is one example of such formats.

The S2E image format, unlike the other formats, is multi-path aware. When in S2E mode, writes are local to each state
and do not clobber other states. Moreover, writes are NEVER written to the image (or the snapshot). This makes it
possible to share one disk image and snapshots among many instances of S2E.

The S2E image format is identical to the RAW format, except that the image file name has the ``.s2e`` extension.
Therefore, to convert from RAW to S2E, renaming the file is enough (a symlink is fine too).

The S2E image format stores snapshots in a separate file, suffixed by the name of the snapshot. For example, if the
base image is called "my_image.raw.s2e", the snapshot ``ready`` (as in ``savevm ready``) will be saved in the file
``my_image.raw.s2e.ready`` in the same folder as ``my_image.raw.s2e``.

General Requirements and Guidelines for VM Images
=================================================

When running in S2E mode, the image **must** be in S2E format. S2E does not support any other image format.

Any x86 image that boots in vanilla QEMU will work in S2E. However, we enumerate a list of tips and optimizations that
will make administration easier and symbolic execution faster. **These tips should be used as guidelines and are not
mandatory.**

Here is a checklist that we recommend you follow:

* Install your operating system in the vanilla QEMU. It is the fastest approach. In general, all installation and setup
  tasks should be done in vanilla QEMU.

* Keep a fresh copy of your OS installation. It is recommended to start with a fresh copy for each analysis task. For
  instance, if you use an image to test a device driver, avoid using this same image to analyze some spreadsheet
  component. One image = one analysis. It is easier to manage and your results will be easier to reproduce.

* Once your image (in S2E format) is set up and ready to be run in symbolic execution mode, take a snapshot and resume
  that snapshot in the S2E-enabled QEMU. This step is not necessary, but it greatly shortens boot times. Booting an
  image in S2E can take a (very) long time.

* It is recommended to use 128MiB of RAM for the guest OS (or less). S2E is not limited by the amount of memory in any
  way (it is 64-bit), but your physical machine is. Use the ``-m`` option when starting QEMU to set the amount of
  memory.

* Disable fancy desktop themes. Most OSes have a GUI, which consumes resources. Disabling all visual effects will make
  program analysis faster.

* Disable the screen saver.

* Disable unnecessary services to save memory and speed up the guest. Services like file sharing, printing, wireless
  network configuration, or firewall are useless unless you want to test them in S2E.

* Avoid the QEMU ``virtio`` network interface for now. In the version of QEMU that is supported by S2E, there can be
  random crashes.
