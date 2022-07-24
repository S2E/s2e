===========================
Customizing stock VM images
===========================

This tutorial will give you an overview of the guest image building system provided with S2E so that you can start
customizing the images for your own needs. You will learn the installation steps and how to customize them
to install additional software in the guest images.

.. warning::

    Building S2E images manually is **not** recommended. There are too many steps and messing them up is very easy,
    even if you are an advanced user. You will save dozens of hours in the long run if you use the automated
    image building scripts provided with S2E.

.. contents::


Image creation overview
=======================

Before you proceed further, read the following documents:

1. The `s2e-env <s2e-env.rst>`__ documentation in order to understand how to build S2E images from the command line.
   This shows the workflow that you will use routinely.

2. The `guest-images <https://github.com/S2E/guest-images/blob/master/README.md>`__ repository documentation. This
   repository contains the actual image building scripts. They produce fully-functional S2E disk images, with all the
   required software installed. As a user, you do not need to call these scripts directly, ``s2e-env`` will do it for
   you. You will need to modify them if you wish to add support for new OSes or install additional software in the
   stock guest images.

At a high level, image build creation scripts proceed as follows:

1. Fetch the ISO images (or have the user supply them in case of proprietary OSes).

2. Customize the images in order to enable unattended installation. The actual mechanics depend on the OS, but
   most commonly the installation scripts copy the additional software to a second ISO that will be read by the
   OS installer.

3. Run the installation. The OS will first perform its own installation, then will install any additional software.

4. Take a ready-to-run snapshot. The S2E launch script resumes the snapshot when starting the analysis. The snapshot
   is built in such a way that when it is resumed, it automatically retrieves a bootstrap script from the host.
   The bootstrap script contains further commands on how to set up the analysis. This kind of setup makes it more
   convenient to re-run analyses as often as needed without having to wait for the guest to boot.

The S2E image format is identical to the RAW format, except that the image file name has the ``.s2e`` extension.
Snapshots are saved in a ``.s2e.snapshot_name`` file, alongside the base image.

.. warning::

    When you copy S2E images, make sure to preserve time stamps of both the base image and the snapshots
    (i.e., use ``cp -p``). If the timestamps do not match, the snapshots will fail to resume. This is a protection
    to avoid resuming snapshots in case the base image was modified.


Building Linux images
=====================

In this section, we briefly discuss how Linux images are built.

S2E ships with custom Linux kernels, one vanilla and one customized for DARPA CGC binary analysis. The kernels are
available in this `repository <https://github.com/S2E/s2e-linux-kernel>`__. Basic build instructions are available in
the README. We recommend however that you study the ``guest-images`` Makefiles, which build the kernel in a Docker image
on the host, then inject the ``.deb`` files in the disk images during image creation.

.. warning::

    Although S2E can run any Linux kernel, we recommend you use a kernel that is compatible with the `LinuxMonitor
    <Plugins/Linux/LinuxMonitor.rst>`__ plugin. This allows S2E plugins to track process creation/termination,
    segmentation faults, etc. S2E will still work and symbolic execution will still function, but you will have to do
    everything manually if ``LinuxMonitor`` is unavailable.


Building Windows images
=======================

This works exactly like for Linux images, except that there is no need to re-compile the Windows kernel.
S2E ships with a custom Windows driver that exposes the kernel events to S2E plugins. This driver is available in
the `guest tools <https://github.com/S2E/s2e/tree/master/guest/windows>`__ repository.


When should I install my software?
==================================

If you wish to install your own software, there are two ways to go about it:

1. Installing during image build

   In order to install software in the image, modify the scripts in the ``guest-images`` repo. They already install
   various software, you can use that as an example. This method is preferred if your software is large and does not
   change.

2. Installing every time you start S2E

   Modify ``bootstrap.sh``, add ``s2ecmd get`` to download and run your software. This method is preferred if you intend to
   change your software very frequently. It adds start up overhead.


The S2E VM image format
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


General guidelines for VM images
================================

When running in S2E mode, the image **must** be in S2E format. S2E does not support any other image format.

Any x86 image that boots in vanilla QEMU will work in S2E. However, we enumerate a list of tips and optimizations that
will make administration easier and symbolic execution faster. These guidelines are also followed by the guest image
installation scripts.

* Keep fresh copies of your disk images. It is recommended to start with a fresh copy for each analysis task. For
  instance, if you use an image to test a device driver, avoid using this same image to analyze some spreadsheet
  component. One image = one analysis. It is easier to manage and your results will be easier to reproduce.

* It is recommended to use as little RAM as possible for the guest OS. S2E is not limited by the amount of memory in any
  way (it is 64-bit), but your physical machine is. Larger guest memory will also add additional management overhead and
  result in longer snapshot resume times. 128-256MB is a good setting for basic Linux images. Windows requires at
  least 2GB. The amount of memory for an image can be set in the ``guest-images`` scripts.

* Disable fancy desktop themes. Most OSes have a GUI, which consumes resources. Disabling all visual effects will make
  program analysis faster.

* Disable the screen saver.

* Disable swap. It is important that the program data is not swapped out during symbolic execution, as this will
  force the concretization of all symbolic data.

* Disable unnecessary services to save memory and speed up the guest. Services like file sharing, printing, wireless
  network configuration, or firewall are useless unless you want to test them in S2E.
