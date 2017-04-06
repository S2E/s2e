========================
Using SystemTap with S2E
========================

SystemTap is a powerful tracing framework on Linux. It can intercept any function calls or instructions in the kernel
and invoke custom scripts. Such scripts have full access to the system state, can leverage debugging information, etc.

SystemTap provides S2E users a flexible way of controlling symbolic execution. The user writes a SystemTap script with
embedded calls to S2E custom instructions. This allows to inject symbolic values in any place, kill states based on
complex conditions, etc.

In this tutorial, we describe how to build and run SystemTap. We also give several examples of useful in-vivo analysis
that can be achieved. 

.. contents::

Building the Linux kernel
=========================

SystemTap requires a kernel built with the following settings::

    - CONFIG_DEBUG_INFO=y
    - CONFIG_RELAY=y
    - CONFIG_KPROBES=y
    - CONFIG_DEBUG_FS=y

For the purpose of this tutorial, also enable the following options:

* ``CONFIG_PCNET32=m`` (To enable this option, issue ``make menuconfig``, then select Device Drivers ---> Network
  device support ---> Ethernet (10 or 100Mbit) ---> AMD PCnet32 PCI support)

Refer to the `Building Linux <BuildingLinux.rst>`_ tutorial for a list of detailed steps.

Install the resulting kernel in the guest OS.

Building SystemTap in the ``chroot`` environment of the host
============================================================

We will compile SystemTap and the scripts in the *chrooted* environment, upload the scripts to the VM, and run them
there. The ``chroot`` environment isolates your production environment from mistakes.

We could also compile the scripts directly inside the VM, but it is much slower.

In the ``chroot`` environment you use to compile your kernel, do the following:

.. code-block:: console

    # Install the compiled kernel, headers, and debug information.
    # You must ensure that kernel-package = 11.015 is installed, later versions (>=12)
    # strip the debug information from the kernel image/modules.

    # Install initramfs-tools and its dependencies
    apt-get install initramfs-tools klibc-utils libklibc udev libvolume-id0

    # Set up the Linux image (an initrd image will be created in /boot/ as well).
    # Adapt all the filenames accordingly.
    dpkg -i linux-image-2.6.26.8-s2e.deb linux-headers-2.6.26.8-s2e.deb   

    # Install packages on which SystemTap depends:
    apt-get install libdw-dev libebl-dev

    # Get SystemTap, configure, compile, and install:
    wget http://sourceware.org/systemtap/ftp/releases/systemtap-1.3.tar.gz
    tar xzvf systemtap-1.3.tar.gz
    cd systemtap-1.3
    ./configure
    make --jobs=8 # Replace 8 with your number of cores
    make install

Building SystemTap on the guest
===============================

Build SystemTap dependencies and fetch SystemTap source:

.. code-block:: console

    # Boot the OS image in the vanilla QEMU and login as root.
    $S2EDIR/build-qemu/i386-softmmu/qemu-system-i386 s2e_disk.raw

    # Get packages on which SystemTap depends and install them:
    wget http://ftp.au.debian.org/debian/pool/main/e/elfutils/libelf1_0.131-4_i386.deb
    wget http://ftp.au.debian.org/debian/pool/main/e/elfutils/libelf-dev_0.131-4_i386.deb
    wget http://ftp.au.debian.org/debian/pool/main/e/elfutils/libdw-dev_0.131-4_i386.deb
    wget http://ftp.au.debian.org/debian/pool/main/e/elfutils/libebl-dev_0.131-4_i386.deb
    dpkg -i *.deb

    # Get SystemTap
    wget http://sourceware.org/systemtap/ftp/releases/systemtap-1.3.tar.gz
    tar xzf systemtap-1.3.tar.gz

Install and boot your new kernel on the guest:

.. code-block:: console

    # Upload the kernel packages to the guest OS, install them (adapt all
    # the filenames accordingly)
    dpkg -i linux-image-2.6.26.8-s2e.deb linux-headers-2.6.26.8-s2e.deb
    # Reboot your QEMU machine, choose your 2.6.26.8-s2e kernel from the
    # grub menu and login as root.
    reboot

    # Verify that the new version of your kernel rebooted.
    uname -a

    # Note: If this is a re-install of a kernel package that you have already
    # installed (i.e. the same 2.6.26.8-s2e flag as an installed kernel
    # package), you need to first remove the old package(s), before you do
    # the dpkg -i of the new ones:
    dpkg -r linux-image-2.6.26.8-s2e.deb

    # You can use the -I option of dpkg to list info about the package file,
    # including its name (used in the -r option).

Install SystemTap with the following steps:

.. code-block:: console

    cd systemtap-1.3
    ./configure
    make
    make install

Shut down the QEMU machine:

.. code-block:: console

    halt
 
Creating a simple S2E-enabled SystemTap script
==============================================

In this section, we show how to intercept the network packets received by the ``pcnet32`` driver and replace the
content of the IP header field with symbolic values.

Create (on the host machine) a ``pcnet32.stp`` file with the following content:

.. code-block:: c

   # We use the embedded C support of SystemTap to access the S2E
   # custom instructions. A comprehensive set of such instructions can
   # be found in s2e.h. You can adapt them to SystemTap, in case
   # you need them.
   
   # Terminate current state.
   # This is a SystemTap function that can be called from SystemTap code.
   function s2e_kill_state(status:long, message: string) %{
     __asm__ __volatile__(
       ".byte 0x0f, 0x3f\n"
       ".byte 0x00, 0x06, 0x00, 0x00\n"
       ".byte 0x00, 0x00, 0x00, 0x00\n"
       : : "a" ((uint32_t)THIS->status), "b" (THIS->message)
     );
   %}

   # Print message to the S2E log.
   # This is a SystemTap function that can be called from SystemTap code.
   function s2e_message(message:string) %{
     __asm__ __volatile__(
       ".byte 0x0f, 0x3f\n"
       ".byte 0x00, 0x10, 0x00, 0x00\n"
       ".byte 0x00, 0x00, 0x00, 0x00\n"
       : : "a" (THIS->message)
     );
   %}

   # SystemTap also allows to paste arbitrary C code.
   # This is useful when calling other C functions.

   %{
   // Make the specified buffer symbolic and assign a name to it.
   static inline void s2e_make_symbolic(void *buf, int size, const char *name)
   {
     __asm__ __volatile__(
       ".byte 0x0f, 0x3f\n"
       ".byte 0x00, 0x03, 0x00, 0x00\n"
       ".byte 0x00, 0x00, 0x00, 0x00\n"
       : : "a" (buf), "b" (size), "c" (name)
     );
   }
   %}

   #### Now comes the real stuff ####   
   
   # Take a pointer to the IP header, and make the options length field symbolic.   
   function s2e_inject_symbolic_ip_optionlength(ipheader: long) %{
     uint8_t *data = (uint8_t*)((uintptr_t)(THIS->ipheader + 0));

     uint8_t len;
     s2e_make_symbolic(&len, 1, "ip_headerlength");
     *data = *data & 0xF0;
     *data = *data | ((len) & 0xF);
   %}

   # Instruct SystemTap to intercept the netif_receive_skb kernel function.
   # NIC drivers call this function when they are ready to give the received packet
   # to the kernel.
   probe kernel.function("netif_receive_skb") {
     msg = sprintf("%s: len=%d datalen=%d\n", probefunc(), $skb->len, $skb->data_len)
     s2e_message(msg)
     s2e_inject_symbolic_ip_optionlength($skb->data)
   }

   
   # Instruct SystemTap to intercept the pcnet32_start_xmit in the pcnet32 driver.
   # We also tell S2E to kill the current state.
   # Intercepting this function can be useful to analyze the reaction of the kernel
   # to the reception of a (symbolic) packet.
   probe module("pcnet32").function("pcnet32_start_xmit") {
     msg = sprintf("%s: len=%d datalen=%d\n", probefunc(), $skb->len, $skb->data_len)
     s2e_message(msg)
     s2e_kill_state(0, "pcnet32_start_xmit")
   }


Compile the script with SystemTap in the ``chroot`` environment, adjusting the kernel version to suit your needs.

.. code-block:: console

    stap -r 2.6.26.8-s2e -g -m pcnet_probe pcnet32.stp
    # WARNING: kernel release/architecture mismatch with host forces last-pass 4.
    # pcnet_probe.ko
    
This will result in a module called ``pcnet_probe.ko`` that we will upload to the VM. Refer to `how to prepare an OS
image <ImageInstallation.rst>`_ to learn how to do it efficiently.

Running the script in S2E
=========================

Create the ``tcpip.lua`` configuration file with the following content:

.. code-block:: lua

    s2e = {
        kleeArgs = {
            "--use-batching-search",
            "--use-random-path",
        }
    }

    plugins = {
        --This is required for s2e_make_symbolic
        "BaseInstructions",
    }

    pluginsConfig = {}

To prepare a snapshot for S2E: start the vanilla QEMU with port forwarding enabled by adding ``-net
user,hostfwd=tcp::2222-:22,hostfwd=udp::2222-:22`` to the QEMU command line. This will redirect port 2222 from
``localhost`` to guest port 22. Adapt the name of the disk image to suit your needs.

.. code-block:: console

    LD_PRELOAD=$S2EDIR/build-s2e/libs2e-release/i386-s2e-softmmu/libs2e.so              \
        $S2EDIR/qemu-s2e/i386-softmmu/qemu-system-i386 -rtc clock=vm                    \
            -net nic,model=pcnet -net user,hostfwd=tcp::2222-:22,hostfwd=udp::2222-:22  \
            -drive file=s2e_disk.raw.s2e,format=s2e,cache=writeback
    # Press Ctrl-Alt-2 to reach the QEMU monitor, then save the snapshot with a tag (e.g., ready)
    savevm ready
    # Press Ctrl-Alt-1 to return to the emulation screen, then shut down the QEMU machine
    su -c halt

Start the S2E-enabled QEMU with port forwarding enabled:

.. code-block:: console

    export S2E_CONFIG_FILE=tcpip.lua
    LD_PRELOAD=$S2EDIR/build-s2e/libs2e-release/i386-s2e-softmmu/libs2e.so              \
        $S2EDIR/build-qemu/i386-s2e-softmmu/qemu-system-i386 -rtc clock=vm              \
            -net nic,model=pcnet -net user,hostfwd=tcp::2222-:22,hostfwd=udp::2222-:22  \
            -drive file=s2e_disk.raw.s2e,format=s2e,cache=writeback -loadvm ready

Once you uploaded the ``pcnet_probe.ko`` module to the guest OS, run the following command in the guest:

.. code-block:: console

    staprun pcnet_probe.ko &
    
This will load the probe into the kernel. Symbolic execution will start when the network card receives the first
packet. To send a packet, use ``netcat`` (in the guest) to send a UDP packet:

.. code-block:: console

    nc -u localhost 2222

Type some characters, and press enter.
