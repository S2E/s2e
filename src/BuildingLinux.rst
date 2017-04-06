==============================
Compiling the S2E Linux Kernel
==============================

Although S2E can run any Linux kernel, we recommend you use a kernel that is compatible with the `LinuxMonitor
<Plugins/Linux/LinuxMonitor.rst>`_ plugin. This allows you to track process creation/termination, segmentation faults,
etc. in S2E.

The S2E Linux kernel is available from https://github.com/S2E/s2e-linux-kernel. Build instructions are
available in the README. Once you have built the deb files, you can transfer them to your image and install them via
``dpkg -i *.deb``.

Note that if you are using `s2e-env <s2e-env.rst>`_ then an S2E-compatible kernel will be built for you.
