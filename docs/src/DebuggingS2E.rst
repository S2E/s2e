=============
Debugging S2E
=============

S2E is a complex aggregation of various tools totaling over 1 million LOCs. Debugging S2E may be hard. The following
types of bugs are often hard to diagnose:

* Non-deterministic crashes
* Crashes that happen after a very long execution time
* Crashes that happen all over the place and seem to be caused by corrupted pointers

If one of these applies to your case, you may want to read the following. The following sections are sorted from
simplest to most advanced.

.. contents::

The obvious checks
------------------

Make sure that your code compiles without warnings. A missing return statement buried somewhere may have dramatic
consequences. Fortunately, recent versions of clang put checks in the binary in such cases (as well as for other
undefined behavior), so the program will crash sooner rather than later.

Try to run your code with address sanitizer and/or undefined behavior sanitizer.

Record-replay
-------------

If your bug is non-deterministic and happens 10s of minutes to hours in your experiment, you may want to try record
replay. VMware Workstation 7 has this feature and will allow you to come as close to the bug as possible so that you can
look at it in a debugger. If you somehow miss the bug, no problem, you can replay over and over again. Unfortunately,
recent versions of VMware Workstation do not have record-replay anymore and you will need a rather old setup and
processor to use version 7.

In general, we do not find this method very useful.

Valgrind
--------

Valgrind works for small-sized VMs only (typically 1-8MB of guest RAM and very little code). It is mostly useful when
debugging the internals of the execution engine, which does not require a lot of environment to run.

Debugging with gdb
------------------

S2E should be compiled with both symbol and debug information in order to use it with gdb:

.. code-block:: console

    cd $S2EDIR/build-s2e
    make -f $S2EDIR/build-s2e/Makefile all-debug

Before starting S2E in GDB, you need a configuration script (``gdb.ini``) that sets up environment variables properly.

.. code-block:: bash

    # GDB specific options
    handle SIG38 noprint
    handle SIGUSR2 noprint
    set debug-file-directory /usr/lib/debug/
    set disassembly-flavor intel
    set print pretty on

    # S2E configuration options
    set environment S2E_CONFIG=s2e-config.lua
    set environment S2E_SHARED_DIR=$S2EDIR/build-s2e/libs2e-debug/i386-s2e-softmmu/
    set environment LD_PRELOAD=$S2EDIR/build-s2e/libs2e-debug/i386-s2e-softmmu/libs2e.so
    set environment S2E_UNBUFFERED_STREAM=1
    set environment S2E_MAX_PROCESSES=1

Then start GDB as follows:

.. code-block:: console

    gdb --init-command=gdb.ini --args $S2EDIR/build-qemu/i386-softmmu/qemu-system-i386  \
        -drive file=/path/to/image.raw.s2e,cache=writeback,format=s2e -other -arbitary -flags

S2E kernel debugging
--------------------

Sometimes you may need to debug the modified Linux kernel. To do this please refer to the following `page
<http://wiki.osdev.org/Kernel_Debugging#Use_GDB_with_QEMU>`__.

S2E debug functions
-------------------

In order to simplify debugging a number of functions for gdb are `available
<https://github.com/S2E/s2e/blob/master/libs2ecore/src/S2E.cpp>`__:

s2e_debug_print_hex(void \*addr, int len)
    Print memory (in hex) at address ``addr`` of length ``len``

s2e_print_constraints(void)
    Print current path constraints.

s2e_print_expr(void \*expr)
    Print a symbolic expression of type ``ref<Expr>``.

s2e_print_value(void \*value)
    Print an ``llvm::Value``.

To invoke these functions use GDB's ``call`` command. For example::

    call s2e_print_expr(&param)

Where ``&param`` is the address of the expression. The output will be printed to ``debug.txt``.
Sometimes, you may need to issue the commands twice, in case the log file is not flushed.
