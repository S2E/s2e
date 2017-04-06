==========================
Building the S2E Platform
==========================

S2E builds and runs on Ubuntu 16.04 64-bit.

.. contents::

Required packages
=================

.. code-block:: console

    # Build dependencies
    sudo apt-get install build-essential
    sudo apt-get install cmake
    sudo apt-get install wget
    sudo apt-get install git
    sudo apt-get install texinfo
    sudo apt-get install flex
    sudo apt-get install bison
    sudo apt-get install python-dev

    # S2E dependencies
    sudo apt-get install libdwarf-dev
    sudo apt-get install libelf-dev
    sudo apt-get install libboost-dev
    sudo apt-get install zlib1g-dev
    sudo apt-get install libjemalloc-dev
    sudo apt-get install nasm
    sudo apt-get install pkg-config
    sudo apt-get install libmemcached-dev
    sudo apt-get install libvdeplug-dev
    sudo apt-get install libpq-dev
    sudo apt-get install libc6-dev-i386
    sudo apt-get install libprocps4-dev
    sudo apt-get install libboost-system-dev
    sudo apt-get install libboost-serialization-dev
    sudo apt-get install libboost-regex-dev
    sudo apt-get install libprotobuf-dev
    sudo apt-get install protobuf-compiler
    sudo apt-get install libbsd-dev
    sudo apt-get install libglib2.0-dev
    sudo apt-get install python-docutils

The following commands ask ``apt-get`` to install build dependencies for qemu:

.. code-block:: console

    sudo apt-get build-dep qemu

If you are going to be analyzing Windows binaries, you will also need to install mingw to compile the guest tools:

.. code-block:: console

    sudo apt-get install mingw-64

Using ``s2e-env``
=================

The simplest way to build S2E is to use the ``s2e-env`` tool. See `Using s2e-env <s2e-env.rst>`_ for instructions.

Building S2E manually
=====================

In addition to using the ``s2e-env`` tool, you can also build S2E manually.

Checking out S2E
----------------

S2E source code can be obtained from the S2E git repository using the following commands. Here ``$S2EDIR`` is the
directory that will hold both the S2E source and build directories.

.. code-block:: console

    cd $S2EDIR
    repo init -u git://github.com/s2e/manifest.git
    repo sync

This will setup the S2E repositories in ``$S2EDIR``.

In order to contribute to S2E (e.g., submit new features or report bugs), please see `here <Contribute.rst>`_.

Building
--------

The S2E Makefile can be run as follows:

.. code-block:: console

    mkdir $S2EDIR/build-s2e
    cd $S2EDIR/build-s2e
    make -f $S2EDIR/s2e-codetickler/Makefile install

   # Go make some coffee, this will take some time (approx. 60 mins on a 4-core machine)

By default, the ``make`` command compiles and installs S2E in release mode to ``$S2EDIR/build-s2e/opt``. To change this
location, set the ``S2EPREFIX`` environment variable when running ``make``.

To compile S2E in Debug mode, use ``make install-debug``.

To build the Windows guest tools:

.. code-block:: console

    make -f $S2EDIR/s2e/Makefile guest-tools-win-install

Note that the Makefile automatically uses the maximum number of available processors in order to speed up compilation.

Updating
--------

You can use the same Makefile to recompile S2E either when changing it yourself or when pulling new versions through
``repo sync``. Note that the Makefile will not automatically reconfigure the packages; for deep changes you might need
to either start from scratch by issuing ``make clean`` or to force the reconfiguration of specific modules by deleting
the corresponding files from the ``stamps`` subdirectory.

Building the documentation
--------------------------

The S2E documentation is written in `reStructuredText <http://docutils.sourceforge.net/rst.html>`_ format. HTML
documentation can be built using the S2E Makefile:

.. code-block:: console

    make -f $S2EDIR/s2e-codetickler/Makefile docs
