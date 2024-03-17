==================================
Building the S2E platform manually
==================================

The simplest way to build S2E is to use the ``s2e-env`` tool. It is the preferred method for development. See `Using
s2e-env <s2e-env.rst>`__ for instructions. However, some build features are not exposed by ``s2e-env`` and you will have
to run them manually.

.. note::

    S2E builds and runs on Ubuntu 22.04 LTS and Debian 11/12 (64-bit).
    Earlier versions may still work, but we do not support them anymore.


Building using Docker
=====================

You can create a self-contained docker image that lets you analyze any supported binary. The following command builds
the demo docker image.

.. code-block:: console

    # Checkout S2E sources (using Google Repo)
    # S2EDIR must be in your home folder (e.g., /home/user/s2e)
    cd $S2EDIR
    repo init -u https://github.com/s2e/manifest.git
    repo sync

    # Create a build directory
    mkdir build && cd build

    # Build the docker image
    make -f $S2EDIR/Makefile.docker demo

You can then run it as follows:

.. code-block:: console

    docker run --rm -ti -w $(pwd) -v $HOME:$HOME cyberhaven/s2e-demo /demo/run.sh $(id -u) $(id -g) /demo/CADET_00001

This command starts the s2e-demo container and creates an S2E environment in ``$(pwd)/s2e-demo``. It then downloads a
VM image and creates a default S2E configuration suitable for running the specified binary. Once configuration is done,
the container starts S2E.

The S2E environment in ``$(pwd)/s2e-demo`` is persistent. It is not kept in the container. You may run the container
multiple times without losing the previous settings. This is possible by mounting your home folder in the container.
The command also takes your current user and group id in order to create the environment folder with the right
permissions (docker uses root by default).

You may specify any binary you want and are not restricted to binaries stored inside the container. You just need to
mount the folder that contains it using the ``-v`` option.

Building S2E manually
=====================

In addition to using the ``s2e-env`` tool, you can also build S2E manually.

Required packages
-----------------

You must install a few packages in order to build S2E manually. Instead of giving you a list that will get out-of-date
very quickly, we will give you some pointers that should be always up-to-date:

- The packages for the build toolchain and S2E dependencies can be found in the S2E docker
  `file <https://github.com/S2E/s2e/blob/master/Dockerfile>`__.

- The packages required to build the guest images can be found
  `here <https://github.com/S2E/guest-images/blob/master/README.md>`__.

Checking out S2E
----------------

The S2E source code can be obtained from the S2E git repository using the following commands. Here ``$S2EDIR`` is the
directory that will hold both the S2E source and build directories.

.. code-block:: console

    cd $S2EDIR
    repo init -u https://github.com/s2e/manifest.git
    repo sync

This will set up the S2E repositories in ``$S2EDIR``.

In order to contribute to S2E (e.g., submit new features or report bugs), please see `here <Contribute.rst>`__.

Building
--------

The S2E Makefile can be run as follows:

.. code-block:: console

    mkdir $S2EDIR/build
    cd $S2EDIR/build
    make -f $S2EDIR/Makefile install

    # Go make some coffee, this will take some time (approx. 60 mins on a 4-core machine)

By default, the ``make`` command compiles and installs S2E in release mode to ``$S2EDIR/build/opt``. To change this
location, set the ``S2E_PREFIX`` environment variable when running ``make``.

To compile S2E in debug mode, use ``make install-debug``.

Note that the Makefile automatically uses the maximum number of available processors in order to speed up compilation.

Updating
--------

You can use the same Makefile to recompile S2E either when changing it yourself or when pulling new versions through
``repo sync``. Note that the Makefile will not automatically reconfigure the packages; for deep changes you might need
to either start from scratch by issuing ``make clean`` or to force the reconfiguration of specific modules by deleting
the corresponding files from the ``stamps`` subdirectory.

Building the documentation
--------------------------

The S2E documentation is written in `reStructuredText <http://docutils.sourceforge.net/rst.html>`__ format. HTML
documentation can be built as follows:

.. code-block:: console

    $ sudo apt-get install linkchecker
    $ pip install sphinx_rtd_theme
    $ cd $S2EDIR/s2e/docs/sphinx
    $ ./build.sh

The documentation will be located in ``$S2EDIR/s2e/docs/sphinx/build/html/index.html``.
