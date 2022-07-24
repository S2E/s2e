====================================
Symbolic Execution of Linux Binaries
====================================

In this tutorial, we will show how to symbolically execute Linux *binaries*, *without*
modifying their source code. Before you start, make sure that you have a working S2E environment.


Getting started
---------------

We will symbolically execute the ``echo`` utility. For this, create a new analysis project as follows:

.. code-block:: console

    # $S2EENV is the root of your S2E environment created with s2e init
    s2e new_project -i debian-11.3-i386 $S2EENV/images/debian-11.3-i386/guestfs/bin/echo abc

This command creates a new analysis project that invokes ``echo`` with one parameter ``abc``, which would normally print
``abc`` on the standard output.

Note that this command uses the ``echo`` binary from the guest VM image as the analysis
target. Do not use ``/bin/echo`` as the target, as this will take the one from your host OS, which may not be compatible
with the VM image that S2E uses.

Finally, we must explicitly pass the image name using ``-i``, because we ``s2e new_project`` may decide to use
a 64-bit image to run the binary, because it is in theory possible to run a 32-bit binary on a 64-bit guest. However,
this could also fail because ``echo`` might use libraries specific to the 32-bit guest.


Using ``s2e.so``
----------------

In this section, we show how to make command line arguments symbolic. Open the ``bootstrap.sh`` file and locate the
following line:

.. code-block:: console

    S2E_SYM_ARGS="" LD_PRELOAD=./s2e.so ./${TARGET} abc > /dev/null 2> /dev/null

Modify this line as follows:

.. code-block:: console

    S2E_SYM_ARGS="1" LD_PRELOAD=./s2e.so ./${TARGET} abc > /dev/null 2> /dev/null

This makes argument 1 (``abc``) symbolic. The process works like this:

1. The ``s2e.so`` library is preloaded in the binary using ``LD_PRELOAD``.
2. ``s2e.so`` reads from the ``S2E_SYM_ARGS`` environment variable which arguments to make symbolic.
3. If the variable is missing, ``s2e.so`` leaves all arguments concrete and proceeds with normal execution.
4. If not, ``s2e.so`` overwrites the specified arguments with symbolic values. It is possible to make only some
   arguments symbolic and leave others concrete by specifying the corresponding argument IDs.

    .. code-block:: console

        S2E_SYM_ARGS="<ID_0> <ID_1> .. <ID_N>" # Mark argument <ID_N> as symbolic


You may have noticed ``> /dev/null 2> /dev/null`` at the end of the command. This avoids printing symbolic characters on
the screen and eliminates forks in the kernel. There are some other tricks that ``s2e-env`` enables in ``bootstrap.sh``
in order to minimize unwanted forks:

* Do not print crashes in the syslog with ``sudo sysctl -w debug.exception-trace=0``
* Prevent core dumps from being created with ``ulimit -c 0`` (you may want to re-enable them if needed)


.. warning::

    You **must** specify default concrete arguments, so that ``s2e.so`` can overwrite them with symbolic data.
    The following command will not work because there is no argument to make symbolic (``abc`` is missing).

    .. code-block:: console

        S2E_SYM_ARGS="1" LD_PRELOAD=./s2e.so ./${TARGET} > /dev/null 2> /dev/null

.. warning::

    You cannot make the content of a file symbolic by just marking the file name symbolic. In other words, the
    following will not have the intended consequence:

    .. code-block:: console

        S2E_SYM_ARGS="1" LD_PRELOAD=./s2e.so /bin/cat /path/to/myfile

    Instead of making the **content** of ``/path/to/myfile`` symbolic, it makes the **file name** itself symbolic.
    The next section explains how to make the content of the file symbolic.

.. warning::

    Your binary **must** be dynamically linked, otherwise you cannot use ``s2e.so``. In case you want to make
    arguments symbolic for a statically-linked binary, see workarounds below.


What about other symbolic input?
--------------------------------

**Piping symbolic data.** You can also feed symbolic data to your program through ``stdin``. The idea is to pipe the
symbolic output of one program to the input of another. Symbolic output can be generated using the ``s2ecmd`` utility.
The command below passes four symbolic bytes to ``cat``:

.. code-block:: console

    ./s2ecmd symbwrite 4 | cat

If your binary is statically linked, you could pass it symbolic arguments as follows:

.. code-block:: console

    /bin/echo $(./s2ecmd symbwrite 4)

Note that this may be much slower than using ``s2e.so`` as symbolic data has to go through several layers of OS and
libraries before reaching the target binary.

**Using symbolic files.** If your binary takes a file name as a parameter and you want the content of that file to be
symbolic, the simplest is to create your analysis project as follows:

.. code-block:: console

    # The @@ is a placeholder for a concrete file name that contains symbolic data
    s2e new_project -i debian-11.3-i386 $S2EENV/images/debian-11.3-i386/guestfs/bin/cat @@

This generates a bootstrap file that creates a symbolic file in ramdisk (i.e., in ``/tmp`` on Linux), writes
some symbolic data to that file, and passes the path to that file to ``cat``. The symbolic file must be stored in RAM
(hence the ramdisk, or tmpfs). Writing symbolic data to a hard drive will concretize it.

.. note::

    In case of ``cat``, you may not see any forks with the command above, as the standard output is redirected
    to ``/dev/null`` and the symbolic data is therefore never branched upon. You must tweak the command line
    according to the aspects of the binary you want to test.

**Using seed files.** This is the preferred way of using S2E. Unconstrained files created by ``@@`` may be less
efficient at guiding the program towards an interesting path. Instead, you can use the concrete data of a file to
`guide <../../Howtos/Concolic.rst>`__ path exploration:

.. code-block:: console

    s2e new_project -i debian-11.3-i386 $S2EENV/images/debian-11.3-i386/guestfs/bin/cat /path/to/file/on/host

This commands scans the command line for arguments that look like paths (e.g., ``/path/to/file/on/host``) and
configures ``bootstrap.sh`` to download such paths into the guest. In addition to that, it creates a ``.symranges``
file in the project directory that specifies which byte ranges of the file to make symbolic.


Configuring S2E for use with ``s2e.so``
---------------------------------------

``s2e-env`` automatically configures all plugins required to use ``s2e.so``. Read this section if you want to know
more about the configuration. You do not need to worry about this during normal use and can skip the rest of this
tutorial.

``s2e.so`` requires two plugins to operate: ``BaseInstructions`` and ``LinuxMonitor``. The first provides general
infrastructure to communicate with plugins, while the second keeps track of various OS-level events (e.g., process
loads or thread creation). The S2E configuration file must contain default settings for these
plugins, as follows:


.. code-block:: lua

    plugins = {
      -- Enable S2E custom opcodes
      "BaseInstructions",

      -- Track when the guest loads programs
      "LinuxMonitor",
    }


Besides making command line arguments symbolic, ``s2e.so`` also reads ``/proc/self/maps`` to figure out which shared
libraries are loaded by the process and communicates their location to ``LinuxMonitor``. ``LinuxMonitor`` then
broadcast this information to any interested plugins. For example, the code coverage plugin uses this information
to map program counters to a module name.

.. warning::

    There is no ``s2e.so`` for Windows yet. In order to make program arguments symbolic, you must modify the
    source code manually. However, writing symbolic data to the standard input or to the ramdisk works like on Linux.
    On Windows, programs and shared libraries are tracked by a special guest driver, ``s2e.sys``, that communicates with
    ``WindowsMonitor``.


Modifying and building ``s2e.so``
---------------------------------

If you use ``s2e-env`` and stock VM images, ``s2e.so`` is automatically copied into the guest VM each time
you start the analysis. You do not have to do anything special unless you want to modify it.

The ``s2e.so`` library source can be found in the ``guest`` folder of the S2E source directory and is built during the
S2E build process. It can also be built manually by running ``make -f $S2ESRC/Makefile guest-tools-install`` from the
build directory. This creates ``guest-tools32`` and ``guest-tools64`` in ``$S2EDIR/build/$S2E_PREFIX/bin`` (by default
``$S2E_PREFIX`` is equal to ``opt``).

The latest build of ``s2e.so`` is copied in your guest VM next time you start the analysis, so all you need is to run
the ``make`` command above if you modify the source code of ``s2e.so``.
