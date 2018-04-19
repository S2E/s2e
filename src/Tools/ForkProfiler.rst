=============
Fork Profiler
=============

The fork profile gives you a summary of all the locations in the system that forked.
This helps debug sources of path explosion.

Using s2e-env
=============

In order to obtain a fork profile, run the `forkprofile` subcommand as follows:

.. code-block:: console

    $ s2e new_project /home/users/coreutils-8.26/build/bin/cat -T @@
    $ ... launch s2e and let it run for a while ...

    $ s2e forkprofile cat
    INFO: [symbols] Looking for debug information for /home/vitaly/s2e/env/projects/cat-symb/././cat
    INFO: [forkprofile] # The fork profile shows all the program counters where execution forked:
    INFO: [forkprofile] # process_pid module_path:address fork_count source_file:line_number (function_name)
    INFO: [forkprofile] 01309 cat:0x08049ade  143 /home/user/coreutils-8.26/src/cat.c:483 (cat)
    INFO: [forkprofile] 01309 cat:0x08049b0a   81 /home/user/coreutils-8.26/src/cat.c:488 (cat)
    INFO: [forkprofile] 01309 cat:0x08049981   73 /home/user/coreutils-8.26/src/cat.c:410 (cat)


The trace above shows that the `cat` module (which has a pid 1309) forked at three different program counters.
The source information (if available) gives the source file, the line, and the function name where the forks occurred.

Using the fork profile to debug path explosion
----------------------------------------------

1. Spot locations that should not fork.
   For example, your program might write something to the console. This typically results in forks in the
   OS's console driver. The source information will point to the responsible linux kernel driver, allowing
   you to quickly fix your bootstrap script (e.g., by redirecting output to `/dev/null` or a symbolic file).

2. Identify library functions that can be optimized.
   You will immediately see if the program forks in functions such as `strlen` or `atoi`. These functions can
   be replaced with `function models <../Plugins/Linux/FunctionModels.rst>`__ that eliminate forks altogether, although
   at the expense of generating more complex expressions.

3. Identify sections of code that can benefit of `state merging <../StateMerging.rst>`__.
   Certain types of code sections are hard to model and can be instead surrounded by `s2e_merge_group_begin()` and
   `s2e_merge_group_end()` API calls, which will merge into one state the subtree in between these two calls.



Using the native fork profiler
==============================

.. warning::

    This method is deprecated and may not work reliably (especially debug information).


1. Create a new project using `s2e-env <../s2e-env.rst>`_.

2. Start symbolic execution using ``./launch-s2e.sh``

3. When analysis is done and the VM has shut down the ``forkprofiler`` may be run.

   .. code-block:: console

       ./bin/forkprofiler -trace ./projects/<name</s2e-last/ExecutionTracer.dat -moddir /path/to/bin/dir

   Running this command will produce a ``forkprofiler.txt`` file. This file will contain the list of function addresses
   where fork occurred.

4. If function names are required the ``-moddir`` option should be used. First `mount the VM image as loop device
   <https://en.wikibooks.org/wiki/QEMU/Images#Mounting_an_image_on_the_host>`_.

   .. code-block:: console

       mkdir /tmp/img-mount/
       sudo mount -o loop,offset=1048576 ./images/s2e-linux-i386.raw.s2e /tmp/img-mount/

5. Further using ``-moddir`` specify path to the directory with analysed program. If you are using image created with
   ``s2e-env`` the program will be located in ``/home/s2e/`` on the guest VM.

   .. code-block:: bash

       ./bin/forkprofiler -trace ./projects/name/s2e-last/ExecutionTracer.dat -moddir /tmp/img-mount/home/s2e/

6. Once everything is done unmount the image.

   .. code-block:: bash

       sudo umount /tmp/img-mount/
       rmdir /tmp/img-mount

Multiple Nodes
~~~~~~~~~~~~~~

If analysis is run on multiple cores each node will produce its own ``ExecutionTracer.dat`` file in
``./s2e-last/<node_number>/ExecutionTracer.dat``. The following script may be used to process such cases. Save it in
the project folder and run,

.. code-block:: bash

    #!/bin/bash

    MODDIR_PATH=/tmp/img-mount/home/s2e/
    forkprofilerpath=../bin/forkprofiler

    path=`find $1/ -mindepth 1 -maxdepth 1 -type d | sort -V`
    cmd=$forkprofilerpath
    cmd="$cmd -moddir=$MODDIR_PATH "

    for d in $path; do
        tmppath=`readlink -f "$d/ExecutionTracer.dat"`
        cmd="$cmd -trace $tmppath "
    done
    echo $cmd

    $cmd

After running this script you will have a single `forkprofiler.txt` file as before.

Options
-------

-moddir=<string>
    Directory containing the binary modules.

-os=<uint>
    The start address of kernel space.

-outputdir=<string>
    Store the fork profile into the given folder.

-trace=<Input trace>
    Specify an execution trace file. These are available in ``./projects/<name>/s2e-last/ExecutionTracer.dat``.


Required Plugins
----------------

* ``ExecutionTracer``

Optional Plugins
----------------

* ``ModuleTracer`` (for debug information)
