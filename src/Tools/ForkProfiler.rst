=============
Fork Profiler
=============

The fork profiler tool lists all the program counters that caused a fork. This allows us to quickly identify the
program's hot spots that cause path explosion problems (as discussed in the `FAQ <../FAQ.rst>`_).

**NOTE**: Function names will be available only if the analyzed program and libraries are built with debug symbols
support.

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

Usage Example
-------------

1. Create a new project using `s2e-env<../s2e-env.rst>`_.
2. Enable the ``ExecutionTracer`` plugin in ``s2e-config.lua``.
3. Start symbolic execution using ``./launch-s2e.sh``
4. When analysis is done and the VM has shut down the ``forkprofiler`` may be run.

   .. code-block:: console
    
       ./bin/forkprofiler -trace ./projects/<name</s2e-last/ExecutionTracer.dat -moddir /path/to/bin/dir

   Running this command will produce a ``forkprofiler.txt`` file. This file will contain the list of function addresses
   where fork occurred.

5. If function names are required the ``-moddir`` option should be used. First `mount the VM image as loop device
   <https://en.wikibooks.org/wiki/QEMU/Images#Mounting_an_image_on_the_host>`_.

   .. code-block:: console

       mkdir /tmp/img-mount/    
       sudo mount -o loop,offset=1048576 ./images/s2e-linux-i386.raw.s2e /tmp/img-mount/

6. Further using ``-moddir`` specify path to the directory with analysed program. If you are using image created with
   ``s2-env`` the program will be located in ``/home/s2e/`` on the guest VM.

   .. code-block:: bash

       ./bin/forkprofiler -trace ./projects/name/s2e-last/ExecutionTracer.dat -moddir /tmp/img-mount/home/s2e/
    
7. Once everything is done unmount the image.

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

Required Plugins
----------------

* ``ExecutionTracer``

Optional Plugins
----------------

* ``ModuleTracer`` (for debug information)
