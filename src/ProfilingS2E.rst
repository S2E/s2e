=============
Profiling S2E
=============

This page explains how to profile and optimize S2E itself.

With Perf
=========

Fix perf issues
---------------

1. Get latest version available. Version 3.13 was not able to sum up children overheads.
   This document was written for 3.19.8-ckt16.
2. Recompile perf to fix C++ demangling bug (http://stackoverflow.com/a/34061874/6219959).

Running perf
------------

1. Run QEMU through perf with the workload you want to profile: ``perf record --call-graph fp -o perf.data ${QEMU}``.
2. Wait for some time to get statistics (remember, this is statistical profiling, time is important).
3. Stop QEMU by pressing CTRL+C or sending SIGINT to perf.

Viewing perf log
----------------

1. Run ``perf report -G -i out/perf.data``.

With OProfile
=============

Running OProfile
----------------

1. Recompile Z3, KLEE and QEMU with ``-fno-omit-frame-pointer`` option in ``CFLAGS`` and ``CXXFLAGS``
2. Run QEMU as usual with the workload you want to profile
3. Start OProfile using the following commands:

.. code-block:: console

    sudo opcontrol --reset
    sudo opcontrol --no-vmlinux --callgraph=128 --start

4. Wait for some time to get statistics (remember, this is statistical profiling, time is important)
5. Stop OProfile using the following command:

.. code-block:: console

    sudo opcontrol --stop

6. Now you can use ``opreport`` to generate various profiling reports

Viewing results with ``kcachegrind``
------------------------------------

You can convert results to kcachegrind-readable format with the following command:

.. code-block:: console

    opreport -gdf | op2calltree

However, callgraph information is not preserved by this conversion tool.

Generating callgraphs with ``gprof2dot`` and ``graphviz``
---------------------------------------------------------

1. Download the ``gprof2dot`` tool from https://github.com/jrfonseca/gprof2dot
2. Run the following commands:

.. code-block:: console

    opreport -lcD smart image:/path/to/qemu | \
        ./gprof2dot.py -f oprofile -n 1 -e 1 -s > prof.dot
    dot prof.dot -Tpng -o prof.png

Now you can view the generated ``prof.png`` file. You can change its verbosity by modifying ``-n`` and ``-e`` options
(minimal percentage of nodes and edges to show) or removing  the ``-s`` option (strip function arguments).
