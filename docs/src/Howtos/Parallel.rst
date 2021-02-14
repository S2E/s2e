============
Parallel S2E
============

S2E can be run in multi-process (or `parallel`) mode in order to speed up path exploration. Each process is called a
worker. Each worker periodically checks whether there are processor cores available, and if yes, forks itself. The child
worker inherits half of the states of the parent. Plugins may customize the state partition.

To enable parallel mode, open ``launch-s2e.sh`` and set the environment variable ``S2E_MAX_PROCESSES=XX``, where ``XX``
is the maximum number of S2E instances you would like to have. Add the ``-nographic`` option as it is not possible to
fork a new S2E window.

Handling execution traces
=========================

In parallel mode, S2E outputs traces in ``s2e-last/XX`` folders, where ``XX`` is the sequence number of the
S2E instance. S2E increments this number each time it launches a new instance. Note that instances can also terminate,
e.g., when they finish exploring their respective state subtree.

Each trace file contains a subtree of the global execution tree. Therefore, analysis tools must process the traces in
the relative order of their creation. The relative order is defined by the sequence number of the instance. The
``s2e execution_trace`` tool takes care of putting the traces in the right order automatically.

Limitations
===========

* S2E can only run on a shared-memory architecture. S2E cannot start on one machine and fork new instances on other
  machines for now.
* It is not possible to have a separate S2E window for each process for now. If you start with ``-nographic``, you will
  not be able to manipulate the console. To start the program that you want to symbolically execute in the guest, use
  the `HostFiles <../MovingFiles.rst>`__ plugin or the ``-vnc :1`` option.
