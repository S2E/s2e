============
Parallel S2E
============

S2E can be run in multi-process mode in order to speed up path exploration. Each process is called a worker. Each
worker periodically checks whether there are processor cores available, and if yes, forks itself. The child worker
inherits half of the states of the parent.

To enable multi-process mode, set the environment variable ``S2E_MAX_PROCESSES=XX``, where ``XX`` is the maximum number
of S2E instances you would like to have.

Add the ``-nographic`` option as it is not possible to fork a new S2E window.

How do I process generated traces?
----------------------------------

In multi-process mode, S2E outputs traces in the ``s2e-last/XX`` folders, where ``XX`` is the sequence number of the
S2E instance. S2E increments this number each time it launches a new instance. Note that instances can also terminate,
e.g., when they finish exploring their respective state subtree.

Each trace file contains a subtree of the global execution tree. Therefore, analysis tools must process the traces in
the relative order of their creation. The relative order is defined by the sequence number of the instance. This can be
done by specifying multiple ``-trace`` arguments to the offline analysis tools. For example, generating the fork
profile of a multi-core run can be done as follows:

.. code-block:: console

    $S2EDIR/build-s2e/tools-release/tools/forkprofiler/forkprofiler -outputdir=s2e-last/    \
        -trace=s2e-last/0/ExecutionTracer.dat -trace=s2e-last/1/ExecutionTracer.dat         \
        -trace=s2e-last/2/ExecutionTracer.dat -trace=s2e-last/3/ExecutionTracer.dat

Limitations
-----------

* S2E can only run on a shared-memory architecture. S2E cannot start on one machine and fork new instances on other
  machines for now.
* It is not possible to have a separate S2E window for each process for now. If you start with ``-nographic``, you will
  not be able to manipulate the console. To start the program that you want to symbolically execute in the guest, use
  the `HostFiles <../MovingFiles.rst>`__ plugin or the ``-vnc :1`` option.
* Because S2E uses the ``fork`` system call, S2E cannot run on Windows in multi-core mode.
