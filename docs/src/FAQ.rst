================================
Frequently Asked Questions (FAQ)
================================

How do I know what S2E is doing?
================================

1. Enable execution tracing and use the fork profiler to identify the code locations that fork the most. In your
   configuration file, enable the ``ExecutionTracer``, ``ModuleTracer`` and the ``ModuleExecutionDetector`` plugins.
   This will allow you to collect all fork locations. Additionally, you can use ``TranslationBlockTracer``  in order to
   have a detailed trace for each execution path, which you can view with the ``tbtrace`` tool. Finally,
   ``TranslationBlockCoverage`` allows you to view the basic block coverage in either IDA Pro or Radare (as described
   in the `Coverage <Howtos/Coverage/index.rst>`__ tutorial).

2. Look at ``s2e-last/debug.txt`` and other files. These files list all the major events occurring during symbolic
   execution. If there are no messages in the logs and the CPU usage is 100%, it may be that execution is stuck
   in the constraint solver. Use the `perf top` Linux utility to get a call stack to identify which part of S2E is busy.

3. ``stats.csv`` contains many types of statistics. S2E updates this file about every second, when executing symbolic
   code. See later in this FAQ for a description of its fields.

Execution seems stuck/slow. What to do?
=======================================

First, ensure that you configured S2E properly. The ``s2e-env`` does its best to have a minimal default configuration
that works in most cases.

* By default, S2E flushes the translation block cache on every state switch. S2E does not implement copy-on-write for
  this cache, therefore it must flush the cache to ensure correct execution. Flushing avoids clobbering in case there
  are two paths that execute different pieces of code loaded at the same memory locations. Flushing is **very**
  expensive in case of frequent state switches. In most of the cases, flushing is not necessary, e.g., if you execute a
  program that does not use self-modifying code or frequently loads/unloads libraries. In this case, use the
  ``--flush-tbs-on-state-switch=false`` option.

* Make sure your VM image is minimal for the components you want to test. ``s2e-env`` generates working Linux images,
  but if you created it manually, make sure it follows some basic guidelines. In most cases, it should not have swap
  enabled and all unnecessary background daemons should be disabled. Refer to the `image installation
  <ImageInstallation.rst>`__ tutorial for more information.

Second, throw hardware at your problem

* Refer to the `How to run S2E on multiple cores <Howtos/Parallel.rst>`__ tutorial for instructions.

Third, use S2E to *selectively* relax and/or over-constrain path constraints.

* First, run the `fork profiler <Tools/ForkProfiler.rst>`__ to understand which program counters in your program fork
  the most. Usually, functions such as ``printf`` can be stubbed out, and others like ``strlen`` can be modeled
  to decrease drastically the number of forks. `s2e.so <Tutorials/BasicLinuxSymbex/s2e.so.rst>`__ comes with models for
  several such functions. You can also give `state merging <StateMerging.rst>`__ a try.

* If you use a depth-first search and execution hits a polling loop, rapid forking may occur and execution may never
  exit the loop. Moreover, depending on the accumulated constraints, each iteration may be slower and slower. Make sure
  you use concolic execution, depth first search, and a test input to make sure at least the first path terminates.
  Then, try to use a different search strategy or kill unwanted execution paths. Plugins such as ``EdgeKiller`` may
  help you kill unwanted loop back edges.

* Try to relax path constraints. For example, there may be a branch that causes a bottleneck because of a complex
  constraint. You could try to stub out the function in which that branch is contained. For example, if it's a CRC
  check that gets stuck in the solver, you may want to replace the CRC function with a stub that returns an unconstrained
  symbolic value. This trades execution  consistency for execution speed. Unconstraining execution may create paths
  that cannot occur in real executions (i.e., false positives), but as long as there are few of them, or you can detect
  them a posteriori, this is an acceptable trade-off.

How do I deal with path explosion?
==================================

Use S2E to *selectively* kill paths that are not interesting and prevent forking outside modules of interest. The
following describes concrete steps that allowed us to explore programs most efficiently.

1. Run your program with minimum symbolic input (e.g., 1 byte) and with tracing enabled (see first section).

2. Insert more and more symbolic values until path explosion occurs (i.e., it takes too long for you to explore all the
   paths or it takes too much memory/CPU resources).

3. Extract the fork profile and identify the code locations that fork the most.

4. If forking occurs outside the module of interest, the following may help:

   * Concretize some symbolic values when execution leaves the module of interest. You may need to use the
     ``FunctionMonitor`` plugin to track function calls and concretize parameters.
   * Provide example values to library functions (e.g., to ``printf``, as described previously)
   * Minimize amount of symbolic data leakage into the kernel (e.g., symbolic file names or symbolic stdio). Redirect
     output to ``/dev/null``.
   * For dynamically-linked Linux binaries, enable the `FunctionModels <Plugins/Linux/FunctionModels.rst>`__ plugin to
     return a symbolic expression rather than forking in common libc functions.

5. Kill the paths that you are not interested in:

   * You may only want to explore error-free paths. For example, kill all those where library functions fail.
   * You may only be interested in error recovery code. In this case, kill all the paths in which no errors occur.
   * Write a custom plugin that probes the program's state to decide when to kill the path.
   * If you exercise multiple entry points of a library (e.g., a device driver), it may make sense to choose only one
     successful path when an entry point exits and kill all the others.
   * Kill back-edges of polling loops using the `EdgeKiller <Plugins/EdgeKiller.rst>`__ plugin. You can also use this
     plugin when execution enters some block of code (e.g., error recovery).

6. Prioritize paths according to a metric that makes sense for your problem. This may be done by writing a custom state
   searcher plugin. S2E comes with several examples of searchers that aim to maximize code coverage as fast as
   possible.

How to keep memory usage low?
=============================

You can use several options, depending on your needs.

* Disable forking when a memory limit is reached using the ``ResourceMonitor`` plugin.

* Explicitly kill unneeded paths. For example, if you want to achieve high code coverage and know that some path is
  unlikely to cover any new code, kill it.

How much time is the constraint solver taking to solve constraints?
===================================================================

Enable logging for constraint solving queries:

.. code-block:: lua

    s2e = {
        kleeArgs = {
            "--use-query-log",
            "--use-query-pc-log",
        }
    }

With this configuration S2E generates two logs: ``s2e-last/queries.pc`` and ``s2e-last/solver-queries.qlog``. Look for
"Elapsed time" in the logs.

What do the various fields in ``stats.csv`` mean?
=================================================

You can open ``stats.csv`` in a spreadsheet as a CSV file. Most of the fields are self-explanatory. Here are the
trickiest ones:

* ``QueryTime`` shows how much time KLEE spent in the solver.
* ``CexCacheTime`` adds to that time also the time spent while looking for a solution in a counter-example cache (which
  is enabled by the ``--use-cex-cache`` KLEE option). ``SolverTime`` shows how much time KLEE spent in total while
  solving queries (this includes all the solver optimizations that could be enabled by various solver-related KLEE
  options).
* ``ForkTime`` shows how much time KLEE spent on forking states.
