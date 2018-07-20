=============
Trace Printer
=============

The trace printer tool outputs for each specified path all the trace items that were collected in these states. Items
include memory accesses, executed translation blocks, or test cases. This tool is useful to quickly observe the
execution sequence that led to a particular event that caused a state to terminate. It can also be useful for
debugging.

Examples
--------

A complete tutorial on how to generate and display a trace can be found `here <../Howtos/ExecutionTracers.rst>`__.

Assuming you have obtained a trace in ``ExecutionTracer.dat``, the following command outputs the translation block
trace for paths 0 and 34. Omitting the ``-pathId`` option will cause the command to output the trace for all paths.

If the ``-printRegisters`` option is specified, the command also prints the contents of the registers before and after
the execution of each translation block (provided that ``TranslationBlockTracer`` was enabled).

``-printMemory`` also shows all memory accesses (provided that ``MemoryTracer`` was enabled).

.. code-block:: console

    $S2EDIR/build-s2e/tools/Release+Asserts/bin/tbtrace -trace=s2e-last/ExecutionTracer.dat \
        -outputdir=s2e-last/traces -pathId=0 -pathId=34 -printMemory

Required Plugins
----------------

* ``ModuleExecutionDetector`` (only the translation blocks of those modules that are configured will be traced)
* ``ExecutionTracer``
* ``TranslationBlockTracer``
* ``ModuleTracer`` (for module information)

Optional Plugins
----------------

* ``TestCaseGenerator`` (for test cases)
* ``MemoryTracer`` (for memory traces)
* ``TranslationBlockTracer`` (for executed translation blocks)
