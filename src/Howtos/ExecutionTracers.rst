=============================
How to Use Execution Tracers?
=============================

.. contents::

Execution tracers are S2E analysis plugins that record various information along the execution of each path. Here is a
list of currently available plugins:

* **ExecutionTracer**: Base plugin upon which all tracers depend. This plugin records fork points so that offline
  analysis tools can reconstruct the execution tree. This plugin is useful by itself to obtain a fork profile of the
  system and answer questions such as: Which branch forks the most? What is causing path explosion?

* **ModuleTracer**: Records when and where the guest OS loads modules, programs, or libraries. Offline analysis tools
  rely on this plugin to display debug information such as which line of code corresponds to which program counter. If
  ``ModuleTracer`` is disabled, no debug information will be displayed.

* **TestCaseGenerator**: Outputs a test case whenever a path terminates. The test case consists of concrete input
  values that would exercise the given path.

* **TranslationBlockTracer**: Records information about the executed translation blocks, including the program counter
  of each executed block and the content of registers before and after execution. This plugin is useful to obtain basic
  block coverage.

* **InstructionCounter**: Counts the number of instructions executed on each path in the modules of interest.

Most of the tracers record information only for the configured modules (except ``ExecutionTracer``, which records forks
anywhere in the system). For this, tracers need to know when execution enters and leaves the modules of interest.
Tracers rely on the ``ModuleExecutionDetector`` plugin to obtain this information. ``ModuleExecutionDetector`` relies
itself on OS monitor plugins to be notified whenever the OS loads or unloads the modules.

Here is an end-to-end example of how to generate an execution trace for the ``echo`` utility using the `s2e.so
<../Howtos/s2e.so.rst>`_ library. The trace will contain all memory accesses done by ``echo``, as well as the list of
executed translation blocks and test cases.

1. Minimal Configuration File
=============================

.. code-block:: lua

    s2e = {
        kleeArgs = {}
    }

    plugins = {
        "BaseInstructions",
        "ExecutionTracer",
        "ModuleTracer",

        "RawMonitor",
        "ModuleExecutionDetector",

        -- The following plugins can be enabled as needed
        "MemoryTracer",
        "TestCaseGenerator",
        "TranslationBlockTracer",
    }

    pluginsConfig = {}

    pluginsConfig.MemoryTracer = {
        monitorMemory = true,
        monitorModules = true,
    }

2. Guest Configuration
======================

The `s2e.so <../Howtos/s2e.so.rst>`_ library will instruct S2E to trace the program as specified in the configuration
file.

.. code-block:: console

    LD_PRELOAD=/home/s2e/s2e.so /bin/echo abc ab > /dev/null

3. Viewing the Traces
=====================

S2E comes with several tools that parse and display the execution traces. They are located in the `tools`  folder of
the source distribution. You can find the documentation for them on the `main page <../index.rst>`_.

Here is an example that prints the list of executed translation blocks and all memory accesses performed in paths 0 and
34.

.. code-block:: console

    $S2EDIR/build-s2e/tools-release/tools/tbtrace/tbtrace -trace=s2e-last/ExecutionTracer.dat \
        -outputdir=s2e-last/traces -pathId=0 -pathId=34 -printMemory

You can also use `s2e-env <../s2e-env.rst>`_ to parse the execution trace.

Mini-FAQ
========

* You followed all steps and no debug information is displayed by the offline tools.

  * Some programs might be relocated by the OS and their load base will differ from their native base. Try to disable
    ASLR.
  * Check that your binutils library understands the debug information in the binaries.
