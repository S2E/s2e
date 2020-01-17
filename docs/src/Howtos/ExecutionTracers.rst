=======================
Using execution tracers
=======================

Execution tracers are S2E analysis plugins that record various information along the execution of each path. Here is a
partial list of available plugins. You can find all the tracers in the
`libs2eplugins <https://github.com/S2E/s2e/tree/master/libs2eplugins/src/s2e/Plugins/ExecutionTracers>`__ repository.

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

* **MemoryTracer**: Records all memory accesses performed by a given process. This plugin also allows filtering
  accesses by module in order to reduce the size of the trace.

* **InstructionCounter**: Counts the number of executed instructions in a path for a given process or module.

Most of the tracers record information only for the configured modules (except ``ExecutionTracer``, which records forks
anywhere in the system). For this, tracers need to know when execution enters and leaves the modules of interest.
Tracers rely on the ``ProcessExecutionDetector`` and ``ModuleMap`` plugins to obtain this information.
These two plugins rely on OS monitor plugins to be notified whenever the OS loads or unloads processes or modules.


1. Recording basic traces
=========================

By default, an S2E project has all the required plugins configured in order to record forks, guest OS events
(e.g., process and module load/unload), and test cases.

Consider the following program that reads an integer from a file and checks its value:

.. code-block:: c

    #include <stdio.h>

    int main(int argc, char **argv) {
        FILE *fp = NULL;
        int value = 0xdeadbeef;

        if (argc != 2) {
            return -1;
        }

        fp = fopen(argv[1], "r");
        if (!fp) {
            printf("Could not open %s\n", argv[1]);
            goto err;
        }

        if (fread(&value, sizeof(value), 1, fp) != 1) {
           goto err;
        }

        if (value == 0) {
           printf("0");
        }

    err:
        if (fp) {
            fclose(fp);
        }

        return 0;
    }


Compile the program above, create a new S2E project, then run it:

.. code-block:: bash

    $ gcc -Wall -g -o test test.c
    $ s2e new_project ./test @@
    $ s2e run test


If everything went well, you should have a non-empty ``ExecutionTracer.dat`` file in the project's directory:

.. code-block:: bash

    $ ls -la projects/test/s2e-last/
    ...
    -rw-rw-r-- 1 ubuntu ubuntu    4846 Dec 20 20:34 ExecutionTracer.dat
    ...


2. Analyzing traces
===================

S2E comes with a few built-in tools that rely on execution traces in order to work. One of these tools is the
fork profiler:

.. code-block:: bash

    $ s2e forkprofile test

    ...
    # The fork profile shows all the program counters where execution forked:
    # process_pid module_path:address fork_count source_file:line_number (function_name)
    01251 test:0x00000885    1 /home/vitaly/s2e/env/test.c:21 (main)

The fork profiler looks for fork entries in ``ExecutionTracer.dat`` in order to aggregate them. It also extracts
module name information in order to provide symbol data (e.g., line numbers and source files).

If you would like to look at the raw trace, you can use the ``execution_trace`` command in order to dump the trace
in JSON format:

.. code-block:: bash

    s2e execution_trace -pp test
    ...
    SUCCESS: [execution_trace] Execution trace saved to /home/ubuntu/s2e/env/projects/test/s2e-last/execution_trace.json


This trace encodes an execution tree:

.. code-block:: bash

    # The first entry belongs to path 0
    {...},
    {...},
    {
        "children": {
            "1": [          # This is the start of path 1
                {...},
                {...},
                ...
            ]
        }
        ...
        "type": "TRACE_FORK"
    },
    {...},                  # Path 0 continues after forking
    {...},
    ...

At the leaves of the execution tree, there are test case entries, which the ``TestCaseGenerator`` plugin creates
when a path terminates:


.. code-block:: bash

    # Path 1:
    {
        "address_space": 225800192,
        "items": [
            {
                "key": "v0___symfile____tmp_input___0_1_symfile___0",
                "value": "AQEBAQEBAQEBAQEBAQE...."
            }
        ],
        "pc": 134518939,
        "pid": 1295,
        "state_id": 1,
        "timestamp": 630185690261719,
        "type": "TRACE_TESTCASE"
    }

    # Path 0
    {
        "address_space": 225800192,
        "items": [
            {
                "key": "v0___symfile____tmp_input___0_1_symfile___0",
                "value": "AAAAAAAAA....."
            }
        ],
        "pc": 134518939,
        "pid": 1295,
        "state_id": 0,
        "timestamp": 630185689994274,
        "type": "TRACE_TESTCASE"
    }

You will find similar items for module/process loads/unloads.


3. Recording memory traces
==========================

In this section, we will record all memory accesses done by the program above. For this, append the following snippet
to ``s2e-config.lua``:

.. code-block:: lua

    add_plugin("MemoryTracer")

    pluginsConfig.MemoryTracer = {
        traceMemory = true,
        tracePageFaults = true,
        traceTlbMisses = true,

        -- Restrict tracing to the "test" binary. Note that the modules specified here
        -- must run in the context of the process(es) defined in ProcessExecutionDetector.
        moduleNames = { "test" }
    }


After re-running S2E and calling `s2e execution_trace -pp test` on the new run, you should be able to find the
following snippet in `execution_trace.json`:


.. code-block:: json

    {
        "address": 140720832808700, // 0x7FFC1F4086FC
        "address_space": 255279104,
        "concrete_buffer": 0,
        "flags": 1,
        "host_address": 0,
        "pc": 94739530127322, // 0x562A440A17DA
        "pid": 1251,
        "size": 4,
        "state_id": 0,
        "timestamp": 630430187009925,
        "type": "TRACE_MEMORY",
        "value": 3735928559  // 0xdeadbeef
    }

This corresponds to writing ``0xdeadbeef`` to the local variable ``value`` to the address ``0x7FFC1F4086FC``.


4. Trace format reference
=========================

S2E uses ``protobuf`` to record traces. You can find more details about the format `here
<../Plugins/Tracers/ExecutionTracer.rst>`__.
