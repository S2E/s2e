=================
Execution Tracers
=================

S2E provides plugins to record execution traces. The main plugin is ``ExecutionTracer``. All other tracing plugins, such
as ``MemoryTracer`` or ``TranslationBlockTracer``, use ``ExecutionTracer`` in order to append various trace entries to
the trace file (e.g., a memory access or a translation block execution). ``ExecutionTracer`` gathers trace data from the
various plugins and outputs them to an ``ExecutionTracer.dat`` file in ``protobuf`` format.


.. note::

    This document is a reference. For a more hands-on explanation of how to generate traces, please
    read this `tutorial <../../Howtos/ExecutionTracers.rst>`__ first.

ExecutionTracer
===============

An execution trace is a sequence of ``(magic, header_size, header, item_size, item)`` entries.
The magic number identifies the start of a trace entry. It is followed by the size of the header, the header, the
item size, then finally the actual item.

The header is defined by the ``PbTraceItemHeader`` protobuf type. For more details, see the
`TraceEntries.proto <https://github.com/S2E/s2e/blob/master/libs2eplugins/src/s2e/Plugins/ExecutionTracers/TraceEntries.proto>`__
file.

.. code-block:: c

    message PbTraceItemHeader {
        required uint32 state_id = 1;
        required uint64 timestamp = 2;
        required uint64 address_space = 3;
        required uint64 pid = 4;
        required uint64 pc = 5;
        required PbTraceItemHeaderType type = 6;
    }

The header entry contains data that is common to all trace items. This includes the program id, the program counter,
and the address space (i.e., ``cr3`` register on x86) at the time a trace entry is created. The type field specifies
the type of the item that follows the header. The header also stores the state identifier to help reconstruct the
execution tree offline.

The execution tracer ensures that it is possible to reconstruct the execution tree and extract individual paths when
S2E terminates. The tree can be decoded even when the trace recording is partial (e.g., in case S2E is forcefully
terminated). In order to do this, the execution tracer plugin monitors forks and records the id of the forked states in
the trace (see ``PbTraceItemFork``). Any subsequent trace item has the corresponding state id in its header. If two
items in the trace have the same state identifier, the item that happened earlier in the path is the one that comes
first in the trace.


ModuleTracer
============

This plugin traces process and module events. The following snippet is an example of a module load event. This indicates
that the OS loaded the shared library ``/lib64/ld-linux-x86-64.so.2`` into a process whose program identifier is 1245.
The event also records the location of each loaded section of the binary. The ``runtime_load_base`` of a section
is its start address in virtual memory as decided by the OS. The ``native_load_base`` is the address of the section
as specified by the linker. The two are often different because of ASLR or relocations.

.. code-block:: json

    {
        "address_space": 255299584,
        "name": "ld-linux-x86-64.so.2",
        "path": "/lib64/ld-linux-x86-64.so.2",
        "pc": 18446744071580784396,
        "pid": 1245,
        "sections": [
            {
                "executable": true,
                "name": "",
                "native_load_base": 0,
                "readable": true,
                "runtime_load_base": 140472821178368,
                "size": 142304,
                "writable": false
            },
            {
                "executable": false,
                "name": "",
                "native_load_base": 2243520,
                "readable": true,
                "runtime_load_base": 140472823421888,
                "size": 5120,
                "writable": true
            }
        ],
        "state_id": 0,
        "timestamp": 630430186029900,
        "type": "TRACE_MOD_LOAD"
    }

``ModuleTracer`` is a fundamental plugin, as it helps resolve the raw program counters in the trace to actual
binary names. ``s2e-env`` uses this extensively to get file and line numbers when binaries have debug information.


TestCaseGenerator
=================

The ``TestCaseGenerator`` has several functions:

- Write test cases to ``debug.txt``
- Store test case files in ``s2e-last``
- Write test cases to ``ExecutionTracer.dat``.

In this document, we will examine the latter. A test case entry has the following format:

.. code-block:: json

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

The most important field is ``items``: it records a list of (key, value) pairs. The key is the name of the symbolic
variable and the value is the concrete assignment to that variable. The variable name has the following format:

.. code-block:: c

    vXXX_variablename_YYY

``XXX`` is the relative order of the variable within the execution path. When a new variable is created, this
number is incremented by one. So the 10th variable of a state will have an id of 9.

``variablename`` is the string passed to ``s2e_make_symbolic``.

``YYY`` is the absolute order of the variable within a given S2E run. This number can be non-deterministic and
influenced by the sequence of state switches.

These two identifiers ensure that each variable is globally unique and can be easily ordered when generating a test
case.


MemoryTracer
============

This plugin traces memory accesses, page faults, and TLB misses in the specified processes. It requires the following
configuration in ``s2e-config.lua``:

.. code-block:: lua

    add_plugin("MemoryTracer")

    pluginsConfig.MemoryTracer = {
        -- You can selectively enable/disable tracing various events
        traceMemory = true,
        tracePageFaults = true,
        traceTlbMisses = true,

        -- This list specifies the modules to trace.
        -- If this list is empty, MemoryTracer will trace all processes specified in ProcessExecutionDetector.
        -- Modules specified here must run in the context of the process(es) defined in ProcessExecutionDetector.
        moduleNames = { "test" }
    }

.. note::

    ``MemoryTracer`` may produce large amounts of data (on the order of gigabytes), so make sure to restrict tracing
    to the modules of interest.

Here is an example of a memory access:

.. code-block:: json

    {
        "address": 140720832808700,
        "address_space": 255279104,
        "concrete_buffer": 0,
        "flags": 1,
        "host_address": 0,
        "pc": 94739530127322,
        "pid": 1251,
        "size": 4,
        "state_id": 0,
        "timestamp": 630430187009925,
        "type": "TRACE_MEMORY",
        "value": 3735928559
    }

- ``address``: the virtual address of the memory access
- ``value``: the concrete value written/read by the memory access
- ``size``: the size in bytes of the memory access
- ``flags``: this is a bitmask that indicates the type of the access

    - bit 0: set to 1 if the access is a write, read otherwise
    - bit 1: set to 1 if the access is memory-mapped I/O. Note that due to how CPU emulation works,
      normal RAM accesses may sometimes appear as MMIO.
    - bit 2: indicates that the value is symbolic. In this case , the trace entry stores the concrete version
      of the data.
    - bit 3: the address is symbolic. In this case, the trace entry stores the concrete version of the symbolic address.

    Several other bits are available, please check ``TraceEntries.proto`` for more details.

Several other fields are stored when ``traceHostAddresses`` is set in the configuration. These are useful under
rare circumstances when debugging the execution engine, e.g., to make sure that memory accesses get translated to
the right memory location on the host machine.

- ``host_address``: this is the address of the access as mapped by QEMU when initializing KVM memory regions.
- ``concrete_buffer``: this is the final address of the access, after S2E translated the host address to the actual
  per-state location.


A TLB miss looks as follows. It only stores the address and whether the access was a read or a write.

.. code-block:: json

    {
        "address": 140720832808704,
        "address_space": 255279104,
        "is_write": false,
        "pc": 94739530127511,
        "pid": 1251,
        "state_id": 1,
        "timestamp": 630430187323794,
        "type": "TRACE_TLBMISS"
    }


TranslationBlockTracer
======================

This plugin records the state of the CPU registers before and/or after a translation block is executed.
A translation block is a sequence of guest instructions that ends in a control flow change.

.. code-block:: lua

    add_plugin("MemoryTracer")

    pluginsConfig.TranslationBlockTracer = {
        -- In general, the CPU state at the beginning of a translation block is equal
        -- to the state at the end of the previous translation block.
        -- In cases where a translation block is interrupted because of an exception, the end state
        -- may not be recorded.
        traceTbStart = true,
        traceTbEnd = false,
        moduleNames = {"test"}
    }

Here is an example of a trace entry for translation blocks for 64-bit x86 code:

.. code-block:: json

    {
        "address_space": 255324160,
        "data": {
            "first_pc": 93907771242192,
            "last_pc": 93907771242228,
            "size": 42,
            "tb_type": "TB_CALL_IND"
        },
        "pc": 93907771242192,
        "pid": 1253,
        "regs": {
            "values": [
                28,
                140723069759552,
                139806606502816,
                0,
                140723069759520,
                0,
                2,
                139806608687472,
                139806608688896,
                0,
                8,
                140723070026140,
                93907771242192,
                140723069759520,
                0,
                0
            ],
            "symb_mask": 0
        },
        "state_id": 0,
        "timestamp": 631227908208916,
        "type": "TRACE_TB_START"
    }

There are several fields specific to this type of trace entry:

- ``tb_type``: the type of the translation block. It is defined by the last instruction of the block
  (e.g., direct call/jump, indirect call/jump, system call, etc.).
- ``regs``: the register data:

    - ``values``: concrete content of the CPU registers.
    - ``symb_mask``: this is a bitmask that indicates which register contains symbolic data. In case a register is
      symbolic, the ``values`` field contains a concrete value that satisfies path constraints at the time of
      the recording. Note that symbolic data is not recorded by the plugin.

- ``size``: the size in bytes of the guest instructions contained in this translation block.
- ``first_pc``: the program counter of the first instruction in the translation block.
- ``last_pc``: the program counter of the last instruction in the translation block.


InstructionTracer
=================

This plugin counts how many instructions have been executed in the configured processes or modules and writes
the count to the execution trace. The plugin keeps a per-path count and writes it when the path terminates.

.. code-block:: lua

    add_plugin("InstructionCounter")
    pluginsConfig.InstructionCounter = {
        -- This list specifies the modules to trace.
        -- If this list is empty, MemoryTracer will trace all processes specified in ProcessExecutionDetector.
        -- Modules specified here must run in the context of the process(es) defined in ProcessExecutionDetector.
        moduleNames = {"test"}
    }


Here is a sample trace entry:


.. code-block:: json

    {
        "address_space": 232222720,
        "count": 191951636,
        "pc": 134518939,
        "pid": 1255,
        "state_id": 0,
        "timestamp": 631227908821908,
        "type": "TRACE_ICOUNT"
    }
