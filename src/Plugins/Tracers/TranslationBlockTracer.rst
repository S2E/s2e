======================
TranslationBlockTracer
======================

The ``TranslationBlockTracer`` plugin records the execution of all translation blocks in the modules of interest.
Recorded information includes that start address of each block as well as the contents of CPU registers before and
after the execution.

Options
-------

manualTrigger=[true|false] (default=false)
    When true, tracing will start and stop upon execution of a special custom instruction. This is useful to restrict
    tracing to particular pieces of code (e.g., a submodule, a function, etc.).

flushTbCache=[true|false] (default=true)
    Tracing works by instrumenting translation blocks at translation time. If some block was already translated at the
    time tracing is enabled, the subsequent execution of that block will not appear in the trace unless the block is
    flushed and retranslated again.

Required Plugins
----------------

* `ExecutionTracer <ExecutionTracer.rst>`_
* `ModuleExecutionDetector <../ModuleExecutionDetector.rst>`_
