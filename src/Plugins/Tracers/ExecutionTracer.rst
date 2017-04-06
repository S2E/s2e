===============
ExecutionTracer
===============

The ``ExecutionTracer`` plugin is the main tracing plugin. This plugin saves a binary trace file in the
``s2e-last/ExecutionTracer.dat`` file. This file is composed of generic trace items. Each item can have an arbitrary
format, determined by the various client tracing plugins. The client plugins call the ``ExecutionTracer``'s API to
write trace items.

By default, ``ExecutionTracer`` records the program counters where fork occurs. This allows offline analysis tools to
rebuild the execution tree and provide per-path analyses.

Options
-------

This plugin does not have any options.
