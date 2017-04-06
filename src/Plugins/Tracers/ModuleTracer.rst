============
ModuleTracer
============

The ``ModuleTracer`` records load events for modules specified by the `ModuleExecutionDetector
<../ModuleExecutionDetector.rst>`_ plugin. ``ModuleTracer`` is required by offline analysis tools to map program
counters to specific modules, e.g. to display user-friendly debug information.

Options
-------

This plugin does not have any options.

Required Plugins
----------------

* `ExecutionTracer <ExecutionTracer.rst>`_
* `ModuleExecutionDetector <../ModuleExecutionDetector.rst>`_
