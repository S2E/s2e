==========
EdgeKiller
==========

The ``EdgeKiller`` plugin looks for the execution of a sequence of program counters and kills all the paths where this
sequence occurs. This is useful to kill polling loops.

Options
-------

The configuration requires one section per module to be monitored. The section name must match the module identifier
defined in the configuration section of the `ModuleExecutionDetector <ModuleExecutionDetector.rst>`__ plugin. Each
section contains a list of named pairs of program counters that define the program edges. All program counters are
relative to the native load base of the module. The name of each pair is not important, but must be unique.

Required Plugins
----------------

* `ModuleExecutionDetector <ModuleExecutionDetector.rst>`__

Configuration Sample
--------------------

The following example shows how to kill the polling loops in the ``pcntpci5.sys`` device driver. Each pair of addresses
represents the source and the target of a polling loop back-edge.

.. code-block:: lua

    pluginsConfig.EdgeKiller = {
        pcntpci5_sys_1 = {
            l1 = {0x14040, 0x1401d},
            l2 = {0x139c2, 0x13993},
            l3 = {0x14c84, 0x14c5e},
       }
    }


