=======================
ModuleExecutionDetector
=======================

The ``ModuleExecutionDetector`` plugin signals to other plugins when execution enters or leaves a module of interest.
It relies on an OS monitor to get the location of the modules in memory.


Configuration Sample
--------------------

The configuration sample below will make ``ModuleExecutionDetector``:

- notify other plugins when execution enters or leaves ``myprogram`` (if ``trackExecution`` is set to ``true``)
- notify other plugins when the DBT translates code that belongs to ``myprogram``

.. code-block:: lua

    pluginsConfig.ModuleExecutionDetector = {
        myprog_id = {
            moduleName = "myprogram",
        },

        trackExecution=true
    }
