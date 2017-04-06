=======================
ModuleExecutionDetector
=======================

The ``ModuleExecutionDetector`` plugin signals other plugins when execution enters or leaves a module of interest. It
relies on an OS monitor to get the location of the modules in memory.

Options
-------

``ModuleExecutionDetector`` accepts global options and an arbitrary number of per-module sections. Per-module options
are  prefixed with "module." in the documentation. Refer to the example below for details.

trackAllModules=[true|false]
    When true, pass events about **all** module loads and unloads to client plugins but do *not* notify them about the
    execution. This is useful for execution tracers to record modules loads to provide debug information offline
    without actually recording any trace. This option is false by default.

configureAllModules=[true|false]
    When true, consider all modules of the system to be of interest, regardless of per-module configuration. This
    option is false by default.

module.moduleName=["string"]
    The name of the module. This must match the name returned by the OS monitoring plugin.

module.kernelMode=[true|false]
    Whether the module lies above or below the kernel-mode threshold. Assumes that the module is mapped in all address
    space at the same location above the kernel/user-space boundary.

Configuration Sample
--------------------

.. code-block:: lua

    pluginsConfig.ModuleExecutionDetector = {
        myprog_id = {
            moduleName = "myprogram",
            kernelMode = false
        },
    }
