============
LinuxMonitor
============

The ``LinuxMonitor`` plugin intercepts process creation/termination, segmentation faults, module load/unload and traps
in S2E. This is achieved by using a specially-modified version of the `Linux kernel
<https://github.com/S2E/s2e-linux-kernel>`__ and a dynamically-loaded kernel module. Upon particular events occurring
(e.g. process creation), the kernel will execute a custom instruction that is interpreted and handled by the
``LinuxMonitor`` plugin. ``LinuxMonitor`` exports these events for other plugins to intercept and process as required.

Options
-------

terminateOnSegfault=[true|false]
    Set to ``true`` to terminate the currently-executing state when a segmentation fault occurs.

terminateOnTrap=[true|false]
    Set to ``true`` to terminate the currently-executing state when a trap occurs (e.g. divide-by-zero, invalid opcode,
    etc.). If you are using a debugger inside the guest VM then you should set this option to ``false`` because it will
    also intercept breakpoints.

Required Plugins
----------------

None
