=====================================
Symbolic Execution Extensions for KVM
=====================================

This document presents extensions to the Linux KVM virtualization interface that enable building multi-path analysis
tools, such as symbolic execution engines. In a nutshell, we built ``libs2e.so``, a shared library that implements the
S2E symbolic execution engine. This library can be preloaded into a target hypervisor process. The library intercepts
and emulates calls to ``/dev/kvm`` to provide symbolic execution capabilities to vanilla hypervisors like QEMU.

We will (1) provide an overview of how KVM works, (2) show how to build a library that emulates vanilla KVM using
a dynamic binary translator as a CPU emulation engine, (3) how to add symbolic execution capabilities on top of that,
and (4) provide a reference of the new KVM extensions so that you can integrate S2E into your own hypervisors.


.. contents::


Kernel-based Virtual Machine (KVM)
==================================

The Linux kernel exposes the KVM interface through the ``/dev/kvm`` file. A program (that we call a KVM client) that
wants to create a VM opens that file and sends commands to it using the ``ioctl`` interface. The most important commands
are creating and setting the state of the virtual CPU (``KVM_CREATE_VM``, ``KVM_CREATE_VCPU``, ``KVM_SET_REGS`` and its
friends), registering guest physical memory (``KVM_SET_USER_MEMORY_REGION``), starting the VM (``KVM_RUN``), and
injecting interrupts in the guest (``KVM_INTERRUPT``). A detailed list of commands is available in the Linux kernel
`documentation <https://github.com/torvalds/linux/blob/master/Documentation/virtual/kvm/api.txt>`__. The figure below
shows the architecture of a standard KVM setup.

.. image:: kvm_interface.svg
    :width: 75%

It is up to the KVM client (running in user space) to emulate virtual hardware, as the KVM kernel driver only provides a
virtual CPU. The clients are responsible for handling I/O, memory-mapped I/O, injecting interrupts in the guest, and
performing DMA. During initialization, the client first allocates a chunk of virtual memory using the plain ``mmap()``
system call, then registers this memory as guest physical memory using ``KVM_SET_USER_MEMORY_REGION``. KVM treats any
memory access that falls outside registered regions as memory-mapped I/O.

When the guest executes an instruction that accesses unmapped physical memory, ``KVM_RUN`` returns to the client, which
determines the type of I/O access and emulates it accordingly. For example, when a guest instruction writes to physical
address ``OxB8000`` the following occurs:

- The virtual CPU (VCPU) attempts to access that memory and realizes that it is unmapped
- The VCPU triggers a VM exit, giving control back to the KVM driver
- KVM determines the cause of the VM exit and returns to user space from the KVM_RUN call
- The client reads the faulting guest physical address and determines the associated virtual device
- The client calls the I/O handler of the VGA virtual device, which eventually displays a character in the
  upper left corner of the screen.
- Once the I/O emulation is done, the client resumes the guest VM by calling ``KVM_RUN`` again.

The KVM client injects interrupts in the guest using the ``KVM_INTERRUPT`` ioctl. Let us take the example of a virtual
clock device. This kind of device would typically trigger a periodic interrupt, e.g., every 10 ms. In order to emulate
it, the client process registers a periodic timer signal handler with the host OS. At the lowest level, the host OS
configures the host machine's clock to generate periodic host interrupts. When a host interrupt occurs, the host CPU
automatically interrupts the running guest VM, context switches to the host OS, which then delivers the timer signal to
the client process. The client then calls the virtual clock device emulation code, which then uses ``KVM_INTERRUPT`` to
inject the virtual interrupt into the guest. At the next invocation of ``KVM_RUN``, the host CPU reloads the guest
context and triggers the guest's interrupt handler.

The KVM client also handles DMA. Remember that during initialization, the client mapped host virtual
memory in its address space, which it then instructed to be used as guest physical memory by KVM. A virtual device
handler would just read and write to that mapped host virtual memory in order to exchange data with the guest VM.
It can do so from another thread while the guest VM is running, or from the same thread when the guest VM is interrupted
by a signal and control is returned to the client.

The above is the minimum required to run a guest such as Windows: a virtual CPU and a collection of virtual devices. KVM
implements many more features that can be optionally used. It has hypercalls, nested virtualization, various MSRs, etc.
KVM provides an interface to verify which features are available (called `capabilities`). For more details, refer to the
various KVM documentation files in the Linux `source
tree <https://github.com/torvalds/linux/tree/master/Documentation/virtual/kvm>`__. You can also browse QEMU's `source
code <https://github.com/qemu/qemu/blob/master/accel/kvm/kvm-all.c>`__ to understand which KVM features it uses.
Finally, there is a great article `here <https://lwn.net/Articles/658511/>`_ that explains in detail how to write
your own KVM client from scratch.


Emulating the KVM interface
===========================

KVM is great for running code at native speeds, but what if we actually want to do some advanced analysis on the guest
code? What if we want to instrument it? One common method for doing that is to use dynamic binary translation.
The dynamic binary translator (DBT) takes a chunk of guest code, disassembles it, injects instrumentation code,
reassembles it, then runs the result on the host CPU. QEMU comes with a powerful DBT that can be used instead of KVM
to run the guest OS. One could take QEMU and modify its DBT in order to analyze guest code.
An alternative to this is to write a CPU emulator, wrap it under the KVM interface, and let QEMU use it transparently.

Emulating the KVM interface allows decoupling the CPU emulation and code instrumentation infrastructure from virtual
hardware emulation. This is very powerful, as one is not stuck anymore with a given KVM client implementation. The
client can live on its own and upgrading it becomes straightforward. For example, the first prototype of S2E released
back in 2011 was tightly coupled to QEMU and was de facto stuck with the QEMU version of that time (v1.0). The current
version of S2E however emulates the KVM interface and is not tied to any particular client. In fact, upgrading
from QEMU 1.0 to QEMU 3.0 was fairly straightforward, despite over six years separating these two versions.


Using system call hooks for emulation
-------------------------------------

There are different ways in which one can implement a KVM-compatible CPU emulator. We chose to take the DBT implemented
by QEMU and refactor it into a standalone user-space library. The advantage of this compared to building our own
emulation is that we get the maturity and performance of QEMU's DBT, with only a small overhead incurred by the
indirection of the KVM interface. Overall, it took about six person-month to refactor the code, most of it was the
tedious task of moving code around. We will explain the process in details later below.

Our KVM CPU emulator comes as a user-space shared library that can be loaded into the KVM client using ``LD_PRELOAD``.
The library intercepts the ``open`` and ``ioctl`` system calls to ``/dev/kvm``, as well as ``mmap`` and a few others.
The ``open`` hook checks that the file name is ``/dev/kvm``, and if so, returns a fake handle that will be later checked
and intercepted by the ``ioctl`` and other system call hooks. We could also have replaced the KVM driver itself and
provided a kernel-mode version of this library, but this would have caused needless complexity and unnecessary switches
to kernel mode.

We refer to the real KVM driver that ships with the Linux kernel as *native KVM* and to our DBT-based emulation of KVM
as *emulated KVM*, implemented by the *KVM emulation engine*.

Differences between actual KVM and KVM emulation
------------------------------------------------

Implementing a KVM-compatible interface poses several challenges. In theory, there should be no difference between the
native KVM implementation and a DBT-based one, except for speed (and of course different CPU features). A proper
implementation of the emulated KVM should give the same outputs for identical inputs (CPU state, interrupts, etc.). In
practice however, due to how the DBT works, there are some differences. The most important one is the significant delay
with which the DBT handles injected guest interrupts. This may cause problems for some guest OSes. A lesser problem is
the inconsistent state of the emulated CPU when handling I/O operations. This only matters if the KVM client
reads the CPU state while handling I/O (e.g., VAPIC emulation in QEMU).

The first difference between actual KVM and KVM emulation is the interrupt injection delay. The virtualization hardware
on the host CPU triggers a VM exit as soon as there is an external interrupt sent to the host (timer, network, etc). It
also triggers a VM exit as soon as the guest unmasks interrupts (e.g., by writing to APIC registers or executing the
``sti`` instruction) and there are pending interrupts (injected by the client with ``KVM_INTERRUPT``). All this happens
without delays at instruction granularity. In contrast, emulated KVM is much slower to react to these events. In the
worst case, the delays may starve lower priority interrupts, causing hangs. Some guests may even crash if interrupts
come too late (e.g., there is a timer DPC in the Windows XP  kernel that is wrongly allocated on the stack, which causes
a crash if the interrupt happens too late, i.e., after the stack is cleaned).

For performance reasons, the DBT cannot check interrupts at every instruction. Instead, it checks them at control flow
change boundaries, i.e., when there is an instruction that modifies the program counter. When the DBT enables
translation block chaining (a technique that speeds up emulation by running translated code continuously without calling
the DBT), pending interrupts are not checked at all and it is up to the KVM client to break the translation block chain
when there is a pending interrupt. Unfortunately, native KVM does not provide a standard API for that and the most
reliable way we found to handle this is to add an additional ``KVM_FORCE_EXIT`` call which the client would invoke
when there are pending interrupts.

The second difference is the imprecise state on device I/O. When native KVM returns from ``KVM_RUN`` because the
guest executed an I/O instruction, the guest CPU's program counter points to the next instruction. In emulated KVM,
however, the program counter can point to some previous instruction close by. This is because the DBT does
not update the program counter after each instruction, for performance reasons. Instead, the DBT updates it at the next
control flow change (i.e., when the guest explicitly sets the program counter), or when there is an exception.

This is not a problem unless the KVM client reads the CPU state when handling I/O. On QEMU, this seems to only matter
for VAPIC emulation. OSes like Windows heavily read and write the APIC's Task Priority Register (TPR). This may trigger
an excessive amount of CPU exits and kernel-user mode switches, slowing down the guest considerably. To solve this, QEMU
patches the guest to replace the I/O instruction that accesses the TPR with a call to BIOS code that emulates the APIC's
TPR without causing a VM exit. To do this patching, QEMU checks the instruction pattern at the program counter that
accessed the `VAPIC <https://github.com/qemu/qemu/blob/master/hw/i386/kvmvapic.c>`__. If this program counter is wrong
(like in emulated KVM), patching will fail. We extended the KVM interface with the ``KVM_CAP_DBT`` flag to disable the
VAPIC when emulated KVM is present. Disabling it does not cause noticeable slowdowns because there are no kernel-user
mode switches involved anyway.

Summary
-------

To summarize, we implemented a shared library that hooks KVM calls in order to emulate the KVM interface. The library
uses DBT-based CPU emulation. In order to accommodate for shortcomings of the DBT-based method, we added two extensions
to KVM: ``KVM_CAP_DBT`` and ``KVM_FORCE_EXIT``. The first is a capability that signals to the KVM client the presence of
a DBT-based implementation so that it can adjust its behavior accordingly. The second allows faster interrupt injection.
We do not believe that these two extensions are fundamental, they could probably be eliminated with a better engineering
of the CPU emulator.



Adding symbolic execution capabilities to KVM
=============================================

In the previous section, we have seen how to build a KVM emulation engine out of a DBT that only supports one execution
path and no symbolic data. In this section, we will show how to extend that engine as well as the KVM interface in order
to support symbolic execution. We will primarily focus on the KVM interface, treating the symbolic execution engine
itself as a black box. The design and implementation of the symbolic execution engine will be covered in another write
up.

Before we begin, let us recap how symbolic execution works. Programs take inputs, perform some computations on them, and
generate some output. If there is a conditional branch, such as ``if (x + 2) ... else ...``, the predicate is evaluated
and one or the other branch is executed. During normal execution (e.g., when running on a normal CPU), all inputs have a
concrete value (e.g., ``x=1`` or ``x=12``) and exercise only one path at a time on each run. Symbolic execution replaces
the concrete inputs with symbols (e.g., ``x=λ``) and builds symbolic expressions (e.g., ``λ + 2``) as the program
executes. When a symbolic expression reaches a conditional branch, the engine calls a constraint solver to determine
which branch to follow. In case both outcomes are feasible, the engine splits the current execution path in two by
taking a snapshot of the system state (CPU, RAM, devices) and then executes each path independently. Each path also gets
a constraint (e.g., ``λ + 2 != 0`` and ``λ + 2 == 0``) so that the constraint solver can remember where execution came
from and compute concrete outputs when execution terminates.

A symbolic execution engine can be decomposed in two main components: one that enables multi-path execution and another
one that handles symbolic data storage and propagation. Hypervisors such as QEMU of VMware  already let users take as
many snapshots as they want. These snapshots include CPU, memory, as well as device state. Multi-path execution requires
the ability to quickly create lightweight whole-system snapshots and be able to switch between them at any time. On top
of that, a symbolic execution engine adds the ability to store symbolic data in the snapshots and perform computations
on that symbolic data.

Multi-path execution
--------------------

The hypervisor needs to be aware of multi-path execution. A vanilla hypervisor normally runs a single path at a time
and all guest memory accesses go to a fixed area of host virtual memory, all disk accesses go to the same file, etc.
In multi-path mode, however, it is necessary to redirect these addresses to *per-path* storage. In other words, each
execution path would have its own area of virtual memory, disk storage, and even device state. Furthermore, this must
be done efficiently using copy-on-write, as each path can have several gigabytes of state.

One approach to solve this is to add several extensions to the KVM interface. The extensions include a call to
read/write memory, a call to read/write the virtual disk, and a callback to save and restore device state. The purpose
of these calls is to redirect disk or DMA accesses done by the hypervisor's virtual devices to per-state storage. This
level of indirection allows keeping the KVM emulation engine decoupled from the hypervisor, which does not need to be
aware of the mechanics of how snapshots are stored, how copy-on-write is implemented, etc. This is all done by the
symbolic execution engine. We will present next each call individually.

The first extension lets the hypervisor specify memory regions that must be saved in the system snapshot. During
initialization, immediately after the hypervisor maps guest physical memory, it must now invoke the
``KVM_CAP_MEM_FIXED_REGION`` API, specifying the host virtual address and the size of the allocated region. The KVM
emulation engine uses this information to initialize per-state storage for that memory region, copy any data from the
original mapped region, then forbid access to that region. The hypervisor cannot dereference the original memory
anymore and must instead call ``KVM_CAP_MEM_RW``, which we will introduce next.

The second extension implements memory accesses. When the hypervisor needs to access guest physical memory (e.g., when
performing DMA), instead of directly dereferencing a pointer to that memory, it must now invoke the ``KVM_CAP_MEM_RW``
API. This call takes as parameters a source and destination pointer, the direction of the transfer (read/write), and
the length. The symbolic execution engine uses this information to lookup the actual per-state data associated with the
given host virtual address and returns (or writes) the requested data.

Finally, a few extensions are needed to manage the disk and device state. Instead of accessing the virtual disk file
using read or write system calls, the hypervisor must now call ``KVM_DISK_RW``. Handling device state is a bit
different: instead of intercepting reads/and writes to every byte of the device state (which would be completely
impractical), the symbolic execution engine leverages the hypervisor's ability to save and restore device state to/from
a file. However, instead of using a file, the hypervisor calls the ``KVM_DEV_SNAPSHOT`` API. This call is only required
when forking or switching to a new execution path. You can find more details about these APIs in the reference below.

.. note::

    You may be wondering if these multi-path extensions are necessary. The short answer is no. If we can find a
    system-level approach to managing the state (vs. manually inserting indirections in the code), then we do not need
    them anymore. For example, it is possible to use the ``fork()`` system call of the host in order to create a new
    execution path (but this is prohibitively expensive, as there would be one hypervisor process per path), or
    implement lightweight system snapshots by tweaking the page tables of the host (see `Dune
    <https://www.usenix.org/conference/osdi12/technical-sessions/presentation/belay>`__ [OSDI'12] and `Hummingbird
    <https://www.usenix.org/conference/hotos13/session/bugnion>`__ [HOTOS'13]). We plan to port S2E to the latter
    approach, which would bring many more benefits besides simplified APIs (e.g., much faster state snapshotting and
    state switching).


Handling symbolic data
----------------------

To keep things simple, we decided that symbolic data cannot leak into the KVM client and therefore the KVM API does not
need support for symbolic data exchange. We observed that symbolic data does not usually propagate through this
interface: QEMU does not normally read CPU registers or memory locations that contain symbolic data. Likewise, data
exchanged between the guest and the virtual devices is concrete. In cases where symbolic data does leak, the KVM
emulation engine concretizes it. Here is what happens when a program tries to print a string containing symbolic
characters:

 * The program running in the guest calls ``printf("%s", buf);`` where ``buf`` has one or more symbolic characters.
 * ``printf`` formats the string into a temporary buffer (which now has symbolic characters too), then issues
   a ``write`` system call with the address of that temporary buffer and the file descriptor of the console as
   a parameter.
 * The kernel forwards the ``write`` request to the console driver.
 * The console driver writes each character to the video memory.
 * The KVM emulation engine determines that the write requires a VM exit to the hypervisor because the address points
   to a memory-mapped I/O region. The engine also checks whether the instruction has symbolic data in its data operand
   and if yes, concretizes the symbolic data before calling the hypervisor, which sees the concrete value.
   Concretization adds a path constraint to ensure correct symbolic execution when control is passed back to
   the program.

Restricting the KVM interface to concrete data brings massive simplifications to the system. There is no need to rewrite
a potentially large and complex hypervisor to support symbolic data. And in practice, simply redirecting the program's
output to ``/dev/null`` or a symbolic file in a RAM disk is enough to work around most concretizations issues (e.g.,
when symbolic data is written to the console or the virtual disk). Of course, one may want to symbolically execute
virtual devices (e.g., when testing device drivers). The solution for this is to write a symbolic device model, which we
leave out for another tutorial.


Reference
=========

This section explains in detail the new KVM extensions that a KVM client should support in order to be compatible
with the KVM emulation engine. Each command is described as follows:

* Command: indicates the name of the command.
* Capability: indicates the KVM capability that signals the presence of that command.
* Requirement: indicates when that capability/command must be supported. Some commands are only required for multi-path
  execution, some are required in all cases.
* Any associated data structures. These are passed along the command identifier to the ``ioctl`` system call.
* The command description.

.. note::

   Here is a pointer to S2E's source code where you can find the implementation of all these extensions.
   `libs2e.c <https://github.com/S2E/s2e/blob/master/libs2e/src/libs2e.c>`__ is the main entry point of the
   ``libs2e.so`` shared library. This module intercepts IOCTLs to ``/dev/kvm`` and forwards them to the appropriate
   handlers. If you are lost in the 90 KLOC that comprise ``libs2e.so``, just start from this file and work your
   way up to the other components. This should help you get started hacking!


Dynamic binary translation
--------------------------

=========== =====================================================
Command     N/A
Capability  KVM_CAP_DBT
Requirement Mandatory for any KVM emulation engine that uses DBT
=========== =====================================================

This capability indicates to the client that the underlying KVM implementation uses dynamic binary translation instead
of actual hardware virtualization. Until the KVM emulation engine perfectly mimics the native KVM interface, this
capability allows the client to adjust its behavior to support the KVM emulation engine.


Registering memory regions
--------------------------

=========== ========================================================================
Command     KVM_MEM_REGISTER_FIXED_REGION
Capability  KVM_CAP_MEM_FIXED_REGION
Requirement - Mandatory for a KVM emulation engine that supports multi-path execution
            - Optional for single-path implementations
=========== ========================================================================

.. code-block:: c

    struct kvm_fixed_region {
        const char *name;
        __u64 host_address;
        __u64 size;

        #define KVM_MEM_SHARED_CONCRETE 1
        __u32 flags;
    };

The KVM client must call this API after it allocates guest physical memory (either RAM or ROM) in order to register them
with the KVM emulation engine. The client must register all memory regions before calling ``KVM_RUN``. The client must
not later pass to ``KVM_SET_USER_MEMORY_REGION`` any region (or part thereof) that has not been previously registered
with ``KVM_MEM_REGISTER_FIXED_REGION``.

This API lets the KVM emulation engine register internal data structures that will track later accesses done with
``KVM_MEM_RW``. After this API return, the memory chunk specified by ``host_address`` and ``size`` becomes read and
write-protected. The client must not access it directly anymore and must always use ``KVM_MEM_RW`` instead. Protecting
the region is helpful to catch any stray accesses and help with debugging.

The ``KVM_MEM_SHARED_CONCRETE`` flag specifies whether the given memory chunk may be shared among all execution paths.
This is useful for video memory, which is typically write-only and whose state does not matter for correct guest
execution (i.e., different execution paths clobbering each other's frame buffers has usually no bad effect on
execution correctness as long as guest code does not read that data back).


Accessing guest memory
----------------------

=========== ========================================================================
Command     KVM_MEM_RW
Capability  KVM_CAP_MEM_RW
Requirement Mandatory for all KVM emulation engine implementations
=========== ========================================================================

.. code-block:: c

    struct kvm_mem_rw {
        /* source and dest are always host pointers */
        __u64 source;
        __u64 dest;
        __u64 is_write;
        __u64 length;
    };

This capability signals to the KVM client that the KVM emulation engine requires the KVM client to perform all accesses
to physical memory through the ``KVM_CAP_MEM_RW API``. For single-path emulators, this is required to properly flush
CPU's code cache in case DMA touches memory that contains code. For multi-path emulators, this also ensures that data is
read/written from/to the correct execution state.


Interrupting execution
----------------------

=========== ========================================================================
Command     KVM_FORCE_EXIT
Capability  KVM_CAP_FORCE_EXIT
Requirement Mandatory for KVM emulation engine implementations that cannot respond quickly to interrupt injection
=========== ========================================================================

This capability signals to the KVM client that the KVM emulation engine cannot return from KVM_RUN quickly enough
(e.g., when there are signals present). A KVM client must call ``KVM_FORCE_EXIT`` when it would otherwise want
KVM_RUN to exit and when ``KVM_CAP_FORCE_EXIT`` is present.


Virtual disk I/O
----------------

=========== ========================================================================
Command     KVM_DISK_RW
Capability  KVM_CAP_DISK_RW
Requirement - Mandatory for a KVM emulation engine that supports multi-path execution
            - Optional for single-path implementations or when the client does not support virtual disks
=========== ========================================================================

.. code-block:: c

    struct kvm_disk_rw {
        /* Address of the buffer in host memory */
        __u64 host_address;
        /* 512-byte sectors */
        __u64 sector;
        /* input: sectors to read/write, output: sectors read/written */
        __u32 count;
        __u8 is_write;
    };


The KVM client must invoke this command when it otherwise would write disk data to a file. The KVM emulation engine
takes the disk data specified in the ``kvm_disk_rw`` structure and store it in a location that is associated with the
current execution path. If the client fails to invoke this command while in multi-path execution, the disk state would
be shared by all execution paths, leading to virtual disk corruption, as the different paths would clobber each other's
disk data.

In practice, KVM clients should implement copy-on-write mechanisms. In case of reads, the client must call first
``KVM_DISK_RW`` to get any dirty sectors, and if there are none, read from the underlying image file. In case of writes,
the client should directly call ``KVM_DISK_RW`` with the modified sector data.


Saving/restoring device snapshots
---------------------------------

=========== ========================================================================
Command     KVM_DEV_SNAPSHOT
Capability  KVM_CAP_DEV_SNAPSHOT
Requirement - Mandatory for a KVM emulation engine that supports multi-path execution
            - Optional for single-path implementations
=========== ========================================================================

.. code-block:: c

    struct kvm_dev_snapshot {
        __u64 buffer;
        /* If is_write == 0, indicates expected size in case of error */
        __u32 size;

        /* Only when is_write == 0, indicates the position from which reading the state */
        __u32 pos;
        __u8 is_write;
    };

This command should only be called when KVM_RUN returns the ``KVM_EXIT_SAVE_DEV_STATE`` or
``KVM_EXIT_RESTORE_DEV_STATE`` exit code.

When saving a device snapshot (``is_write = 1``), only ``buffer`` and ``size`` are valid. ``buffer`` must point to a host
virtual address containing the state of all virtual devices. The KVM client  must call ``KVM_DEV_SNAPSHOT`` only once.
The call returns the number of bytes written, which should be equal to ``size``.

When restoring a device snapshot (``is_write = 0``), the commands allows reading any range of snapshot data previously
saved. ``pos`` and ``size`` must be set to read the desired chunk of data. The KVM client must call ``KVM_DEV_SNAPSHOT``
multiple times. The call returns the number of bytes effectively read, which may be smaller than ``size`` in case
the specified range exceeds the amount of data in the snapshot.


Setting the clock scale pointer
-------------------------------

=========== ========================================================================
Command     KVM_SET_CLOCK_SCALE
Capability  KVM_CAP_CPU_CLOCK_SCALE
Requirement - Mandatory when the overhead of the KVM emulation engine is large
            - Optional otherwise
=========== ========================================================================

This command communicates to the KVM emulation engine the address of a variable that contains the clock scale.
The address must be in the KVM client's address space.
The KVM client must honor this factor as soon as possible, typically the next time a virtual device calls a time-related
function (e.g., to schedule a timer interrupt).

The clock scale is an integer that specifies by what factor the client must slow down the guest's virtual clock.
A factor of one indicates no slow down (real-time). A factor of two indicates that the client must run its clock
two times slower than real-time. In other words, for every second of elapsed time seen by the guest, the wall time
would have advanced by two seconds.

The KVM emulation engine sets the clock scale when it performs slow operations, e.g., interpreting LLVM instructions
in the symbolic execution engine. This may be several orders of magnitude slower than real-time (100-1000x clock
scale factor). Failing to set the factor accordingly would cause the client to inject timer interrupts too
frequently, preventing any progress of the guest.


KVM_RUN exit codes
------------------

When the KVM_RUN command exits, it indicates to the KVM client the reason of the exit in the form of an exit code. In
addition to the standard codes, the KVM emulation engine adds the following exit codes. They should be implemented by
any client that supports multi-path execution.

``KVM_EXIT_FLUSH_DISK``

    This exit code indicates to the client that it must flush any buffers associated with virtual disks.
    The client should call ``KVM_DISK_RW`` in order to flush any in-progress transfers before invoking ``KVM_RUN`` again.

    The KVM emulation engine returns this code when it is ready to fork a new execution path or in any other case where
    it needs the disk state to be consistent.

    Implementing this code is optional if the client does not support virtual disks.


``KVM_EXIT_SAVE_DEV_STATE``

    This exit code indicates to the client that it must take a snapshot of all virtual devices and send the
    snapshot data to the KVM emulation engine using the ``KVM_DEV_SNAPSHOT`` command.

    The KVM emulation engine returns this code when it is ready to fork a new execution path or wants to switch to
    another execution path. In either case, it needs the virtual device state to be committed to the per-state storage
    before continuing.


``KVM_EXIT_RESTORE_DEV_STATE``

    This exit code indicates to the client that it must restore a snapshot of all virtual devices after reading
    the snapshot data from the KVM emulation engine by using the ``KVM_DEV_SNAPSHOT`` command.

    The KVM emulation engine returns this code when it wants to switch to another execution path and needs the client
    to restore the associated virtual device state.


``KVM_EXIT_CLONE_PROCESS``

    This exit code indicates to the KVM client that it must re-initialize the state of all its threads.

    The KVM emulation engine returns this code after it calls the ``fork()`` system call in order to create a new
    instance of the emulator. In this new instance, there is only one thread (the one that called ``fork()``). The
    client must ensure that before calling KVM_RUN again, the new process instance is completely independent from the
    parent one and can run on its own. In particular, the client must close and re-open any file descriptors that
    ``fork()`` would otherwise share with the parent.
