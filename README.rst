==============================================
S2E: The Selective Symbolic Execution Platform
==============================================

S2E is a platform for writing tools that analyze the properties and behavior of software systems. S²E comes as a modular
library that gives virtual machines symbolic execution and program analysis capabilities. S²E runs unmodified x86,
x86-64, or ARM software stacks, including programs, libraries, the kernel, and drivers. Symbolic execution then
automatically explores hundreds of thousands of paths through the system, while analyzers check that the desired
properties hold on these paths and selectors focus path exploration on components of interest.

This documentation explains in details how to set up S2E, how to symbolically execute programs, and how to find
vulnerabilities in them.

Documentation
=============

* Getting Started

  1. `Creating analysis projects with s2e-env <src/s2e-env.rst>`_
  2. `Building S2E without s2e-env <src/BuildingS2E.rst>`_
  3. `Symbolic execution of Linux binaries <src/Howtos/s2e.so.rst>`_
  4. `Symbolic execution of arbitrary programs <src/ManualTesting.rst>`_

* Tutorials

  1. `Automated Generation of Proofs of Vulnerability with S2E <src/Tutorials/pov.rst>`_
  2. `DARPA Cyber Grand Challenge <src/Tutorials/CGC.rst>`_
  3. `Coreutils <src/Tutorials/Coreutils.rst>`_
  4. `Windows DLL <src/Tutorials/WindowsDLL.rst>`_
  5. `Combining Kaitai Struct and S2E for analyzing parsers <https://adrianherrera.github.io/post/kaitai-s2e>`_
     (external link)
  6. `Testing Error Recovery Code in Windows Drivers with Multi-Path Fault Injection <src/Tutorials/WindowsDrivers/FaultInjection.rst>`_

* Howtos

  1. `Preparing a VM image for S2E <src/ImageInstallation.rst>`_
  2. `Moving files between the guest and host <src/MovingFiles.rst>`_
  3. `Using execution tracers <src/Howtos/ExecutionTracers.rst>`_
  4. `Running S2E on multiple cores <src/Howtos/Parallel.rst>`_
  5. `Writing S2E plugins <src/Howtos/WritingPlugins.rst>`_
  6. `Communicating between the guest and S2E plugins <src/Plugins/BaseInstructions.rst>`_

* Advanced topics

  1. `Equivalence testing <src/EquivalenceTesting.rst>`_
  2. `Exponential analysis speedup with state merging <src/StateMerging.rst>`_
  3. `How to debug guest code? <src/Howtos/Debugging.rst>`_
  4. `Executing large programs with concolic execution <src/Howtos/Concolic.rst>`_

* Analyzing the Linux Kernel

  1. `Building the Linux kernel <src/BuildingLinux.rst>`_
  2. `Using SystemTap with S2E <src/SystemTap.rst>`_

* S2E Tools

  1. `Fork profiler <src/Tools/ForkProfiler.rst>`_
  2. `Trace printer <src/Tools/TbPrinter.rst>`_
  3. `Execution profiler <src/Tools/ExecutionProfiler.rst>`_

* `Frequently Asked Questions <src/FAQ.rst>`_

S2E Development
===============

* `Contributing to S2E <src/Contribute.rst>`_
* `Profiling S2E <src/ProfilingS2E.rst>`_
* `Debugging S2E <src/DebuggingS2E.rst>`_


S2E Plugin Reference
====================

OS Monitors
-----------

To implement selectivity, S2E relies on several OS-specific plugins to detect module loads/unloads and execution of
modules of interest.

* `LinuxMonitor <src/Plugins/Linux/LinuxMonitor.rst>`_
* `WindowsMonitor <src/Plugins/Windows/WindowsMonitor.rst>`_
* `RawMonitor <src/Plugins/RawMonitor.rst>`_
* `ModuleExecutionDetector <src/Plugins/ModuleExecutionDetector.rst>`_

Execution Tracers
-----------------

These plugins record various types of multi-path information during execution. This information can be processed by
offline analysis tools. Refer to the `How to use execution tracers? <src/Howtos/ExecutionTracers.rst>`_ tutorial to
understand how to combine these tracers.

* `ExecutionTracer <src/Plugins/Tracers/ExecutionTracer.rst>`_
* `ModuleTracer <src/Plugins/Tracers/ModuleTracer.rst>`_
* `TestCaseGenerator <src/Plugins/Tracers/TestCaseGenerator.rst>`_
* `TranslationBlockTracer <src/Plugins/Tracers/TranslationBlockTracer.rst>`_
* `InstructionCounter <src/Plugins/Tracers/InstructionCounter.rst>`_

Selection Plugins
-----------------

These plugins allow you to specify which paths to execute and where to inject symbolic values.

* `EdgeKiller <src/Plugins/EdgeKiller.rst>`_ kills execution paths that execute some sequence of instructions (e.g.,
  polling loops).

Annotation Plugins
------------------

These plugins allow the user to write plugins in `Lua <http://lua.org/>`_.

* Function and Instruction `Annotations <src/Plugins/Annotations.rst>`_

Miscellaneous Plugins
---------------------

* `FunctionMonitor <src/Plugins/FunctionMonitor.rst>`_ provides client plugins with events triggered when the guest code
  invokes specified functions.
* `FunctionModels <src/Plugins/Linux/FunctionModels.rst>`_ reduces path explosion by transforming common functions into
  symbolic expressions.


S2E Publications
================

* `S2E: A Platform for In Vivo Multi-Path Analysis of Software Systems <http://dslab.epfl.ch/pubs/s2e.pdf>`_.
  Vitaly Chipounov, Volodymyr Kuznetsov, George Candea. 16th Intl. Conference on Architectural Support for Programming
  Languages and Operating Systems (`ASPLOS <http://asplos11.cs.ucr.edu/>`_), Newport Beach, CA, March 2011.

* `Testing Closed-Source Binary Device Drivers with DDT <http://dslab.epfl.ch/pubs/ddt>`_.
  Volodymyr Kuznetsov, Vitaly Chipounov, George Candea. USENIX Annual Technical Conference (`USENIX
  <http://www.usenix.org/event/atc10/>`_), Boston, MA, June 2010.

* `Reverse Engineering of Binary Device Drivers with RevNIC <http://dslab.epfl.ch/pubs/revnic>`_.
  Vitaly Chipounov and George Candea. 5th ACM SIGOPS/EuroSys European Conference on Computer Systems (`EuroSys
  <http://eurosys2010.sigops-france.fr/>`_), Paris, France, April 2010.

* `Selective Symbolic Execution <http://dslab.epfl.ch/pubs/selsymbex>`_.
  Vitaly Chipounov, Vlad Georgescu, Cristian Zamfir, George Candea. Proc. 5th Workshop on Hot Topics in System
  Dependability, Lisbon, Portugal, June 2009
