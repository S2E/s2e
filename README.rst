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

Getting started
===============

  1. `Creating analysis projects with s2e-env <src/s2e-env.rst>`_
  2. `Building S2E without s2e-env <src/BuildingS2E.rst>`_
  3. `Symbolic execution of Linux binaries <src/Tutorials/BasicLinuxSymbex/s2e.so.rst>`_
  4. `Symbolic execution of arbitrary programs <src/Tutorials/BasicLinuxSymbex/SourceCode.rst>`_

Tutorials
=========

  1. Automated proof of vulnerability generation with S2E

     a. `The theory behind automated PoV generation using symbolic execution <src/Tutorials/PoV/pov.rst>`_
     b. `Using S2E to generate PoVs for Linux, Windows, and CGC binaries <src/Tutorials/PoV/index.rst>`_

  2. `Combining Kaitai Struct and S2E for analyzing parsers <https://adrianherrera.github.io/post/kaitai-s2e>`_
     (external link)

  3. `Measuring code coverage with S2E <src/Howtos/Coverage/index.rst>`_

  4. Analysis of Linux binaries

     a. `Symbolic execution of Coreutils <src/Tutorials/coreutils/index.rst>`_
     b. `Using SystemTap with S2E <src/Tutorials/SystemTap/index.rst>`_

  5. Analysis of Windows binaries

     a. `Analysis of Windows DLLs <src/Tutorials/WindowsDLL/index.rst>`_
     b. `Testing error recovery code in Windows drivers with multi-path fault injection <src/Tutorials/WindowsDrivers/FaultInjection.rst>`_


  6. `Customizing stock VM images <src/ImageInstallation.rst>`_
  7. `Moving files between the guest and host <src/MovingFiles.rst>`_
  8. `Communicating between the guest and S2E plugins <src/Plugins/BaseInstructions.rst>`_
  9. `Running S2E on multiple cores <src/Howtos/Parallel.rst>`_
  10. `Writing S2E plugins <src/Howtos/WritingPlugins.rst>`_
  11. `Using execution tracers <src/Howtos/ExecutionTracers.rst>`_
  12. `Equivalence testing <src/EquivalenceTesting.rst>`_

Scaling symbolic execution
==========================

  1. `Executing large programs with concolic execution <src/Howtos/Concolic.rst>`_
  2. `Exponential analysis speedup with state merging <src/StateMerging.rst>`_
  3. `Debugging path explosion with the fork profiler <src/Tools/ForkProfiler.rst>`_
  4. `Frequently asked questions <src/FAQ.rst>`_


S2E development
===============

* `Contributing to S2E <src/Contribute.rst>`_
* `Profiling S2E <src/ProfilingS2E.rst>`_
* `Debugging S2E <src/DebuggingS2E.rst>`_


Plugin reference
================

OS monitors
-----------

To implement selectivity, S2E relies on several OS-specific plugins to detect module loads/unloads and execution of
modules of interest.

* `LinuxMonitor <src/Plugins/Linux/LinuxMonitor.rst>`_
* `WindowsMonitor <src/Plugins/Windows/WindowsMonitor.rst>`_
* `RawMonitor <src/Plugins/RawMonitor.rst>`_
* `ModuleExecutionDetector <src/Plugins/ModuleExecutionDetector.rst>`_

Execution tracers
-----------------

These plugins record various types of multi-path information during execution. This information can be processed by
offline analysis tools. Refer to the `How to use execution tracers? <src/Howtos/ExecutionTracers.rst>`_ tutorial to
understand how to combine these tracers.

* `ExecutionTracer <src/Plugins/Tracers/ExecutionTracer.rst>`_
* `ModuleTracer <src/Plugins/Tracers/ModuleTracer.rst>`_
* `TestCaseGenerator <src/Plugins/Tracers/TestCaseGenerator.rst>`_
* `TranslationBlockTracer <src/Plugins/Tracers/TranslationBlockTracer.rst>`_
* `InstructionCounter <src/Plugins/Tracers/InstructionCounter.rst>`_

Annotation plugins
------------------

These plugins allow the user to write plugins in `Lua <http://lua.org/>`_.

* Function and Instruction `Annotations <src/Plugins/Annotations.rst>`_

Miscellaneous plugins
---------------------

* `FunctionMonitor <src/Plugins/FunctionMonitor.rst>`_ provides client plugins with events triggered when the guest code
  invokes specified functions.
* `FunctionModels <src/Plugins/Linux/FunctionModels.rst>`_ reduces path explosion by transforming common functions into
  symbolic expressions.
* `EdgeKiller <src/Plugins/EdgeKiller.rst>`_ kills execution paths that execute some sequence of instructions (e.g.,
  polling loops).


Publications
============

* `S2E: A Platform for In-Vivo Multi-Path Analysis of Software Systems <http://dslab.epfl.ch/pubs/EPFL_TH6251.pdf>`_.
  Vitaly Chipounov. EPFL PhD Thesis, July 2014

* `The S2E Platform: Design, Implementation, and Applications <http://dslab.epfl.ch/pubs/s2e-tocs.pdf>`_.
  Vitaly Chipounov, Volodymyr Kuznetsov, George Candea.
  ACM Transactions on Computer Systems (TOCS), 30(1), Special issue: Best papers of ASPLOS, February 2012.

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
