==============================================
S2E: The Selective Symbolic Execution Platform
==============================================

S2E is a platform for writing tools that analyze the properties and behavior of software systems. S2E comes as a modular
library that gives virtual machines symbolic execution and program analysis capabilities. S2E runs unmodified x86,
x86-64, or ARM software stacks, including programs, libraries, the kernel, and drivers. Symbolic execution then
automatically explores hundreds of thousands of paths through the system, while analyzers check that the desired
properties hold on these paths and selectors focus path exploration on components of interest.

This documentation explains in details how to set up S2E, how to symbolically execute programs, and how to find
vulnerabilities in them. S2E is pronounced *S two E*.


.. toctree::
   :caption: Getting Started
   :maxdepth: 1

   Start here: setting up S2E <s2e-env>
   BuildingS2E
   Tutorials/BasicLinuxSymbex/s2e.so
   Tutorials/BasicLinuxSymbex/SourceCode


.. toctree::
   :caption: Use Cases
   :maxdepth: 1

   Tutorials/PoV/pov
   Tutorials/PoV/index

   Combining Kaitai Struct and S2E for analyzing parsers [external] <https://adrianherrera.github.io/posts/kaitai-s2e>
   Analyzing trigger-based malware with S2E [external] <https://adrianherrera.github.io/posts/malware-s2e>
   Solving CTF challenges with S2E [external] <https://adrianherrera.github.io/posts/google-ctf-2016/>

   Tutorials/SystemTap/index.rst
   Tutorials/WindowsDLL/index.rst
   Tutorials/WindowsDrivers/FaultInjection.rst
   Tutorials/MSOffice/index.rst
   Tutorials/CFI/index.rst
   Tutorials/Revgen/Revgen.rst
   EquivalenceTesting

.. toctree::
   :caption: Howtos
   :maxdepth: 1

   Howtos/Coverage/index.rst
   Communicating between the guest and S2E plugins <Plugins/BaseInstructions>
   MovingFiles
   Running S2E on multiple cores <Howtos/Parallel>
   Using execution tracers <Howtos/ExecutionTracers>
   ImageInstallation
   Writing S2E plugins <Howtos/WritingPlugins>
   Howtos/LuaInstrumentation


.. toctree::
   :caption: Scaling Symbolic Execution
   :maxdepth: 1

   Howtos/Concolic
   StateMerging
   Tools/ForkProfiler
   FAQ

.. toctree::
   :caption: Development
   :maxdepth: 1

   DesignAndImplementation/KvmInterface
   Contribute
   Profiling/ProfilingS2E
   DebuggingS2E
   Testsuite
   WindowsEnvSetup


.. toctree::
   :caption: Plugin Reference
   :maxdepth: 1

   Plugins/Linux/LinuxMonitor
   Plugins/Windows/WindowsMonitor
   Plugins/RawMonitor
   Plugins/ModuleExecutionDetector

   ExecutionTracer <Plugins/Tracers/ExecutionTracer>

   Plugins/FunctionMonitor
   Plugins/Linux/FunctionModels
   Plugins/EdgeKiller


Publications
============

* `S2E: A Platform for In-Vivo Multi-Path Analysis of Software Systems <http://dslab.epfl.ch/pubs/EPFL_TH6251.pdf>`_.
  Vitaly Chipounov. EPFL PhD Thesis, July 2014

* `The S2E Platform: Design, Implementation, and Applications <http://dslab.epfl.ch/pubs/s2e-tocs.pdf>`_.
  Vitaly Chipounov, Volodymyr Kuznetsov, George Candea.
  ACM Transactions on Computer Systems (TOCS), 30(1), Special issue: Best papers of ASPLOS, February 2012.

* `Enabling Sophisticated Analysis of x86 Binaries with RevGen <http://dslab.epfl.ch/pubs/revgen.pdf>`_.
  Vitaly Chipounov and George Candea.
  7th Workshop on Hot Topics in System Dependability (HotDep), Hong Kong, China, June 2011

* `S2E: A Platform for In Vivo Multi-Path Analysis of Software Systems <http://dslab.epfl.ch/pubs/s2e.pdf>`_.
  Vitaly Chipounov, Volodymyr Kuznetsov, George Candea. 16th Intl. Conference on Architectural Support for Programming
  Languages and Operating Systems (`ASPLOS <http://asplos11.cs.ucr.edu/>`_), Newport Beach, CA, March 2011.

* `Testing Closed-Source Binary Device Drivers with DDT <http://dslab.epfl.ch/pubs/ddt.pdf>`_.
  Volodymyr Kuznetsov, Vitaly Chipounov, George Candea. USENIX Annual Technical Conference (`USENIX
  <http://www.usenix.org/event/atc10/>`_), Boston, MA, June 2010.

* `Reverse Engineering of Binary Device Drivers with RevNIC <http://dslab.epfl.ch/pubs/revnic.pdf>`_.
  Vitaly Chipounov and George Candea. 5th ACM SIGOPS/EuroSys European Conference on Computer Systems (`EuroSys
  <http://eurosys2010.sigops-france.fr/>`_), Paris, France, April 2010.

* `Selective Symbolic Execution <http://dslab.epfl.ch/pubs/selsymbex.pdf>`_.
  Vitaly Chipounov, Vlad Georgescu, Cristian Zamfir, George Candea. Proc. 5th Workshop on Hot Topics in System
  Dependability, Lisbon, Portugal, June 2009
