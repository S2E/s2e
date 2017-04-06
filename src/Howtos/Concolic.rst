=================================================
Analyzing Large Programs Using Concolic Execution
=================================================

Unfortunately, symbolic execution may get stuck at the start of an execution and have a hard time reaching deep paths.
This is caused by the path selection heuristics and by the constraint solver. Path selection heuristics may not know
very well which execution paths to choose so that execution goes deeper. For example, in a loop that depends on a
symbolic condition, the heuristics may blindly keep selecting paths that would never exit the loop. Even if the path
selection heuristics knew which path to select to go through the whole program, invoking the constraint solver on every
branch that depends on symbolic input may become increasingly slower with larger and larger path depths.

To alleviate this, S2E also implements *concolic execution*. Concolic execution works exactly as traditional symbolic
execution: it propagates symbolic inputs through the system, allowing conditional branches to fork new paths whenever
necessary. The key difference is that concolic execution augments these symbolic values with *concrete* values (hence
the term *concolic*). The concrete values give a hint to the search heuristics about which paths to follow first. In
practice, the S2E user launches the program with concrete arguments that would drive the program down the path that
reaches interesting parts of that program, which S2E would then thoroughly explore. More practical details are provided
in the next sections of this tutorial.

Concolic execution allows the program under analysis to run to completion (without getting lost in the state space) while
exploring additional paths along the main concrete path. On each branch that depends on a symbolic value, the engine
follows in priority the one that would have been followed had the program been executed with concrete values. When the
first path that corresponds to the initial concrete values terminates, the engine will pick another path, recompute a
new set of concrete values, and proceed similarly until this second path terminates. Of course, custom path selection
plugins can optimize the selection for different needs (high code coverage, bug finding, etc.).


Executing Programs in Concolic Mode
===================================

Using custom instructions
-------------------------

The ``s2e_make_concolic`` custom instruction injects symbolic values while keeping the original concrete values. It is
used in the same way as ``s2e_make_symbolic``. It reads the original concrete values from memory, stores them in an
internal cache, and overwrites the memory with symbolic values. The cache maps the symbolic values to the actual
concrete values and allows the substitution of symbolic inputs with the concrete ones during expression evaluation
(e.g., at fork points).


Using the ``s2e.so`` plugin
-----------------------------

The `s2e.so <s2e.so.rst>`_ library enables symbolic execution without modifying the program's source code. This library
also supports concolic execution with the ``--concolic`` switch, that can be added right before the concrete program
arguments. The following example invokes the ``tr`` Unix utility via the ``tr ab ab ab`` command. The library
automatically assigns symbolic arguments to all arguments while keeping the concrete ``ab`` values.


::

   LD_PRELOAD=/home/s2e/s2e.so tr --concolic ab ab ab


FAQ
===

* *Can I use s2e_make_symbolic in concolic mode?*

  Yes. S2E will automatically assign default concrete values satisfying the path constraints during concolic execution.

* *I have cryptographic routines in my code. Can concolic execution get through them?*

  Probably not. Concolic execution will use the initial concrete values to get through cryptographic routines without
  getting lost in the large state space. However, it is very likely to get stuck in the constraint solver when checking
  the feasibility of a a branch condition (and computing new sets of concrete inputs).

* *I implemented custom plugins to aggressively prune paths because symbolic execution was getting stuck.
   Are these plugins still useful?*

  Yes, reducing state space by discarding uninteresting paths is always useful. Concolic execution does not solve the path
  explosion problem by itself. It merely helps getting to deep parts of the program faster.
