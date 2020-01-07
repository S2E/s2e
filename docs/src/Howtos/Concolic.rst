=================================================
Analyzing large programs using concolic execution
=================================================

Symbolic execution may get stuck at the start of an execution and have a hard time reaching deep paths.
This is caused by path selection heuristics and the constraint solver. Path selection heuristics may not know
well which execution paths to choose so that execution can go deeper. For example, in a loop that depends on a
symbolic condition, the heuristics may blindly keep selecting paths that would never exit the loop. Even if the path
selection heuristics knew which path to select to go through the whole program, invoking the constraint solver on every
branch that depends on symbolic input may become increasingly slower with larger and larger path depths.

To alleviate this, S2E also implements a form of *concolic execution*. It works like traditional symbolic execution: it
propagates symbolic inputs through the system, allowing conditional branches to fork new paths whenever necessary. In
addition to this, concolic execution augments these symbolic values with *concrete* values (hence the term *concolic*).
The concrete values give a hint to the execution engine about which path to follow first. These values can be viewed as
a *seed*. In practice, the S2E user launches the program with symbolic arguments augmented with concrete seeds that
would drive the program down the path that reaches interesting parts of that program, while forking side branches, which
S2E would then thoroughly explore once the main seed path is completed.

Concolic execution allows the program under analysis to run to completion without getting lost in the state space,
while exploring additional paths along the seed path. On each branch that depends on a symbolic value, the
engine follows in priority the one that would have been followed had the program been executed with the concrete seed.
When the first path that corresponds to the initial concrete values terminates, the engine picks another path (with
the help of a search heuristic), recomputes a new set of concrete values, and proceeds similarly until this second path
terminates. Plugins that implement custom search heuristics can optimize path selection for different needs
(high code coverage, bug finding, etc.).


.. note::

    You may be familiar with a different form of concolic execution initially introduced by the DART paper (PLDI 2005).
    DART runs programs *concretely* along one path while collecting path constraints. When the program
    terminates, DART takes one constraint, negates it, computes an alternate set of concrete input values, then re-runs
    the program again using these new concrete inputs in order to exercise the new path.

    Unlike symbolic execution (and S2E), DART runs the program entirely concretely and does not
    fork the state of the program. In contrast, symbolic execution (and S2E) interprets instructions symbolically and
    builds an execution tree as a result of forking states when encountering a branch instruction that depends on
    symbolic data.

    In the context of S2E, *concolic execution* refers to normal symbolic execution where symbolic values are
    augmented with concrete data. Symbolic execution merely uses the concrete inputs as a seed to guide path exploration
    along specific paths of the execution tree.


Executing programs in concolic mode
===================================

Concolic execution is the default mode of operation of S2E. You do not need to do anything special other than
specifying initial concrete data (*seeds*) when creating symbolic values.

At the lowest level, one can create symbolic values with ``s2e_make_symbolic()``. This API writes the specified number
of symbolic bytes to the given buffer. However, before doing that, it saves into an internal cache the existing concrete
data stored in the buffer. The cache maps the symbolic values to the given concrete values and allows the substitution
of symbolic inputs with the concrete ones during expression evaluation (e.g., at fork points).

You can also create symbolic files, symbolic program arguments, symbolic standard input, etc. All these methods
eventually call ``s2e_make_symbolic()``. You may find more information about this
`here <../Tutorials/BasicLinuxSymbex/s2e.so.rst>`__ and `here <../Tutorials/BasicLinuxSymbex/SourceCode.rst>`__.


FAQ
===

**How is concolic execution as implemented in S2E similar to / different from symbolic execution as implemented
in KLEE?**

Concolic execution builds upon symbolic execution. They both require symbolic inputs, they both interpret instructions
symbolically, build expressions, and both require a constraint solver to be called on a branch that depend on symbolic
expressions in order to determine the feasibility of the outcomes.

When a branch depends on symbolic data, symbolic execution does not know which branch outcome is feasible without
calling the solver. Concolic execution, however, can use concrete inputs associated with the symbolic value to determine
the feasibility of at least one branch outcome. In theory, concolic execution will not get stuck if it cannot determine
the feasibility of the alternate branch. It would simply discard the alternate path.

**Can I disable concolic execution in S2E and just use normal symbolic execution like in KLEE?**

No. In practice, concolic execution as implemented in S2E behaves like symbolic execution. Just like symbolic
execution, concolic execution calls the constraint solver on each branch that has a symbolic condition.
In addition to that, concolic execution makes sure that the path constraints of the current state satisfy
the initial concrete inputs. You may set concrete inputs to zero (i.e., pass a zero-filled buffer to
``s2e_make_symbolic()``) if you do not care about them. This will not have any effect on the state space of the program.
Given enough resources, both approaches will discover the same states.

**If concolic execution uses concrete data to guide exploration, does it still need a constraint solver?**

Yes. Concolic execution does not know if the other outcome of a branch is feasible or not. It must therefore
use a constraint solver on each branch that depends on symbolic input in order to determine the feasibility
of the alternate branch outcome.

**Does concolic execution call the constraint solver when a path terminates in order to compute concrete inputs?**

No. Concrete inputs for a state are fully known when the state is created or forked. The symbolic execution engine
ensures that all new constraints added to the state satisfy these initial inputs. Any new symbolic values created
in the state during execution automatically get corresponding concrete values as well. Overall, this removes a call to
the solver compared to vanilla symbolic execution.

**The test case generator produces inputs that do not look at all like my initial concrete seed, what is wrong?**

Consider the following function. It makes a 4-byte buffer symbolic while using the concrete data stored there
as seed (``abcd``).

.. code:: c

    int main(void) {
        char buffer[4] = {'a', 'b', 'c', 'd'};
        s2e_make_symbolic(buffer, sizeof(buffer), "mydata");
        if (buffer[0] == 'd' && buffer[1] == 'c') {
            printf("found");
        }
        return 0;
    }

The first path (i.e., state 0) follows the concrete inputs and terminate without printing anything.
The solution is ``abcd`` (i.e., taken from the initial concrete assignments).
The second path, however, may have something like ``dc12``. The first two characters
are set by the path conditions, while the last two are arbitrary because the constraint solver may choose
random values for them while still satisfying path constraints.

Note that in the example above, the constraint solver is called only once at the if statement in order to verify
whether the *then* branch is feasible. It it not necessary to call the solver when the path terminates in order to
get concrete solutions because each path already contains a valid assignment of concrete values (i.e., the seed).


**Is it possible to have forked paths have concrete inputs as close as possible to the original seed?**

S2E does not currently implement this. In theory, one would need to ask the solver to choose values from the
original seed provided that the path constraints allow it.

**When does concolic execution call the constraint solver to compute concrete inputs?**

When a state forks. At this moment, the forked state gets assigned a new set of concrete inputs. These inputs will
hold true for this state until it terminates. So unlike in KLEE, there is no need for S2E to call the constraint
solver when a state terminates.

**How does concolic execution interact with path selection heuristics?**

It does not. Concolic execution only ensures that each state runs along the path that
corresponds to its initial set of concrete inputs. As the path runs, it may fork one or more states, which the
path selection heuristics may decide to choose.

**How can I add additional constraints to a state from my plugin?**

Call ``state->addConstraint(expression, true)``. The second parameter determines whether or not the engine
should recompute concrete inputs for that state in case ``expression`` does not evaluate to ``true`` in the
given state. Note that ``addConstraint`` mail fail and return false if the passed expression makes the constraint
set of the state unsatisfiable.

**I implemented custom plugins to aggressively prune paths because symbolic execution was getting stuck.
Are these plugins still useful?**

Yes. Reducing state space by discarding uninteresting paths is always useful. Concolic execution does not solve
the path explosion problem by itself. It merely helps getting to deeper parts of the program faster, assuming
you know the good seeds.

**I was previously disabling concolic execution with use-concolic-execution=false. How do I migrate?**

First, replace any calls to ``s2e_make_concolic`` with ``s2e_make_symbolic``. If you are using ``s2ecmd`` and other
S2E tools to create symbolic values, you do not need to worry about it.

Second, if you call ``state->addConstraint(...)`` from your plugins, make sure to set the second parameter to true in
order to recompute concrete values if needed. Please also check the return value (the compiler will show a warning if
you don't). If ``addConstraint`` fails, the usual action is to kill the state as further execution of that state may be
inconsistent.

**Why did you remove s2e_make_concolic instead of s2e_make_symbolic?**

Historically, S2E used to have ``s2e_make_concolic`` and ``s2e_make_symbolic`` APIs in order to let guest code create
symbolic data. In concolic mode, ``s2e_make_symbolic`` used zeros as concrete data. In symbolic mode,
``s2e_make_concolic`` behaved like ``s2e_make_symbolic`` (i.e., ignoring concrete data).

We believe that this unification makes it easier to use S2E. There is no need to worry about which API to use in which
case and no need to understand what concolic execution is. Fundamentally, both APIs create symbolic data because S2E is
first and foremost a symbolic execution engine. The "concolic" aspect is merely an improvement on top of symbolic
execution. It has no effect on the state space of the program.

**I have cryptographic routines in my code. Can concolic execution get through them?**

Probably not. Concolic execution will use the initial concrete values to get through cryptographic routines without
getting lost in the large state space. However, it is very likely to get stuck in the constraint solver when checking
the feasibility of a branch condition (and computing new sets of concrete inputs).

**I want to use the content of a file as a seed for concolic execution. How do I do it?**

Please refer to the `s2e.so <../Tutorials/BasicLinuxSymbex/s2e.so.rst>`_ tutorial, which explains all the different
ways you can create symbolic data.
