===================
Equivalence Testing
===================

Given two functions ``f`` and ``g``, we would like to check whether for all input, they produce the same output. In
other words, we verify whether ``f`` and ``g`` are equivalent.

Equivalence testing is useful to check that two implementations of the same algorithm produce identical results. E.g.,
scripts may parse the output of some tools (e.g., ls) and thus expect certain behavior. The developers of alternative
and compatible implementations (e.g., ls for Busybox) of such tools can use equivalence testing to gain confidence that
their implementation behaves in the same way. Another example is to check the equivalence of two implementations of the
same protocol (e.g., TCP/IP).

In this tutorial, we show how to perform equivalence testing with S2E. At a high level, this is done by passing
identical symbolic inputs to the functions, letting S2E explore the execution tree, and when both functions return,
check whether they produced the same output (e.g., with an assertion check).

Program to Test
---------------

This sample program contains two implementations of the factorial algorithm that we want to test for equivalence. Both
implementations behave in the same way except in some corner cases.

.. code-block:: c

    #include <inttypes.h>
    #include <s2e/s2e.h>

    /**
     *  Computes x!
     *  If x > max, computes max!
     */
    uint64_t factorial1(uint64_t x, uint64_t max) {
        uint64_t ret = 1;
        for (uint64_t i = 1; i<=x && i<=max; ++i) {
            ret = ret * i;
        }
        return ret;
    }

    /**
     *  Computes x!
     *  If x > max, computes max!
     */
    uint64_t factorial2(uint64_t x, uint64_t max) {
        if (x > max) {
            return max;
        }

        if (x == 1) {
            return x;
        }
        return x * factorial2(x-1, max);
    }

    int main() {
        uint64_t x;
        uint64_t max = 10;

        //Make x symbolic
        s2e_make_symbolic(&x, sizeof(x), "x");

        uint64_t f1 = factorial1(x, max);
        uint64_t f2 = factorial2(x, max);

        //Check the equivalence of the two functions for each path
        s2e_assert(f1 == f2);

        //In case of success, terminate the state with the
        //appropriate message
        s2e_kill_state(0, "Success");
        return 0;
    }

Compile it as follows after adapting the include path:

.. code-block:: console

    gcc -I /path/to/s2e/guest/include/ -std=c99 -o factorial factorial.c

Configuring S2E
---------------

We will instruct S2E to compute test cases at the end of each execution path (i.e., when ``s2e_kill_state`` is called),
in order to reproduce potential assertion failures on our own. A test case consists of concrete program inputs that
would drive the program down the corresponding execution path.

.. code-block:: lua

   -- File: config.lua
   s2e = {
     kleeArgs = {
       --Switch states only when the current one terminates
       "--use-dfs-search"
     }
   }
   plugins = {
     -- Enable S2E custom opcodes
     "BaseInstructions",

     -- Basic tracing required for test case generation
     "ExecutionTracer",

     -- Enable the test case generator plugin
     "TestCaseGenerator",
   }

Running the Program in S2E
--------------------------

Run the program in S2E. Refer to `this tuorial <Tutorials/BasicLinuxSymbex/SourceCode.rst>`__ for more details. S2E will
exit when all paths terminate.

Make sure to have at least 8 GB of available virtual memory and set the stack size to unlimited using ``ulimit -s
unlimited``.

Interpreting the Results
------------------------

After the run, the ``s2e-last/messages.txt`` file contains the following output:

* Messages explaining the reason why each state terminated (either success or failure)
* The concrete input that would allow replaying the same path independently of S2E

For several states, we see the following type of message::

    message: "Assertion failed: f1 == f2"
    TestCaseGenerator: processTestCase of state 0 at address 0x8048525
    x: 7f 7f 7f 7f 7f 7f 7f 7f

This indicates that when ``x == 0x7f7f7f7f7f7f7f7f``, the two implementations of factorial produce a different output.
To reproduce this behavior, take the computed value for x (it is displayed in little endian format by the test case
generator), plug it into the original program, and run the program in a debugger to understand what happens. When you
fixed the deviating behavior, rerun the program again in S2E, until all states terminate with a success.
