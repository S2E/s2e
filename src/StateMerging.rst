===============================================
Exponential Analysis Speedup with State Merging
===============================================

Symbolic execution can produce an exponential number of paths, considerably slowing down analysis. When S2E encounters
a branch that depends on a symbolic condition and both outcomes are possible, S2E forks the current execution path in
two. This process can repeat recursively, resulting in an exponential number of paths.

The following piece of code demonstrates the problem. It is a simplification of the ``ShiftInBits()`` function of the
Intel e100bex NIC driver from the Windows WDK. It consists of a loop that reads a value from a hardware register
bit-by-bit.

.. code-block:: c

    uint16_t ShiftInBits() {
        uint16_t value = 0;

        for (int i = 0; i < sizeof(value) * 8; ++i) {
            value <<= 1;

            if (read_register()) {
                value |= 1;
            }
        }

        return value;
    }

On each iteration, ``read_register()`` returns a fresh symbolic value, causing a fork at the conditional statement.
Since there are 16 iterations in total, this amounts to 65,536 execution states.

If we look closely, every forked path in the function above differs only by one bit, set to zero or one depending on
the register value. If S2E could merge both paths back together while remembering that small difference, there would
remain only one path at the end of the function, reducing by four orders of magnitude the number of paths to explore.

Using State Merging in S2E
==========================

To use state merging in S2E, first enable the ``MergingSearcher`` plugin.

.. code-block:: lua

    -- File: config.lua
    s2e = {
        kleeArgs = {
            -- needed to avoid merge failures due to different shared-concrete objects:
            "--state-shared-memory=true"
        }
    }

    plugins = {
        "BaseInstructions",
        "MergingSearcher"
    }

Then, compile the following program, then run it in S2E:

.. code-block:: c

    #include <s2e/s2e.h>

    uint16_t ShiftInBits() {
        uint16_t value = 0;
        int i;

        for (i = 0; i < sizeof(value) * 8; ++i) {
            value <<= 1;

            /* Simulates read_register() */
            uint8_t reg = 0;
            s2e_make_symbolic(&reg, sizeof(reg), "reg");

            s2e_disable_all_apic_interrupts();
            s2e_merge_group_begin();

            if (reg) {
                value |= 1;
            }

            s2e_merge_group_end();
            s2e_enable_all_apic_interrupts();
        }

        return value;
    }

    int main(int argc, char **argv) {
        uint16_t value = ShiftInBits();
        if (value == 0xabcd) {
            s2e_printf("found it\n");
        }

        return 0;
    }

* How many paths do you observe?
* Comment out calls to ``s2e_merge_group_begin()`` and ``s2e_merge_group_end()``. How does this affect the number of
  paths?

State Merging API
=================

The S2E state merging API offers two calls: ``s2e_merge_group_begin()`` and ``s2e_merge_group_end()``.

The subtree that begins at ``s2e_merge_group_begin()`` and whose leaves end at ``s2e_merge_group_end()`` is merged into
one path. The ``MergingSearcher`` behaves as follows:

The searcher suspends the first path (path A) that reaches ``s2e_merge_group_begin()``.

* If path A did not fork any other path between ``s2e_merge_group_begin()`` and ``s2e_merge_group_end()``, there is
  nothing to merge, and the searcher resumes path A normally.

* If path A forked other paths (e.g., B and C), the searcher schedules another path. The scheduled path could be B, C,
  or any other path outside the subtree to be merged.

* When path B reaches ``s2e_merge_group_end()``, ``MergingSearcher`` merges it with A, then kills B.

* When path C reaches ``s2e_merge_group_end()``, ``MergingSearcher`` merges it with A+B, then kills C.

Limitations
===========

* It is not possible to nest pairs of ``s2e_merge_group_begin()`` and ``s2e_merge_group_end()``.

* S2E must be running in concrete mode when merging states (``s2e_merge_group_end()`` ensures that it is the case).

* The set of symbolic memory objects must be identical in all states that are going to be merged. For example, there
  shouldn't be calls to ``s2e_make_symbolic`` between ``s2e_merge_group_begin()`` and ``s2e_merge_group_end()``.

* It is not possible to merge two states if their concrete CPU state differs (e.g., floating point or MMX registers,
  program counter, etc.).

* ``s2e_disable_all_apic_interrupts()`` and ``s2e_enable_all_apic_interrupts()`` ensure that the concrete state is not
  clobbered needlessly by interrupts. The direct consequence is that the merged subtree cannot call into the
  environment (no syscalls, etc.). Not disabling interrupts will make merging much harder because the side effects of
  the interrupt handlers and those of the OS will have to be merged as well. If the side effects affected the concrete CPU state,
  merging will fail.
