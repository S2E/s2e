===============================================
Debugging path explosion with the fork profiler
===============================================

The fork profile gives you a summary of all the locations in the system that forked.
This helps debug sources of path explosion.

In order to obtain a fork profile, run the `forkprofile` subcommand as follows:

.. code-block:: console

    $ s2e new_project /home/users/coreutils-8.26/build/bin/cat -T @@
    $ ... launch s2e and let it run for a while ...

    $ s2e forkprofile cat
    INFO: [symbols] Looking for debug information for /home/vitaly/s2e/env/projects/cat-symb/././cat
    INFO: [forkprofile] # The fork profile shows all the program counters where execution forked:
    INFO: [forkprofile] # process_pid module_path:address fork_count source_file:line_number (function_name)
    INFO: [forkprofile] 01309 cat:0x08049ade  143 /home/user/coreutils-8.26/src/cat.c:483 (cat)
    INFO: [forkprofile] 01309 cat:0x08049b0a   81 /home/user/coreutils-8.26/src/cat.c:488 (cat)
    INFO: [forkprofile] 01309 cat:0x08049981   73 /home/user/coreutils-8.26/src/cat.c:410 (cat)


The trace above shows that the `cat` module (which has a pid 1309) forked at three different program counters.
The source information (if available) gives the source file, the line, and the function name where the forks occurred.

Using the fork profile to debug path explosion
==============================================

1. Spot locations that should not fork.
   For example, your program might write something to the console. This typically results in forks in the
   OS's console driver. The source information will point to the responsible linux kernel driver, allowing
   you to quickly fix your bootstrap script (e.g., by redirecting output to `/dev/null` or a symbolic file).

2. Identify library functions that can be optimized.
   You will immediately see if the program forks in functions such as `strlen` or `atoi`. These functions can
   be replaced with `function models <../Plugins/Linux/FunctionModels.rst>`__ that eliminate forks altogether, although
   at the expense of generating more complex expressions.

3. Identify sections of code that can benefit of `state merging <../StateMerging.rst>`__.
   Certain types of code sections are hard to model and can be instead surrounded by `s2e_merge_group_begin()` and
   `s2e_merge_group_end()` API calls, which will merge into one state the subtree in between these two calls.
