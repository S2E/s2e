==============
FunctionModels
==============

The ``FunctionModels`` plugin can be used to reduce `path explosion
<https://en.wikipedia.org/wiki/Symbolic_execution#Path_Explosion>`__. It works by replacing typical libc functions with
a symbolic expression that represents that function's return value. The ``FunctionModels`` plugin currently supports
the following libc functions:

* ``strcpy``
* ``strncpy``
* ``strcat``
* ``strncat``
* ``strcmp``
* ``strstrncmp``
* ``memcpy``
* ``memcmp``
* ``printf``
* ``fprintf``

For example, ``strlen`` is typically implemented as follows:

.. code-block:: c

    // Adapted from  µlibc
    size_t strlen(const char *s) {
        for (const char *p = s; *p; p++) ;

        return p - s;
    }

If the input string ``s`` is symbolic, each iteration of the ``for`` loop will result in a state fork. This will
quickly grow intractible as the length of the input string grows. Instead of symbolically executing this function and
forking states, the ``FunctionModels`` plugin will return a symbolic expression that essentially "merges" these states
and return a symbolic expression that describes the string length (see the ``strlenHelper`` function `here
<https://github.com/S2E/s2e/blob/master/libs2eplugins/src/s2e/Plugins/Models/BaseFunctionModels.cpp>`__
to see how this is done).

The astute reader will note that while this will reduce the number of forked states that S2E must explore, it will do
so by increasing the complexity of the path constraints. This may put pressure on the constraint solver and cause it to
take more time to solve path constraints. It is up to the user to decide if this is an acceptable trade-off.

The ``FunctionModels`` plugin uses `s2e.so <../../Tutorials/BasicLinuxSymbex/s2e.so.rst>`__ to replace the function
calls (e.g. ``strlen``, ``memcpy``, etc.) with calls to the functions in ``guest/linux/function_models/models.c``. The
functions in ``models.c`` determine whether any of the function arguments are symbolic, and if so invoke the
``FunctionModels`` plugin to generate the appropriate symbolic expression. Function call replacement relies on the
target program being dynamically linked, so **you cannot use function models on statically-linked binaries**.

To use function models, enable the ``FunctionModels`` plugin in your S2E configuration file and use ``LD_PRELOAD`` to
load ``s2e.so`` in your ``bootstrap.sh`` script. If you are using `s2e-env <../../s2e-env.rst>`__ you will be informed
at project creation time whether you can use the ``FunctionModels`` plugin. Note however that by default ``s2e-env``
will **not** automatically enable the ``FunctionModels`` plugin.

Testing
-------

There is a test suite suite available in ``guest/linux/function_models/models_test.c``. This test suite is compiled
along with the guest tools and placed in ``$S2EDIR/build-s2e/guest-tools{32,64}/linux/function_models``. It can be
used with the ``s2e-env new_project`` command to run in a guest virtual machine. You should see the "Good Model"
message in S2E's debug output.

Options
-------

This plugin does not have any options.
