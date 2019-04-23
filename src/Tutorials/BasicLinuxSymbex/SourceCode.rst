=========================================
Instrumenting Program Source Code for S2E
=========================================

`s2e-env <../../s2e-env.rst>`__ and `s2e.so <s2e.so.rst>`__ automate most of the tedious tasks of setting up virtual
machines, S2E configuration files, launch scripts, etc. This tutorial assumes that you have already built S2E and
prepared a VM image as described on the `Building the S2E Platform <../../BuildingS2E.rst>`__ page, that you are
familiar with `s2e-env <../../s2e-env.rst>`__, and that you tried symbolic execution on simple `Linux binaries
<s2e.so.rst>`__.

In this tutorial, you will learn in more details what happens under the hood of `s2e-env <../../s2e-env.rst>`__ and
`s2e.so <s2e.so.rst>`__, in particular how they actually make input symbolic, and how you can do the same for arbitrary
programs. This may be useful on targets and platforms that are not supported yet by S2E's project creation scripts. We
advise you to study how these tools work and adapt them to your own needs. Don't hesitate to look at their source code.

.. contents::

Introduction
============

We want to cover all of the code of the following program by exploring all the possible paths through it.

.. code-block:: c

    #include <stdio.h>
    #include <string.h>

    int main(void) {
        char str[3];

        printf("Enter two characters: ");

        if (!fgets(str, sizeof(str), stdin)) {
            return 1;
        }

        if (str[0] == '\n' || str[1] == '\n') {
            printf("Not enough characters\n");
        } else {
            if (str[0] >= 'a' && str[0] <= 'z') {
                printf("First char is lowercase\n");
            } else {
                printf("First char is not lowercase\n");
            }

            if (str[0] >= '0' && str[0] <= '9') {
                printf("First char is a digit\n");
            } else {
                printf("First char is not a digit\n");
            }

            if (str[0] == str[1]) {
                printf("First and second chars are the same\n");
            } else {
                printf("First and second chars are not the same\n");
            }
        }

        return 0;
    }


Compiling and running
=====================

First, compile and run the program as usual, to make sure that it works.

.. code-block:: bash

    $ gcc -m32 -O3 tutorial1.c -o tutorial1
    $ ./tutorial1
    Enter two characters: ab
    First char is lowercase
    First char is not a digit
    First and second chars are not the same

Then, create a new project using `s2e-env <../../s2e-env.rst>`__ . Once it is created, run it, and check that it runs
properly in the guest. You will need to run S2E with graphics output enabled so that you can type the input.

.. code-block:: bash

    s2e new_project /path/to/tutorial1


Preparing the program for symbolic execution
============================================

In order to execute the program symbolically, it is necessary to specify what values should become symbolic. There are
many ways to do it in S2E, but the simplest one is to use the S2E opcodes library. This library provides a way for guest
code to communicate with the S2E system.

In order to explore all possible paths through the program that correspond to all possible inputs, we want to make these
inputs symbolic. To accomplish this, we replace the call to ``fgets()`` by a call to ``s2e_make_symbolic()``:

.. code-block:: c

     ...
     char str[3];
     // printf("Enter two characters: ");
     // if(!fgets(str, sizeof(str), stdin))
     //   return 1;
     s2e_make_symbolic(str, 2, "str");
     str[3] = 0;
     ...

Finally, it would be interesting to see an example of input value that cause a program to take a particular execution
path. This can be useful to reproduce a bug in a debugger, independently of S2E. For that, use the ``s2e_get_example()``
function. This function gives a concrete example of symbolic values that satisfy the current path constraints (i.e., all
branch conditions along the execution path).

After these changes, the example program looks as follows:

.. code-block:: c

    #include <stdio.h>
    #include <string.h>
    #include <s2e/s2e.h>

    int main(void) {
        char str[3] = { 0 };

        // printf("Enter two characters: ");
        // if (!fgets(str, sizeof(str), stdin)) {
        //     return 1;
        // }

        s2e_make_symbolic(str, 2, "str");

        if (str[0] == '\n' || str[1] == '\n') {
            printf("Not enough characters\n");
        } else {
            if (str[0] >= 'a' && str[0] <= 'z') {
                printf("First char is lowercase\n");
            } else {
                printf("First char is not lowercase\n");
            }

            if (str[0] >= '0' && str[0] <= '9') {
                printf("First char is a digit\n");
            } else {
                printf("First char is not a digit\n");
            }

            if (str[0] == str[1]) {
                printf("First and second chars are the same\n");
            } else {
                printf("First and second chars are not the same\n");
            }
        }

        s2e_get_example(str, 2);
        printf("'%c%c' %02x %02x\n", str[0], str[1],
               (unsigned char) str[0], (unsigned char) str[1]);

        return 0;
    }

.. note::

    There are alternatives to ``s2e_get_example`` to get test cases. The simplest one is using the ``TestCaseGenerator``
    plugin, which is enabled by default, and outputs test cases in ``s2e-last/debug.txt``.


Compile the program and try to run it on your host:

.. code-block:: bash

   $ gcc -I$S2ESRC/guest/common/include -O3 tutorial1.c -o tutorial1
   $ ./tutorial1
   Illegal instruction

You see the ``Illegal instruction`` message because all ``s2e_*`` functions use
special CPU opcodes that are only recognized by S2E.

Running the program in S2E
==========================

Now rerun the program above in S2E, using the launch scripts generated by ``s2e-env``. You should see several states
forked, one for each possible program input. Each state is a completely independent snapshot of the whole system. You
can even interact with each state independently, for example by launching different programs. Try to launch
``tutorial1`` in one of the states again!

In the host terminal (i.e., the S2E standard output), you see various information about state execution, forking and
switching. This output is also saved into the ``s2e-last/debug.txt`` log file. As an exercise, try to follow the
execution history of a state through the log file.

Terminating execution paths
===========================

By default, S2E runs paths forever and needs a special order in order to terminate an execution path. The ``s2e-env``
tool wraps programs in a script that will take care of terminating paths when the program returns or when it crashes.
Sometimes, you may want to terminate the execution path yourself, directly from your program. This is particularly
useful if you run S2E on a system that is not yet supported by ``s2e-env``, such as embedded OSes.

Terminating an execution path is accomplished with the ``s2e_kill_state()`` function. A call to this function
immediately stops the execution of the current path and exits S2E if there are no more paths to explore. Add a call to
this function just before the program returns control to the OS. Before that, you may want to print example values in
the S2E log using ``s2e_printf()``:

.. code-block:: c

   int main(void)
   {
     char str[3] = { 0 };

     ...

     s2e_get_example(str, 2);
     s2e_printf("'%c%c' %02x %02x\n", str[0], str[1], (unsigned char) str[0], (unsigned char) str[1]);
     s2e_kill_state(0, "program terminated");

     return 0;
   }

When you rerun the program, you will see that the logs contain the message ``program terminated``.

You can also terminate the execution from a script, using the ``s2ecmd`` tool.

.. code-block:: bash

   guest$ ./tutorial; ./s2ecmd kill 0 "done"
