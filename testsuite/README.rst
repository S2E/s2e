=============
S2E Testsuite
=============

This folder contains the S2E testsuite. It has a collection of programs that help test various aspects of the S2E
engine. They also serve as a reference for various S2E tutorials.

A test is comprised of a program binary and a script that sets up an S2E analysis project, runs it, and then checks that
the results are as expected.

Please refer to the S2E documentation for details on how to run and extend the testsuite.
The information below only gives a quick summary.


Building and running the testsuite
==================================

.. code-block:: bash

    # Switch to the root of the S2E environment created with s2e-env init
    cd $S2EENV

    # List the available tests
    s2e testsuite list

    # Compile the testsuite and generate projects for all tests.
    # It is possible to specify individual tests.
    s2e testsuite generate [test1, test2, ...]

    # Run the testsuite
    s2e testsuite run


Creating tests
==============

This can be done in a few simple steps:

1. Create a subdirectory named after the test.

2. Create a makefile. It must have an ``all`` target that builds the binaries

3. Create a ``config.yml`` file that describes the tests.

4. Create a ``run-tests.tpl`` script that launches the test project and checks the output after S2E terminates.
