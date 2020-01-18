=============
S2E Testsuite
=============

In this document, you will learn how to build and run the S2E testsuite. The testsuite is a collection of programs that
help test various aspects of the S2E engine. It also serves as a reference for various S2E tutorials. A test is
comprised of one or more program binaries, a script that sets up an S2E analysis project, runs it, and then checks that
the results are correct.


Building the testsuite
======================

Before proceeding, set up your S2E environment using ``s2e-env``. Once it is up and running (i.e., you can create
analysis projects and run them), you are ready to build and run the testsuite:

.. code-block:: bash

    s2e testsuite generate

This creates test projects named ``testsuite_*`` in the ``projects`` folder. One test may have several different
projects, each project running the test in a particular configuration. For example, a test that checks that a Windows
32-bit binary runs properly may want to do so on say three different versions of Windows, resulting in three separate
projects.

The ``s2e testsuite generate`` command also accepts a list of test names. If one or more test names are specified, the
command generates test projects only for those tests. This may be useful to make it faster when you want to generate and
run only one or two tests, e.g., when you write your own test and want to debug it.

You can view the list of available tests with the following command:

.. code-block:: bash

    s2e testsuite list

.. note::

    Some tests require a Windows build server. This server must be set up as described `here <WindowsEnvSetup.rst>`_ and
    enabled in the ``s2e.yaml`` file located at the root of your S2E environment. If you do not want to build the
    server, you may skip the tests that require it as follows:

    .. code-block:: bash

       s2e testsuite generate --no-windows-build

.. warning::

    Testsuite generation recreates test projects from scratch and overwrites previously generated tests. Avoid
    modifying generated tests directly and modify the testsuite source instead (see later for details).


Running the testsuite
=====================

There are two ways to run the testsuite: using ``s2e testsuite run`` or invoking the ``run-tests`` script.

1. Using the ``s2e`` command.

   .. code-block:: bash

        s2e testsuite run

   This command automatically starts the optimal number of parallel tests depending on how many
   CPU cores and memory the machine has.

   You may also specify one or more test project names, in which case the command will
   run only those tests.

   This command saves the console output of all tests in ``stdout.txt`` and ``stderr.txt`` files in the test project's
   directory.

2. Manually invoking the ``run-tests`` script in the test project's folder.
   This is useful when you want to integrate tests in your own testing environment (e.g., Jenkins).
   The script returns a non-zero status code if the test fails. Additionally,
   the script writes the ``status`` file in the ``s2e-last`` folder containing either
   ``SUCCESS`` or ``FAILURE``.

   You can use GNU parallel to run multiple tests at once:

   .. code-block:: bash

        S2EDIR=$(pwd) parallel -j5  ::: projects/testsuite_*/run-tests


.. note::

    A test project contains all the usual S2E configuration files and scripts.
    For example, you can run the project with ``s2e run`` or ``launch-s2e.sh``. However, this will just
    run S2E and will not check the output. Make sure to use ``run-tests`` or ``s2e testsuite run``
    instead.


Adding your own tests
=====================

The testsuite is located in the `testsuite <https://github.com/S2E/s2e/tree/master/testsuite>`__ repository.
In order to add a test, follow these steps:

1. Create a subdirectory named after the test.

2. Create a makefile. It must have an ``all`` target that builds the binaries.

3. Create a ``config.yml`` file that describes the tests. See the reference section for details.

4. Create a ``run-tests.tpl`` file that launches the test project and checks the output after S2E terminates.
   This is a Jinja template that ``s2e testsuite generate`` instantiates into ``run-tests`` and places
   in the project's directory. This file would typically start with the following lines:

   .. code-block:: bash

        #!/bin/bash

        {% include 'common-run.sh.tpl' %}

        s2e run -n {{ project_name }}


   ``common-run.sh.tpl`` contains various helper functions and variables that the ``run-tests`` can use
   to check the test results.

.. note::

    You may write ``run-tests.tpl`` in any language (e.g. Python).
    Just make sure that it checks for ``S2EDIR``, sets the proper exit code on failure and creates
    the ``status`` file as appropriate.


Test configuration reference
============================

This section describes the contents of the ``config.yml`` file.

- **description**: a string describing the purpose of the test. It is displayed by ``s2e testsuite list``

- **targets**: a list of binaries to be tested. These binaries are produced by the makefile.
  Each entry is a path relative to the test folder.

- **target_arguments**: a list of parameters to give to the binary. These are the same parameters passed
  to the binary in the ``s2e new_project`` command. Typically, the argument is ``@@`` to allow symbolic
  input files.

- **options**: a list of parameters to be passed to ``s2e new_project``. In general, these are usual parameters with
  leading dashes stripped and others converted to underscores, e.g., ``--enable-pov-generation``
  becomes ``enable_pov_generation: true``.

- **build-options**: a list of options that control test project generation.

    - **windows-build-server**: when set to true, indicates that the test requires a Windows build server
      to create binaries.

    - **post-project-generation-script**: path to a script that is ran after ``s2e new_project`` is called.
      You can use this script to customize the project configuration.

- **target-images**: a list of images to use for the tests. When this option is missing, the test
  generator creates a project for every usable image, unless it is blacklisted.

- **blacklisted-images**: list of images for which to not create tests.
  This is useful in case a binary is incompatible with a specific OS version.
