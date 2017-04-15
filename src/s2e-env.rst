===========================================
Creating Analysis Projects with ``s2e-env``
===========================================

``s2e-env`` is a Python-based tool that automates much of the build and configuration steps that are required to work
with S2E. The following steps describe how to use ``s2e-env``.

.. contents::

Installing s2e-env
------------------

``s2e-env`` can be obtained and built from GitHub using the following commands:

.. code-block:: console

    git clone https://github.com/s2e/s2e-env.git
    cd s2e-env

    # Optional: install s2e-env in a virtual env
    virtual-env venv
    . venv/bin/activate

    # By default, s2e-env uses https to clone repositories.
    # If you want ssh, please edit s2e_env/dat/config.yaml
    # before running pip install.
    # If your key is password-protected, use ssh-agent.
    pip install .


Using s2e-env
-------------

General instructions for using ``s2e-env`` can be found in its `README
<https://github.com/s2e/s2e-env/blob/master/README.md>`_. Help for each command is available by running:

.. code-block:: console

    s2e <subcommand> --help

Creating a new environment
~~~~~~~~~~~~~~~~~~~~~~~~~~

An S2E environment consists of the S2E engine and associated tools, one or more virtual machine images and one or more
analysis targets, known as "projects".

To create a new S2E environment in ``/home/user/s2e``, run:

.. code-block:: console

    s2e init /home/user/s2e

This will fetch the required source code, install S2E's dependencies (via apt) and create the directory structure
described `here <https://github.com/s2e/s2e-env/blob/master/README.md>`_. If you want to skip the dependency
installation step (e.g. if you have already installed the dependencies) use the ``--skip-dependencies`` flag.

Building S2E
~~~~~~~~~~~~

Building S2E is simple. Simply run:

.. code-block:: console

    cd /home/user/s2e
    s2e build

Building S2E and QEMU takes some time (approx. 60 minutes), so go and grab a coffee while you wait. Note that you can
build a debug version of S2E by specifying the ``--debug`` flag.

Building an image
~~~~~~~~~~~~~~~~~

You will need a virtual machine image to run your analysis target in. To see what images are available to build, run:

.. code-block:: console

    cd /home/user/s2e
    s2e image_build

This will list an image template name and a description of that image. For example, to build a Linux 4.9.3 i386 image
run:

.. code-block:: console

    cd /home/user/s2e
    s2e image_build linux-4.9.3-i386

This will:

* Create a Debian-based image under the ``images`` directory of your environment
* Configure the image for S2E
* Install an S2E-compatible kernel that can be used with the `LinuxMonitor <Plugins/Linux/LinuxMonitor.rst>`_ plugin
  and snapshot the image
* Create a JSON file describing the image. This JSON description is important for the ``new_project`` command
* Create a ready-to-run snapshot so that you do not have to reboot the guest everytime you
  want to run an analysis.

Building the image will take some time (approx. 30 minutes), so go and make another coffee.

You may also build all images at once:

.. code-block:: console

    cd /home/user/s2e
    s2e image_build all

You may find more information about the infrastructure that builds the images
in the following repositories:

  * `guest-images <https://github.com/S2E/guest-images>`_
  * `s2e-linux-kernel <https://github.com/S2E/s2e-linux-kernel>`_

Creating a new analysis project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Now that you have a virtual machine image that you can use to analyze programs in, you will need to create a "project"
to analyze your target program. To create such a project, run:

.. code-block:: console

    cd /home/user/s2e
    s2e new_project --image <image_name> /path/to/target/binary [target_args...]

This will create a new project under the ``projects`` directory. When you run the analysis the virtual machine image
that you specified with the ``--image`` option will be used. The target binary will be inspected so that the
appropriate configuration files and launch scripts are generated. By default ``new_project`` will create the following
files:

launch-s2e.sh
    This is the script that you will run most frequently. It starts S2E and runs the analysis as configured in the following
    files. This script contains various variables that you may edit depending on how you want to run S2E (multi-core mode,
    gdb, etc.).

bootstrap.sh
    S2E downloads this file from the host into the guest, then executes it. This file contains instructions on how
    to start the program, where to inject symbolic arguments, etc. When ``s2e-env`` creates a VM image, it configures
    the image to run `launch.sh <https://github.com/S2E/guest-tools/blob/master/linux/scripts/launch.sh>`_ automatically
    when the s2e user logs in. This script fetches ``bootstrap.sh`` from the host and executes it.
    This script varies depending on your target program, so you should always check this file and modify it as required
    **before** running your analysis.

s2e-config.lua
   The main S2E configuration file. Analysis plugins are enabled and configured here.

guest-tools
    A symlink to the S2E `guest tools <https://github.com/S2E/guest-tools>`_. These will be downloaded to the guest by the
    bootstrap script every time you launch a new analysis. This way, you do not have to rebuild the VM image
    every time you modify these tools.


Target program arguments
~~~~~~~~~~~~~~~~~~~~~~~~

The `new_project` command also allows the user to specify any command line arguments they may wish to run their program
with. These are specified as if the user was running the program normally.

For example, the following command would create a new project based on ``ls`` executing with the ``-a`` option (i.e.
all entries):

.. code-block:: console

    s2e new_project --image <image_name> /bin/ls -a

For programs that (a) take input from a file and (b) the user would like to use a "symbolic file", ``@@`` can be used
to mark the location in the target's command line where the input file should be placed. ``s2e-env`` will generate an
appropriate bootstrap script that creates this symbolic file and substitutes it into the command line. For example, to
``cat`` a symbolic file:

.. code-block:: console

    s2e new_project --image <image_name> /bin/cat @@

Using seed files
~~~~~~~~~~~~~~~~

Seed files (or test inputs) are concrete inputs for the target program. These files can be anything that the target
program accepts (e.g. PNG files, documents, etc.). They can be obtained from a fuzzer, generated by hand, etc. These
seed files can then be used by S2E to concolically guide execution in the target program.

To enable seed files in your project, use the ``new_project`` subcommand's ``--use-seeds`` flag. This will create a
``seeds`` directory in your project where seed files can be placed.

For further discussion on seed files please see the `CGC tutorial <Tutorials/CGC.rst>`_.

Running your analysis
~~~~~~~~~~~~~~~~~~~~~

You will need to ``cd`` into your project directory to run the analysis. While ``s2e new_project`` does its best to
create suitable configuration files, you should first examine these files and modify them as required. You may want to
add/remove plugins from ``s2e-config.lua`` and add/remove QEMU runtime options and/or S2E environment variables from
the launch scripts.

Some "real-world" examples of how to configure your project are presented in the next section.

Once you have finalized your configuration files and launch scripts, run ``launch-s2e.sh`` to begin the analysis.

Next steps
----------

Now that you know how to use ``s2e-env``, why not start using it to analyze binaries from `DARPA's Cyber Grand
Challenge <Tutorials/CGC.rst>`_, programs from `Coreutils <Tutorials/Coreutils.rst>`_, or even your own programs!
