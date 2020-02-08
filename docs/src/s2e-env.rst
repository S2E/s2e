===========================================
Creating analysis projects with ``s2e-env``
===========================================

S2E is a powerful platform that can analyze software at any level of the software stack. This flexibility requires
quite a bit of configuration. Most of it is boilerplate that can be automatically generated based on the type of
binary to analyze.

``s2e-env`` is a Python-based tool that automates much of the build and configuration steps that are required to work
with S2E. It entirely automates the complex tasks of building guest VM images ready for symbolic execution and
generating configuration files to run various types of binaries. The following steps describe how to use ``s2e-env``.
You will find in the documentation various tutorials that go deeper into various topics.

Before you start, make sure you have a working 64-bit Ubuntu 18.04 LTS installation. Earlier versions may
still work, but we do not actively support them anymore.

.. contents::

Installing s2e-env
==================

``s2e-env`` can be obtained and built from GitHub using the following commands:

.. code-block:: console

    sudo apt-get install git gcc python3 python3-dev python3-venv

    git clone https://github.com/s2e/s2e-env.git
    cd s2e-env

    python3 -m venv venv
    . venv/bin/activate
    pip install --upgrade pip

    # By default, s2e-env uses https to clone repositories.
    # If you want ssh, please edit s2e_env/dat/config.yaml before running pip install.
    # If your key is password-protected, use ssh-agent.
    pip install .

    # Note: if your pip version is earlier than v19, use the following command:
    pip install --process-dependency-links .


Using s2e-env
=============

General instructions for using ``s2e-env`` can be found in its `README
<https://github.com/s2e/s2e-env/blob/master/README.md>`__. Help for each command is available by running:

.. code-block:: console

    s2e <subcommand> --help

Creating a new environment
--------------------------

An S2E environment consists of the S2E engine and associated tools, one or more virtual machine images and one or more
analysis targets, known as "projects".

To create a new S2E environment in ``/home/user/s2e``, run:

.. code-block:: console

    s2e init /home/user/s2e

This will fetch the required source code, install S2E's dependencies (via apt) and create the directory structure
described `here <https://github.com/s2e/s2e-env/blob/master/README.md>`__. If you want to skip the dependency
installation step (e.g. if you have already installed the dependencies) use the ``--skip-dependencies`` flag.

``s2e_activate``
~~~~~~~~~~~~~~~~

By default, all other ``s2e`` subcommands only work when executed in the root directory of your environment. However,
you can change this behaviour by sourcing ``s2e_activate`` in the root directory of your environment. Sourcing
``s2e_activate`` will set the ``S2EDIR`` environment variable to the current environment, and so all ``s2e``
subcommands will execute relative to this directory. Sourcing ``s2e_activate`` also makes the ``s2e_deactivate``
command available, which unsets the S2E environment variables.

.. note::

    The remainder of this document assumes that you have activated your S2E environment, and so all ``s2e`` subcommands
    will operate in this environment.

Building S2E
------------

Building S2E is simple. Simply run:

.. code-block:: console

    s2e build

Building S2E and QEMU takes some time (approx. 60 minutes), so go and grab a coffee while you wait. Note that you can
build a debug version of S2E by specifying the ``--debug`` flag.

``s2e build`` will build all of the S2E components, including KLEE, QEMU, libs2e, Z3, etc. To force the rebuild of a
particular component (after the initial build), we must use the following flag:

.. code-block:: console

    s2e build --rebuild-components libs2e qemu

This will force the rebuild of the libs2e and QEMU components.

Updating the source code
------------------------

To update the source code under ``source``, run:

.. code-block:: console

    s2e update

This essentially acts as a wrapper around Google's `Repo <https://code.google.com/p/git-repo/>`__ tool, which is used to
manage the core S2E code.

Building an image
-----------------

You will need a virtual machine image to run your analysis target in. To see what images are available to build, run:

.. code-block:: console

    s2e image_build

This will list an image template name and a description of that image. For example, to build a Linux Debian 9.2.1 i386
image run:

.. code-block:: console

    s2e image_build debian-9.2.1-i386

This will:

* Create a Debian-based image under the ``images`` directory of your environment
* Configure the image for S2E
* Install an S2E-compatible kernel that can be used with the `LinuxMonitor <Plugins/Linux/LinuxMonitor.rst>`__ plugin
  and snapshot the image
* Create a JSON file describing the image. This JSON description is important for the ``new_project`` command
* Create a ready-to-run snapshot so that you do not have to reboot the guest everytime you want to run an analysis

Building the image will take some time (approx. 30 minutes), so go and make another coffee. By default, ``image_build``
requires `KVM <https://www.linux-kvm.org>`__ to accelerate the build process. If you do not have access to KVM (e.g. you
are running S2E in `WSL <https://blogs.msdn.microsoft.com/wsl/>`__), you can disable this requirement with the ``-n``
option.

You may also build all images at once:

.. code-block:: console

    s2e image_build all

Note that this will build all Linux **and** Windows images. To only build the Linux images, use ``s2e image_build
linux``. You can find more information about the infrastructure that builds the images in the following repositories:

* `guest-images <https://github.com/S2E/guest-images>`__
* `s2e-linux-kernel <https://github.com/S2E/s2e-linux-kernel>`__

**NOTE**: The image build process caches intermediate build output in ``.tmp-output`` that can grow quite large. Once
the images have been built you may wish to delete this directory if disk space is an issue.

Windows images
~~~~~~~~~~~~~~

``s2e-env`` can also be used to build Windows images. The supported Windows versions can be found
`here <https://github.com/S2E/guest-images/blob/master/images.json>`__. The ``--iso-dir`` option **must** be
specified when building Windows images. The directory specified must also contain an ISO with the name listed in
`images.json <https://github.com/S2E/guest-images/blob/master/images.json>`__. For example, the following command can
be used to build a Windows 7, SP1 image:

.. code-block:: console

    s2e image_build --iso-dir /path/to/isos windows-7sp1ent-x86_64

Where ``/path/to/isos`` is a directory containing ``en_windows_7_enterprise_with_sp1_x64_dvd_u_677651.so``.

The ISOs listed in ``images.json`` are available from `MSDN <https://msdn.microsoft.com/>`__. ``s2e image_build
--iso-dir /path/to/isos windows`` can be used to build all Windows images.

Creating a new analysis project
-------------------------------

Now that you have a virtual machine image that you can use to analyze programs in, you will need to create a "project"
to analyze your target program. To create such a project, run:

.. code-block:: console

    s2e new_project --image <image_name> /path/to/target/binary [target_args...]

This will create a new project under the ``projects`` directory. When you run the analysis the virtual machine image
that you specified with the ``--image`` option will be used. The target binary will be inspected so that the
appropriate configuration files and launch scripts are generated. By default ``new_project`` will create the following
files and directories:

bootstrap.sh
    S2E downloads this file from the host into the guest, then executes it. This file contains instructions on how
    to start the program, where to inject symbolic arguments, etc. When ``s2e-env`` creates a VM image, it configures
    the image to run `launch.sh <https://github.com/S2E/s2e/blob/master/guest/linux/scripts/launch.sh>`__ automatically
    when the s2e user logs in. This script fetches ``bootstrap.sh`` from the host and executes it.
    This script varies depending on your target program, so you should always check this file and modify it as required
    **before** running your analysis.

guestfs
    A symlink to the images guestfs. This is essentially a copy of the guest filesystem extracted from the VM image and
    is used by S2E's ``VMI`` plugin for virtual machine introspection. Note that not all images provide a guestfs.

guest-tools
    A symlink to the S2E `guest tools <https://github.com/S2E/s2e/blob/master/guest>`__.
    These will be downloaded to the guest by the bootstrap script every time you launch a new analysis.
    This way, you do not have to rebuild the VM image every time you modify these tools.

launch-s2e.sh
    This is the script that you will run most frequently. It starts S2E and runs the analysis as configured in the
    following files. This script contains various variables that you may edit depending on how you want to run S2E
    (multi-core mode, gdb, etc.).

library.lua
    Contains convenience functions for the s2e-config.lua file.

models.lua:
    For specifying `function models <Plugins/Linux/FunctionModels.rst>`__.

s2e-config.lua
   The main S2E configuration file. Analysis plugins are enabled and configured here (in the ``pluginsConfig`` table).
   S2E (and KLEE) arguments are also specified here (under ``kleeArgs`` in the ``s2e`` table). The available S2E
   arguments are defined in `S2EExecutor.cpp <https://github.com/S2E/s2e/blob/master/libs2ecore/src/S2EExecutor.cpp>`__.

Target program arguments
------------------------

The ``new_project`` command also allows the user to specify any command line arguments they may wish to run their
program with. These are specified as if the user was running the program normally.

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
----------------

Seed files (or test inputs) are concrete inputs for the target program. These files can be anything that the target
program accepts (e.g. PNG files, documents, etc.). They can be obtained from a fuzzer, generated by hand, etc. These
seed files can then be used by S2E to concolically guide execution in the target program.

To enable seed files in your project, use the ``new_project`` subcommand's ``--use-seeds`` flag. This will create a
``seeds`` directory in your project where seed files can be placed.

For further discussion on seed files please see the `CGC tutorial <Tutorials/PoV/index.rst>`__.

Running your analysis
---------------------

You will need to ``cd`` into your project directory to run the analysis. While ``s2e new_project`` does its best to
create suitable configuration files, you should first examine these files and modify them as required. You may want to
add/remove plugins from ``s2e-config.lua`` and add/remove QEMU runtime options and/or S2E environment variables from
the launch scripts.

Some "real-world" examples of how to configure your project are presented in the next section.

Once you have finalized your configuration files and launch scripts, run ``launch-s2e.sh`` to begin the analysis.

Parsing an execution trace
--------------------------

The ``execution_trace`` command can be used to parse one or more ``ExecutionTracer.dat`` files generated by S2E's
`execution tracer <Howtos/ExecutionTracers.rst>`__ plugins.

The following can be used to output the complete execution trace in ``s2e-last`` in JSON format:

.. code-block:: console

    s2e execution_trace my_project

The ``--path-id`` option can be specified one or more times to limit the number of execution paths in the JSON trace.
For example, to only output the execution trace for states 0 and 34, do:

.. code-block:: console

    s2e execution_trace -p 0 -p 34 my_project

Importing and exporting projects
--------------------------------

Projects can be exported and shared with others. The following command will export a project named my_project as a
tar.xz archive.

.. code-block:: console

    s2e export_project my_project /path/to/my/my_project_archive.tar.xz

The export process will replace all absolute paths relating to your S2E environment with a placeholder string. This
placeholder is then rewritten when the project is imported into another S2E environment via:

.. code-block:: console

    s2e import_project /path/to/my/my_project_archive.tar.xz

There are a few things to note when exporting and importing projects:

* Image information for the specific project is exported "as-is". Therefore the destination environment for the
  imported project must have a valid image with the details provided in the ``project.json`` file.
* The guest-tools and guestfs directories are not exported. Instead symlinks to these directories are recreated on
  project import.


Next steps
==========

Now that you know how to use ``s2e-env``, why not start using it to analyze binaries from `DARPA's Cyber Grand
Challenge <Tutorials/PoV/index.rst>`__, programs from `Coreutils <Howtos/Coverage/index.rst>`__, or even your own
programs!
