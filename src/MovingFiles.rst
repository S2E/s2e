=======================================
Moving Files Between the Host and Guest
=======================================

The ``s2eget`` and ``s2eput`` tools require easy downloading and uploading of files between the guest virtual machine
and the host in S2E mode.

.. contents::

Setting up the HostFiles Plugin
-------------------------------

To use ``s2eget`` and ``s2eput`` you **must** enable the ``HostFiles`` plugin in the S2E configuration file. To do so,
add the following lines to your ``s2e-config.lua`:

.. code-block:: lua

    plugins = {
        ...

        "HostFiles",
    }

    pluginsConfig.HostFiles = {
        baseDirs = {
            "/path/to/host/dir1",
            "/path/to/host/dir2",
        },

        -- This option must be enabled for s2eput to work
        allowWrite = true,
    }

The ``pluginsConfig.HostFiles.baseDirs`` configuration option specifies what directories on the host should be shared
with the guest. The paths can be either absolute, relative, or empty. If an empty directory is specified the S2E output
directory will be exported.

The ``pluginsConfig.HostFiles.allowWrite`` must be set to ``true`` for allowing writes to the base directories.

If you are using a VM created with `s2e-env <s2e-env.rst>`_ then both ``s2eget`` and ``s2eput`` should already exist in
the home directory. Otherwise they can be copied into the guest over SSH (or any other method).

Running ``s2eget``
------------------

First, boot the VM in non-S2E mode. Then run the tool in the guest, for example, as follows:

.. code-block:: console

    ./s2eget <filename> && chmod +x ./<filename> && ./<filename>

Where ``<filename>`` specifies the file to download from the host and execute in the guest. Note that the filename
argument to ``s2eget`` must be specified relative to the ``HostFiles``' base directory.

When being run like that in non-S2E mode, ``s2eget`` simply waits. At that point, save the VM snapshot and then load it
in S2E mode. ``s2eget`` will detect it and download the file. The rest of the command line will make it executable and
execute it.

Note that you could resume this snapshot as many times as you want, changing the program and/or trying different S2E
options.

Running ``s2eput``
------------------

To upload a file ``fileName`` to the host use ``./s2eput fileName`` command. The file will be uploaded to the
``s2e-last/outfiles`` directory.

**NOTE**: The upload will fail if a file with the same name already exists in the outfiles directory.
