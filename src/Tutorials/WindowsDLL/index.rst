========================
Analysis of Windows DLLs
========================

This tutorial outlines how a Windows dynamic-link library (DLL) can be analyzed in S2E. As an example we will analyze
the `Beep <https://msdn.microsoft.com/en-us/library/windows/desktop/ms679277>`__ function in ``kernel32.dll``.

.. contents::

Preparing the test environment
==============================

As usual, use `s2e-env <../../s2e-env.rst>`__ to create your S2E environment. Build a Windows image using the
``image_build`` command. Note that when building a Windows image the ``--iso-dir`` option must be provided. E.g.

.. code-block:: console

    s2e image_build --iso-dir /path/to/windows/iso/dir windows-7sp1ent-x86_64

Once you have a suitable image, a DLL project can be created. E.g.

.. code-block:: console

    s2e new_project /path/to/kernel32.dll Beep 5000 1000

This will create the ``kernel32`` project in your S2E environment. Note that when creating a DLL project the target DLL
**must** have the ``.dll`` extension. Opening the ``bootstrap.sh`` script you can see that Windows' ``rundll32``
program will be used to execute the DLL and that the ``Beep`` function will be used as the entry point. The arguments
5000 and 1000 were also specified when creating the new project. These correspond to the frequency and duration of the
sound, as specified in the ``Beep``
`documentation <https://msdn.microsoft.com/en-us/library/windows/desktop/ms679277>`__.

``rundll32`` never terminates after launching, so we must modify ``s2e-config.lua`` to ensure that translation block
coverage is recorded. To do so, we will enable periodic coverage updates for the ``TranslationBlockCoverage`` plugin.
We can do this by modifying the ``TranslationBlockCoverage`` configuration as follows:

.. code-block:: lua

    pluginsConfig.TranslationBlockCoverage = {
        writeCoverageOnStateKill = true,
        writeCoveragePeriod = 60,
    }

Finally, start the analysis using the ``launch-s2e.sh`` script. Let S2E run for approximately 2 minutes before stopping
it (e.g. via ``killall -9 qemu-system-x86_64``).

Generate basic block coverage
=============================

You can use ``s2e-env`` to generate basic block coverage to confirm that the ``Beep`` function was executed.

.. code-block:: console

    s2e coverage basic_block kernel32

This will generate ``projects/kernel32/s2e-last/basic_block_coverage.json``. Running the
``install/bin/ida_highlight_basic_blocks.py`` script to highlight the basic block coverage should give a similar
result to the following:

.. image:: ida_kernel32_beep_coverage.png
