==========================
Coreutils Coverage Testing
==========================

The `GNU Core Utilities <https://www.gnu.org/software/coreutils/coreutils.html>`_ are the basic file, shell and text
manipulation utilities of the GNU operating system. This demo walks you through the process of using S2E to analyze the
``cat`` program and generate basic block and line coverage information.

.. contents::

Preparing the target binary
===========================

The first step is to build the coreutils package. In this tutorial, we will use version `8.26
<https://ftp.gnu.org/gnu/coreutils/coreutils-8.26.tar.xz>`_ . We will build a 32-bit version of Coreutils with debug
symbols (so that we can generate line coverage).

.. code-block:: console

    wget https://ftp.gnu.org/gnu/coreutils/coreutils-8.26.tar.xz
    tar xf coreutils-8.26.tar.xz

    cd coreutils-8.26
    mkdir build
    cd build
    ../configure CFLAGS="-g -m32" --prefix=$(pwd)
    make
    make install

The coreutils programs will be available in ``coreutils-8.26/build/bin``.

Setting up the test environment
===============================

Use ``s2e-env`` to create your S2E environment. Follow `these <../s2e-env.rst>`_ instructions to build a 32-bit Linux
image (from ``linux-4.9.3-i386``). Once you have an image you can create your project.

.. code-block:: console

    s2e new_project --image debian-8.7.1-i386 /path/to/coreutils-8.26/build/bin/cat -T @@

The ``@@`` symbol tells ``s2e-env`` to generate a bootstrap file that will run ``cat`` with a symbolic file as input.
By default this symbolic file will be a 256 byte file filled with ``null`` bytes.

The ``-T`` option forces ``cat`` to display TAB characters (0x09). This is important because it forces ``cat`` to read
the symbolic values and fork two states - one state for the character being a TAB and another state for a character
being a non-TAB.

For testing ``cat`` we will have to modify this symbolic file slightly. Instead of having the symbolic file filled with
``null`` bytes, we will add some actual text to the file to make it more representative of using ``cat``. Open
``bootstrap.sh`` and replace ``truncate -s 256 ${SYMB_FILE}`` with:

.. code-block:: bash

    echo "Here is some text" > ${SYMB_FILE}

The ``TranslationBlockCoverage`` plugin is required for generating coverage information. This plugin is enabled by
default in ``s2e-config.lua``. A translation block is a sequence of instructions ending with a change of control flow.
In comparison, a basic block is a translation block with the added restriction that no code outside of the basic block
can jump into the middle of it. At runtime, QEMU splits guest code into translation blocks and further translates
these blocks into host instructions so that they can be executed. S2E intercepts and logs this translation process.
These logs are saved as JSON files when the ``writeCoverageOnStateKill`` option is enabled (also enabled by default).
These JSON files will be used to produce the basic block and line coverage summary.

You can then run S2E with the ``launch-s2e.sh`` script. You may wish to leverage multi-process mode by setting
``S2E_MAX_PROCESSES=XX`` in ``launch-s2e.sh``. Let S2E run for a few minutes minutes before stopping it (e.g. via
``killall -9 qemu-system-i386``).

Generate line coverage
======================

``s2e-env`` also provides a subcommand to summarize line coverage information. Generating line coverage information
requires that the target program be compiled with debug symbols and that the source code is available. Line coverage
information is generated in the `lcov <http://ltp.sourceforge.net/coverage/lcov.php>`_ format.

To generate the lcov file, run:

.. code-block:: console

    s2e coverage lcov --html cat

This will generate the following in ``projects/cat/s2e-last``:

* A ``coverage.info`` file containing the line coverage information in lcov format
* A HTML report in the ``lcov`` directory

Note that the ``lcov`` format also allows for function and branch coverage information to be recorded - however this
is not yet available. The image below shows a snippet from the generated HTML report.

.. image:: ../img/lcov_example.png

Generate basic block coverage
=============================

``s2e-env`` provides a subcommand that can summarize basic block coverage. This subcommand requires either IDA Pro or
Radare to disassemble the target binary and extract the basic blocks from it. If you are using IDA Pro, you must
specify the path to its location ``s2e-env`` config file. If you are using Radare, it must be installed into a location
and your path and you must have the ``r2pipe`` Python package installed via pip (see
`here <https://github.com/S2E/s2e-env/blob/master/README.md>`_ for details). In order to produce this basic block
listing you can run one of the following commands:

.. code-block:: console

    s2e coverage basic_block --disassembler=ida cat
    s2e coverage basic_block --disassembler=r2 cat

The basic block coverage subcommand will perform a block coverage analysis on ``s2e-last`` in the ``cat`` project by
mapping translation block coverage generated by the ``TranslationBlockCoverage`` plugin to the basic block information
extracted by IDA Pro/Radare. The result will be written to ``projects/cat/s2e-last/basic_block_coverage.json``, part of
which is shown below.

.. code-block:: json

    {
        "coverage": [
            {
                "end_addr": 134516923,
                "function": "__do_global_dtors_aux",
                "start_addr": 134516916
            },
            {
                "end_addr": 134516165,
                "function": ".__fpending",
                "start_addr": 134516160
            },
            {
                "end_addr": 134515758,
                "function": ".init_proc",
                "start_addr": 134515754
            },
            {
                "end_addr": 134516940,
                "function": "frame_dummy",
                "start_addr": 134516939
            },
            {
                "end_addr": 134522228,
                "function": "set_program_name",
                "start_addr": 134522217
            },
            {
                "end_addr": 134533853,
                "function": "fstat64",
                "start_addr": 134533830
            }
        ],
        "stats": {
            "covered_basic_blocks": 215,
            "total_basic_blocks": 1456
        }
    }

The user can then use this data for further analysis. For example, the S2E `tools <https://github.com/S2E/tools>`_ repo
contains an IDA Pro script to highlight the basic blocks covered by S2E during analysis. This script can be found at
``install/bin/ida_highlight_basic_blocks.py`` in your S2E environment. To run the script, open the ``cat`` binary in
IDA Pro, select "Script file" from the "File" menu and open ``install/bin/ida_highlight_basic_blocks.py``. You will be
prompted for the ``basic_block_coverage.json`` file generated by S2E. Select this file and the basic blocks executed by
S2E will be colored green. Depending on how long you let S2E run for and how many translation blocks it executed, you
should get a graph similar to the following:

.. image:: ../img/ida_cat_coverage.png

Examining the debug log in ``s2e-last/debug.txt`` you should see a fork at address 0x8049ADE. If you look at this
address in IDA Pro, you should see a ``cmp [ebp+ch_0], 9`` at the previous instruction (address 0x8049ADA). This is
``cat`` checking if the current character is a TAB or not (as previously mentioned the ASCII value for TAB is 0x09).
Because the file contains symbolic data, a fork will occur at the ``jnz`` instruction.

Similarly, Radare can be used to annotate the basic blocks covered by S2E with `metadata
<https://radare.gitbooks.io/radare2book/content/disassembling/adding_metadata.html>`_. This script can be found at
``install/bin/r2_highlight_basic_blocks.py`` in your S2E environment. To run the script, open the ``cat`` binary in
Radare as follows:

.. code-block:: console

    r2 -i install/bin/r2_highlight_basic_blocks.py projects/cat/cat

You will be prompted for the ``basic_block_coverage.json`` file generated by S2E. Enter the path to this file and the
basic blocks executed by S2E will be annotated with a ``Covered by S2E`` comment. The image below illustrates this.

.. image:: ../img/r2_cat_coverage.png
