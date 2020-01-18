===================
Contributing to S2E
===================

S2E welcomes any contribution, such as fixing bugs, adding new functionality, documentation, code comments, etc. Below
are some guidelines which help make code review easier.

All contributions to S2E must be **sent as pull requests** on GitHub. Please create an account and create a private
fork of the repository to which you would like to contribute. Patch contributions should not be posted on the mailing
list, bug tracker, posted on forums, or externally hosted and linked to.

You must accept the *Contributor License Agreement* before your pull requests can be merged. This can be done with a
few clicks from GitHub.

Patches must include a Signed-off-by: line
    For more information see `submitting patches
    <https://github.com/torvalds/linux/blob/master/Documentation/process/submitting-patches.rst>`__. This is vital or we
    will not be able to apply your patch! Please use your real name to sign a patch (not an alias name).

Correct English is appreciated
    If you are not sure, `codespell <http://wiki.qemu.org/Contribute/SpellCheck>`__ or other programs help finding the
    most common spelling mistakes in code and documentation.

Patches should be against current git master
    There's no point submitting a patch which is based on a released version of S2E because development will have moved
    on from then and it probably won't even apply to master.

Split up longer patches
    Into a patch series of logical code changes. Each change should compile and execute successfully. For instance, do
    not add a file to the makefile in patch one and then add the file itself in patch two. This rule is here so that
    people can later use tools like `git bisect <http://git-scm.com/docs/git-bisect>`__ without hitting points in the
    commit history where S2E does not work for reasons unrelated to the bug they are chasing.

Don't include irrelevant changes
    In particular, don't include formatting, coding style or whitespace changes to bits of code that would otherwise
    not be touched by the patch. It's OK though to fix coding style issues in the immediate area (few lines) of the
    lines you're changing. If you think a section of code really does need a reindent or other large-scale style fix,
    submit this as a separate patch which makes no semantic changes; don't put it in the same patch as your bug fix.

Write a good commit message
    S2E follows the following format::

        module: short description

        Detailed description

        Signed-off-by: Your Name <name@example.com>

Ensure your code is formatted correctly
    Before committing your code you **must** run `clang-format`. There is a script in the root directory,
    ``run-clang-format.sh``, that can be used to format the entire S2E source tree. Alternatively you may use the
    ``.clang-format`` file in the root of the repository. Note that Windows guest tools have their own code style.

    To check Python code, run the following `pylint <https://www.pylint.org>`__-based script:

    .. code-block:: console

        $ cd $S2EDIR/s2e-env
        $ . venv/bin/activate
        $ pip install pylint
        $ pylint -rn -j8 --rcfile=./pylint_rc s2e_env

    There must be no warnings.

Your code must be documented
    If you write a plugin, please write Doxygen-style documentation in the source code as well as an ``.rst`` file that
    explains how to use the plugin on some real examples. Please be as thorough as possible in the documentation. The
    clearer it is, the fewer questions that will be asked. When formatting your ``.rst`` file please use a line limit
    of 120 characters.

License
    Your contributions to existing code must use the license specified for that code. Each repository contains a
    LICENSE file which specifies the license under which that repository is distributed. Your contribution must use
    that license. If you contribute significant portions of fresh code, you may also use the MIT license for new files
    that you add (copy/paste below).

    .. code-block:: cpp

        /// Copyright (c) <year> <copyright holders>
        ///
        /// Permission is hereby granted, free of charge, to any person obtaining a copy
        /// of this software and associated documentation files (the "Software"), to deal
        /// in the Software without restriction, including without limitation the rights
        /// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        /// copies of the Software, and to permit persons to whom the Software is
        /// furnished to do so, subject to the following conditions:
        ///
        /// The above copyright notice and this permission notice shall be included in all
        /// copies or substantial portions of the Software.
        ///
        /// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        /// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        /// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        /// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        /// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        /// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        /// SOFTWARE.
