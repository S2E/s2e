#!/usr/bin/python

# Copyright (c) 2017 Dependable Systems Laboratory, EPFL
# Copyright (c) 2017 Cyberhaven
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from subprocess import Popen, PIPE
import sys
import os

blacklist = ['.git', '.repo', 'docs', 'doxygen']

files = []
for root, directories, filenames in os.walk('.'):
    for filename in filenames:
        files.append(os.path.join(root, filename))

files.sort()

dirs = set([""])
s2e_files = open('s2e.files', 'w')
s2e_includes = open('s2e.includes', 'w')
for fname in files:
    for b in blacklist:
        if b in fname:
            break
    else:
        if not os.path.isdir(fname):
            s2e_files.write(fname + '\n')

            fdir = fname
            while fdir != "":
                fdir = os.path.dirname(fdir)
                if fdir not in dirs and os.path.isdir(fdir):
                    s2e_includes.write(fdir + '\n')
                    dirs.add(fdir)

s2e_includes.write('\n'.join([
    '../../build/llvm-9.0.0.src/include',
    '../../build/llvm-release/include',
    '../../build/lua-5.3.4/src',
    '/usr/include/glib-2.0',

    # This is for protobuf headers, pick one build folder
    '../build/libs2e-release/i386-s2e-softmmu/libs2eplugins/src/',
]))

s2e_files.close()
s2e_includes.close()

with open("s2e.creator", "w") as fp:
    fp.write("[General]\n")

with open("s2e.config", "w") as fp:
    fp.write("#define CONFIG_SYMBEX\n")
    fp.write("#define CONFIG_SYMBEX_MP\n")
    fp.write("#define CONFIG_SOFTMMU\n")

