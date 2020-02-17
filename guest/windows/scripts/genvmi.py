#!/usr/bin/env python

# Copyright (C) 2014-2017, Cyberhaven
# Copyright (C) 2017, Dependable Systems Laboratory, EPFL
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

"""
Generates symbol definitions for the S2E Vmi plugin.
"""

import os
#import pp

from common import extract


def get_info(pdb):
    filename = os.path.basename(pdb.m_exe) #XXX: ask symbol server for native name!

    symbols = ['RtlpExceptionHandler',
               '_C_specific_handler',
               '_CxxFrameHandler3',
               '_GSHandlerCheck',
               '_GSHandlerCheck_SEH',
               'X86SwitchTo64BitMode']

    ret = {
        'version': '.'.join(str(x) for x in pdb.product_version),
        'name': filename,
        'checksum': pdb.checksum,
        'bits': pdb.bits,
        'nativebase': pdb.native_base,
        'symbols': {},
    }

    added = False
    for f in symbols:
        address = pdb.get_function_address(f, True)
        if address != 0:
            ret['symbols'][f] = address
            added = True

    syscalls = pdb.syscalls
    if len(syscalls) > 0:
        added = True
        ret['syscalls'] = syscalls

    if not added:
        return None

    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(ret)
    return ret


def main():
    extract(get_info, 'genvmi.tpl')


if __name__ == '__main__':
    main()
