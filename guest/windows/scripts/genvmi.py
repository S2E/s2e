#!/usr/bin/env python

# Copyright (C) 2014-2017, Cyberhaven
# Copyright (C) 2017, Dependable Systems Laboratory, EPFL
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

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
