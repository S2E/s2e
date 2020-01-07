"""
Adds metadata to basic blocks that have been covered by S2E (as measured by
S2E's TranslationBlockCoverage plugin).
"""

from __future__ import division, print_function

import json
import os
import sys

import r2pipe
from termcolor import colored


SCRIPT_NAME = os.path.basename(__file__)
MSG_PREFIX = colored('[%s]' % SCRIPT_NAME, 'yellow')
S2E_COMMENT = 'Covered by S2E'
COVERAGE_MESSAGE = 'S2E Basic Block Coverage\n'                             \
                   '========================\n'                             \
                   'Total basic blocks: {num_bbs}\n'                        \
                   'Covered basic blocks: {num_covered_bbs} ({percent})\n'


def print_stats(bb_coverage):
    total_bbs = bb_coverage['stats']['total_basic_blocks']
    covered_bbs = bb_coverage['stats']['covered_basic_blocks']

    # Calculate the coverage percentage to avoid divide-by-zero
    if total_bbs:
        percent_str = '{:.1%}'.format(covered_bbs / total_bbs)
    else:
        percent_str = '-%'

    print(COVERAGE_MESSAGE.format(num_bbs=total_bbs,
                                  num_covered_bbs=covered_bbs,
                                  percent=percent_str))


def basic_block_coverage(json_path):
    bb_coverage = {}
    with open(json_path, 'r') as f:
        bb_coverage = json.load(f)

    r2 = r2pipe.open()
    r2.cmd('aaa')

    for covered_basic_block in bb_coverage['coverage']:
        start_addr = covered_basic_block['start_addr']

        r2.cmd('CCa 0x%x %s' % (start_addr, S2E_COMMENT))

    print_stats(bb_coverage)


if __name__ == '__main__':
    while True:
        json_path = raw_input('%s Path to basic_block_coverage.json: ' %
                              MSG_PREFIX)

        if os.path.isfile(json_path):
            break
        else:
            text = colored('[%s] %s is not a valid path\n' %
                           (SCRIPT_NAME, json_path), 'red')
            sys.stderr.write(text)


    basic_block_coverage(json_path)
