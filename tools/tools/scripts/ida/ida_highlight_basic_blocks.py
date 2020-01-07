"""
Highlights basic blocks that have been covered by S2E (as measured by S2E's
TranslationBlockCoverage plugin).
"""

from __future__ import division

import json

import idaapi
import idautils
import idc


def _color_block(bb, color=0x00ff00):
    for ea in idautils.Heads(bb.startEA, bb.endEA):
        idc.SetColor(ea, idc.CIC_ITEM, color)


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

    idc.Message(COVERAGE_MESSAGE.format(num_bbs=total_bbs,
                                        num_covered_bbs=covered_bbs,
                                        percent=percent_str))


def basic_block_coverage(json_path):
    bb_coverage = {}
    with open(json_path, 'r') as f:
        bb_coverage = json.load(f)

    for covered_basic_block in bb_coverage['coverage']:
        start_addr = covered_basic_block['start_addr']

        func = idaapi.get_func(start_addr)
        if not func:
            idc.Warning('Could not find function associated with address '
                        '0x%x' % start_addr)
            return

        for block in idaapi.FlowChart(func):
            if block.startEA <= start_addr and block.endEA > start_addr:
                _color_block(block)

    print_stats(bb_coverage)


if __name__ == '__main__':
    json_path = idc.AskFile(0, '*.json',
                            'Select the basic_block_coverage.json file')
    if json_path:
        basic_block_coverage(json_path)
