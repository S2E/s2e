"""
Highlights basic blocks that have been covered by S2E (as measured by S2E's
TranslationBlockCoverage plugin).
"""

import json
import sys

import idaapi
import idautils
import idc


def _color_block(bb, color=0x00ff00):
    for ea in idautils.Heads(bb.startEA, bb.endEA):
        idc.SetColor(ea, idc.CIC_ITEM, color)


def basic_block_coverage(json_path):
    bb_coverage = {}
    with open(json_path, 'r') as f:
        bb_coverage = json.load(f)

    for covered_basic_block in bb_coverage:
        start_addr = covered_basic_block['start_addr']

        func = idaapi.get_func(start_addr)
        if not func:
            idc.Warning('Could not find function associated with address '
                        '0x%x' % start_addr)
            return

        for block in idaapi.FlowChart(func):
            if block.startEA <= start_addr and block.endEA > start_addr:
                _color_block(block)


if __name__ == '__main__':
    json_path = idc.AskFile(0, '*.json',
                            'Select the basic_block_coverage.json file')
    if json_path:
        basic_block_coverage(json_path)
