import json

import idaapi
import idautils
import idc


def _split_basic_block(start_ea, end_ea):
    """
    IDA Pro's ``idaapi.Flowchart`` does not consider function calls as basic
    block boundaries. This function takes an address range and splits the
    basic blocks found within that range so that function calls are considered
    basic block boundaries.
    """
    split_bbs = []
    func_name = idc.GetFunctionName(start_ea)
    demangled_name = idc.Demangle(func_name,
                                  idc.GetLongPrm(idc.INF_SHORT_DN))
    if demangled_name:
        func_name = demangled_name

    bb_start_addr = start_ea
    block = idautils.Heads(start_ea, end_ea)

    for inst in block:
        mnem = idc.GetMnem(inst)
        if mnem == 'call' and inst != end_ea:
            split_bbs.append(dict(start_addr=bb_start_addr,
                                  end_addr=idc.NextHead(inst, end_ea + 1) - 1,
                                  function=func_name))
            bb_start_addr = idc.NextHead(inst, end_ea + 1)

    if bb_start_addr < end_ea:
        split_bbs.append(dict(start_addr=bb_start_addr, end_addr=end_ea - 1,
                              function=func_name))

    return split_bbs


def _get_basic_blocks():
    """
    Extract basic block information from the target binary.
    """
    bbs = []

    for func in idautils.Functions():
        flowchart = idaapi.FlowChart(idaapi.get_func(func))

        for basic_block in flowchart:
            split_bbs = _split_basic_block(basic_block.startEA,
                                           basic_block.endEA)
            bbs.extend(split_bbs)

    return bbs


def main():
    disas_path = idc.AskFile(1, '*.disas', 'Save basic blocks')
    do_exit = False

    if not disas_path:
        basename = idc.GetInputFile()
        disas_path = '%s.disas' % basename
        idc.GenerateFile(idc.OFILE_ASM, '%s.asm' % basename, 0, idc.BADADDR, 0)
        idc.GenerateFile(idc.OFILE_LST, '%s.lst' % basename, 0, idc.BADADDR, 0)
        do_exit = True

    # Get basic blocks
    bbs = _get_basic_blocks()

    # Get the module's base address
    base_addr = idaapi.get_imagebase()

    # Get the module's end address
    segs = sorted(idautils.Segments())
    end_addr = idc.SegEnd(segs[-1])

    disas_info = {
        'bbs': bbs,
        'base_addr': base_addr,
        'end_addr': end_addr,
    }

    with open(disas_path, 'w') as disas_file:
        json.dump(disas_info, disas_file)

    if do_exit:
        idc.Exit(0)


if __name__ == '__main__':
    idc.Wait()
    main()
