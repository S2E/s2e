import idaapi
import idautils
import idc


def cls_split_block(fp, start_ea, end_ea):
    """
    ``idaapi.Flowchart`` does not consider function calls as basic block
    boundaries. This function takes a range of addresses and splits additional
    basic blocks.
    """
    cur_name = idc.GetFunctionName(start_ea)
    dem_name = idc.Demangle(cur_name, idc.GetLongPrm(idc.INF_SHORT_DN))
    if dem_name != None:
        cur_name = dem_name

    first = start_ea
    block = idautils.Heads(start_ea, end_ea)
    for inst in block:
        mnem = idc.GetMnem(inst)
        if mnem == 'call' and inst != end_ea:
            fp.write('%#010x %#010x %s\n' % (first,
                                             idc.NextHead(inst, end_ea + 1) - 1,
                                             cur_name))
            first = idc.NextHead(inst, end_ea + 1)

    if first < end_ea:
        fp.write('%#010x %#010x %s\n' % (first, end_ea - 1, cur_name))


def cls_main(fp, func):
    flow_chart = idaapi.FlowChart(idaapi.get_func(func))
    for block in flow_chart:
        cls_split_block(fp, block.startEA, block.endEA)


def extract_bbs():
    filename = idc.AskFile(1, '*.*', 'Save list of basic blocks')
    do_exit = False

    if not filename:
        basename = idc.GetInputFile()
        filename = '%s.bblist' % basename
        idc.GenerateFile(idc.OFILE_ASM, '%s.asm' % basename, 0, idc.BADADDR, 0)
        idc.GenerateFile(idc.OFILE_LST, '%s.lst' % basename, 0, idc.BADADDR, 0)
        do_exit = True

    with open(filename, 'w') as fp:
        funcs = idautils.Functions()
        for func in funcs:
            cls_main(fp, func)

    if do_exit:
        idc.Exit(0)


if __name__ == '__main__':
    idc.Wait()
    extract_bbs()
