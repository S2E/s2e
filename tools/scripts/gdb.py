# Copyright (C) 2013, Dependable Systems Laboratory, EPFL
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

import array
import ast
from curses.ascii import isgraph

REGS = {"EAX": 0, "ECX": 1, "EDX": 2, "EBX": 3, "ESP": 4, "EBP": 5, "ESI": 6, "EDI": 7}
SEGS = {"ES": 0, "CS": 1, "SS": 2, "DS": 3, "FS": 4, "GS": 5}
CPU_TLB_SIZE = 256
TARGET_PAGE_BITS = 12
TARGET_PAGE_SIZE = 1 << TARGET_PAGE_BITS
TARGET_PAGE_MASK = ~(TARGET_PAGE_SIZE - 1)

TARGET_PHYS_ADDR_SPACE_BITS = 36
TARGET_VIRT_ADDR_SPACE_BITS = 32
L2_BITS = 10
L2_SIZE = (1 << L2_BITS)
P_L2_LEVELS = (((TARGET_PHYS_ADDR_SPACE_BITS - TARGET_PAGE_BITS - 1) / L2_BITS) + 1)
PHYS_MAP_NODE_NIL = 0xffff >> 1

def pc_to_linear(env, pc):
    base = env['segs'][SEGS['CS']]['base']
    return base + pc;

def virt_to_host(env, addr):
    mmu_idx = 0
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1)
    tlb_entry = env['tlb_table'][mmu_idx][index]
    if tlb_entry['se_addend'] == 0:
        print "%x is not mapped" % addr
        return

    return addr + tlb_entry['se_addend']

####################################################################
def phys_page_find(index):
    lp = gdb.parse_and_eval("phys_map")
    s_index = gdb.parse_and_eval("phys_section_unassigned")
    phys_map_nodes = gdb.parse_and_eval("phys_map_nodes")
    phys_sections = gdb.parse_and_eval("phys_sections")
    i = P_L2_LEVELS - 1
    while i >= 0 and not lp['is_leaf']:
        if lp['ptr'] == PHYS_MAP_NODE_NIL:
            return None
        p = phys_map_nodes[lp['ptr']]
        lp = p[(index >> (i * L2_BITS)) & (L2_SIZE - 1)]
        i = i - 1

    s_index = lp['ptr'];
    return phys_sections[s_index];

def memory_region_is_ram(mr):
    return mr['ram']

def is_ram_rom(s):
    mr = s['mr'].dereference()
    return memory_region_is_ram(mr)

def is_romd(s):
    mr = s['mr'].dereference()
    return mr['rom_device'] and mr['readable']

def is_ram_rom_romd(s):
    return is_ram_rom(s) or is_romd(s)

"""
#define QLIST_FOREACH(var, head, field)                                 \
        for ((var) = ((head)->lh_first);                                \
                (var);                                                  \
                (var) = ((var)->field.le_next))
"""

def qemu_get_ram_ptr(addr):
    ram_list = gdb.parse_and_eval("ram_list")
    pblock = ram_list['blocks']['lh_first']
    while pblock != 0:
        #print "pblock", pblock
        block = pblock.dereference()
        if addr - block['offset'] < block['length']:
            return block['host'] + (addr - block['offset'])

        pblock = block['next']['le_next']

    #print "qemu_get_ram_ptr =", ram_list, "lh_first", block

def memory_region_get_ram_ptr(mr):
    if mr['alias']:
        return None
    return qemu_get_ram_ptr(mr['ram_addr'] & TARGET_PAGE_MASK);

def section_addr(section, addr):
    addr -= section['offset_within_address_space']
    addr += section['offset_within_region']
    return addr

def se_get_host_address(paddr):
    section = phys_page_find(paddr >> TARGET_PAGE_BITS)
    #print "get_host_address =", section
    if section == None or not is_ram_rom_romd(section):
        return None

    return memory_region_get_ram_ptr(section['mr']) + section_addr(section, paddr)

"""
Convert a host address to a KLEE concrete buffer
"""
def s2e_to_state_local(haddr):
    hpaddr = long(haddr) & TARGET_PAGE_MASK
    root_node = gdb.parse_and_eval("g_s2e_state->addressSpace.objects.elts.node").dereference()

    cur_node = root_node
    ##XXX: check for terminators
    while True:
        mo = cur_node['value']['first'].dereference()
        mo_gp = long(mo['address'])
        mo_gp_size = long(mo['size'])

        if hpaddr < mo_gp:
            cur_node = cur_node['left'].dereference()
        elif hpaddr > mo_gp:
            cur_node = cur_node['right'].dereference()
        else:
            return cur_node['value']

    return None

def s2e_get_state_host_address(paddr):
    qemu_host_addr = se_get_host_address(paddr)
    ret = s2e_to_state_local(qemu_host_addr)
    os = ret['second']['os'].dereference()
    mbuffer = os['concreteStore'].dereference()['m_buffer']
    return mbuffer + (long(paddr) & ~TARGET_PAGE_MASK)

####################################################################
class QEMUPhysPageFind(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, "qemu_phys_page_find", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)
        address = ast.literal_eval(arg_list[0])
        print s2e_get_state_host_address(address)

QEMUPhysPageFind()

####################################################################
class QEMUVirtualToGuestPhysical(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, "virt2phys", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)

        if len(arg_list) == 1:
            vaddr = long(ast.literal_eval(arg_list[0]))
            env = gdb.parse_and_eval("env").dereference()
            cr3 = long(env['cr'][3])
        else:
            cr3 = long(ast.literal_eval(arg_list[0]))
            vaddr = long(ast.literal_eval(arg_list[1]))

        vaddr = long(ast.literal_eval(arg_list[0]))
        pdir_index = (vaddr >> 22)
        ptbl_index = (vaddr >> TARGET_PAGE_BITS) & 0x3ff

        env = gdb.parse_and_eval("env").dereference()
        cr3 = long(env['cr'][3])
        print "CR3 = %#010x pdir_index=%d ptbl_index=%d" % (cr3, pdir_index, ptbl_index)

        #####################################
        pdir_data = gdb.parse_and_eval("(uint32_t*) %d" % (long(s2e_get_state_host_address(cr3))))
        pdir_entry = long(pdir_data[pdir_index])

        pt_ha = 0
        if (pdir_entry & 1) == 1:
            pt_ha = long(s2e_get_state_host_address(pdir_entry & TARGET_PAGE_MASK))

        print "pdir_entry=%#010x phys=%#010x ha=%#x" %  \
            (pdir_entry, pdir_entry & TARGET_PAGE_MASK, pt_ha)

        if (pdir_entry & 1) == 0:
            print "Address not mapped in page directory"
        #####################################

        ptbl_data = gdb.parse_and_eval("(uint32_t*) %d" % (pt_ha))
        ptbl_entry = long(ptbl_data[ptbl_index])

        ha = 0
        if (ptbl_entry & 1) == 1:
            ha = long(s2e_get_state_host_address(ptbl_entry & TARGET_PAGE_MASK))

        print "ptbl_entry=%#010x phys=%#010x ha=%#x" %  \
            (ptbl_entry, ptbl_entry & TARGET_PAGE_MASK, ha)

        if (ptbl_entry & 1) == 0:
            print "Address not mapped in page table"

QEMUVirtualToGuestPhysical()


####################################################################
class S2EPrintCpu(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, "s2e-printcpu", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)
        env = gdb.parse_and_eval("env")
        if env.type.code != gdb.lookup_type('CPUX86State').pointer().code:
            print "env has incorrect type"
            return

        for reg in REGS:
            print "%s=%#010x" % (reg, env['regs'][REGS[reg]]),

        print

        for reg in SEGS:
            seg = env['segs'][SEGS[reg]]
            print "%s selector=%#06x base=%#010x limit=%#010x" % (reg, seg['selector'], seg['base'], seg['limit'])

        print "EIP=%#010x (%#010x)" % (env['eip'], pc_to_linear(env, env['eip']))

S2EPrintCpu()

####################################################################
class S2EDisassemble(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, "s2e-dis", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) != 1:
            raise gdb.GdbError('s2e-x takes the number of instructions to disassemble')

        env = gdb.parse_and_eval("env")
        if env.type.code != gdb.lookup_type('CPUX86State').pointer().code:
            print "env has incorrect type"
            return

        count = gdb.parse_and_eval(argv[0])
        pc = pc_to_linear(env, env['eip'])
        #XXX: Assumes the code is entirely contained in one page
        addr = virt_to_host(env, pc)

        gdb.execute("x /%di 0x%x" % (count, addr))

S2EDisassemble()

####################################################################
#Breaks at the next translation block
class S2ENextTb(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, "s2e-next", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        env = gdb.parse_and_eval("env")
        if env.type.code != gdb.lookup_type('CPUX86State').pointer().code:
            print "env has incorrect type"
            return


S2EDisassemble()



####################################################################
class S2EPrintMem(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, "s2e-x", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if len(argv) != 2:
            raise gdb.GdbError('s2e-x takes 2 arguments')
        addr = gdb.parse_and_eval(argv[0]).cast(gdb.lookup_type('void').pointer())

        try:
            bytes = int(gdb.parse_and_eval(argv[1]))
        except ValueError:
            raise gdb.GdbError('Byte count numst be an integer value.')

        env = gdb.parse_and_eval("env")
        if env.type.code != gdb.lookup_type('CPUX86State').pointer().code:
            print "env has incorrect type"
            return


        inferior = gdb.selected_inferior()

        align = gdb.parameter('hex-dump-align')
        width = gdb.parameter('hex-dump-width')
        if width == 0:
            width = 16

        mem = [0] * bytes

        for n in range(0, bytes):
            addr = virt_to_host(env, gdb.parse_and_eval(argv[0]) + n)
            tmp = inferior.read_memory(addr, 1)
            mem[n] = tmp[0]

        pr_addr = int(str(argv[0]), 16)
        pr_offset = width

        if align:
            pr_offset = width - (pr_addr % width)
            pr_addr -= pr_addr % width

        for group in groups_of(mem, width, pr_offset):
            print '0x%x: ' % (pr_addr,) + '   '*(width - pr_offset),
            print ' '.join(['%02X' % (ord(g),) for g in group]) + \
                '   ' * (width - len(group) if pr_offset == width else 0) + ' ',
            print ' '*(width - pr_offset) +  ''.join(
                [g if isgraph(g) or g == ' ' else '.' for g in group])
            pr_addr += width
            pr_offset = width

S2EPrintMem()
####################################################################

def groups_of(iterable, size, first=0):
    first = first if first != 0 else size
    chunk, iterable = iterable[:first], iterable[first:]
    while chunk:
        yield chunk
        chunk, iterable = iterable[:size], iterable[size:]

class HexDump(gdb.Command):
    def __init__(self):
        super (HexDump, self).__init__ ('hex-dump', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) != 2:
            raise gdb.GdbError('hex-dump takes exactly 2 arguments.')
        addr = gdb.parse_and_eval(argv[0]).cast(
            gdb.lookup_type('void').pointer())
        try:
            bytes = int(gdb.parse_and_eval(argv[1]))
        except ValueError:
            raise gdb.GdbError('Byte count numst be an integer value.')

        inferior = gdb.selected_inferior()

        align = gdb.parameter('hex-dump-align')
        width = gdb.parameter('hex-dump-width')
        if width == 0:
            width = 16

        mem = inferior.read_memory(addr, bytes)
        pr_addr = int(str(addr), 16)
        pr_offset = width

        if align:
            pr_offset = width - (pr_addr % width)
            pr_addr -= pr_addr % width

        for group in groups_of(mem, width, pr_offset):
            print '0x%x: ' % (pr_addr,) + '   '*(width - pr_offset),
            print ' '.join(['%02X' % (ord(g),) for g in group]) + \
                '   ' * (width - len(group) if pr_offset == width else 0) + ' ',
            print ' '*(width - pr_offset) +  ''.join(
                [g if isgraph(g) or g == ' ' else '.' for g in group])
            pr_addr += width
            pr_offset = width

class HexDumpAlign(gdb.Parameter):
    def __init__(self):
        super (HexDumpAlign, self).__init__('hex-dump-align',
                                            gdb.COMMAND_DATA,
                                            gdb.PARAM_BOOLEAN)

    set_doc = 'Determines if hex-dump always starts at an "aligned" address (see hex-dump-width'
    show_doc = 'Hex dump alignment is currently'

class HexDumpWidth(gdb.Parameter):
    def __init__(self):
        super (HexDumpWidth, self).__init__('hex-dump-width',
                                            gdb.COMMAND_DATA,
                                            gdb.PARAM_INTEGER)

    set_doc = 'Set the number of bytes per line of hex-dump'

    show_doc = 'The number of bytes per line in hex-dump is'

HexDump()
HexDumpAlign()
HexDumpWidth()
