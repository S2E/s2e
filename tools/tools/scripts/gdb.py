# Copyright (C) 2013, Dependable Systems Laboratory, EPFL
# Copyright (C) 2019, Cyberhaven
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
#
# This script adds a few commands to gdb to help debug S2E.
# Load it as follows:
#
#     (gdb) source ~/s2e/s2e/tools/tools/scripts/gdb.py
#

import array
import ast
from curses.ascii import isgraph

g_cpu_env = 'g_cpu_env'

CPU_TLB_SIZE = 256
TARGET_PAGE_BITS = 12
TARGET_PAGE_SIZE = 1 << TARGET_PAGE_BITS
TARGET_PAGE_MASK = ~(TARGET_PAGE_SIZE - 1)


def get_cpu_env():
    env = gdb.parse_and_eval(g_cpu_env)
    if env.type.code != gdb.lookup_type('CPUX86State').pointer().code:
        raise Exception('env has incorrect type')

    return env


def make_uint32_ptr(addr):
    return gdb.parse_and_eval('(uint32_t*) %d' % addr)


def make_uint8_ptr(addr):
    return gdb.parse_and_eval('(uint8_t*) %d' % addr)


def call_function(name, *args):
    cmd = name + '('
    for arg in args:
        cmd += ' %s' % arg
        cmd += ')'

    return gdb.parse_and_eval(cmd)


def host_to_state(haddr):
    # TODO: return haddr if there is no S2E
    addr = call_function('s2e_host_to_state_address', haddr)
    if not addr:
        raise Exception('Could not get per-state address for host address %#' % haddr)
    return addr


def phys_to_host(paddr):
    desc = call_function('mem_desc_find', paddr)
    if not desc:
        raise Exception('Could not get memory descriptor for address %#x' % paddr)

    offset = paddr - desc['kvm']['guest_phys_addr']
    ram_addr = desc['ram_addr'] + offset

    ram_ptr = call_function('get_ram_ptr_internal', ram_addr)
    if not ram_ptr:
        raise Exception('Could not get ram ptr for address %#x' % paddr)

    return ram_ptr


def x86_guest_virt_to_phys(cr0, cr3, vaddr):
    if not (cr0 & 0x80000000):
        return vaddr

    pdir_index = vaddr >> 22
    ptbl_index = (vaddr >> TARGET_PAGE_BITS) & 0x3ff

    print('CR3 = %#010x pdir_index=%d ptbl_index=%d' % (cr3, pdir_index, ptbl_index))

    #####################################
    pdir_data = make_uint32_ptr(host_to_state(phys_to_host(cr3)))
    pdir_entry = int(pdir_data[pdir_index])

    pt_ha = 0

    if (pdir_entry & 1) == 0:
        raise Exception('Address not mapped in page directory')

    pt_ha = phys_to_host(pdir_entry & TARGET_PAGE_MASK)

    print('pdir_entry=%#010x phys=%#010x ha=%#x' %
          (pdir_entry, pdir_entry & TARGET_PAGE_MASK, pt_ha))

    #####################################

    ptbl_data = gdb.parse_and_eval('(uint32_t*) %d' % host_to_state(pt_ha))
    ptbl_entry = int(ptbl_data[ptbl_index])

    return (ptbl_entry & TARGET_PAGE_MASK) + (vaddr & (TARGET_PAGE_SIZE - 1))


def read_host_memory(addr, count):
    data = []

    ptr = make_uint8_ptr(addr)
    for i in range(0, count):
        data.append(int(ptr[i]))
    return data


def read_phys_memory(addr, count):
    host_ptr = phys_to_host(addr)

    # If the guest runs in S2E mode, translate the host pointer to a state-local pointer.
    state_ptr = host_to_state(host_ptr)
    return read_host_memory(state_ptr, count)


def read_virt_memory(cr0, cr3, addr, count):
    data = []
    while count:
        print("Count: %#x" % (count))
        addr1 = addr + count - 1
        max_count = count
        if (addr1 >> TARGET_PAGE_BITS) != (addr >> TARGET_PAGE_BITS):
            max_count = (addr & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE - addr
            print("max_count: %#x" % (addr & TARGET_PAGE_MASK))

        phys_ptr = x86_guest_virt_to_phys(cr0, cr3, addr)
        new_data = read_phys_memory(phys_ptr, max_count)
        data += new_data
        count -= len(new_data)
        addr += len(new_data)
        if not len(new_data):
            raise Exception("Could not read memory add physical memory %#x" % phys_ptr)
    return data


class X86CPU(object):
    REGS = {'eax': 0, 'ecx': 1, 'edx': 2, 'ebx': 3, 'esp': 4, 'ebp': 5, 'esi': 6, 'edi': 7}
    SEGS = {'es': 0, 'cs': 1, 'ss': 2, 'ds': 3, 'fs': 4, 'gs': 5}

    def __init__(self, env):
        self._env = env

    @staticmethod
    def create():
        env = get_cpu_env()
        return X86CPU(env)

    @property
    def regs(self):
        ret = {}
        for name, idx in X86CPU.REGS.items():
            ret[name] = self._env['regs'][idx]
        return ret

    @property
    def segs(self):
        ret = {}
        for name, idx in X86CPU.SEGS.items():
            ret[name] = self._env['segs'][idx]
        return ret

    @property
    def pc(self):
        return self._env['eip']

    @property
    def pc_linear(self):
        return self.get_linear_address('cs', self._env['eip'])

    def get_linear_address(self, seg, addr):
        base = self.segs[seg]['base']
        return int(base + addr)

    def virt_to_host_tlb(self, addr):
        mmu_idx = 0
        index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1)
        tlb_entry = self.env['tlb_table'][mmu_idx][index]
        if tlb_entry['addend'] == -1:
            raise Exception('Address %x is not mapped' % addr)

        # TODO: check if we run in S2E mode or not
        return int(addr + tlb_entry['addend'])

    def guest_virt_to_phys(self, vaddr):
        cr0 = int(self._env['cr'][0])
        cr3 = int(self._env['cr'][3])
        return x86_guest_virt_to_phys(cr0, cr3, vaddr)

    def read_memory(self, vaddr, count):
        cr0 = int(self._env['cr'][0])
        cr3 = int(self._env['cr'][3])
        return read_virt_memory(cr0, cr3, vaddr, count)

    def dump_tlb(self):
        tlb_table = self._env['tlb_table']
        for i in range(0, CPU_TLB_SIZE):
            tlb_entry = tlb_table[0][i]
            if tlb_entry['addend'] == -1:
                continue

            line = '0x{0:02x} read=0x{1:08x} write=0x{2:08x} code=0x{3:08x} addend=0x{4:x}'.format(
                i, int(tlb_entry['addr_read']),
                int(tlb_entry['addr_write']),
                int(tlb_entry['addr_code']),
                int(tlb_entry['addend'])
            )

            print(line)

    def dump_regs(self):
        print('eip=%#010x (%#010x)' % (self.pc, self.pc_linear))

        print()

        for name, value in self.regs.items():
            print('%s=%#010x' % (name, value),)

        print()

        for name, seg in self.segs.items():
            print('%s selector=%#06x base=%#010x limit=%#010x' % (name, seg['selector'], seg['base'], seg['limit']))


####################################################################
class S2ECPUPrintRegs(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 's2e-cpu-print-regs', gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        cpu = X86CPU.create()
        cpu.dump_regs()


S2ECPUPrintRegs()


class S2ECPUPrintTlb(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 's2e-cpu-print-tlb', gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        cpu = X86CPU.create()
        cpu.dump_tlb()


S2ECPUPrintTlb()


####################################################################
class S2EAddressInfo(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 's2e-addr-info', gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)
        if len(arg_list) != 1:
            print('Usage: s2e-addr-info address')
            return

        vaddr = ast.literal_eval(arg_list[0])
        print('Virtual address: %#x' % vaddr)

        cpu = X86CPU.create()
        guest_phys = cpu.guest_virt_to_phys(vaddr)
        print('Guest physical address: %#x' % guest_phys)

        host_addr = phys_to_host(guest_phys)
        print('Host address: %#x' % host_addr)

        state_addr = host_to_state(host_addr)
        print('Per-state address: %#x' % state_addr)


S2EAddressInfo()


####################################################################
class S2EDisassemble(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 's2e-dis', gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        cpu = X86CPU.create()

        if len(argv) == 1:
            pc = cpu.pc_linear
            count = gdb.parse_and_eval(argv[0])
        elif len(argv) == 2:
            pc = gdb.parse_and_eval(argv[0])
            count = gdb.parse_and_eval(argv[1])
        else:
            raise gdb.GdbError('Usage: s2e-dis [pc] num_instr')

        # XXX: Assumes the code is entirely contained in one page
        # TODO: detect 16-32-64 bit modes
        phys_addr = cpu.guest_virt_to_phys(pc)
        host_addr = phys_to_host(phys_addr)
        state_addr = host_to_state(host_addr)

        print("pc=%#x host_addr=%#x state_addr=%#x\n" % (pc, host_addr, state_addr))
        gdb.execute('x /%di 0x%x' % (count, state_addr))


S2EDisassemble()


class S2EDisassembleTb(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 's2e-dis-tb', gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        count = 20
        if len(argv) == 1:
           count = gdb.parse_and_eval(argv[0])

        env = get_cpu_env()
        tc = env['current_tb']['tc']
        print("TB ptr=%#x size=%#x pc=%#x" % (tc['ptr'], tc['size'], env['eip']))
        gdb.execute('x /%di 0x%x' % (count, tc['ptr']))


S2EDisassembleTb()


####################################################################
def groups_of(iterable, size, first=0):
    first = first if first != 0 else size
    chunk, iterable = iterable[:first], iterable[first:]
    while chunk:
        yield chunk
        chunk, iterable = iterable[:size], iterable[size:]


class S2EPrintMem(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 's2e-x', gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if len(argv) != 2:
            raise gdb.GdbError('Usage: s2e-x vaddress count')
        addr = gdb.parse_and_eval(argv[0]).cast(gdb.lookup_type('void').pointer())

        try:
            count = int(gdb.parse_and_eval(argv[1]))
        except ValueError:
            raise gdb.GdbError('Byte count must be an integer value')

        cpu = X86CPU.create()
        mem = cpu.read_memory(int(addr), count)

        align = 0 #gdb.parameter('hex-dump-align')
        width = 16 #gdb.parameter('hex-dump-width')
        if width == 0:
            width = 16

        pr_addr = int(str(argv[0]), 16)
        pr_offset = width

        if align:
            pr_offset = width - (pr_addr % width)
            pr_addr -= pr_addr % width

        raw = True

        for group in groups_of(mem, width, pr_offset):
            if not raw:
                s = '0x%x: ' % (pr_addr,) + '   '*(width - pr_offset)
            else:
                s = ''

            s += ' '.join(['%02x' % (g,) for g in group]) + \
                '   ' * (width - len(group) if pr_offset == width else 0) + ' '

            if not raw:
                s += ' '*(width - pr_offset) + ''.join(
                    [chr(g) if isgraph(g) or g == ' ' else '.' for g in group])
            print(s)
            pr_addr += width
            pr_offset = width


S2EPrintMem()
####################################################################
