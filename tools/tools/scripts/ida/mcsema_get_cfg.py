##
## Instructions:
## 1) Install python-protobuf for your IDAPython installation. This probably means
## downloading it from https://protobuf.googlecode.com/files/protobuf-2.5.0.tar.gz
## and manually running setup.py
## 2) This script should be run via IDA's batch mode. See the output
## of --help for more details on the command line options.
##

import idautils
import idaapi
import idc
import sys
import cfg_pb2
from os import path
import os
import argparse
import struct

class ToFileStdOut(object):
    def __init__(self, filename):
        self.outfile = open(filename, "w")

    def write(self, text):
        self.outfile.write(text)

    def flush(self):
        self.outfile.flush()

    def isatty(self):
        return False

    def __del__(self):
        self.outfile.close()


class JmpTable:
    """Object which represent a Jmp Table"""

    def __init__(self, addr=0x0, element_size=4, function=None, entries=list()):
        self._addr = addr
        self._entries = entries[:]
        self._element_size = element_size
        self._function = function

    def add_entry(self, e):
        if e not in self._entries:
            self._entries.append(e)

    def overlap_with(self, e):
        return self._addr >= e._addr and self._addr < e._addr + e._element_size * len(e.entries())

    def entries(self):
        return self._entries[:]

    def shrink(self, succ):
        """Return a new JmpTable object with the elements of self which don't overlap with succ"""
        n_elements = (succ._addr - self._addr) // self._element_size
        n = JmpTable(addr=self._addr, function=self._function, entries=self._entries[:n_elements])

        return n

    def get_function(self):
        return self._function

    def get_start(self):
        return self._addr

class JmpTableList:
    """Represent a set of JmpTables"""

    def __init__(self):
        self._tables = set()

    @staticmethod
    def findBlock(f, ea):
        for i in f.blocks:
            if i.base_address == ea:
                return i

        return None

    @staticmethod
    def removeBlock(f, ea):
        i = 0
        while i < len(f.blocks):
            if f.blocks[i].base_address == ea:
                DEBUG("remove block_{0:#x} from {1:x}\n".format(f.blocks[i].base_address, f.entry_address))
                del f.blocks[i]
                return

            i += 1

        return

    @staticmethod
    def removeFollowBlocks(b, not_good):
        i = 0
        while i < len(b.block_follows):
            for e in not_good:
                if e == b.block_follows[i]:
                    DEBUG("remove block_{0:#x} from follows of block_{1:#x}\n".format(b.block_follows[i], b.base_address))
                    del b.block_follows[i]
                    i -= 1
                    break

            i += 1

        return

    @staticmethod
    def removeBBs(f, entries):
        useless = set()

        to_remove = entries[:]
        blocks = {}

        while len(to_remove) > 0:
            bstart = to_remove.pop()
            newb = JmpTableList.findBlock(f, bstart)
            if newb is None:
                continue

            blocks[newb.base_address] = newb
            for fba in newb.block_follows:
                if fba not in blocks:
                    to_remove.append(fba)

        for k in sorted(blocks.keys()):
            JmpTableList.removeBlock(f, blocks[k].base_address)

        # remove blocks from follows of f.blocks
        for b in f.blocks:
            JmpTableList.removeFollowBlocks(b, blocks.keys())

    def add(self, e):
        #FIXME: what happens when we find the same jmptable from two different fn?

        # when the new jmptable is in the middle of another one, shrink the old one
        prec = self.prec(e)
        if prec is not None and e.overlap_with(prec):
            newprec = prec.shrink(e)
            self.replace(prec, newprec)

            # if jmptables are used in two different functions, remove basic block
            # in the second jmptable from the basicblock list of the first
            # XXX: we should remove also all basicblocks reached through BBs in the
            #      "wrong" jmptable, but we are able to remove them later during lifting
            #      because probably no other blocks will reference those BBs
            pF = prec.get_function()
            lF = e.get_function()
            if pF.entry_address != lF.entry_address:
                DEBUG("different functions {0:x} {1:x}\n".format(pF.entry_address, lF.entry_address))
                DEBUG("prec @ {0:x}\n".format(prec.get_start()))
                DEBUG("new  @ {0:x}\n".format(e.get_start()))

                #XXX: revgen does not like when BBs are removed
                #It needs all the BBs of a function
                #JmpTableList.removeBBs(pF, e.entries())

        DEBUG("about to add likelyJmpTable to JMPTABLES\n")
        DEBUG("likelyJmpTable @ {0:x} #{1}\n".format(e.get_start(), len(e.entries())))
        self._tables.add(e)

    def replace(self, olde, newe):
        self._tables.discard(olde)
        self._tables.add(newe)

    def prec(self, e):
        """Return the predecessor of e in the list, based on the JmpTable address"""
        lo = sorted(self._tables, cmp=lambda x,y: cmp(x._addr, y._addr))

        prec = None
        for i in lo:
            if i._addr <= e._addr:
                prec = i

        return prec

    def succ(self, e):
        """Return the successor of e in l, based on the JmpTable address"""
        lo = sorted(self._tables, cmp=lambda x,y: cmp(x._addr, y._addr))

        for i in lo:
            if i._addr > e._addr:
                return i

        return None

    def tables(self):
        return list(self._tables)[:]


_DEBUG = False

EXTERNALS = set()
DATA_SEGMENTS = []

RECOVERED_EAS = set()
EMAP = {}
EMAP_DATA = {}

FUNCTIONS_NEED_TRAMPOLINE = False
JMPTABLES = JmpTableList()

TRAPS = [
        idaapi.NN_int3,
        idaapi.NN_icebp,
        ]

INTS = [
        idaapi.NN_int
       ]

CALLS = [
        idaapi.NN_call,
        idaapi.NN_callfi,
        idaapi.NN_callni]

RETS = [
        idaapi.NN_retf,
        idaapi.NN_retfd,
        idaapi.NN_retfq,
        idaapi.NN_retfw,
        idaapi.NN_retn,
        idaapi.NN_retnd,
        idaapi.NN_retnq,
        idaapi.NN_retnw]

COND_BRANCHES = [\
    idaapi.NN_ja,\
    idaapi.NN_jae,\
    idaapi.NN_jb,\
    idaapi.NN_jbe,\
    idaapi.NN_jc,\
    idaapi.NN_jcxz,\
    idaapi.NN_je,\
    idaapi.NN_jecxz,\
    idaapi.NN_jg,\
    idaapi.NN_jge,\
    idaapi.NN_jl,\
    idaapi.NN_jle,\
    idaapi.NN_jna,\
    idaapi.NN_jnae,\
    idaapi.NN_jnb,\
    idaapi.NN_jnbe,\
    idaapi.NN_jnc,\
    idaapi.NN_jne,\
    idaapi.NN_jng,\
    idaapi.NN_jnge,\
    idaapi.NN_jnl,\
    idaapi.NN_jnle,\
    idaapi.NN_jno,\
    idaapi.NN_jnp,\
    idaapi.NN_jns,\
    idaapi.NN_jnz,\
    idaapi.NN_jo,\
    idaapi.NN_jp,\
    idaapi.NN_jpe,\
    idaapi.NN_jpo,\
    idaapi.NN_jrcxz,\
    idaapi.NN_js,\
    idaapi.NN_jz,]

UCOND_BRANCHES = [\
    idaapi.NN_jmp,\
    idaapi.NN_jmpfi,\
    idaapi.NN_jmpni,\
    idaapi.NN_jmpshort]

def DEBUG(s):
    if _DEBUG:
        sys.stdout.write(s)

def isLinkedElf():
    return idc.GetLongPrm(INF_FILETYPE) == idc.FT_ELF and \
        idc.BeginEA() !=0xffffffffL

def fixExternalName(fn):

    if fn in EMAP:
        return fn

    if not isLinkedElf() and fn[0] == '_':
        return fn[1:]

    return fn

def nameInMap(themap, fn):

    return fixExternalName(fn) in themap


def getFromEMAP(fname):

    fixname = fixExternalName(fname)
    return EMAP[fixname]


def doesNotReturn(fname):
    try:
        args, conv, ret = getFromEMAP(fname)
        if ret == "Y":
            return True
    except KeyError, ke:
        raise Exception("Unknown external: " + fname)

    return False

def isHlt(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in [idaapi.NN_hlt]

def isJmpTable(ea):
    insn_t = idautils.DecodeInstruction(ea)
    is_jmp = insn_t.itype in [idaapi.NN_jmp,
            idaapi.NN_jmpfi,
            idaapi.NN_jmpni]

    if not is_jmp: return False

    if idaapi.get_switch_info_ex(ea):
        return True

    return False

def isIndirectJmp(ea):
    insn_t = DecodeInstruction(ea)
    return isUnconditionalJump(ea) and insn_t[0].type == idaapi.o_reg

def isIndirectCall(ea):
    insn_t = DecodeInstruction(ea)
    return isCall(ea) and (insn_t[0].type == idaapi.o_reg or insn_t[0].type == idaapi.o_mem or insn_t[0].type == idaapi.o_displ or insn_t[0].type == idaapi.o_phrase)

def isRepPrefix(ea):
    mnem = idc.GetDisasm(ea)
    return "rep " in mnem

def isDataInst(ea):
    mnem = idc.GetDisasm(ea)
    return mnem.startswith("dd ") or mnem.startswith("dw ") or mnem.startswith("db ")

def hasDispl(ins, op_x):
    return ins[op_x].type == idaapi.o_mem and ins[op_x].specflag1 != 0

def getAddressParts(ins, op_x):
    op = ins[op_x]
    sib = op.specflag2

    base = sib & 7
    index = (sib >> 3) & 7
    scale = (sib >> 6) & 3
    displ = op.addr

    return (base, scale, index, displ)

def isLikeLoadJmpTable(ea):
    insn_t = idautils.DecodeInstruction(ea)

    # 1) mov reg, off[reg*4]
    if hasDispl(insn_t, 1):
        base, scale, index, displ = getAddressParts(insn_t, 1)
        if base == 5 and scale == 2 and idc.isData(idc.GetFlags(displ)):
            # check if there is a table of valid code pointers
            ncases = 0
            bs = idaapi.get_many_bytes(displ, 4)
            if bs == None or len(bs) != 4:
                return False

            jmpaddress = struct.unpack('<I', bs)[0]
            while idc.isCode(idc.GetFlags(jmpaddress)):
                ncases += 1
                bs = idaapi.get_many_bytes(displ+ncases*4, 4)
                if bs == None or len(bs) != 4:
                    break
                jmpaddress = struct.unpack('<I', bs)[0]

            if ncases != 0:
                return True

    return False

def addFunction(M, ep):
    F = M.internal_funcs.add()
    F.entry_address = ep
    F.name = idc.GetFunctionName(ep)

    DEBUG("Added function {0} {1}\n".format(ep, F.name))

    return F

def entryPointHandler(M, ep, name, args_from_stddef=False):

    EP = M.entries.add()
    EP.entry_name = name
    EP.entry_address = ep

    have_edata = False


    # should we get argument count
    # calling ocnvention, and return type from std_defs?
    if args_from_stddef:
        try:
            (argc, conv, ret) = getFromEMAP(name)
            have_edata = True
        except KeyError as ke:
            pass

    if not have_edata:
        (argc, conv, ret) = getExportType(name, ep)

    EP.entry_extra.entry_argc = argc
    EP.entry_extra.entry_cconv = conv
    if ret == 'Y':
        EP.entry_extra.does_return = False
    else:
        EP.entry_extra.does_return = True

    F = addFunction(M, ep)

    DEBUG("At EP {0}:{1:x}\n".format(name,ep))

    return F

def basicBlockHandler(F, block, blockset, processed_blocks, need_trampolines):
    B = F.blocks.add()
    B.base_address = block.startEA
    B.need_trampoline = B.base_address in need_trampolines
    DEBUG("BB: {0:x}\n".format(block.startEA))

    B.block_follows.extend(block.succs)

    if _DEBUG:
        str_l = ["{0:x}".format(i) for i in block.succs]
        if len(str_l) > 0:
            DEBUG("Successors: {0}\n".format(", ".join(str_l)))

    return B

def readInstructionBytes(inst):
    insn_t = idautils.DecodeInstruction(inst)
    return [idc.Byte(b) for b in xrange(inst, inst+insn_t.size)]

def isInternalCode(ea):

    pf = idc.GetFlags(ea)
    return idc.isCode(pf) and not idc.isData(pf)

def isExternalReference(ea):
    # see if this is in an internal or external code ref
    DEBUG("Testing {0:x} for externality\n".format(ea))
    ext_types = [idc.SEG_XTRN]
    seg = idc.SegStart(ea)
    if seg == idc.BADADDR:
        raise Exception("Could not get segment addr for: {0:x}\n".format(ea))

    segtype = idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE)
    if segtype in ext_types:
        return True

    return False

def getFunctionName(ea):
    return idc.GetTrueNameEx(ea,ea)

def addInst(block, addr, inst_bytes, true_target=None, false_target=None):
    # check if there is a lock prefix:
    insn_t = idautils.DecodeInstruction(addr)
    if insn_t is not None and (insn_t.auxpref & 0x1) == 0x1:
        # has LOCK
        i_lock = block.insts.add()
        i_lock.inst_addr = addr
        i_lock.inst_bytes = chr(inst_bytes[0])
        i_lock.inst_len = 1

        addr += 1
        inst_bytes = inst_bytes[1:]

    inst = block.insts.add()
    inst.inst_addr = addr
    str_val = "".join([chr(b) for b in inst_bytes])
    inst.inst_bytes = str_val
    inst.inst_len = len(inst_bytes)
    if true_target != None: inst.true_target = true_target
    if false_target != None: inst.false_target = false_target

    return inst

def isConditionalJump(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in COND_BRANCHES

def isUnconditionalJump(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in UCOND_BRANCHES

def isCall(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in CALLS

def isInt(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in INTS

def isRet(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in RETS

def isTrap(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in TRAPS

def findRelocOffset(ea, size):
    for i in xrange(ea,ea+size):
        if idc.GetFixupTgtOff(i) != -1:
            return i-ea

    return -1

def handleExternalRef(fn):
    # Don't mangle symbols for fully linked ELFs... yet
    if not isLinkedElf():
        if fn.startswith("__imp_"):
            fn = fn[6:]

        if fn.endswith("_0"):
            fn = fn[:-2]

        if fn.startswith("_") and fn not in EMAP:
            fn = fn[1:]

        if fn.startswith("@") and fn not in EMAP:
            fn = fn[1:]

        if '@' in fn:
            fn = fn[:fn.find('@')]

    EXTERNALS.add(fn)
    return fn

def isInData(start_ea, end_ea):
    for (start,end) in DATA_SEGMENTS:
        if start_ea >= start and start_ea < end:
            DEBUG("{0:x} > {1:x}\n".format(start_ea, start))
            if end_ea <= end:
                return True
            else:
                DEBUG("{0:x} NOT <= {1:x}\n".format(end_ea, end))
                DEBUG("{0:x}-{1:x} overlaps with: {2:x}-{3:x}\n".format(start_ea, end_ea, start, end))
                raise Exception("Overlapping data segments!")
        else:
            if end_ea > start and end_ea <= end:
                DEBUG("Overlaps with: {0:x}-{1:x}\n".format(start, end))
                raise Exception("Overlapping data segments!")

    return False

def isExternalData(fn):
    indata = fn in EMAP_DATA
    incode = fn in EMAP

    if indata and not incode:
        return True
    elif indata and incode:
        raise Exception("Symbol "+fn+" defined as both code and data!")
    else:
        return False

# we look for an array of code pointer
# *) when we try to determine the size of the new jmp table, don't overlap with the successive one
def handleLikeLoadJmpTable(ins, F):
    insn_t = DecodeInstruction(ins)
    base, index, scale, displ = getAddressParts(insn_t, 1)

    ncases = 0
    bs = idaapi.get_many_bytes(displ, 4)
    if bs == None or len(bs) != 4:
            return None

    jmpt = JmpTable(addr=displ, function=F)
    succ = JMPTABLES.succ(jmpt)

    jmpaddress = struct.unpack('<I', bs)[0]
    while idc.isCode(idc.GetFlags(jmpaddress)) and (succ is None or displ+ncases*4 < succ.get_start()):
        DEBUG("jmpaddress = {0:x}\n".format(jmpaddress))
        jmpt.add_entry(jmpaddress)
        ncases += 1

        bs = idaapi.get_many_bytes(displ+ncases*4, 4)
        if bs == None or len(bs) != 4:
            break
        jmpaddress = struct.unpack('<I', bs)[0]

    DEBUG("handleLikeLoadJmp @ {0:x} #{1}".format(jmpt.get_start(), len(jmpt.entries())))
    return jmpt

def handleJmpTable(I, F, inst, new_eas):
    si = idaapi.get_switch_info_ex(inst)
    jsize = si.get_jtable_element_size()
    jstart = si.jumps

    # try to fix a problem with IDA, which
    # doesn't recognise completely switch
    if jstart == 0xffffffff:
        jstart = list(DataRefsFrom(inst))[0]

    # only handle size 4 cases
    if jsize != 4:
        raise Exception("Jump table size not 4!")
        return

    DEBUG("\tJMPTable Start: {0:x}\n".format(jstart))
    if I is not None:
        I.jump_table.zero_offset = 0

    jmpt = JmpTable(addr=jstart, function=F)

    # Return empty object - jump tables disabled
    return jmpt

    i = 0
    data = idaapi.get_many_bytes(jstart+i*jsize, 4)
    #TODO: fix this
    if data is None:
        return jmpt

    je = struct.unpack('<I', data)[0]
    while i < si.ncases:
        if I is not None:
            I.jump_table.table_entries.append(je)
            if je not in RECOVERED_EAS:
                new_eas.add(je)

            DEBUG("\t\tAdding JMPTable {0}: {1:x}\n".format( i, je))
        else:
            new_eas.add(je)

        jmpt.add_entry(je)

        i += 1
        je = struct.unpack('<I', idaapi.get_many_bytes(jstart+i*jsize, 4))[0]

    return jmpt

def isElfThunk(ea):
    if not isLinkedElf():
        return False, None


    if isUnconditionalJump(ea):
        have_ext_ref = False
        for cref in idautils.CodeRefsFrom(ea, 0):
            if isExternalReference(cref):
                have_ext_ref = True
                break

        if have_ext_ref:
            fn = getFunctionName(cref)
            return True, fn

    return False, None

def instructionHandler(M, F, B, inst, new_eas):
    insn_t = idautils.DecodeInstruction(inst)
    if not insn_t:
        # handle jumps after noreturn functions
        if idc.Byte(inst) == 0xCC:
            I = addInst(B, inst, [0xCC])
            return I, True
        else:
            raise Exception("Cannot read instruction at: {0:x}".format(inst))

    # check for align instruction
    pf = idc.GetFlags(inst)
    if idaapi.isAlign(pf):
        return None, True

    # skip HLTs -- they are privileged, and are used in ELFs after a noreturn call
    if isHlt(inst):
        return None, False

    DEBUG("\t\tinst: {0}\n".format(idc.GetDisasm(inst)))
    inst_bytes = readInstructionBytes(inst)
    DEBUG("\t\tBytes: {0}\n".format(inst_bytes))

    I = addInst(B, inst, inst_bytes)

    if isJmpTable(inst):
        handleJmpTable(I, F, inst, new_eas)
        return I, False

    if isIndirectCall(inst):
        global FUNCTIONS_NEED_TRAMPOLINE
        FUNCTIONS_NEED_TRAMPOLINE = True

    #check for code refs from here
    crefs = []
    for cref in idautils.CodeRefsFrom(inst, 0):
        crefs.append(cref)
        fn = getFunctionName(cref)
        if isCall(inst):

            elfy, fn_replace = isElfThunk(cref)
            if elfy:
                fn = fn_replace

            if isExternalReference(cref) or elfy:
                fn = handleExternalRef(fn)
                I.ext_call_name = fn
                DEBUG("EXTERNAL CALL: {0}\n".format(fn))

                if doesNotReturn(fn):
                    return I, True
            else:
                I.call_target = cref

                if cref not in RECOVERED_EAS:
                    new_eas.add(cref)

                DEBUG("INTERNAL CALL: {0}\n".format(fn))
        elif isUnconditionalJump(inst):
            if isExternalReference(cref):
                fn = handleExternalRef(fn)
                I.ext_call_name = fn
                DEBUG("EXTERNAL JMP: {0}\n".format(fn))

                if doesNotReturn(fn):
                    DEBUG("Nonreturn JMP\n")
                    return I, True
            else:
                DEBUG("INTERNAL JMP: {0:x}\n".format(cref))
                I.true_target = cref

    #true: jump to where we have a code-ref
    #false: continue as we were
    print hex(inst), crefs
    if isConditionalJump(inst):
        I.true_target = crefs[0]
        I.false_target = inst+len(inst_bytes)
        return I, False

    relo_off = findRelocOffset(inst, len(inst_bytes))
    if relo_off != -1:
        I.reloc_offset = relo_off

    for dref in idautils.DataRefsFrom(inst):
        if dref in crefs:
            continue

        if inValidSegment(dref):
            if isExternalReference(dref):
                fn = getFunctionName(dref)

                fn = handleExternalRef(fn)
                if isExternalData(fn):
                    I.ext_data_name = fn
                    sys.stdout.write("EXTERNAL DATA REF FROM {0:x} to {1}\n".format(inst, fn))
                else:
                    I.ext_call_name = fn
                    sys.stdout.write("EXTERNAL CODE REF FROM {0:x} to {1}\n".format(inst, fn))

            elif isInternalCode(dref):
                DEBUG("\t\tCode Ref from {0:x} to {1:x}\n".format(inst, dref))
                I.call_target = dref
                if dref not in RECOVERED_EAS:
                    new_eas.add(dref)
            else:
                dref_size = idc.ItemSize(dref)
                I.data_offset = handleDataRelocation(M, dref, new_eas)
                DEBUG("\t\tData Ref: {0:x}, size: {1}, offset : {2:x}\n".format(
                    dref, dref_size, I.data_offset))
        else:
            DEBUG("Data not in valid segment {0:x}\n".format(dref))

    # if we have a mov sth, imm with imm that it's likely a fn pointer,
    # we add that pointer to the list of ones to disassemble
    # TODO: use also some other info to assume this
    if insn_t[1].type == idaapi.o_imm and insn_t.itype == idaapi.NN_mov and inValidSegment(insn_t[1].value):
        ref = insn_t[1].value
        if isInternalCode(ref) and ref not in RECOVERED_EAS:
            new_eas.add(ref)

    if isCall(inst):
            coderefs = [i for i in idautils.CodeRefsFrom(inst, 0)]
            coderefs_normal = [i for i in idautils.CodeRefsFrom(inst, 1)]
            if len(coderefs) == 0 and len(coderefs_normal) == 1 and insn_t[0].type == idaapi.o_near:
                    for cref in coderefs_normal:
                            I.call_target = cref
                            if cref not in RECOVERED_EAS:
                                    new_eas.add(cref)

    return I, False

def parseDefsFile(df):
    emap = {}
    emap_data = {}
    for l in df.readlines():
        #skip comments
        if l[0] == "#":
            continue

        l = l.strip()

        if l.startswith('DATA:') :
            # process as data
            (marker, symname, dsize) = l.split()
            emap_data[symname] = int(dsize)
        else:

            (fname, args, conv, ret) = l.split()

            if conv == "C":
                realconv = cfg_pb2.ExternalFunction.CallerCleanup
            elif conv == "E":
                realconv = cfg_pb2.ExternalFunction.CalleeCleanup
            elif conv == "F":
                realconv = cfg_pb2.ExternalFunction.FastCall
            else:
                raise Exception("Unknown calling convention:"+conv)

            if ret not in ['Y', 'N']:
                raise Exception("Unknown return type:"+ret)

            emap[fname] = (int(args), realconv, ret)


    df.close()

    return emap, emap_data

def processExternalFunction(M, fn):

    args, conv, ret = getFromEMAP(fn)

    extfn = M.external_funcs.add()
    extfn.symbol_name = fn
    extfn.calling_convention = conv
    extfn.argument_count = args
    if ret == 'N':
        extfn.has_return = True
        extfn.no_return = False
    else:
        extfn.has_return = False
        extfn.no_return = True

def processExternalData(M, dt):

    data_size = EMAP_DATA[dt]

    extdt = M.external_data.add()
    extdt.symbol_name = dt
    extdt.data_size = data_size

def processExternals(M):

    for fn in EXTERNALS:

        fn = fixExternalName(fn)

        if nameInMap(EMAP, fn):
            processExternalFunction(M, fn)
        elif nameInMap(EMAP_DATA, fn):
            processExternalData(M, fn)
        else:
            sys.stderr.write("UNKNOWN API: {0}\n".format(fn))

def readBytesSlowly(start, end):
    bytestr = ""
    for i in xrange(start, end):
        if idc.hasValue(idc.GetFlags(i)):
            bt = idc.Byte(i)
            bytestr += chr(bt)
        else:
            #virtual size may be bigger than size on disk
            #pad with nulls
            #DEBUG("Failed on {0:x}\n".format(i))
            bytestr += "\x00"
    return bytestr

def handleDataRelocation(M, dref, new_eas):
    dref_size = idc.ItemSize(dref)
    if not isInData(dref, dref+dref_size):
        return dref + addDataSegment(M, dref, dref+dref_size, new_eas)
    else:
        return dref

def scanDataForCodePointers(start, end, fn_pointers):
    while start + 4 < end:
        bs = idaapi.get_many_bytes(start, 4)
        if bs is None or len(bs) != 4:
            break

        data = struct.unpack('<I', bs)[0]
        if inValidSegment(data) and idc.isCode(idc.GetFlags(data)):
            DEBUG("{0:x} Found code pointer to: {1:x}\n".format(start, data))
            if data not in RECOVERED_EAS:
                fn_pointers.add(data)

        start += 1

def resolveRelocation(ea):
    rtype = idc.GetFixupTgtType(ea)
    if rtype == idc.FIXUP_OFF32:
        bytestr = readBytesSlowly(ea, ea+4);
        relocVal = struct.unpack("<L", bytestr)[0]
        return relocVal
    elif rtype == -1:
        raise Exception("No relocation type at ea: {:x}".format(ea))
    else:
        return idc.GetFixupTgtOff(ea)

def processRelocationsInData(M, D, start, end, new_eas, seg_offset):

    if start == 0:
        start = 1

    i = idc.GetNextFixupEA(start-1)

    while i < end and i != idc.BADADDR:

        pointsto = resolveRelocation(i)
        fn = getFunctionName(i)
        DEBUG("{0:x} Found reloc to: {1:x}\n".format(i, pointsto))

        if not isExternalReference(pointsto):
            pf = idc.GetFlags(pointsto)

            DS = D.symbols.add()
            DS.base_address = i+seg_offset

            if idc.isCode(pf):
                DS.symbol_name = "sub_"+hex(pointsto)
                DEBUG("Code Ref: {0:x}!\n".format(pointsto))

                if pointsto not in RECOVERED_EAS:
                    new_eas.add(pointsto)

            elif idc.isData(pf):
                pointsto = handleDataRelocation(M, pointsto, new_eas)
                DS.symbol_name = "dta_"+hex(pointsto)
                DEBUG("Data Ref!\n")
            else:
                pointsto = handleDataRelocation(M, pointsto, new_eas)
                DS.symbol_name = "dta_"+hex(pointsto)
                DEBUG("UNKNOWN Ref, assuming data\n")


        i = idc.GetNextFixupEA(i)

def inValidSegment(ea):
    if idc.SegStart(ea) == idc.BADADDR:
        return False

    return True

def findFreeData():

    max_end = 0
    for (start, end) in DATA_SEGMENTS:
        if end > max_end:
            max_end = end

    return max_end+4

def isHeader(bs, start, end):
    DEBUG(bs + "\n")
    CGC_IDENT = "\x7fCGC\x01\x01\x01\x43\x01"
    return bs[0:len(CGC_IDENT)] == CGC_IDENT and bs[16:24] == '\x02\x00\x03\x00\x01\x00\x00\x00' and start & 0xfff == 0


def addDataSegment(M, start, end, new_eas):
    if end < start:
        raise Exception("Start must be before end")

    seg = idaapi.getseg(start)

    if not seg:
        raise Exception("Data must be in a valid segment")

    # if this is in an executalbe region,
    # move it to a data section
    seg_offset = 0
    need_move = (seg.perm & idaapi.SEGPERM_EXEC) != 0
    if need_move:
        free_data = findFreeData()
        seg_offset = free_data - start
        DEBUG("Data Segment {0:x} moved to: {1:x}\n".format(start, start+seg_offset))

    bs = readBytesSlowly(start, end)
    if isHeader(bs, start, end):
        DEBUG("{0:#x}-{1:#x} is header\n".format(start, end))
        return 0

    D = M.internal_data.add()
    D.base_address = start+seg_offset

    SEGPERM_WRITE = 2

    if (seg.perm & SEGPERM_WRITE) == 0:
        D.read_only = True
    else:
        D.read_only = False

    #D.data = idaapi.get_many_bytes(start, end-start)
    D.data = bs
    DATA_SEGMENTS.append( (start+seg_offset,end+seg_offset) )

    processRelocationsInData(M, D, start, end, new_eas, seg_offset)

    DEBUG("Adding data seg: {0}: {1}-{2}\n".format(
        idc.SegName(start),
        hex(start+seg_offset),
        hex(end+seg_offset)))

    return seg_offset

def processDataSegments(M, new_eas):
    for n in xrange(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(n)
        ea = seg.startEA
        segtype = idc.GetSegmentAttr(ea, idc.SEGATTR_TYPE)
        if segtype in [idc.SEG_DATA, idc.SEG_BSS]:
            start = idc.SegStart(ea)
            end = idc.SegEnd(ea)
            addDataSegment(M, start, end, new_eas)

def recoverFunctionFromSet(M, F, blockset, new_eas, need_trampolines):
    processed_blocks = set()

    while len(blockset) > 0:
        block = blockset.pop()

        if block.startEA == block.endEA:
            sys.stdout.write("Zero sized block: {0:x}\n".format(block.startEA))

        if block.startEA in processed_blocks:
            raise Exception("Attempting to add same block twice: {0:x}".format(block.startEA))

        processed_blocks.add(block.startEA)

        B = basicBlockHandler(F, block, blockset, processed_blocks, need_trampolines)
        for head in idautils.Heads(block.startEA, block.endEA):
            I, endBlock = instructionHandler(M, F, B, head, new_eas)
            # sometimes there is junk after a terminator due to off-by-ones in
            # IDAPython. Ignore them.
            if endBlock or isRet(head) or isUnconditionalJump(head) or isTrap(head):
                break

        if block.startEA not in RECOVERED_EAS:
            RECOVERED_EAS.add(block.startEA)
            DEBUG("RECOVERED_EAS.add({0:x})\n".format(block.startEA))

def recoverFunction(M, F, fnea, new_eas):
    need_trampolines = set()
    blockset = getFunctionBlocks(F, fnea, need_trampolines)
    recoverFunctionFromSet(M, F, blockset, new_eas, need_trampolines)

class Block:
    def __init__(self, startEA):
        self.startEA = startEA
        self.endEA = startEA
        self.succs = []

def recoverBlock(F, startEA, need_trampolines):
    b = Block(startEA)
    curEA = startEA

    # TODO: link some metadata to any block to keep track
    #       of this table, because the indirect jmp
    #       may be in a follower block and not directly in
    #       the block where the address is loaded
    likelyJmpTable = None

    while True:
        insn_t = idautils.DecodeInstruction(curEA)
        if insn_t is None:
            if idc.Byte(curEA) == 0xCC:
                b.endEA = curEA+1
                return b
            else:
                sys.stdout.write("WARNING: Couldn't decode insn at: {0:x}. Ending block.\n".format(curEA))
                b.endEA = curEA
                return b

        # check for xrefs
        j = 0
        for op in insn_t:
            # if it is a MEM operand
            if op.type == idaapi.o_mem and inValidSegment(op.addr):
                if isCall(curEA):
                    if isInternalCode(op.addr):
                            idaapi.add_cref(curEA, op.addr, idaapi.fl_CN)
                    else:
                            idaapi.add_dref(curEA, op.addr, idaapi.dr_R)
                elif isUnconditionalJump(curEA) or isConditionalJump(curEA):
                    if isInternalCode(op.addr):
                            idaapi.add_cref(curEA, op.addr, idaapi.fl_JN)
                    else:
                            idaapi.add_dref(curEA, op.addr, idaapi.dr_R)
                else:
                    if j == 0:
                        idaapi.add_dref(curEA, op.addr, idaapi.dr_W)
                    else:
                        idaapi.add_dref(curEA, op.addr, idaapi.dr_R)

            j += 1

        nextEA = curEA+insn_t.size

        crefs = idautils.CodeRefsFrom(curEA, 1)

        # get curEA follows
        follows = [cref for cref in crefs]
        if isJmpTable(curEA):
            # this is a jmptable (according to IDA)
            # XXX: we assume jmp tables found by IDA don't overlap
            #      with others
            jmpentries = set()
            jmpt = handleJmpTable(None, F, curEA, jmpentries)
            follows = list(jmpentries.union(set(follows)))

            JMPTABLES.add(jmpt)
        elif isIndirectJmp(curEA) and likelyJmpTable is not None:
            # this is an indirect jmp and in the same block there
            # was a mov to take the address of a "likely" jmptable
            for ref in likelyJmpTable.entries():
                need_trampolines.add(ref)
            follows = list(set(likelyJmpTable.entries() + follows))

            JMPTABLES.add(likelyJmpTable)
            likelyJmpTable = None
        elif isLikeLoadJmpTable(curEA):
            # this is an instruction which take the address of a
            # switch table (or something we *think* is a jmp table)
            likelyJmpTable = handleLikeLoadJmpTable(curEA, F)

        if isRepPrefix(curEA):
            sys.stdout.write("Found rep prefix at {0:#x}\n".format(curEA))
            b.succs.append(nextEA)
            b.succs.append(curEA)
            b.endEA = nextEA
            return b

        if isDataInst(curEA):
            sys.stdout.write("Found data in middle of code at {0:#x}\n".format(curEA))
            b.endEA = curEA
            return b

        if isCall(curEA):
            sys.stdout.write("Found call\n")
            fcrefs = idautils.CodeRefsFrom(curEA, 0)
            ffollows = [cref for cref in fcrefs]

            if len(ffollows) == 0 or idaapi.func_does_return(ffollows[0]):
                b.succs.append(nextEA)

            b.endEA = nextEA
            return b

        if isInt(curEA):
            sys.stdout.write("Found int\n")
            b.endEA = nextEA
            b.succs.append(nextEA)
            return b

        if (follows == [nextEA] and not isUnconditionalJump(curEA)) or isCall(curEA):
            # read next instruction
            curEA = nextEA
        # check if we need to make a new block
        elif len(follows) == 0:
            # this is a ret, no follows
            b.endEA = nextEA
            return b
        else:
            # this block has several follow blocks
            b.endEA = nextEA
            for f in follows:
                # do not decode external code refs
                if not isExternalReference(f):
                    b.succs.append(f)
            return b

def getFunctionBlocks(F, startea, need_trampolines):
    to_recover = [startea]

    blocks = {}

    while len(to_recover) > 0:
        # get new block start to recover
        bstart = to_recover.pop()
        # recover the block
        newb = recoverBlock(F, bstart, need_trampolines)
        DEBUG('Adding new block %x %x\n' % (newb.startEA, newb.endEA))
        # save to our recovered block list
        blocks[newb.startEA] = newb
        # add new workers
        for fba in newb.succs:
            if fba not in blocks:
                to_recover.append(fba)

    rv = []
    # easier to debug
    for k in sorted(blocks.keys()):
        rv.append(blocks[k])

    return rv

def add_result_from_IDA(new_eas):
    for i in Functions():
        new_eas.add(i)

def recoverCfg(to_recover, outf, exports_are_apis=False):
    M = cfg_pb2.Module()
    M.module_name = idc.GetInputFile()
    DEBUG("PROCESSING: {0}\n".format(M.module_name))

    our_entries = []
    entrypoints = idautils.Entries()
    exports = {}
    for index,ordinal,exp_ea, exp_name in entrypoints:
        exports[exp_name] = exp_ea

    new_eas = set()
    add_result_from_IDA(new_eas)
    processDataSegments(M, new_eas)

    for name in to_recover:

        if name in exports:
            ea = exports[name]
        else:
            ea = idc.LocByName(name)
            if ea == idc.BADADDR:
                raise Exception("Could not locate entry symbol: {0}".format(name))

        fwdname = isFwdExport(name, ea)

        if fwdname is not None:
            sys.stdout.write("Skipping fwd export {0} : {1}\n".format(name, fwdname))
            continue

        if not isInternalCode(ea):
            sys.stdout.write("Export {0} does not point to code; skipping\n".format(name))
            continue

        our_entries.append( (name, ea) )

    recovered_fns = 0

    # process main entry points
    for fname, fea in our_entries:

        sys.stdout.write("Recovering: {0}\n".format(fname))

        F = entryPointHandler(M, fea, fname, exports_are_apis)

        RECOVERED_EAS.add(fea)
        recoverFunction(M, F, fea, new_eas)

        recovered_fns += 1

    # process subfunctions
    new_eas.difference_update(RECOVERED_EAS)

    while len(new_eas) > 0:
        cur_ea = new_eas.pop()
        if cur_ea in RECOVERED_EAS:
            continue

        if not isInternalCode(cur_ea):
            raise Exception("Function EA not code: {0:x}".format(cur_ea))

        F = addFunction(M, cur_ea)
        sys.stdout.write("Recovering: {0}\n".format(hex(cur_ea)))
        RECOVERED_EAS.add(cur_ea)

        recoverFunction(M, F, cur_ea, new_eas)

        recovered_fns += 1

    if recovered_fns == 0:
        sys.stderr.write("COULD NOT RECOVER ANY FUNCTIONS\n")
        return

    probably_fn_pointers = set()
    map(lambda (s,e): scanDataForCodePointers(s,e,probably_fn_pointers), DATA_SEGMENTS);

    # add functions found by scanning data section
    while len(probably_fn_pointers) > 0:
        cur_ea = probably_fn_pointers.pop()
        if not isInternalCode(cur_ea):
            raise Exception("Function EA not code: {0:x}".format(cur_ea))

        F = addFunction(M, cur_ea)
        sys.stdout.write("Recovering: {0}\n".format(hex(cur_ea)))
        RECOVERED_EAS.add(cur_ea)

        recoverFunction(M, F, cur_ea, probably_fn_pointers)

        recovered_fns += 1

    # if FUNCTIONS_NEED_TRAMPOLINE is true it means
    # there is some indirect calls and we need to set
    # trampolines for those functions we think may be
    # targets
    # XXX: for the moment every function is a target
    if FUNCTIONS_NEED_TRAMPOLINE:
        for f in M.internal_funcs:
            f.need_trampoline = True

    mypath = path.dirname(__file__)
    processExternals(M)

    outf.write(M.SerializeToString())
    outf.close()

    sys.stdout.write("Recovered {0} functions.\n".format(recovered_fns))
    sys.stdout.write("Saving to: {0}\n".format(outf.name))

def isFwdExport(iname, ea):
    l = ea
    if l == idc.BADADDR:
        raise Exception("Cannot find addr for: " + iname)

    pf = idc.GetFlags(l)

    if not idc.isCode(pf) and idc.isData(pf):
        sz = idc.ItemSize(l)
        iname = idaapi.get_many_bytes(l, sz-1)
        return iname

    return None

def writeDriverLine(batfile, name, ea):

    args, conv, ret = getExportType(name, ea)

    retstr = "return"
    if ret == "Y": retstr = "noreturn"

    batfile.write(" -driver=driver_{0},{0},{1},{2}".format(name, args, retstr))

def generateBatFile(batname, eps):
    infile = idc.GetInputFile()
    batfile = open(batname, 'wb')
    batheader = """
    @echo off
    set /p LLVM_PATH= < LLVM_PATH
    set /p CFG_TO_BC_PATH= < CFG_TO_BC_PATH

    set CFG_TO_BC=%CFG_TO_BC_PATH%\cfg_to_bc.exe
    set OPT=%LLVM_PATH%\opt.exe
    set LLC=%LLVM_PATH%\llc.exe
    REM
    REM
    echo Making API Import libs...
    cmd /c makelibs.bat > NUL
    echo Converting CFG to Bitcode
    del {}.bc 2>NUL
    """.format(infile)

    batfile.write(batheader)
    batfile.write("%CFG_TO_BC% ")
    batfile.write("-ignore-unsupported=true -i={0}_ida.cfg -o={0}.bc\n".format(infile))
    batfile.write("\n")
    batfile.write(" echo Optimizing Bitcode\n")
    batfile.write("%OPT% ")
    batfile.write("-O3 -o {0}_opt.bc {0}.bc\n".format(infile))
    batfile.write("echo Creating .obj\n")
    batfile.write("del kernel32.dll.obj 2>NUL\n")
    batfile.write("%LLC% ")
    batfile.write("-O3 -filetype=obj -o {0}.obj {0}_opt.bc\n".format(infile))
    batfile.write("echo Building export stub\n")
    batfile.write("cl /c {0}_exportstub.c \n".format(infile))
    batfile.write("REM Below is a compilation template. You need to uncomment it to build.\n")
    batfile.write("REM and add some .lib files to the line as well.\n")
    batfile.write("REM \n")
    batfile.write("REM link /NODEFAULTLIB /ENTRY:export_DllEntryPoint /DLL /DEF:{0}.def /OUT:{0} {0}.obj {0}_exportstub.obj msvcrt.lib *.lib \n".format(infile))
    batfile.write("echo Uncomment lines to attempt linking to a DLL\n")
    batfile.close()

def parseTypeString(typestr, ea):

    if "__stdcall" in typestr:
        conv = cfg_pb2.ExternalFunction.CalleeCleanup
    elif "__cdecl" in typestr:
        conv = cfg_pb2.ExternalFunction.CallerCleanup
    elif "__fastcall" in typestr:
        conv = cfg_pb2.ExternalFunction.FastCall
    elif "__usercall" in typestr:
        # do not handle this for now
        return (0, cfg_pb2.ExternalFunction.CalleeCleanup, "N")
    else:
        raise Exception("Could not parse function type:"+typestr)

    fn = idaapi.get_func(ea)
    if fn is None:
        raise Exception("Could not get function args for: {0:x}".format(ea))
    args = fn.argsize / 4

    ret = 'N'

    return args, conv, ret

def getExportType(name, ep):
    try:
        DEBUG("Processing export name: {} at: {:x}\n".format(name, ep))
        args, conv, ret = getFromEMAP(name)
    except KeyError as ke:
        tp = idc.GetType(ep);
        if tp is None or "__" not in tp:
            #raise Exception("Cannot determine type of function: {0} at: {1:x}".format(name, ep))
            sys.stdout.write("WARNING: Cannot determine type of function: {0} at: {1:x}".format(name, ep))
            return (0, cfg_pb2.ExternalFunction.CalleeCleanup, "N")

        return parseTypeString(tp, ep)

    return args, conv, ret

def generateDefFile(defname, eps):
    deffile = open(defname, 'wb')
    deffile.write("EXPORTS\n")
    entrypoints = idautils.Entries()

    for ep_tuple in entrypoints:
        (index, ordinal, ea, name) = ep_tuple

        if name not in eps:
            continue

        fwdname = isFwdExport(name, ea)
        if fwdname is not None:
            deffile.write("{0}={1}\n".format(name, fwdname))
        else:
            args, conv, ret = getExportType(name, ea)

            if conv == cfg_pb2.ExternalFunction.CallerCleanup:
                decor_name = "_export_{0}".format(name)
            elif conv == cfg_pb2.ExternalFunction.CalleeCleanup:
                decor_name = "_export_{0}@{1}".format(name, args*4)
            elif conv == cfg_pb2.ExternalFunction.FastCall:
                decor_name = "@export_{0}@{1}".format(name, args*4)
            else:
                raise Exception("Unknown calling convention: " + str(conv))

            deffile.write("{0}={1}\n".format(name, decor_name))

    deffile.close()

def makeArgStr(name, declaration):

    argstr = "void"
    args, conv, ret = getFromEMAP(name)

    # return blank string for void calls
    if not declaration and args == 0:
        return ""

    if declaration:
        joinstr = "int a"
    else:
        joinstr = "a"

    argl = [joinstr+str(a) for a in xrange(args)]

    if args > 0:
        argstr = ", ".join(argl)

    return argstr

def generateExportStub(cname, eps):
    cfile = open(cname, 'wb')
    entrypoints = idautils.Entries()

    for ep_tuple in entrypoints:
        (index, ordinal, ea, name) = ep_tuple

        if name not in eps:
            continue

        fwdname = isFwdExport(name, ea)
        if fwdname is not None:
            continue
        else:
            args, conv, ret =  getExportType(name, ea)

            if conv == cfg_pb2.ExternalFunction.CallerCleanup:
                convstr = "__cdecl"
            elif conv == cfg_pb2.ExternalFunction.CalleeCleanup:
                convstr = "__stdcall"
            elif conv == cfg_pb2.ExternalFunction.FastCall:
                convstr = "__fastcall"
            else:
                raise Exception("Unknown calling convention")

            declargs = makeArgStr(name, declaration=True)
            callargs = makeArgStr(name, declaration=False)

            cfile.write("extern int {2} driver_{0}({1});\n".format(name, declargs, convstr))
            cfile.write("int {3} export_{0}({1}) {{ return driver_{0}({2}); }} \n".format(
                name, declargs, callargs, convstr))
            cfile.write("\n")

    cfile.close()

def getAllExports() :
    entrypoints = idautils.Entries()
    to_recover = set()
    # recover every entry point
    for ep_tuple in entrypoints:
        (index, ordinal, ea, name) = ep_tuple
        to_recover.add(name)

    return to_recover


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--batch",
        help="Indicate the script is running in batch mode",
        action="store_true",
        default=False)

    parser.add_argument("--entry-symbol", nargs='*', help="Symbol(s) to start disassembling from")

    parser.add_argument("-o", "--output", type=argparse.FileType('wb'),
        default=None,
        help="The output control flow graph recovered from this file")

    parser.add_argument("-s", "--std-defs", nargs='*', type=argparse.FileType('r'),
        default=None,
        help="std_defs file: definitions and calling conventions of imported functions and data"
        )

    parser.add_argument('-f', '--flirt-sig', metavar='sig', type=str,
                    default=None,
                    help='FLIRT signature')

    parser.add_argument("-e", "--exports-to-lift", type=argparse.FileType('r'),
        default=None,
        help="A file containing a exported functions to lift, one per line. If not specified, all exports will be lifted."
        )
    parser.add_argument("--make-export-stubs", action="store_true",
        default=False,
        help="Generate a .bat/.c/.def combination to provide export symbols. Use this if you're lifting a DLL and want to re-export the same symbols"
        )
    parser.add_argument("--exports-are-apis", action="store_true",
        default=False,
        help="Exported functions are defined in std_defs. Useful when lifting DLLs"
        )
    parser.add_argument("-d", "--debug", action="store_true",
        default=False,
        help="Enable verbose debugging mode"
        )

    parser.add_argument("-l", "--generate-lst", action="store_true",
        default=False,
        help="Generate disassembly listing file"
        )

    args = parser.parse_args(args=idc.ARGV[1:])

    if args.debug:
        _DEBUG = True

    # for batch mode: ensure IDA is done processing
    if args.batch:
        analysis_flags = idc.GetShortPrm(idc.INF_START_AF)
        analysis_flags &= ~idc.AF_IMMOFF
        # turn off "automatically make offset" heuristic
        idc.SetShortPrm(idc.INF_START_AF, analysis_flags)
        idaapi.autoWait()

    myname = idc.GetInputFile()
    mypath = path.dirname(__file__)

    EMAP = {}
    EMAP_DATA = {}

    if args.std_defs:
        for defsfile in args.std_defs:
            sys.stdout.write("Loading Standard Definitions file: {0}\n".format(defsfile.name))
            em_update, emd_update = parseDefsFile(defsfile)
            EMAP.update(em_update)
            EMAP_DATA.update(emd_update)

    if args.output:
        outpath = os.path.dirname(args.output.name)
    else:
        outpath =  os.path.join(mypath, myname)
        try:
            os.mkdir(outpath)
        except:
            pass


    if args.flirt_sig is not None:
        idc.ApplySig(args.flirt_sig)
        idc.Wait()

    stdout_file = os.path.join(outpath, os.path.basename(myname)) + '.stdout.txt'
    sys.stdout = sys.stderr = ToFileStdOut(stdout_file)

    eps = []
    try:
        if args.exports_to_lift:
            eps = args.exports_to_lift.readlines()
        elif args.entry_symbol is None:
            eps = getAllExports()

        eps = [ep.strip() for ep in eps]

    except IOError as e:
        sys.stdout.write("Could not open file of exports to lift. See source for details\n")
        sys.exit(-1)

    if args.entry_symbol:
        eps.extend(args.entry_symbol)

    assert len(eps) > 0, "Need to have at least one entry point to lift"

    sys.stdout.write("Will lift {0} exports\n".format(len(eps)))
    if args.make_export_stubs:
        sys.stdout.write("Generating export stubs...\n");

        outdef = path.join(outpath, "{0}.def".format(myname))
        sys.stdout.write("Output .DEF file: {0}\n".format(outdef))
        generateDefFile(outdef, eps)

        outstub = path.join(outpath, "{0}_exportstub.c".format(myname))
        sys.stdout.write("Output export stub file: {0}\n".format(outstub))
        generateExportStub(outstub, eps)

        outbat = path.join(outpath, "{0}.bat".format(myname))
        sys.stdout.write("Output build .BAT: {0}\n".format(outbat))
        generateBatFile(outbat, eps)


    if args.output:
        outf = args.output
    else:
        cfgname = path.join(outpath, myname + "_ida.cfg")
        cfgpath = path.join(outpath, cfgname)
        outf = open(cfgpath, 'wb')

    sys.stdout.write("CFG Output File file: {0}\n".format(outf.name))
    recoverCfg(eps, outf, args.exports_are_apis)

    lstfile = os.path.join(outpath, os.path.basename(myname)) + '.lst'

    if args.generate_lst:
        idc.GenerateFile(idc.OFILE_LST, lstfile, 0, idc.BADADDR, 0)

    #for batch mode: exit IDA when done
    if args.batch:
        idc.Exit(0)

