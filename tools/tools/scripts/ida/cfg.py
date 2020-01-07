#Usage:
#/opt/ida-6.6/idaq64 -B "-S$S2E_SRC/tools/tools/scripts/ida/cfg.py --output-dir=/output/path --flirt-sig=flirt_sig_name" /path/to/binary
#
#Produces binary.bbinfo, binary.cfg, and binary.lst files


import sys
import idautils
import idaapi
import idc
import argparse

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



class BBScanner(object):
    def __init__(self):
        self._callbacks = []

    def add_callback(self, cb):
        self._callbacks += [cb]

    def _invoke_cbs(self, start, end, size, call_target, successors):
        for cb in self._callbacks:
            cb.process_bb(start, end, size, call_target, successors)

    def _invoke_cbs_fcn(self, start):
        name = idc.GetFunctionName(start)
        for cb in self._callbacks:
            cb.process_function(start, name)

    def _get_call_target(self, instruction):
        for xref in idautils.XrefsFrom(instruction, 0):
            if xref.type == 17: #Code_Near_Call
                callsite_function_name = idc.GetFunctionName(xref.to)
                #XXX: sometimes IDA can't identify the function (e.g., athwx.sys)
                if callsite_function_name is not None and len(callsite_function_name) > 0:
                    return xref.to
        return 0

    def _scan_block(self, block):
        current_bb_start = block.startEA
        instructions = idautils.Heads(block.startEA, block.endEA)
        last_instruction = None
        last_instruction_size = None

        for i in instructions:
            last_instruction = i
            last_instruction_size = idc.ItemSize(i)
            mnem = idc.GetMnem(i)
            is_call = mnem == "call"
            is_int = mnem == "int"

            if (is_call or is_int) and i != block.endEA:
                next_instruction = i + last_instruction_size
                bb_size = next_instruction - current_bb_start
                ct = None
                if is_call:
                    ct = self._get_call_target(i)
                self._invoke_cbs(current_bb_start, i, bb_size, ct, [next_instruction])

                #Start a new translation block
                current_bb_start = idc.NextHead(i, block.endEA + 1)

        if current_bb_start == idc.BADADDR:
            current_inst = last_instruction + last_instruction_size
            self._invoke_cbs(current_inst, idc.BADADDR, 0, None, [])
            #The call instruction probably doesn't return.
            return

        if current_bb_start < block.endEA:
            bb_size = block.endEA - current_bb_start
            ct = None
            if mnem == "call":
                ct = self._get_call_target(last_instruction)

            succs = []
            for succ_block in block.succs():
                succs.append(succ_block.startEA)

            self._invoke_cbs(current_bb_start, last_instruction, bb_size, self._get_call_target(i), succs)

    def scan(self):
        for fcn in idautils.Functions():
            self._invoke_cbs_fcn(fcn)
            f = idaapi.FlowChart(idaapi.get_func(fcn))
            for block in f:
                self._scan_block(block)


class BasicBlockPrinter():
    def __init__(self):
        self._to_disassemble = []

    def process_bb(self, start, end, size, call_target, successors):
        print "BB ", hex(start), hex(end), size, successors

        if size == 0:
            global to_disassemble
            self._to_disassemble += [start]
            return

        h = idautils.Heads(start, end+1)
        for i in h:
            print hex(i), GetDisasm(i)
        print ""

    def process_function(self, start, name):
        print "Function", name
        pass

#Outputs a list of basic blocks in text form.
#Each line has the following format:
#start_pc end_pc bb_size [c|n] call_target
#c: bb ends with a call
#n: normal bb
#call_target: can be 0 if N/A or indirect call
class BasicBlockExtractor():
    def __init__(self, filename):
        self.fp = open(filename, "w")

    def process_bb(self, start, end, size, call_target, successors):
        if size > 0:
            print >>self.fp, hex(start), hex(end), hex(size), \
                'n 0x0' if call_target is None else " ".join(('c', hex(call_target)))

    def process_function(self, start, name):
        pass

class CFGExtractor():
    def __init__(self, filename):
        self.fp = open(filename, "w")
        pass

    def process_bb(self, start, end, size, call_target, successors):
        if size == 0:
            return

        print >>self.fp, hex(start), ' '.join(hex(s) for s in successors)

    def process_function(self, start, name):
        print >>self.fp, "#function", hex(start), name

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output-dir', metavar='output_dir', type=str,
                        default='.',
                        help='Output directory')

    parser.add_argument('-s', '--flirt-sig', metavar='sig', type=str,
                        default=None,
                        help='FLIRT signature')

    parser.add_argument("-d", "--json", action="store_true",
                        default=False,
                        help="Enable json output")

    parser.add_argument("-l", "--generate-lst", action="store_true",
                        default=False,
                        help="Generate disassembly listing file")

    args = parser.parse_args(args=idc.ARGV[1:])



    outputDir = args.output_dir
    if not os.path.isdir(outputDir):
        print outputDir, "is not a directory"
        idc.Exit(0)

    sys.stdout = sys.stderr = ToFileStdOut(os.path.join(outputDir, "stdout.txt"))
    print "Starting analysis..."

    output_json = args.json

    if args.flirt_sig is not None:
        idc.ApplySig(args.flirt_sig)

    idc.Wait()

    basename = os.path.join(outputDir, idc.GetInputFile())

    bb_printer = BasicBlockPrinter()
    bb_extractor = BasicBlockExtractor(basename + ".bbinfo")
    cfg_extractor = CFGExtractor(basename + ".cfg")

    scanner = BBScanner()
    scanner.add_callback(bb_printer)
    scanner.add_callback(bb_extractor)
    scanner.add_callback(cfg_extractor)
    scanner.scan()


    #Generate the final assembly after more advanced decoding
    #and analysis is done
    if args.generate_lst:
        idc.GenerateFile(idc.OFILE_LST, basename + ".lst", 0, idc.BADADDR, 0)

    idc.Exit(0)
