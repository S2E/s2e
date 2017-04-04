import idaapi
import idautils
import idc


def extract_functions():
	filename = idc.AskFile(1, "*.*", "Save list of functions")
        exit = False
        if not filename:
            basename = idc.GetInputFile()
            filename = basename + ".fcn"
            idc.GenerateFile(idc.OFILE_ASM, basename + ".asm", 0, idc.BADADDR, 0)
            idc.GenerateFile(idc.OFILE_LST, basename + ".lst", 0, idc.BADADDR, 0)
            exit = True
	fp = open(filename,'w')
	funcs = idautils.Functions()
	for f in funcs:
		print >>fp, "%#010x %s" % (f, GetFunctionName(f))
        if exit:
            idc.Exit(0)
			
q = None
f = None
idc.Wait()
extract_functions()

