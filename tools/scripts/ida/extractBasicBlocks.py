import idaapi
import idautils
import idc

#Flowchart does not consider function calls as basic block boundaries.
#This function takes a range of addresses and splits additional basic blocks.
def cls_split_block(fp, startEA, endEA):
	curName = GetFunctionName(startEA);
	dem = idc.Demangle(curName, idc.GetLongPrm(INF_SHORT_DN));
	if dem != None:
		curName = dem;
	
	first=startEA
	h = idautils.Heads(startEA, endEA)
	for i in h:
		mnem = idc.GetMnem(i)
		if mnem == "call" and i != endEA:
			print >>fp, "%#010x %#010x %s" % (first, idc.NextHead(i, endEA+1)-1, curName)
			first=idc.NextHead(i, endEA+1)
	

	if first < endEA:
		print >>fp, "%#010x %#010x %s" % (first, endEA-1, curName)		
			
# -----------------------------------------------------------------------
# Using the class
def cls_main(fp, func, p=True):
    global f
    f = idaapi.FlowChart(idaapi.get_func(func))
    for block in f:
		cls_split_block(fp, block.startEA, block.endEA)
		#if p: print >>fp, "%#10x %#10x" % (block.startEA, block.endEA)
        #for succ_block in block.succs():
        #    if p: print "  %x - %x [%d]:" % (succ_block.startEA, succ_block.endEA, succ_block.id)
        #for pred_block in block.preds():
        #    if p: print "  %x - %x [%d]:" % (pred_block.startEA, pred_block.endEA, pred_block.id)

def extract_bbs():
	filename = idc.AskFile(1, "*.*", "Save list of basic blocks")
        exit = False
        if not filename:
            basename = idc.GetInputFile()
            filename = basename + ".bblist"
            idc.GenerateFile(idc.OFILE_ASM, basename + ".asm", 0, idc.BADADDR, 0)
            idc.GenerateFile(idc.OFILE_LST, basename + ".lst", 0, idc.BADADDR, 0)
            exit = True
	fp = open(filename,'w')
	funcs = idautils.Functions()
	for f in funcs:
		cls_main(fp, f)
        if exit:
            idc.Exit(0)
			
q = None
f = None
idc.Wait()
extract_bbs()

