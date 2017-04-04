///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <sstream>
#include <stdio.h>
#include <vmi/ElfDwarf.h>
#include <vmi/ExecutableFile.h>
#include <vmi/Vmi.h>

using namespace vmi;

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s elf_binary struc path\n", argv[0]);
        fprintf(stderr, "Example: %s vmlinux task_struct se.on_rq\n", argv[0]);
        return -1;
    }

    ElfDwarf *d = ElfDwarf::get(llvm::errs(), argv[1]);
    if (!d) {
        return -1;
    }

    Vmi *vmi = new Vmi(d);

    uintptr_t offset;
    if (vmi->getOffset(argv[2], argv[3], offset)) {
        fprintf(stdout, "Offset=%d\n", (int) offset);
    } else {
        fprintf(stderr, "Could not deterine offset of %s in %s\n", argv[3], argv[2]);
    }

    std::string path(argv[1]);
    FileSystemFileProvider *fp = FileSystemFileProvider::get(path, false);
    if (!fp) {
        llvm::errs() << "Could not open " << path << "\n";
        return -1;
    }

    ExecutableFile *exec = ExecutableFile::get(fp, false, 0);
    if (exec) {
        std::stringstream ss;
        ss << "ModuleName: " << exec->getModuleName() << '\n';
        ss << "ImageSize:  0x" << std::hex << exec->getImageSize() << '\n';
        ss << "ImageBase:  0x" << std::hex << exec->getImageBase() << '\n';
        ss << "EntryPoint: 0x" << std::hex << exec->getEntryPoint() << '\n';

        llvm::errs() << ss.str();
    }

    delete vmi;
    delete d;
    return 0;
}
