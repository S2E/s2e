///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
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

    auto d = ElfDwarf::get(llvm::errs(), argv[1]);
    if (!d) {
        return -1;
    }

    auto vmi = Vmi::get(d);

    uintptr_t offset;
    if (vmi->getOffset(argv[2], argv[3], offset)) {
        fprintf(stdout, "Offset=%d\n", (int) offset);
    } else {
        fprintf(stderr, "Could not deterine offset of %s in %s\n", argv[3], argv[2]);
    }

    std::string path(argv[1]);
    auto fp = FileSystemFileProvider::get(path, false);
    if (!fp) {
        llvm::errs() << "Could not open " << path << "\n";
        return -1;
    }

    auto exec = ExecutableFile::get(fp, false, 0);
    if (exec) {
        std::stringstream ss;
        ss << "ModuleName: " << exec->getModuleName() << '\n';
        ss << "ImageSize:  0x" << std::hex << exec->getImageSize() << '\n';
        ss << "ImageBase:  0x" << std::hex << exec->getImageBase() << '\n';
        ss << "EntryPoint: 0x" << std::hex << exec->getEntryPoint() << '\n';

        llvm::errs() << ss.str();
    }

    return 0;
}
