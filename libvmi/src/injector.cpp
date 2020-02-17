///
/// Copyright (C) 2015, Cyberhaven
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

#include <iomanip>
#include <llvm/Support/raw_ostream.h>
#include <sstream>
#include <stdio.h>
#include <unistd.h>
#include <vmi/PEFile.h>

using namespace vmi;

int main(int argc, char **argv) {
    if (argc != 2) {
        llvm::outs() << "Usage: " << argv[0] << " pe_file";
        return -1;
    }

    std::string path(argv[1]);
    auto fp = FileSystemFileProvider::get(path, true);
    if (!fp) {
        llvm::errs() << "Could not open " << path << "\n";
        return -1;
    }

    auto file = ExecutableFile::get(fp, false, 0);
    if (!file) {
        llvm::errs() << path << " is not a valid executable file\n";
        return -1;
    }

    auto peFile = std::dynamic_pointer_cast<PEFile>(file);
    if (!peFile) {
        llvm::errs() << "Only PE files are supported for now\n";
    }

    /* Create a dummy section */
    unsigned size = 0x12400;
    uint8_t *sec = new uint8_t[size];
    for (unsigned i = 0; i < size; ++i) {
        sec[i] = (uint8_t) i;
    }

    if (!peFile->appendSection(".inj", sec, size)) {
        llvm::errs() << "Could not append section\n";
    }

    delete[] sec;
    return 0;
}
