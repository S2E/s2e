///
/// Copyright (C) 2014, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <iomanip>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>
#include <sstream>
#include <stdio.h>
#include <unistd.h>
#include <vmi/ExecutableFile.h>

using namespace llvm;

namespace {
cl::opt<std::string> File("file", cl::desc("File to dump"), cl::Positional);

cl::opt<std::string> Address("address", cl::desc("Address where to dump"), cl::Required);

cl::opt<std::string> Count("count", cl::desc("How many bytes to dump"), cl::Required);
}

using namespace vmi;

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, (char **) argv, " reader");

    FileProvider *fp = FileSystemFileProvider::get(File, false);
    if (!fp) {
        llvm::errs() << "Can't open " << File << "\n";
        return -1;
    }

    ExecutableFile *binary = vmi::ExecutableFile::get(fp, false, 0);
    if (!binary) {
        llvm::errs() << "Can't parse " << File << "\n";
        return -1;
    }

    uint64_t address = strtol(Address.c_str(), NULL, 16);
    ssize_t count = strtol(Count.c_str(), NULL, 10);

    uint8_t *buffer = new uint8_t[count];

    ssize_t read_count = binary->read(buffer, count, address);
    if (read_count != count) {
        printf("Could only read %ld bytes from %lx\n", read_count, address);
    }

    for (ssize_t i = 0; i < read_count; ++i) {
        printf("%08lx: %02x\n", address + i, buffer[i]);
    }

    delete[] buffer;

    delete binary;
    delete fp;

    return 0;
}
