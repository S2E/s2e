///
/// Copyright (C) 2014-2017, Cyberhaven
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

static void dumpSections(const ExecutableFile &file, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Sections (Name, Type, VirtualAddr, PhysicalAddr, FileSize, VirtSize)\n"
           << "====================================================================\n";
    }

    auto sections = file.getSections();
    if (sections.size() == 0) {
        if (!compact) {
            ss << "No sections present\n";
        }
        return;
    }

    for (auto &section : sections) {
        char L = section.loadable ? 'L' : '-';
        char R = section.readable ? 'R' : '-';
        char W = section.writable ? 'W' : '-';
        char X = section.executable ? 'X' : '-';
        ss << std::setfill(' ') << std::setw(20) << std::left << section.name << " " << L << R << W << X << " 0x"
           << std::hex << std::setfill('0') << std::right << std::setw(10) << section.start << " 0x" << std::hex
           << std::setfill('0') << std::right << std::setw(10) << section.physStart << " 0x" << std::hex
           << std::setfill('0') << std::right << std::setw(10) << section.size << " 0x" << std::hex << std::setfill('0')
           << std::right << std::setw(10) << section.virtualSize << '\n';
    }

    if (!compact) {
        ss << '\n';
    }
}

static void dumpExports(const PEFile &peFile, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Export Directory\n"
           << "================\n";
    }

    auto exports = peFile.getExports();
    if (exports.size() == 0) {
        if (!compact) {
            ss << "Export directory is empty\n";
        }
        return;
    }

    for (auto it : exports) {
        uint64_t address = peFile.getImageBase() + it.first;
        std::string name = it.second;
        ss << std::setfill(' ') << std::setw(40) << std::left << name << " @0x" << std::hex << address << '\n';
    }

    if (!compact) {
        ss << '\n';
    }
}

static void dumpImports(const PEFile &peFile, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Import Directory\n"
           << "================\n";
    }

    auto imports = peFile.getImports();

    if (imports.size() == 0) {
        if (!compact) {
            ss << "Import directory is empty\n";
        }
        return;
    }

    for (auto it : imports) {
        const std::string &libName = it.first;
        const ImportedSymbols &symbols = it.second;
        ss << libName << std::dec << " (" << symbols.size() << " symbols)\n";

        for (auto fit : symbols) {
            std::string symbolName = fit.first;
            uint64_t address = fit.second.address;
            uint64_t itl = fit.second.importTableLocation;
            ss << std::setfill(' ') << std::setw(40) << std::left << symbolName << " @0x" << std::hex << address
               << " @0x" << std::hex << itl << '\n';
        }
    }

    if (!compact) {
        ss << '\n';
    }
}

static void dumpRelocations(const PEFile &peFile, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Relocations\n"
           << "===========\n";
    }

    auto relocations = peFile.getRelocations();

    if (relocations.size() == 0) {
        if (!compact) {
            ss << "No relocations present\n";
        }
        return;
    }

    for (auto it : relocations) {
        ss << std::hex << it.first << ": " << it.second << '\n';
    }

    if (!compact) {
        ss << '\n';
    }
}

static void dumpExceptions(const PEFile &peFile, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Exceptions\n"
           << "==========\n";
    }

    auto h = peFile.getExceptions();

    ss << std::hex;

    for (unsigned i = 0; i < h.size(); ++i) {
        ss << "Begin: 0x" << h[i] << '\n';
    }

    if (!compact) {
        ss << '\n';
    }
}

static void dumpFunctions(const ExecutableFile &file, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Functions\n"
           << "=========\n";
    }

    for (auto f : file.guessFunctionAddresses()) {
        ss << "0x" << std::hex << f << "\n";
    }
}

static void printUsage(const char *progName) {
    fprintf(stderr, "Usage: %s [options] pe|elf|decree\n", progName);
    fprintf(stderr, "Options:\n\n"
                    "  -h:  print header\n"
                    "  -s:  print sections\n"
                    "  -e:  print exports\n"
                    "  -i:  print imports\n"
                    "  -r:  print relocations\n"
                    "  -f:  print functions\n"
                    "  -x:  print exceptions\n\n"
                    "  -c:  compact printing\n\n");
    fprintf(stderr, "Example: %s -s driver.sys\n", progName);
}

static void dumpPeFile(const PEFile &peFile, bool printHeader, bool printExports, bool printImports, bool printSections,
                       bool printRelocations, bool printExceptions, bool printFunctions, bool compact) {
    std::stringstream ss;
    if (printHeader) {
        ss << "Dumping contents of " << peFile.getModuleName() << '\n';
        ss << "Base address: 0x" << std::hex << peFile.getImageBase() << '\n';
        ss << "Image size:   0x" << std::hex << peFile.getImageSize() << '\n';
        ss << "Entry point:  0x" << std::hex << peFile.getEntryPoint() << '\n';
        ss << "Checksum:     0x" << std::hex << peFile.getCheckSum() << '\n';
    }

    if (printSections) {
        dumpSections(peFile, ss, compact);
    }

    if (printExports) {
        dumpExports(peFile, ss, compact);
    }

    if (printImports) {
        dumpImports(peFile, ss, compact);
    }

    if (printRelocations) {
        dumpRelocations(peFile, ss, compact);
    }

    if (printExceptions) {
        dumpExceptions(peFile, ss, compact);
    }

    if (printFunctions) {
        dumpFunctions(peFile, ss, compact);
    }

    llvm::outs() << ss.str();
}

static void dumpDefault(const ExecutableFile &file, bool printHeader, bool printSections, bool printFunctions,
                        bool compact) {
    std::stringstream ss;

    if (printHeader) {
        ss << "Dumping contents of " << file.getModuleName() << '\n';
        ss << "Base address: 0x" << std::hex << file.getImageBase() << '\n';
        ss << "Image size:   0x" << std::hex << file.getImageSize() << '\n';
        ss << "Entry point:  0x" << std::hex << file.getEntryPoint() << '\n';
    }

    if (printSections) {
        dumpSections(file, ss, compact);
    }

    if (printFunctions) {
        dumpFunctions(file, ss, compact);
    }

    llvm::outs() << ss.str();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printUsage(argv[0]);
        return -1;
    }

    bool printHeader = false;
    bool printExports = false;
    bool printImports = false;
    bool printSections = false;
    bool printRelocations = false;
    bool printExceptions = false;
    bool printFunctions = false;
    bool compact = false;
    int nbSelected = 0;

    int c;
    while ((c = getopt(argc, argv, "cfheirxs")) != -1) {
        switch (c) {
            case 'f':
                printFunctions = true;
                ++nbSelected;
                break;
            case 'h':
                printHeader = true;
                ++nbSelected;
                break;
            case 's':
                printSections = true;
                ++nbSelected;
                break;
            case 'i':
                printImports = true;
                ++nbSelected;
                break;
            case 'e':
                printExports = true;
                ++nbSelected;
                break;
            case 'r':
                printRelocations = true;
                ++nbSelected;
                break;
            case 'x':
                printExceptions = true;
                ++nbSelected;
                break;
            case 'c':
                compact = true;
                break;
        }
    }

    if (!nbSelected) {
        printUsage(argv[0]);
        return -1;
    }

    std::string path(argv[argc - 1]);
    auto fp = FileSystemFileProvider::get(path, false);
    if (!fp) {
        llvm::errs() << "Could not open " << path << '\n';
        return -1;
    }

    auto file = ExecutableFile::get(fp, false, 0);
    if (!file) {
        llvm::errs() << path << " is not a valid executable file\n";
        return -1;
    }

    auto peFile = std::dynamic_pointer_cast<PEFile>(file);
    if (peFile) {
        dumpPeFile(*peFile.get(), printHeader, printExports, printImports, printSections, printRelocations,
                   printExceptions, printFunctions, compact);
    } else {
        dumpDefault(*file.get(), printHeader, printSections, printFunctions, compact);
    }

    return 0;
}
