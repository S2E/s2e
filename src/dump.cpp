///
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <iomanip>
#include <llvm/Support/raw_ostream.h>
#include <sstream>
#include <stdio.h>
#include <unistd.h>
#include <vmi/PEFile.h>

using namespace vmi;

static void dumpSections(ExecutableFile *file, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Sections (Name, Type, Size)\n"
           << "===========================\n";
    }

    const Sections &sections = file->getSections();
    if (sections.size() == 0) {
        if (!compact) {
            ss << "No sections present\n";
        }
        return;
    }

    for (Sections::const_iterator it = sections.begin(); it != sections.end(); ++it) {
        const SectionDescriptor &section = *it;
        char R = section.isReadable() ? 'R' : '-';
        char W = section.isWritable() ? 'W' : '-';
        char X = section.isExecutable() ? 'X' : '-';
        ss << std::setfill(' ') << std::setw(20) << std::left << section.name << " " << R << W << X << " 0x" << std::hex
           << std::setfill('0') << std::right << std::setw(10) << section.start << " 0x" << std::hex
           << std::setfill('0') << std::right << std::setw(10) << section.size << '\n';
    }

    if (!compact) {
        ss << '\n';
    }
}

static void dumpExports(PEFile *peFile, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Export Directory\n"
           << "================\n";
    }

    const Exports &exports = peFile->getExports();
    if (exports.size() == 0) {
        if (!compact) {
            ss << "Export directory is empty\n";
        }
        return;
    }

    for (Exports::const_iterator it = exports.begin(); it != exports.end(); ++it) {
        uint64_t address = peFile->getImageBase() + (*it).second;
        std::string name = (*it).first;
        ss << std::setfill(' ') << std::setw(40) << std::left << name << " @0x" << std::hex << address << '\n';
    }

    if (!compact) {
        ss << '\n';
    }
}

static void dumpImports(PEFile *peFile, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Import Directory\n"
           << "================\n";
    }

    const Imports &imports = peFile->getImports();

    if (imports.size() == 0) {
        if (!compact) {
            ss << "Import directory is empty\n";
        }
        return;
    }

    for (Imports::const_iterator it = imports.begin(); it != imports.end(); ++it) {
        const std::string &libName = (*it).first;
        const ImportedSymbols &symbols = (*it).second;
        ss << libName << std::dec << " (" << symbols.size() << " symbols)\n";

        for (ImportedSymbols::const_iterator fit = symbols.begin(); fit != symbols.end(); ++fit) {
            std::string symbolName = (*fit).first;
            uint64_t address = (*fit).second.address;
            uint64_t itl = (*fit).second.importTableLocation;
            ss << std::setfill(' ') << std::setw(40) << std::left << symbolName << " @0x" << std::hex << address
               << " @0x" << std::hex << itl << '\n';
        }
    }

    if (!compact) {
        ss << '\n';
    }
}

static void dumpRelocations(PEFile *peFile, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Relocations\n"
           << "===========\n";
    }

    const vmi::Relocations &relocations = peFile->getRelocations();

    if (relocations.size() == 0) {
        if (!compact) {
            ss << "No relocations present\n";
        }
        return;
    }

    for (vmi::Relocations::const_iterator it = relocations.begin(); it != relocations.end(); ++it) {
        ss << std::hex << it->first << ": " << it->second << '\n';
    }

    if (!compact) {
        ss << '\n';
    }
}

static void dumpExceptions(PEFile *peFile, std::ostream &ss, bool compact) {
    if (!compact) {
        ss << '\n'
           << "Exceptions\n"
           << "==========\n";
    }

    const vmi::ExceptionHandlers &h = peFile->getExceptions();

    ss << std::hex;

    for (unsigned i = 0; i < h.size(); ++i) {
        ss << "Begin: 0x" << h[i] << '\n';
    }

    if (!compact) {
        ss << '\n';
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
                    "  -x:  print exceptions\n\n"
                    "  -c:  compact printing\n\n");
    fprintf(stderr, "Example: %s -s driver.sys\n", progName);
}

static void dumpPeFile(PEFile *peFile, bool printHeader, bool printExports, bool printImports, bool printSections,
                       bool printRelocations, bool printExceptions, bool compact) {
    std::stringstream ss;
    if (printHeader) {
        ss << "Dumping contents of " << peFile->getModuleName() << '\n';
        ss << "Base address: 0x" << std::hex << peFile->getImageBase() << '\n';
        ss << "Image size:   0x" << std::hex << peFile->getImageSize() << '\n';
        ss << "Entry point:  0x" << std::hex << peFile->getEntryPoint() << '\n';
        ss << "Checksum:     0x" << std::hex << peFile->getCheckSum() << '\n';
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

    llvm::outs() << ss.str();
}

static void dumpDefault(ExecutableFile *file, bool printHeader, bool printSections, bool compact) {
    std::stringstream ss;

    if (printHeader) {
        ss << "Dumping contents of " << file->getModuleName() << '\n';
        ss << "Base address: 0x" << std::hex << file->getImageBase() << '\n';
        ss << "Image size:   0x" << std::hex << file->getImageSize() << '\n';
        ss << "Entry point:  0x" << std::hex << file->getEntryPoint() << '\n';
    }

    if (printSections) {
        dumpSections(file, ss, compact);
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
    bool compact = false;
    int nbSelected = 0;

    int c;
    while ((c = getopt(argc, argv, "cheirxs")) != -1) {
        switch (c) {
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
    FileSystemFileProvider *fp = FileSystemFileProvider::get(path, false);
    if (!fp) {
        llvm::errs() << "Could not open " << path << '\n';
        return -1;
    }

    ExecutableFile *file = ExecutableFile::get(fp, false, 0);
    if (!file) {
        llvm::errs() << path << " is not a valid executable file\n";
        return -1;
    }

    PEFile *peFile = dynamic_cast<PEFile *>(file);
    if (peFile) {
        dumpPeFile(peFile, printHeader, printExports, printImports, printSections, printRelocations, printExceptions,
                   compact);
    } else {
        dumpDefault(file, printHeader, printSections, compact);
    }

    return 0;
}
