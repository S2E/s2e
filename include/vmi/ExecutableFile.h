///
/// Copyright (C) 2012-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef VMI_EXECUTABLEFILE_H

#define VMI_EXECUTABLEFILE_H

#include <inttypes.h>
#include <llvm/Support/Path.h>
#include <map>
#include <string>
#include <vector>
#include "FileProvider.h"

namespace vmi {

/**
 *  Defines some section of memory
 */
struct SectionDescriptor {
    enum SectionType { NONE = 0, READ = 1, WRITE = 2, READWRITE = 3, EXECUTE = 4 };

    uint64_t start;
    uint64_t size;
    bool hasData;
    SectionType type;
    std::string name;

    SectionDescriptor() {
        start = size = 0;
        hasData = false;
        type = NONE;
    }

    void setRead(bool b) {
        if (b)
            type = SectionType(type | READ);
        else
            type = SectionType(type & (-1 - READ));
    }

    void setWrite(bool b) {
        if (b)
            type = SectionType(type | WRITE);
        else
            type = SectionType(type & (-1 - WRITE));
    }

    void setExecute(bool b) {
        if (b)
            type = SectionType(type | EXECUTE);
        else
            type = SectionType(type & (-1 - EXECUTE));
    }

    bool isReadable() const {
        return type & READ;
    }
    bool isWritable() const {
        return type & WRITE;
    }
    bool isExecutable() const {
        return type & EXECUTE;
    }

    bool operator<(const SectionDescriptor &s) const {
        return start + size <= s.start;
    }
};

typedef std::vector<SectionDescriptor> Sections;

// Maps the name of the exported function to its actual address
typedef std::map<std::string, uint64_t> Exports;

/* The actual values may vary depending if the image file
   is actually loaded or not */
struct ImportedSymbol {

    ImportedSymbol() {
        address = importTableLocation = 0;
    }

    ImportedSymbol(uint64_t _address, uint64_t _importTableLocation) {
        address = _address;
        importTableLocation = _importTableLocation;
    }

    /* The actual run-time address of the imported symbol */
    uint64_t address;

    /* The address of the image that the OS loader has to patch
       to actually import the symbol */
    uint64_t importTableLocation;
};

// Maps the name of the function to its actual address
typedef std::map<std::string, ImportedSymbol> ImportedSymbols;

// Maps the library name to the set of functions it exports
typedef std::map<std::string, ImportedSymbols> Imports;

// List of virtual addresses whose content needs to be relocated.
typedef std::vector<std::pair<uint64_t, uint64_t>> Relocations;

typedef std::vector<uint64_t> ExceptionHandlers;
typedef std::vector<uint64_t> FunctionAddresses;

class ExecutableFile {

protected:
    FileProvider *m_file;
    bool m_loaded;
    uint64_t m_loadAddress;

    ExecutableFile(FileProvider *file, bool loaded, uint64_t loadAddress);

public:
    static ExecutableFile *get(FileProvider *file, bool loaded, uint64_t loadAddress);

    virtual ~ExecutableFile();

    virtual std::string getModuleName() const = 0;
    virtual uint64_t getImageBase() const = 0;
    virtual uint64_t getImageSize() const = 0;
    virtual uint64_t getEntryPoint() const = 0;
    virtual bool getSymbolAddress(const std::string &name, uint64_t *address) = 0;
    virtual bool getSourceInfo(uint64_t addr, std::string &source, uint64_t &line, std::string &function) = 0;
    virtual unsigned getPointerSize() const = 0;
    virtual ssize_t read(void *buffer, size_t nbyte, off64_t va) const {
        return -1;
    }
    virtual ssize_t write(void *buffer, size_t nbyte, off64_t va) {
        return -1;
    }

    virtual const Sections &getSections() const = 0;
    FileProvider *get() {
        return m_file;
    }
};
}

#endif
