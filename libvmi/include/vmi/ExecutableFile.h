///
/// Copyright (C) 2012-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
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

#ifndef VMI_EXECUTABLEFILE_H

#define VMI_EXECUTABLEFILE_H

#include <inttypes.h>
#include <llvm/Support/Path.h>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "FileProvider.h"

namespace vmi {

/**
 *  Defines some section of memory
 */
struct SectionDescriptor {
    uint64_t start;
    uint64_t physStart;
    uint64_t size;
    uint64_t virtualSize;

    bool loadable;

    bool readable;
    bool writable;
    bool executable;

    std::string name;

    SectionDescriptor() {
        loadable = false;
        physStart = start = size = 0;
        readable = writable = executable = false;
    }

    bool operator<(const SectionDescriptor &s) const {
        return start + size <= s.start;
    }
};

typedef std::vector<SectionDescriptor> Sections;

// Maps the address of an exported function to its name
typedef std::map<uint64_t, std::string> Exports;

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
typedef std::unordered_map<std::string, ImportedSymbol> ImportedSymbols;

// Maps the library name to the set of functions imported from it
typedef std::unordered_map<std::string, ImportedSymbols> Imports;

// List of virtual addresses whose content needs to be relocated.
typedef std::vector<std::pair<uint64_t, uint64_t>> Relocations;

typedef std::vector<uint64_t> ExceptionHandlers;
typedef std::vector<uint64_t> FunctionAddresses;

class ExecutableFile {

protected:
    std::shared_ptr<FileProvider> m_file;
    bool m_loaded;
    uint64_t m_loadAddress;

    ExecutableFile(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress);

public:
    static std::shared_ptr<ExecutableFile> get(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress);

    virtual ~ExecutableFile();

    virtual std::string getModuleName() const = 0;
    virtual uint64_t getImageBase() const = 0;
    virtual uint64_t getImageSize() const = 0;
    virtual uint64_t getEntryPoint() const = 0;
    virtual bool getSymbolAddress(const std::string &name, uint64_t *address) = 0;
    virtual bool getSourceInfo(uint64_t addr, std::string &source, uint64_t &line, std::string &function) = 0;
    virtual unsigned getPointerSize() const = 0;
    virtual uint32_t getCheckSum() const = 0;
    virtual ssize_t read(void *buffer, size_t nbyte, off64_t va) const {
        return -1;
    }
    virtual ssize_t write(void *buffer, size_t nbyte, off64_t va) {
        return -1;
    }

    virtual const Sections &getSections() const = 0;
    std::shared_ptr<FileProvider> get() {
        return m_file;
    }
};
} // namespace vmi

#endif
