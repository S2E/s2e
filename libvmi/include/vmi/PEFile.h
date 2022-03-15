///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
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

#ifndef VMI_PE_FILE_H

#define VMI_PE_FILE_H

#include <llvm/ADT/StringMap.h>
#include <llvm/Support/Allocator.h>
#include <map>
#include <memory>
#include <set>
#include "ExecutableFile.h"
#include "Pe.h"

namespace vmi {

class PEFile : public ExecutableFile {
public:
    typedef std::vector<windows::IMAGE_SECTION_HEADER> PeSections;

protected:
    uint64_t m_imageBase;
    uint64_t m_imageSize;
    uint64_t m_entryPoint;
    unsigned m_pointerSize;
    std::string m_moduleName;

    vmi::windows::IMAGE_DOS_HEADER m_dosHeader;
    vmi::windows::IMAGE_FILE_HEADER m_fileHeader;

    union {
        windows::IMAGE_NT_HEADERS64 m_ntHeader64;
        windows::IMAGE_NT_HEADERS32 m_ntHeader32;
    };

    Exports m_exports;
    Imports m_imports;
    Relocations m_relocations;
    ExceptionHandlers m_exceptions;
    ExceptionHandlers m_exceptionFilters;
    FunctionAddresses m_additionalFunctionAddresses;

    Sections m_sections;
    bool m_sectionsInited;
    bool m_modified;

    PeSections m_peSections;
    mutable const windows::IMAGE_SECTION_HEADER *m_cachedSection;

protected:
    PEFile(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress, unsigned pointerSize);
    uint64_t offset(uint64_t rva) const;
    void *readDirectory(llvm::BumpPtrAllocator &alloc, unsigned index);

    virtual void getAlignment(uint64_t &FileAlignment, uint64_t &SectionAlignment) const = 0;
    virtual const vmi::windows::IMAGE_DATA_DIRECTORY *getDirectory(unsigned index) const = 0;
    bool initSections(void);

    template <typename T> bool initImports(void);

    bool initExports(void);

    bool initRelocations(void);

    bool initExceptions(void);

    bool initAdditionalFunctionAddresses(void);

    windows::IMAGE_DATA_DIRECTORY *getDataDirectory(unsigned index);
    uint32_t computeChecksum();
    bool rewrite();

public:
    static std::shared_ptr<PEFile> get(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress);

    virtual ~PEFile();

    virtual bool initialize() = 0;

    virtual bool parseExceptionStructures(uint64_t CHandler, std::set<uint64_t> CXXHandler);

    virtual std::string getModuleName() const {
        return m_moduleName;
    }

    virtual uint64_t getImageBase() const {
        return m_imageBase;
    }

    virtual uint64_t getImageSize() const {
        return m_imageSize;
    }

    virtual uint64_t getEntryPoint() const {
        return m_entryPoint;
    }

    virtual bool getSymbolAddress(const std::string &name, uint64_t *address) {
        return false;
    }

    virtual bool getSourceInfo(uint64_t addr, std::string &source, uint64_t &line, std::string &function) {
        return false;
    }

    const Exports &getExports() const {
        return m_exports;
    }

    const Imports &getImports() const {
        return m_imports;
    }

    const Sections &getSections() const {
        return m_sections;
    }

    const Relocations &getRelocations() const {
        return m_relocations;
    }

    const ExceptionHandlers &getExceptions() const {
        return m_exceptions;
    }

    const ExceptionHandlers &getExceptionFilters() const {
        return m_exceptionFilters;
    }

    const FunctionAddresses &getAdditionalFunctionAddresses() const {
        return m_additionalFunctionAddresses;
    }

    virtual unsigned getPointerSize() const {
        switch (m_fileHeader.Machine) {
            case vmi::windows::IMAGE_FILE_MACHINE_I386:
                return sizeof(uint32_t);
            case vmi::windows::IMAGE_FILE_MACHINE_AMD64:
                return sizeof(uint64_t);
            default:
                assert(false && "Bug");
        }

        // Control should not reach here
        abort();
    }

    virtual ssize_t read(void *buffer, size_t nbyte, off64_t va) const;
    virtual ssize_t write(void *buffer, size_t nbyte, off64_t va);

    windows::IMAGE_SECTION_HEADER *appendSection(const std::string &name, void *data, unsigned size);
    void getFreeSectionHeader(windows::IMAGE_SECTION_HEADER &sec, unsigned size);
};

class PEFile32 : public PEFile {
public:
    PEFile32(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress);

protected:
    virtual bool initialize();

    virtual void getAlignment(uint64_t &FileAlignment, uint64_t &SectionAlignment) const {
        FileAlignment = m_ntHeader32.OptionalHeader.FileAlignment;
        SectionAlignment = m_ntHeader32.OptionalHeader.SectionAlignment;
    }

    virtual const vmi::windows::IMAGE_DATA_DIRECTORY *getDirectory(unsigned index) const {
        return &m_ntHeader32.OptionalHeader.DataDirectory[index];
    }

    virtual uint32_t getCheckSum() const {
        return m_ntHeader32.OptionalHeader.CheckSum;
    }
};

class PEFile64 : public PEFile {
private:
    uint64_t offset(uint64_t rva) const;

public:
    PEFile64(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress);

protected:
    virtual bool initialize();
    void *readDirectory(llvm::BumpPtrAllocator &alloc, unsigned index);

    virtual void getAlignment(uint64_t &FileAlignment, uint64_t &SectionAlignment) const {
        FileAlignment = m_ntHeader64.OptionalHeader.FileAlignment;
        SectionAlignment = m_ntHeader64.OptionalHeader.SectionAlignment;
    }

    virtual const vmi::windows::IMAGE_DATA_DIRECTORY *getDirectory(unsigned index) const {
        return &m_ntHeader64.OptionalHeader.DataDirectory[index];
    }

    virtual uint32_t getCheckSum() const {
        return m_ntHeader64.OptionalHeader.CheckSum;
    }
};
} // namespace vmi

#endif
