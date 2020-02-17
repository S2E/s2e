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

#include <algorithm>
#include <iostream>
#include <llvm/ADT/DenseSet.h>
#include <llvm/Support/raw_ostream.h>
#include <sstream>
#include <stddef.h>
#include <stdio.h>
#include <string>
#include <vmi/PEFile.h>

namespace vmi {

using namespace vmi::windows;

PEFile::PEFile(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress, unsigned pointerSize)
    : ExecutableFile(file, loaded, loadAddress), m_imageBase(0), m_imageSize(0), m_entryPoint(0),
      m_pointerSize(pointerSize), m_moduleName(llvm::sys::path::filename(std::string(file->getName()))),
      m_sectionsInited(false), m_modified(false), m_cachedSection(nullptr) {
}

std::shared_ptr<PEFile> PEFile::get(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress) {
    vmi::windows::IMAGE_DOS_HEADER dosHeader;
    windows::IMAGE_NT_HEADERS32 ntHeader;

    if (!file->readb(&dosHeader, sizeof(m_dosHeader), loadAddress)) {
        return nullptr;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }

    if (!file->readb(&ntHeader, sizeof(ntHeader), loadAddress + dosHeader.e_lfanew)) {
        return nullptr;
    }

    if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }

    std::shared_ptr<PEFile> ret;

    switch (ntHeader.FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386: {
            std::shared_ptr<PEFile32> p{new PEFile32(file, loaded, loadAddress)};
            ret = p;
        } break;

        case IMAGE_FILE_MACHINE_AMD64: {
            std::shared_ptr<PEFile64> p{new PEFile64(file, loaded, loadAddress)};
            ret = p;
        } break;

        default: {
            std::string moduleName = llvm::sys::path::filename(std::string(file->getName()));
            llvm::errs() << moduleName << " has unsupported architecture\n";
            break;
        }
    }

    if (ret && !ret->initialize()) {
        ret = nullptr;
    }

    return ret;
}

bool PEFile::initExports(void) {
    // Will free memory when returning from the function
    llvm::BumpPtrAllocator alloc;

    const IMAGE_DATA_DIRECTORY *ExportDataDir = getDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT);

    // Get the whole export directory
    IMAGE_EXPORT_DIRECTORY *ExportDir =
        static_cast<IMAGE_EXPORT_DIRECTORY *>(readDirectory(alloc, IMAGE_DIRECTORY_ENTRY_EXPORT));

    if (!ExportDir) {
        llvm::errs() << m_moduleName << ": Could not read export directory\n";
        return false;
    }

    uint32_t FunctionPointerSize = ExportDir->NumberOfFunctions * sizeof(uint32_t);
    uint32_t NamePointersSize = ExportDir->NumberOfNames * sizeof(uint32_t);
    uint32_t NameOrdinalsSize = ExportDir->NumberOfNames * sizeof(uint16_t);

    std::vector<uint32_t> FunctionPointers(ExportDir->NumberOfFunctions);
    std::vector<uint32_t> NamePointers(ExportDir->NumberOfNames);
    std::vector<uint16_t> NameOrdinals(ExportDir->NumberOfNames);

    if (FunctionPointerSize > 0) {
        if (!m_file->readb(&FunctionPointers[0], FunctionPointerSize, offset(ExportDir->AddressOfFunctions))) {
            llvm::errs() << m_moduleName << ": Could not load addresses of exported functions\n";
            return false;
        }
    }

    if (NamePointersSize > 0) {
        if (!m_file->readb(&NamePointers[0], NamePointersSize, offset(ExportDir->AddressOfNames))) {
            llvm::errs() << m_moduleName << ": Could not load names of exported functions\n";
            return false;
        }
    }

    if (NameOrdinalsSize > 0) {
        if (!m_file->readb(&NameOrdinals[0], NameOrdinalsSize, offset(ExportDir->AddressOfNameOrdinals))) {
            llvm::errs() << m_moduleName << ": Could not load names of exported functions\n";
            return false;
        }
    }

    std::vector<bool> HasName(FunctionPointers.size(), false);
    for (unsigned i = 0; i < NamePointers.size(); i++) {
        uint32_t NameRva = NamePointers[i];
        uint16_t NameOrd = NameOrdinals[i];
        uint64_t FuncRva = FunctionPointers[NameOrd];

        std::string FunctionName;

        if (!m_file->readString(offset(NameRva), FunctionName)) {
            continue;
        }

        // skip the forwarded exports
        if (FuncRva > ExportDataDir->VirtualAddress &&
            FuncRva < (ExportDataDir->VirtualAddress + ExportDataDir->Size)) {
            continue;
        }

        HasName[NameOrd] = true;
        m_exports[FuncRva + m_loadAddress] = FunctionName;
    }

    for (unsigned i = 0; i < FunctionPointers.size(); ++i) {
        if (HasName[i])
            continue;

        uint64_t FuncRva = FunctionPointers[i];
        // skip the forwarded exports
        if (FuncRva > ExportDataDir->VirtualAddress &&
            FuncRva < (ExportDataDir->VirtualAddress + ExportDataDir->Size)) {
            continue;
        }

        std::string _str;
        llvm::raw_string_ostream FunctionName(_str);
        FunctionName << i;
        m_exports[FuncRva + m_loadAddress] = FunctionName.str();
    }

    return true;
}

template <typename T> bool PEFile::initImports(void) {
    // Will free memory when returning from the function
    llvm::BumpPtrAllocator alloc;

    const IMAGE_DATA_DIRECTORY *ImportDataDir = getDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);

    // Get the whole export directory
    IMAGE_IMPORT_DESCRIPTOR *ImportDesc =
        static_cast<IMAGE_IMPORT_DESCRIPTOR *>(readDirectory(alloc, IMAGE_DIRECTORY_ENTRY_IMPORT));

    if (!ImportDesc) {
        return false;
    }

    uint32_t ImportDescCount = ImportDataDir->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    // For each imported library
    for (unsigned i = 0; i < ImportDescCount; ++i) {
        if (!ImportDesc[i].Name) {
            break;
        }

        std::string LibraryName;
        if (!m_file->readString(offset(ImportDesc[i].Name), LibraryName)) {
            continue;
        }

        std::transform(LibraryName.begin(), LibraryName.end(), LibraryName.begin(), ::tolower);

        uint32_t ImportAddressTable = ImportDesc[i].FirstThunk;
        uint32_t ImportNameTable = ImportDesc[i].OriginalFirstThunk;

        // For each imported function
        T AddressEntry, NameEntry;
        do {
            bool res = true;
            res &= m_file->readb(&AddressEntry, sizeof(AddressEntry), offset(ImportAddressTable));
            res &= m_file->readb(&NameEntry, sizeof(AddressEntry), offset(ImportNameTable));
            if (!res) {
                return false;
            }

            ImportAddressTable += sizeof(T);
            ImportNameTable += sizeof(T);

            if (!NameEntry.u1.AddressOfData)
                break;

            std::string FunctionName;

            uint64_t NameOffset = offset(NameEntry.u1.AddressOfData);

            // Skip the hint (+2)
            if (!m_file->readString(NameOffset + 2, FunctionName)) {
                continue;
            }

            ImportedSymbols &ImpFcnIt = m_imports[LibraryName];
            ImpFcnIt[FunctionName] =
                ImportedSymbol(AddressEntry.u1.Function, m_loadAddress + ImportAddressTable - sizeof(T));

        } while (NameEntry.u1.AddressOfData);
    }

    return true;
}

uint64_t PEFile::offset(uint64_t rva) const {
    if (m_loaded) {
        return m_loadAddress + rva;
    }

    if (m_cachedSection) {
        if (m_cachedSection->VirtualAddress <= rva &&
            rva < m_cachedSection->VirtualAddress + m_cachedSection->Misc.VirtualSize) {
            return rva - m_cachedSection->VirtualAddress + m_cachedSection->PointerToRawData;
        }
    }

    // Find the section
    for (unsigned i = 0; i < m_peSections.size(); ++i) {
        const IMAGE_SECTION_HEADER &section = m_peSections[i];
        if (section.VirtualAddress <= rva && rva < section.VirtualAddress + section.Misc.VirtualSize) {
            m_cachedSection = &section;
            return rva - section.VirtualAddress + section.PointerToRawData;
        }
    }

    return 0;
}

void *PEFile::readDirectory(llvm::BumpPtrAllocator &alloc, unsigned index) {
    const IMAGE_DATA_DIRECTORY *DataDir = getDirectory(index);
    uint32_t DirAddress = DataDir->VirtualAddress;
    uint32_t DirSize = DataDir->Size;

    if (!DataDir || !DataDir->VirtualAddress) {
        return nullptr;
    }

    // Get the whole export directory
    uint8_t *Buffer = (uint8_t *) alloc.Allocate(DirSize, 1);
    if (!Buffer) {
        return nullptr;
    }

    if (!m_file->readb((uint8_t *) Buffer, DirSize, offset(DirAddress))) {
        llvm::errs() << m_moduleName << ": Could not load directory " << index << "\n";
        return nullptr;
    }

    return Buffer;
}

bool PEFile::initSections(void) {
    unsigned sections = m_fileHeader.NumberOfSections;

    IMAGE_SECTION_HEADER sectionHeader;
    uint64_t pSection = m_loadAddress + m_dosHeader.e_lfanew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER);

    if (m_pointerSize == sizeof(uint32_t)) {
        pSection += sizeof(IMAGE_OPTIONAL_HEADER32);
    } else {
        pSection += sizeof(IMAGE_OPTIONAL_HEADER64);
    }

    for (unsigned i = 0; i < sections; ++i) {
        if (!m_file->readb(&sectionHeader, sizeof(sectionHeader), pSection)) {
            return false;
        }
        SectionDescriptor sectionDesc;
        sectionDesc.start = getImageBase() + sectionHeader.VirtualAddress;
        sectionDesc.size = sectionHeader.SizeOfRawData;
        sectionDesc.virtualSize = sectionHeader.Misc.VirtualSize;

        for (unsigned i = 0; i < IMAGE_SIZEOF_SHORT_NAME && sectionHeader.Name[i]; ++i) {
            sectionDesc.name += sectionHeader.Name[i];
        }

        sectionDesc.loadable = true;
        sectionDesc.writable = sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE;
        sectionDesc.readable = sectionHeader.Characteristics & IMAGE_SCN_MEM_READ;
        sectionDesc.executable = sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE;
        m_sections.push_back(sectionDesc);
        m_peSections.push_back(sectionHeader);

        pSection += sizeof(sectionHeader);
    }

    return true;
}

bool PEFile::initRelocations(void) {
    // Will free memory when returning from the function
    llvm::BumpPtrAllocator alloc;

    const IMAGE_DATA_DIRECTORY *RelocDataDir = getDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC);

    uint8_t *RelocDir = static_cast<uint8_t *>(readDirectory(alloc, IMAGE_DIRECTORY_ENTRY_BASERELOC));

    if (!RelocDir) {
        return false;
    }

    uint32_t offset = 0;
    uint64_t pointerSize = getPointerSize();
    while (offset < RelocDataDir->Size) {
        IMAGE_BASE_RELOCATION *RelocEntry = reinterpret_cast<IMAGE_BASE_RELOCATION *>(RelocDir);
        if (RelocEntry->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
            llvm::errs() << "Warning: broken relocation for " << m_file->getName() << "\n";
            break;
        }

        unsigned count = (RelocEntry->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        uint16_t *types = (uint16_t *) &RelocEntry[1];
        for (unsigned i = 0; i < count; ++i) {
            uint16_t addr = types[i] & 0xfff;
            uint16_t type = types[i] >> 12;

            // This type is used for padding
            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                if (i != count - 1) {
                    llvm::errs() << "Warning: unexpected relocation type\n";
                }
                break;
            }

            uint64_t RVA = RelocEntry->VirtualAddress + addr;
            uint64_t target = 0;

            if (!m_file->readb(&target, pointerSize, this->offset(RVA))) {
                llvm::errs() << "Warning: cannot read relocation target\n";
                target = 0; // XXX
            }

            uint64_t VirtualAddress = m_imageBase + RelocEntry->VirtualAddress + addr;

#if 0
            if (type != IMAGE_REL_BASED_HIGHLOW) {
                std::stringstream ss;
                ss << "Va: " << std::hex << VirtualAddress << " type=" << type << "\n";
                llvm::errs() << ss.str();
            }
#endif

            // Looks like PE for x86 32-bits and 64-bits has only one type of
            // relocation
            if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                m_relocations.push_back(std::make_pair(VirtualAddress, target));
            } else {
                llvm::errs() << "Warning: Unknown type of relocation (" << type << ")\n";
            }
        }

        offset += RelocEntry->SizeOfBlock;
        RelocDir += RelocEntry->SizeOfBlock;
    }

    return true;
}

bool PEFile::initAdditionalFunctionAddresses(void) {
    Relocations::const_iterator it;
    for (it = m_relocations.begin(); it != m_relocations.end(); ++it) {
        uint64_t src = it->first;
        uint64_t dst = it->second;

        /**
         * Some DLLs do weird stuff with the base address to compute function
         * addresses, e.g.:
         * .text:10053DE3                 mov     esi, dword_10234358
         * .text:10053DE9                 add     esi, offset __ImageBase
         * .text:10053DFE                 call    esi
         * We try to extract such patterns here
         */
        if (dst == m_imageBase) {
            uint32_t dwordptr, dword;
            uint64_t instr = src - 2 - 6;
            union {
                struct {
                    uint16_t i;
                    uint32_t imm;
                } __attribute__((packed)) b;
                uint8_t buffer[12];
            } __attribute__((packed));
            uint64_t addr;

            if (read(buffer, sizeof(buffer), instr) != sizeof(buffer)) {
                goto e1;
            }
            if (buffer[6] != 0x81 || buffer[7] != 0xc6) {
                goto e1;
            }
            if (buffer[0] != 0x8b || buffer[1] != 0x35) {
                goto e1;
            }

            dwordptr = b.imm;
            if (read(&dword, sizeof(dword), dwordptr) != sizeof(dword)) {
                goto e1;
            }

            addr = dst + dword;
            m_additionalFunctionAddresses.push_back(addr);

        e1:;
        }
    }

    return true;
}

bool PEFile::initExceptions(void) {
    llvm::DenseSet<uint64_t> hdlrs;

    llvm::BumpPtrAllocator alloc;

    const IMAGE_DATA_DIRECTORY *ExceptionDataDir = getDirectory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);

    RUNTIME_FUNCTION *ExceptionDir =
        static_cast<RUNTIME_FUNCTION *>(readDirectory(alloc, IMAGE_DIRECTORY_ENTRY_EXCEPTION));

    if (!ExceptionDir) {
        return false;
    }

    uint32_t offset = 0;
    int i = 0;
    while (offset < ExceptionDataDir->Size) {
        const RUNTIME_FUNCTION *Function = &ExceptionDir[i];

        hdlrs.insert(m_imageBase + Function->BeginAddress);

        UNWIND_INFO unwindInfo;

        if (m_file->readb(&unwindInfo, sizeof(unwindInfo), this->offset(Function->UnwindData))) {

            if ((unwindInfo.Flags & UNW_FLAG_EHANDLER) || (unwindInfo.Flags & UNW_FLAG_UHANDLER)) {
                uint32_t ehaddr = 0;
                uint32_t off = 0;

                /* Read the ExceptionHandler field */
                off = Function->UnwindData + (uint32_t) offsetof(UNWIND_INFO, UnwindCode);
                off += sizeof(UNWIND_CODE) * unwindInfo.CountOfCodes;
                /* Proper alignment */
                if (off % 4 != 0)
                    off += 2;

                if (m_file->readb(&ehaddr, sizeof(ehaddr), this->offset(off))) {
                    uint64_t handler = m_imageBase + ehaddr;
                    hdlrs.insert(handler);

                    off += sizeof(unwindInfo.ExceptionHandler);
                    /* Try to parse C++ handlers */
                    EhRef tbl;
                    bool ok = true;
                    ok &= m_file->readb(&ehaddr, sizeof(ehaddr), this->offset(off));
                    ok &= m_file->readb(&tbl, sizeof(tbl), this->offset(ehaddr));
                    ok &= (tbl.Id == MAGIC_VC8 || tbl.Id == MAGIC_VC7 || tbl.Id == MAGIC_VC);

                    if (ok) {
                        /* This is highly likely to be C++ handlers */
                        UnwindHandler h;
                        ExceptionTypeHandler eht;

                        /* No support for older versions yet */
                        if (tbl.Id != MAGIC_VC8) {
                            goto next;
                        }

                        /* Read unwind map handlers */
                        while (tbl.Cnt1) {
                            if (m_file->readb(&h, sizeof(h), this->offset(tbl.Tbl1))) {
                                if (m_imageBase + h.Entry < m_imageBase) {
                                    /* We have invalid data */
                                    break;
                                }
                                hdlrs.insert(m_imageBase + h.Entry);
                                tbl.Tbl1 += sizeof(h);
                            }
                            tbl.Cnt1--;
                        }

                        /* Read exception types handlers */
                        while (tbl.Cnt3) {
                            if (m_file->readb(&eht, sizeof(eht), this->offset(tbl.Tbl3))) {
                                if (m_imageBase + eht.Entry < m_imageBase) {
                                    /* We have invalid data */
                                    break;
                                }

                                hdlrs.insert(m_imageBase + eht.Entry);
                                tbl.Tbl3 += sizeof(eht);
                            }
                            tbl.Cnt3--;

                            /* Only the first one seems to be a function, the others might not
                             * be called */
                            break;
                        }

                    } else {
                        /* Highly likely to be C handlers */
                        SCOPE_TABLE sctable;

                        if (m_file->readb(&sctable, sizeof(sctable), this->offset(off))) {
                            off += sizeof(sctable.Count);
                            for (unsigned i = 0; i < sctable.Count; i++) {
                                if (!m_file->readb(&sctable.ScopeRecord[0], sizeof(sctable.ScopeRecord[0]),
                                                   this->offset(off))) {
                                    break;
                                }

                                ehaddr = m_imageBase + sctable.ScopeRecord[0].HandlerAddress;

                                if ((ehaddr < m_imageBase) || (ehaddr >= m_imageBase + m_imageSize)) {
                                    /* We have invalid data */
                                    break;
                                }

                                hdlrs.insert(ehaddr);

                                off += sizeof(sctable.ScopeRecord[0]);
                            }
                        }
                    }
                }
            }
        }

    next:
        ++i;
        offset += sizeof(*Function);
    }

    m_exceptions.insert(m_exceptions.begin(), hdlrs.begin(), hdlrs.end());

    return true;
}

/** XXX: this is deprecated */
bool PEFile::parseExceptionStructures(uint64_t CHandler, std::set<uint64_t> CXXHandlers) {

    llvm::DenseSet<uint64_t> hdlrs;

    llvm::BumpPtrAllocator alloc;

    const IMAGE_DATA_DIRECTORY *ExceptionDataDir = getDirectory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);

    RUNTIME_FUNCTION *ExceptionDir =
        static_cast<RUNTIME_FUNCTION *>(readDirectory(alloc, IMAGE_DIRECTORY_ENTRY_EXCEPTION));

    if (!ExceptionDir) {
        return false;
    }

    uint32_t offset = 0;
    int i = 0;
    while (offset < ExceptionDataDir->Size) {
        const RUNTIME_FUNCTION *Function = &ExceptionDir[i];

        hdlrs.insert(m_imageBase + Function->BeginAddress);

        UNWIND_INFO unwindInfo;
        if (m_file->readb(&unwindInfo, sizeof(unwindInfo), this->offset(Function->UnwindData))) {
            if (unwindInfo.Flags & UNW_FLAG_EHANDLER) {
                uint32_t ehaddr = 0;
                uint32_t off = 0;

                off = Function->UnwindData + (uint32_t) offsetof(UNWIND_INFO, UnwindCode);
                off += sizeof(UNWIND_CODE) * unwindInfo.CountOfCodes;

                /* Proper alignment */
                if (off % 4 != 0)
                    off += 2;

                if (m_file->readb(&ehaddr, sizeof(ehaddr), this->offset(off))) {
                    uint64_t handler = m_imageBase + ehaddr;

                    off += sizeof(unwindInfo.ExceptionHandler);

                    if (CXXHandlers.count(handler)) {
                        EhRef tbl;

                        if (m_file->readb(&ehaddr, sizeof(ehaddr), this->offset(off))) {
                            if (m_file->readb(&tbl, sizeof(tbl), this->offset(ehaddr))) {
                                UnwindHandler h;
                                ExceptionTypeHandler eht;

                                /* No support for older versions yet */
                                if (tbl.Id != MAGIC_VC8) {
                                    goto next;
                                }

                                /* Read unwind map handlers */
                                while (tbl.Cnt1) {
                                    if (m_file->readb(&h, sizeof(h), this->offset(tbl.Tbl1))) {
                                        hdlrs.insert(m_imageBase + h.Entry);
                                        tbl.Tbl1 += sizeof(h);
                                    }
                                    tbl.Cnt1--;
                                }

                                /* Read exception types handlers */
                                while (tbl.Cnt3) {
                                    if (m_file->readb(&eht, sizeof(eht), this->offset(tbl.Tbl3))) {
                                        hdlrs.insert(m_imageBase + eht.Entry);
                                        tbl.Tbl3 += sizeof(eht);
                                    }
                                    tbl.Cnt3--;

                                    /* Only the first one seems to be a function, the others might
                                     * not be called */
                                    break;
                                }
                            }
                        }
                    } else if (CHandler == handler) {

                        SCOPE_TABLE sctable;

                        if (m_file->readb(&sctable, sizeof(sctable), this->offset(off))) {
                            off += sizeof(sctable.Count);
                            for (unsigned i = 0; i < sctable.Count; i++) {
                                m_file->readb(&sctable.ScopeRecord[0], sizeof(sctable.ScopeRecord[0]),
                                              this->offset(off));
                                ehaddr = m_imageBase + sctable.ScopeRecord[0].HandlerAddress;
                                hdlrs.insert(ehaddr);

                                off += sizeof(sctable.ScopeRecord[0]);
                            }
                        }
                    }
                }
            }
        }
    next:
        ++i;
        offset += sizeof(*Function);
    }

    m_exceptionFilters.insert(m_exceptionFilters.begin(), hdlrs.begin(), hdlrs.end());

    return true;
}

ssize_t PEFile::read(void *buffer, size_t nbyte, off64_t va) const {
    off64_t o = offset(va - getImageBase());
    if (!o) {
        return 0;
    }

    return m_file->read(buffer, nbyte, o);
}

ssize_t PEFile::write(void *buffer, size_t nbyte, off64_t va) {
    off64_t o = offset(va - getImageBase());
    if (!o) {
        return 0;
    }

    m_modified = true;
    return m_file->write(buffer, nbyte, o);
}

PEFile::~PEFile() {
    if (m_modified) {
        if (!rewrite()) {
            llvm::errs() << "Could not rewrite file\n";
        }
    }
}

void PEFile::getFreeSectionHeader(windows::IMAGE_SECTION_HEADER &sec, unsigned size) {
    memset(&sec, 0, sizeof(sec));

    sec.Misc.VirtualSize = size;
    sec.VirtualAddress = 0xdeadbeef;
    sec.SizeOfRawData = size;
    sec.PointerToRawData = 0xbadcafe;
    sec.Characteristics = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE |
                          IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_CODE;

    uint64_t last_va = 0, last_size = 0, last_ptr_data = 0, last_ptr_data_sz = 0;
    for (unsigned i = 0; i < m_peSections.size(); ++i) {
        const IMAGE_SECTION_HEADER &s = m_peSections[i];
        if (s.VirtualAddress > last_va) {
            last_va = s.VirtualAddress;
            last_size = s.Misc.VirtualSize;
        }

        if (s.PointerToRawData > last_ptr_data) {
            last_ptr_data = s.PointerToRawData;
            last_ptr_data_sz = s.SizeOfRawData;
        }
    }

    sec.VirtualAddress = last_va + last_size;
    if (sec.VirtualAddress & 0xfff) {
        sec.VirtualAddress &= ~0xfff;
        sec.VirtualAddress += 0x1000;
    }
    sec.Misc.VirtualSize = size;
    sec.PointerToRawData = last_ptr_data + last_ptr_data_sz;
}

windows::IMAGE_SECTION_HEADER *PEFile::appendSection(const std::string &name, void *data, unsigned size) {
    uint32_t FileAlignment, SectionAlignment;
    if (m_pointerSize == sizeof(uint32_t)) {
        FileAlignment = m_ntHeader32.OptionalHeader.FileAlignment;
        SectionAlignment = m_ntHeader32.OptionalHeader.SectionAlignment;
    } else {
        FileAlignment = m_ntHeader64.OptionalHeader.FileAlignment;
        SectionAlignment = m_ntHeader64.OptionalHeader.SectionAlignment;
    }

    if (size & (FileAlignment - 1)) {
        llvm::errs() << "Size of new section must be multiple of " << m_ntHeader32.OptionalHeader.FileAlignment << "\n";
        return nullptr;
    }

    IMAGE_SECTION_HEADER sec;
    getFreeSectionHeader(sec, size);
    strncpy((char *) &sec.Name, name.c_str(), IMAGE_SIZEOF_SHORT_NAME);

    m_peSections.push_back(sec);

    m_ntHeader32.FileHeader.NumberOfSections++;

    uint32_t AlignedSize = sec.Misc.VirtualSize;
    if (AlignedSize & (SectionAlignment - 1)) {
        AlignedSize &= ~(SectionAlignment - 1);
        AlignedSize += SectionAlignment;
    }

    if (m_pointerSize == sizeof(uint32_t)) {
        m_ntHeader32.OptionalHeader.SizeOfImage += AlignedSize;
    } else {
        m_ntHeader64.OptionalHeader.SizeOfImage += AlignedSize;
    }

    if (!m_file->writeb(data, sec.SizeOfRawData, sec.PointerToRawData)) {
        m_peSections.pop_back();
        return nullptr;
    }

    m_modified = true;
    return &m_peSections.back();
}

uint32_t PEFile::computeChecksum() {
    struct stat stats;
    if (m_file->stat(&stats) < 0) {
        return 0;
    }

    __off_t sz = stats.st_size;

    uint64_t checksum = 0;
    long remainder = sz % sizeof(uint32_t);
    long data_len = sz + ((sizeof(uint32_t) - remainder) * (remainder != 0));

    for (long i = 0; i < data_len / 4; ++i) {
        uint32_t dword = 0;
        uint32_t l = sizeof(dword);
        if (i + 1 == ((data_len / 4) && remainder)) {
            l = remainder;
        }

        if (!m_file->readb(&dword, l, i * 4)) {
            return 0;
        }

        checksum += dword;
        if (checksum > (1LL << 32LL)) {
            checksum = (checksum & 0xffffffff) + (checksum >> 32);
        }
    }

    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum) + (checksum >> 16);
    checksum = checksum & 0xffff;
    return checksum + sz;
}

bool PEFile::rewrite() {
    IMAGE_DATA_DIRECTORY *dir;
    long data_start = 0;
    bool ret = false;

    /**
     * Clear the security directory. Tweaking the PE file
     * invalidates the Authenticode signature, so we don't copy it
     * in the rewritten binary.
     */
    dir = getDataDirectory(IMAGE_DIRECTORY_ENTRY_SECURITY);
    dir->Size = 0;
    dir->VirtualAddress = 0;

    /* NT header */
    unsigned ntHeaderSize, SizeOfHeaders;

    if (m_pointerSize == sizeof(uint32_t)) {
        ntHeaderSize = sizeof(m_ntHeader32);
        m_ntHeader32.OptionalHeader.CheckSum = 0;
        SizeOfHeaders = m_ntHeader32.OptionalHeader.SizeOfHeaders;
    } else {
        ntHeaderSize = sizeof(m_ntHeader64);
        m_ntHeader64.OptionalHeader.CheckSum = 0;
        SizeOfHeaders = m_ntHeader64.OptionalHeader.SizeOfHeaders;
    }

    if (!m_file->writeb(&m_ntHeader32, ntHeaderSize, m_dosHeader.e_lfanew)) {
        goto err1;
    }

    if (m_file->seek(m_dosHeader.e_lfanew + ntHeaderSize) < 0) {
        goto err1;
    }

    /* Section headers */
    for (unsigned i = 0; i < m_peSections.size(); ++i) {
        if (!m_file->writeb(&m_peSections[i], sizeof(IMAGE_SECTION_HEADER))) {
            goto err1;
        }
    }

    data_start = m_file->tell();
    std::cout << std::hex << "Headers ended at:" << data_start << "\n";

    if (data_start > SizeOfHeaders) {
        std::cout << "Headers too big, need to move sections (not implemented yet)\n";
        goto err1;
    }

    /** Recompute the checksum **/
    {
        uint32_t cs = computeChecksum();
        if (m_pointerSize == sizeof(uint32_t)) {
            m_ntHeader32.OptionalHeader.CheckSum = cs;
        } else {
            m_ntHeader64.OptionalHeader.CheckSum = cs;
        }
    }

    if (m_file->seek(m_dosHeader.e_lfanew) < 0) {
        goto err1;
    }

    if (!m_file->writeb(&m_ntHeader32, ntHeaderSize)) {
        goto err1;
    }
    /****************************/

    ret = true;
err1:
    return ret;
}

windows::IMAGE_DATA_DIRECTORY *PEFile::getDataDirectory(unsigned index) {
    if (index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        return nullptr;
    }

    if (m_pointerSize == sizeof(uint32_t)) {
        return &m_ntHeader32.OptionalHeader.DataDirectory[index];
    } else {
        return &m_ntHeader64.OptionalHeader.DataDirectory[index];
    }
}

/***************************************************/
PEFile32::PEFile32(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress)
    : PEFile(file, loaded, loadAddress, sizeof(uint32_t)) {
}

bool PEFile32::initialize() {
    if (!m_file->readb(&m_dosHeader, sizeof(m_dosHeader), m_loadAddress)) {
        return false;
    }

    if (!m_file->readb(&m_ntHeader32, sizeof(m_ntHeader32), m_loadAddress + m_dosHeader.e_lfanew)) {
        return false;
    }

    m_fileHeader = m_ntHeader32.FileHeader;
    m_imageBase = m_ntHeader32.OptionalHeader.ImageBase;
    m_imageSize = m_ntHeader32.OptionalHeader.SizeOfImage;
    m_entryPoint = m_ntHeader32.OptionalHeader.AddressOfEntryPoint + m_imageBase;

    /*
    if (m_ntHeader.OptionalHeader.FileAlignment !=
    m_ntHeader.OptionalHeader.SectionAlignment) {
        llvm::errs() << m_moduleName << " does not have the same on-disk and
    in-memory alignment\n";
    }
    */

    initSections();
    initExports();
    initImports<IMAGE_THUNK_DATA32>();
    initRelocations();
    initExceptions();
    initAdditionalFunctionAddresses();

    return true;
}

/***************************************************/
PEFile64::PEFile64(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress)
    : PEFile(file, loaded, loadAddress, sizeof(uint64_t)) {
}

bool PEFile64::initialize() {
    if (!m_file->readb(&m_dosHeader, sizeof(m_dosHeader), m_loadAddress)) {
        return false;
    }

    if (!m_file->readb(&m_ntHeader64, sizeof(m_ntHeader64), m_loadAddress + m_dosHeader.e_lfanew)) {
        return false;
    }

    m_fileHeader = m_ntHeader64.FileHeader;
    m_imageBase = m_ntHeader64.OptionalHeader.ImageBase;
    m_imageSize = m_ntHeader64.OptionalHeader.SizeOfImage;
    m_entryPoint = m_ntHeader64.OptionalHeader.AddressOfEntryPoint + m_imageBase;

    /*
    if (m_ntHeader.OptionalHeader.FileAlignment !=
    m_ntHeader.OptionalHeader.SectionAlignment) {
        llvm::errs() << m_moduleName << " does not have the same on-disk (" <<
    m_ntHeader.OptionalHeader.FileAlignment
    << ")"
                << " and in-memory alignment (" <<
    m_ntHeader.OptionalHeader.SectionAlignment << ")\n";
    }
    */

    initSections();
    initExports();
    initImports<IMAGE_THUNK_DATA64>();
    initRelocations();
    initExceptions();

    return true;
}
} // namespace vmi
