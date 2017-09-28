///
/// Copyright (c) 2017 Adrian Herrera
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

#ifndef VMI_ELF_FILE_H
#define VMI_ELF_FILE_H

extern "C" {
#include <libelf.h>
}

#include <sstream>
#include <vector>

#include <llvm/Support/raw_ostream.h>

#include "ExecutableFile.h"

namespace vmi {

///
/// \brief Abstract base class for Executable and Linkable Format (ELF) files.
///
/// Internally it uses libelf to parse and query the ELF file. libelf provides is a C library that provides different
/// types and functions for 32 and 64 bit ELF files. To abstract away these difference, this class uses templates and
/// polymorphism to ensure that the correct libelf functions are called with the correct types.
///
/// \tparam EhdrT The ELF header type. The ELF header format is different depending on whether the ELF file is 32 or 64
///               bits
/// \tparam PhdrT The program header type. The program header format is different depending on whether the ELF file is
///               32 or 64 bits
///
template <typename EhdrT, typename PhdrT> class ELFFile : public ExecutableFile {
private:
    char *m_elfBuffer;
    Elf *m_elf;

    uint64_t m_imageBase;
    uint64_t m_imageSize;
    uint64_t m_entryPoint;
    uint64_t m_pointerSize;
    std::string m_moduleName;
    Sections m_sections;

    std::vector<PhdrT> m_phdrs;

    bool initLibelf();
    int getSectionIndex(uint64_t va) const;

protected:
    virtual EhdrT *getEhdr(Elf *elf) const = 0;
    virtual PhdrT *getPhdr(Elf *elf) const = 0;

public:
    ELFFile(FileProvider *file, bool loaded, uint64_t loadAddress, unsigned pointerSize);
    virtual ~ELFFile();

    template <typename ELF_T, unsigned ELFClass>
    static ELF_T *get(FileProvider *file, bool loaded, uint64_t loadAddress);

    bool initialize();

    virtual std::string getModuleName() const;
    virtual uint64_t getImageBase() const;
    virtual uint64_t getImageSize() const;
    virtual uint64_t getEntryPoint() const;
    virtual bool getSymbolAddress(const std::string &name, uint64_t *address);
    virtual bool getSourceInfo(uint64_t addr, std::string &source, uint64_t &line, std::string &function);
    virtual unsigned getPointerSize() const;
    virtual ssize_t read(void *buffer, size_t nbyte, off64_t va) const;
    virtual const Sections &getSections() const;
};

///
/// \brief 32-bit ELF file.
///
class ELFFile32 : public ELFFile<Elf32_Ehdr, Elf32_Phdr> {
protected:
    virtual Elf32_Ehdr *getEhdr(Elf *elf) const;
    virtual Elf32_Phdr *getPhdr(Elf *elf) const;

public:
    ELFFile32(FileProvider *file, bool loaded, uint64_t loadAddress);

    static ELFFile32 *get(FileProvider *file, bool loaded, uint64_t loadAddress);
};

///
/// \brief 64-bit ELF file.
///
class ELFFile64 : public ELFFile<Elf64_Ehdr, Elf64_Phdr> {
protected:
    virtual Elf64_Ehdr *getEhdr(Elf *elf) const;
    virtual Elf64_Phdr *getPhdr(Elf *elf) const;

public:
    ELFFile64(FileProvider *file, bool loaded, uint64_t loadAddress);

    static ELFFile64 *get(FileProvider *file, bool loaded, uint64_t loadAddress);
};

/***************************************************/

template <typename EhdrT, typename PhdrT>
ELFFile<EhdrT, PhdrT>::ELFFile(FileProvider *file, bool loaded, uint64_t loadAddress, unsigned pointerSize)
    : ExecutableFile(file, loaded, loadAddress), m_elf(nullptr), m_imageBase(0), m_imageSize(0), m_entryPoint(0),
      m_pointerSize(pointerSize), m_moduleName(llvm::sys::path::filename(std::string(file->getName()))) {
}

template <typename EhdrT, typename PhdrT> ELFFile<EhdrT, PhdrT>::~ELFFile() {
    if (m_elf) {
        elf_end(m_elf);
        m_elf = nullptr;
    }

    if (m_elfBuffer) {
        delete[] m_elfBuffer;
    }
}

template <typename EhdrT, typename PhdrT>
template <typename ELF_T, unsigned ELFClass>
ELF_T *ELFFile<EhdrT, PhdrT>::get(FileProvider *file, bool loaded, uint64_t loadAddress) {
    uint8_t e_ident[EI_NIDENT];

    // Read the ELF header's e_ident field
    if (!file->readb(e_ident, EI_NIDENT, loadAddress)) {
        return nullptr;
    }

    // Perform some basic checks on e_ident to ensure that the file looks like an ELF
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 || e_ident[EI_MAG2] != ELFMAG2 ||
        e_ident[EI_MAG3] != ELFMAG3 || e_ident[EI_CLASS] == ELFCLASSNONE || e_ident[EI_DATA] == ELFDATANONE ||
        e_ident[EI_VERSION] != EV_CURRENT) {
        return nullptr;
    }

    // Check that the ELF class is the one that we are expecting
    if (e_ident[EI_CLASS] == ELFClass) {
        ELF_T *ret = new ELF_T(file, loaded, loadAddress);

        if (ret && !ret->initialize()) {
            delete ret;
            ret = nullptr;
        }

        return ret;
    } else if (e_ident[EI_CLASS] > ELFCLASS64) {
        // The ELF may still be valid, it may just be of a different class. So only print the error message if the
        // ELF cannot possibly be valid
        std::string moduleName = llvm::sys::path::filename(std::string(file->getName()));
        llvm::errs() << moduleName << " has unsupported architecture\n";
    }

    return nullptr;
}

template <typename EhdrT, typename PhdrT> bool ELFFile<EhdrT, PhdrT>::initLibelf() {
    // Initialize the ELF version
    if (elf_version(EV_CURRENT) == EV_NONE) {
        return false;
    }

    // Get the size of the file
    struct stat stats;
    if (m_file->stat(&stats) < 0) {
        return false;
    }

    off_t size = stats.st_size;

    // Read the entire buffer so that we can pass it to libelf
    m_elfBuffer = new char[size];
    if (!m_elfBuffer) {
        return false;
    }

    if (!m_file->readb(m_elfBuffer, size, m_loadAddress)) {
        goto error;
    }

    // Create the libelf Elf struct
    m_elf = elf_memory(m_elfBuffer, size);
    if (!m_elf) {
        goto error;
    }

    // Check that the ELF file is valid
    if (elf_kind(m_elf) != ELF_K_ELF) {
        goto error;
    }

    return true;

error:
    delete[] m_elfBuffer;
    m_elfBuffer = nullptr;

    return false;
}

template <typename EhdrT, typename PhdrT> bool ELFFile<EhdrT, PhdrT>::initialize() {
    if (!initLibelf()) {
        return false;
    }

    // ELF header
    EhdrT *ehdr = getEhdr(m_elf);
    if (!ehdr) {
        return false;
    }

    // Number of ELF program headers
    size_t numPhdrs;
    if (elf_getphdrnum(m_elf, &numPhdrs) != 0) {
        return false;
    }

    uint64_t imageBase = 0;
    uint64_t imageSize = 0;
    PhdrT *phdr = getPhdr(m_elf);

    for (unsigned i = 0; i < numPhdrs; ++i, ++phdr) {
        // Only segments of type PT_LOAD are loaded into memory
        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        // Use the memory image size to account for any bss data that will not exist on disk
        imageSize += phdr->p_memsz;

        // The image base will be the lowest loadable address
        if ((imageBase == 0) || (phdr->p_vaddr < imageBase)) {
            imageBase = phdr->p_vaddr;
        }

        // Create a section descriptor for sections that contain data at runtime
        if (phdr->p_memsz > 0) {
            SectionDescriptor sd;

            std::stringstream ss;
            ss << "section_" << i;

            sd.setRead(phdr->p_flags & PF_R);
            sd.setWrite(phdr->p_flags & PF_W);
            sd.setExecute(phdr->p_flags & PF_X);

            sd.start = phdr->p_vaddr;
            sd.size = phdr->p_filesz;
            sd.hasData = true;
            sd.name = ss.str();

            m_sections.push_back(sd);
            m_phdrs.push_back(*phdr);

            // If the section has uninitialized data, we need to create a corresponding section (bss)
            if (phdr->p_memsz > phdr->p_filesz) {
                SectionDescriptor bss = sd;

                ss << "_bss";

                bss.start += phdr->p_filesz;
                bss.size = phdr->p_memsz - phdr->p_filesz;
                bss.hasData = false;
                bss.name = ss.str();

                m_sections.push_back(bss);
            }
        }
    }

    m_imageBase = imageBase;
    m_imageSize = imageSize;
    m_entryPoint = ehdr->e_entry;

    return true;
}

template <typename EhdrT, typename PhdrT> std::string ELFFile<EhdrT, PhdrT>::getModuleName() const {
    return m_moduleName;
}

template <typename EhdrT, typename PhdrT> uint64_t ELFFile<EhdrT, PhdrT>::getImageBase() const {
    return m_imageBase;
}

template <typename EhdrT, typename PhdrT> uint64_t ELFFile<EhdrT, PhdrT>::getImageSize() const {
    return m_imageSize;
}

template <typename EhdrT, typename PhdrT> uint64_t ELFFile<EhdrT, PhdrT>::getEntryPoint() const {
    return m_entryPoint;
}

template <typename EhdrT, typename PhdrT>
bool ELFFile<EhdrT, PhdrT>::getSymbolAddress(const std::string &name, uint64_t *address) {
    return false;
}

template <typename EhdrT, typename PhdrT>
bool ELFFile<EhdrT, PhdrT>::getSourceInfo(uint64_t addr, std::string &source, uint64_t &line, std::string &function) {
    return false;
}

template <typename EhdrT, typename PhdrT> unsigned ELFFile<EhdrT, PhdrT>::getPointerSize() const {
    return m_pointerSize;
}

template <typename EhdrT, typename PhdrT> int ELFFile<EhdrT, PhdrT>::getSectionIndex(uint64_t va) const {
    for (unsigned i = 0; i < m_phdrs.size(); ++i) {
        const PhdrT &phdr = m_phdrs[i];

        if (va >= phdr.p_vaddr && va < phdr.p_vaddr + phdr.p_memsz) {
            return i;
        }
    }

    return -1;
}

template <typename EhdrT, typename PhdrT>
ssize_t ELFFile<EhdrT, PhdrT>::read(void *buffer, size_t nbyte, off64_t va) const {
    int idx = getSectionIndex(va);
    if (idx < 0) {
        return 0;
    }

    const SectionDescriptor &sd = m_sections[idx];
    off64_t end = sd.start + sd.size;
    off64_t rend = va + nbyte;
    size_t overflow = rend - end;
    ssize_t maxSize = std::min(nbyte, nbyte - overflow);

    if (!sd.hasData) {
        memset(buffer, 0, maxSize);

        return maxSize;
    } else {
        const PhdrT &phdr = m_phdrs[idx];
        off64_t offset = va - phdr.p_vaddr + phdr.p_offset;

        return m_file->read(buffer, maxSize, offset);
    }
}

template <typename EhdrT, typename PhdrT> const Sections &ELFFile<EhdrT, PhdrT>::getSections() const {
    return m_sections;
}

/***************************************************/

ELFFile32::ELFFile32(FileProvider *file, bool loaded, uint64_t loadAddress)
    : ELFFile(file, loaded, loadAddress, sizeof(uint32_t)) {
}

ELFFile32 *ELFFile32::get(FileProvider *file, bool loaded, uint64_t loadAddress) {
    return ELFFile::get<ELFFile32, ELFCLASS32>(file, loaded, loadAddress);
}

Elf32_Ehdr *ELFFile32::getEhdr(Elf *elf) const {
    return elf32_getehdr(elf);
}

Elf32_Phdr *ELFFile32::getPhdr(Elf *elf) const {
    return elf32_getphdr(elf);
}

/***************************************************/

ELFFile64::ELFFile64(FileProvider *file, bool loaded, uint64_t loadAddress)
    : ELFFile(file, loaded, loadAddress, sizeof(uint64_t)) {
}

ELFFile64 *ELFFile64::get(FileProvider *file, bool loaded, uint64_t loadAddress) {
    return ELFFile::get<ELFFile64, ELFCLASS64>(file, loaded, loadAddress);
}

Elf64_Ehdr *ELFFile64::getEhdr(Elf *elf) const {
    return elf64_getehdr(elf);
}

Elf64_Phdr *ELFFile64::getPhdr(Elf *elf) const {
    return elf64_getphdr(elf);
}

} // namespace vmi

#endif
