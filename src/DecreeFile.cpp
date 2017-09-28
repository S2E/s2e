///
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <vmi/Decree.h>
#include <vmi/DecreeFile.h>

#include <sstream>

namespace vmi {

DecreeFile::DecreeFile(FileProvider *file, bool loaded, uint64_t loadAddress)
    : ExecutableFile(file, loaded, loadAddress), m_imageBase(0), m_imageSize(0), m_entryPoint(0) {
    m_moduleName = llvm::sys::path::filename(std::string(m_file->getName()));
}

DecreeFile::~DecreeFile() {
}

ExecutableFile *DecreeFile::get(FileProvider *file, bool loaded, uint64_t loadAddress) {
    decree::DECREE32_hdr hdr;

    if (!file->readb(&hdr, sizeof(hdr), loadAddress)) {
        return nullptr;
    }

    if (hdr.ci_mag0 != 0x7f || hdr.ci_mag1 != 'C' || hdr.ci_mag2 != 'G' || hdr.ci_mag3 != 'C' || hdr.ci_class != 1 ||
        hdr.ci_data != 1 || hdr.ci_version != 1 || hdr.ci_osabi != 'C' || hdr.ci_abivers != 1 || hdr.c_type != 2 ||
        hdr.c_machine != 3 || hdr.c_version != 1 || hdr.c_flags != 0 ||
        hdr.c_phentsize != sizeof(decree::DECREE32_phdr) || hdr.c_phnum < 1 ||
        hdr.c_phnum > 65536U / sizeof(decree::DECREE32_phdr)) {
        return nullptr;
    }

    DecreeFile *f = new DecreeFile(file, loaded, loadAddress);
    if (!f->initialize()) {
        delete f;
        f = nullptr;
    }

    return f;
}

bool DecreeFile::initialize(void) {
    if (!m_file->readb(&m_header, sizeof(m_header), m_loadAddress)) {
        return false;
    }

    for (unsigned i = 0; i < m_header.c_phnum; ++i) {
        SectionDescriptor sd;
        decree::DECREE32_phdr phdr;

        unsigned offs = m_loadAddress + m_header.c_phoff + i * sizeof(phdr);
        if (!m_file->readb(&phdr, sizeof(phdr), offs)) {
            return false;
        }

        if (phdr.p_type != decree::PT_LOAD) {
            continue;
        }

        sd.setRead(phdr.p_flags & decree::CPF_R);
        sd.setWrite(phdr.p_flags & decree::CPF_W);
        sd.setExecute(phdr.p_flags & decree::CPF_X);

        assert(phdr.p_memsz >= phdr.p_filesz);

        std::stringstream ss;
        ss << "section_" << i;

        /**
         * Handle sections that contain data
         */
        if (phdr.p_memsz > 0) {
            decree::DECREE32_phdr nphdr = phdr;

            sd.size = phdr.p_filesz;
            sd.start = phdr.p_vaddr;
            sd.hasData = true;
            sd.name = ss.str();

            nphdr.p_memsz = phdr.p_filesz;

            m_sections.push_back(sd);
            m_phdrs.push_back(nphdr);

            m_imageSize += sd.size;

            if ((m_imageBase == 0) || (sd.start < m_imageBase)) {
                m_imageBase = sd.start;
            }
        }

        /**
         * If the section has uninitialized data, we need to create
         * a corresponding section (bss).
         */
        if (phdr.p_memsz > phdr.p_filesz) {
            SectionDescriptor bss = sd;
            decree::DECREE32_phdr bss_phdr = phdr;

            bss_phdr.p_vaddr = phdr.p_vaddr + phdr.p_filesz;
            bss_phdr.p_memsz = phdr.p_memsz - phdr.p_filesz;
            bss_phdr.p_filesz = 0;
            bss_phdr.p_offset = 0;

            bss.size = bss_phdr.p_memsz;
            bss.start = bss_phdr.p_vaddr;
            bss.hasData = false;

            ss << "_bss";
            bss.name = ss.str();

            m_sections.push_back(bss);
            m_phdrs.push_back(bss_phdr);

            if ((m_imageBase == 0) || (bss.start < m_imageBase)) {
                m_imageBase = bss.start;
            }
        }
    }

    m_entryPoint = m_header.c_entry;

    return true;
}

int DecreeFile::getSectionIndex(uint64_t va) const {
    for (unsigned i = 0; i < m_phdrs.size(); ++i) {
        const decree::DECREE32_phdr &hdr = m_phdrs[i];
        if (va >= hdr.p_vaddr && va < hdr.p_vaddr + hdr.p_memsz) {
            return i;
        }
    }

    return -1;
}

ssize_t DecreeFile::read(void *buffer, size_t nbyte, off64_t va) const {
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
        const decree::DECREE32_phdr &hdr = m_phdrs[idx];
        off64_t offset = va - hdr.p_vaddr + hdr.p_offset;
        return m_file->read(buffer, maxSize, offset);
    }
}
}
