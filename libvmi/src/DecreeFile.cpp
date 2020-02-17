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

#include <vmi/Decree.h>
#include <vmi/DecreeFile.h>

#include <sstream>

namespace vmi {

DecreeFile::DecreeFile(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress)
    : ExecutableFile(file, loaded, loadAddress), m_imageBase(0), m_imageSize(0), m_entryPoint(0) {
    m_moduleName = llvm::sys::path::filename(std::string(m_file->getName()));
}

DecreeFile::~DecreeFile() {
}

std::shared_ptr<ExecutableFile> DecreeFile::get(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress) {
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

    std::shared_ptr<DecreeFile> f{new DecreeFile(file, loaded, loadAddress)};
    if (!f->initialize()) {
        return nullptr;
    }
    return f;
}

bool DecreeFile::initialize(void) {
    if (!m_file->readb(&m_header, sizeof(m_header), m_loadAddress)) {
        return false;
    }

    auto imageSize = 0LL;

    for (unsigned i = 0; i < m_header.c_phnum; ++i) {
        SectionDescriptor sd;
        decree::DECREE32_phdr phdr;

        unsigned offs = m_loadAddress + m_header.c_phoff + i * sizeof(phdr);
        if (!m_file->readb(&phdr, sizeof(phdr), offs)) {
            return false;
        }

        if (phdr.p_type == decree::PT_LOAD) {
            imageSize += phdr.p_memsz;
            sd.loadable = true;
        }

        sd.readable = phdr.p_flags & decree::CPF_R;
        sd.writable = phdr.p_flags & decree::CPF_W;
        sd.executable = phdr.p_flags & decree::CPF_X;

        std::stringstream ss;
        ss << "section_" << i;

        sd.start = phdr.p_vaddr;
        sd.physStart = phdr.p_paddr;
        sd.size = phdr.p_filesz;
        sd.virtualSize = phdr.p_memsz;
        sd.name = ss.str();

        m_sections.push_back(sd);
        m_phdrs.push_back(phdr);
    }

    m_entryPoint = m_header.c_entry;
    m_imageSize = imageSize;

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

    if (!sd.loadable) {
        return 0;
    } else {
        const decree::DECREE32_phdr &hdr = m_phdrs[idx];
        off64_t offset = va - hdr.p_vaddr + hdr.p_offset;
        return m_file->read(buffer, maxSize, offset);
    }
}
} // namespace vmi
