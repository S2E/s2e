///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
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

#include <fstream>
#include <iomanip>
#include <llvm/Support/raw_ostream.h>
#include <sstream>
#include <stdio.h>
#include <vmi/FileProvider.h>
#include <vmi/pdb.h>

namespace vmi {

using namespace vmi::windows;

PDBReader::PDBReader(FileProvider *fp) {
    m_fp = fp;
}

bool PDBReader::msfLoadPages(bytearray_t &result, const uint32_t *pagePointers, unsigned nPages) {
    result.clear();
    result.resize(nPages * m_header.dwPageSize);

    for (unsigned i = 0; i < nPages; ++i) {
        unsigned offset = m_header.dwPageSize * i;
        bool ret = m_fp->readb(&result[offset], m_header.dwPageSize, pagePointers[i] * m_header.dwPageSize);
        if (!ret) {
            llvm::errs() << "Could not read page " << pagePointers[i] << "\n";
            return false;
        }
    }

    return true;
}

void PDBReader::computeStreamPointers(MSF_ROOT *root) {
    uint32_t *streamPointers = &root->dwStreamSizes[root->dwStreamCount];
    m_streamPointers.resize(root->dwStreamCount);

    for (unsigned i = 0; i < root->dwStreamCount; ++i) {
        unsigned pageCount = ConvertSizeToPageCount(root->dwStreamSizes[i]);

        m_streamPointers[i].resize(pageCount);
        for (unsigned j = 0; j < pageCount; ++j) {
            m_streamPointers[i][j] = *streamPointers;
            streamPointers++;
        }

        m_streamSizes.push_back(root->dwStreamSizes[i]);
    }
}

bool PDBReader::loadStream(bytearray_t &result, unsigned streamIndex) {
    if (streamIndex >= m_streamPointers.size()) {
        return false;
    }

    if (!m_streamSizes[streamIndex]) {
        return false;
    }

    unsigned pages = ConvertSizeToPageCount(m_streamSizes[streamIndex]);
    assert(m_streamPointers[streamIndex].size() == pages);

    bool b = msfLoadPages(result, &m_streamPointers[streamIndex][0], pages);
    if (!b) {
        return false;
    }

    result.resize(m_streamSizes[streamIndex]);
    return true;
}

bool PDBReader::dumpImpExp() {
    const bytearray_t &impexp = m_streams[PDB_STREAM_IMPEXP];

    unsigned offset = 0;
    std::stringstream ss;
    while (offset < impexp.size()) {
        const PDB_IMPEXP_HDR *hdr = reinterpret_cast<const PDB_IMPEXP_HDR *>(&impexp[offset]);
        ss << std::left << std::setfill(' ') << std::setw(40) << (char *) hdr->Name;
        ss << std::setw(8) << std::setfill('0') << "  0x" << std::hex << (unsigned) hdr->Unknown1;
        ss << "  0x" << std::hex << std::setw(8) << std::right << std::setfill('0') << (unsigned) hdr->Unknown2;
        ss << "  0x" << std::hex << std::setw(8) << std::right << std::setfill('0') << (unsigned) hdr->Unknown3;
        ss << "  0x" << std::hex << std::setw(4) << std::right << std::setfill('0') << (unsigned) hdr->Unknown4;

        offset += hdr->Size;
        uint16_t extra = *reinterpret_cast<const uint16_t *>(&impexp[offset]);
        ss << "  0x" << std::hex << std::setw(4) << std::right << std::setfill('0') << (unsigned) extra;
        ss << "\n";
        offset += 2;
    }

    llvm::outs() << ss.str() << "\n";

    return true;
}

bool PDBReader::initialize() {
    if (!m_fp->read(&m_header, sizeof(m_header), 0)) {
        llvm::errs() << "Could not read header\n";
        return false;
    }

    if (memcmp(m_header.szMagic, MSF_SIGNATURE_700, sizeof(m_header.szMagic))) {
        llvm::errs() << "Invalid header magic\n";
        return false;
    }

    llvm::outs() << "Root pointers: " << m_header.dwRootPointers << "\n";
    llvm::outs() << "Root size: " << m_header.dwRootSize << "\n";

    unsigned rootSizeInPages = ConvertSizeToPageCount(m_header.dwRootSize);

    unsigned rootPointerPageCount = ConvertSizeToPageCount(rootSizeInPages * sizeof(uint32_t));

    llvm::outs() << "rootSizeInPages: " << rootSizeInPages << "\n";
    llvm::outs() << "rootPointerPageCount: " << rootPointerPageCount << "\n";

    bytearray_t rootPointers;
    bool ret = msfLoadPages(rootPointers, m_header.dwRootPointers, rootPointerPageCount);
    if (!ret) {
        return false;
    }

    bytearray_t root;
    ret = msfLoadPages(root, (uint32_t *) &rootPointers[0], rootSizeInPages);
    if (!ret) {
        return false;
    }

    MSF_ROOT *msfRoot = reinterpret_cast<MSF_ROOT *>(&root[0]);
    computeStreamPointers(msfRoot);

#if 0
    llvm::outs() << "Stream count: " << msfRoot->dwStreamCount << "\n";
    for (unsigned i = 0; i < msfRoot->dwStreamCount; ++i) {
        llvm::outs() << msfRoot->dwStreamSizes[i] << " ";
    }
    llvm::outs() << "\n";
#endif

    m_streams.resize(msfRoot->dwStreamCount);

    std::stringstream ss;
    for (unsigned i = 0; i < msfRoot->dwStreamCount; ++i) {
        loadStream(m_streams[i], i);
    }

#if 0
    ss << "Stream " << i << "\n  ";

    if () {
        std::stringstream p;
        p << "/tmp/stream" << i;
        std::ofstream ofs(p.str().c_str(), std::ios_base::binary);
        ofs.write((char *)&m_streams[i][0], m_streams[i].size());
    }

    ss << "\n";

    llvm::outs() << ss.str() << "\n";



    /*std::stringstream ss;
    for (unsigned i = 0; i < rootPointers.size(); ++i) {
        ss << std::hex << (unsigned) rootPointers[i] << " ";
    }

    llvm::outs() << ss.str() << "\n";*/
#endif

    return true;
}
} // namespace vmi

using namespace vmi;

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s file.pdb\n", argv[0]);
        return -1;
    }

    llvm::sys::Path path(argv[1]);
    FileSystemFileProvider *fp = new FileSystemFileProvider(path);
    if (!fp->open(false)) {
        llvm::errs() << "Could not open " << path.c_str() << "\n";
        return -1;
    }

    PDBReader reader(fp);
    reader.initialize();
    reader.dumpImpExp();

    delete fp;
}
