///
/// Copyright (C) 2014, Cyberhaven
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

#ifndef VMI_DECREE_FILE_H

#define VMI_DECREE_FILE_H

#include "Decree.h"
#include "ExecutableFile.h"

namespace vmi {

class DecreeFile : public ExecutableFile {

private:
    std::string m_moduleName;
    uint64_t m_imageBase;
    uint64_t m_imageSize;
    uint64_t m_entryPoint;

    decree::DECREE32_hdr m_header;

    std::vector<decree::DECREE32_phdr> m_phdrs;
    Sections m_sections;

    bool initialize(void);
    int getSectionIndex(uint64_t va) const;

protected:
    DecreeFile(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress);

public:
    static std::shared_ptr<ExecutableFile> get(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress);

    virtual ~DecreeFile();

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

    const Sections &getSections() const {
        return m_sections;
    }

    virtual bool getSymbolAddress(const std::string &name, uint64_t *address) {
        return false;
    }

    virtual bool getSourceInfo(uint64_t addr, std::string &source, uint64_t &line, std::string &function) {
        return false;
    }

    virtual unsigned getPointerSize() const {
        return sizeof(uint32_t);
    }

    virtual ssize_t read(void *buffer, size_t nbyte, off64_t offset) const;

    virtual uint32_t getCheckSum() const {
        return 0;
    }
};
} // namespace vmi

#endif
