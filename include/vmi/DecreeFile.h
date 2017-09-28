///
/// Copyright (C) 2014, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
    DecreeFile(FileProvider *file, bool loaded, uint64_t loadAddress);

public:
    static ExecutableFile *get(FileProvider *file, bool loaded, uint64_t loadAddress);

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
};
}

#endif
