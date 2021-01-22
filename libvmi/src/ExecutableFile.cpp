///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
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

#include <vmi/DecreeFile.h>
#include <vmi/ELFFile.h>
#include <vmi/PEFile.h>

namespace vmi {

ExecutableFile::ExecutableFile(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress)
    : m_file(file), m_loaded(loaded), m_loadAddress(loadAddress), m_functionsInited(false) {
}

ExecutableFile::~ExecutableFile() {
}

std::shared_ptr<ExecutableFile> ExecutableFile::get(std::shared_ptr<FileProvider> file, bool loaded,
                                                    uint64_t loadAddress) {
    std::shared_ptr<ExecutableFile> ret;

    ret = PEFile::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = DecreeFile::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = ELFFile32::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = ELFFile64::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    return nullptr;
}

static const int MAX_PATTERN_SIZE = 32;

struct Prolog {
    int size;
    const uint8_t pattern[MAX_PATTERN_SIZE];
};

static const Prolog s_prologs[] = {
    // mov edx, 0FFFFFFFh shows up in MS Office mso.dll in a few functions
    {9,
     {
         0xba, 0xff, 0xff, 0xff, 0x0f, // mov edx, 0FFFFFFFh
         0x55,                         // push ebp
         0x8b, 0xec,                   // mov ebp, esp
         0x81, 0xec                    // sub esp, ...
     }},
    {9,
     {
         0x55,                         // push ebp
         0xba, 0xff, 0xff, 0xff, 0x0f, // mov edx, 0FFFFFFFh
         0x8b, 0xec,                   // mov ebp, esp
         0x81, 0xec                    // sub esp, ...
     }},
    {9,
     {
         0x55,                         // push ebp
         0x8b, 0xec,                   // mov ebp, esp
         0xba, 0xff, 0xff, 0xff, 0x0f, // mov edx, 0FFFFFFFh
         0x81, 0xec                    // sub esp, ...
     }},

    // Standard prolog
    {5,
     {
         0x55,       // push ebp
         0x8b, 0xec, // mov ebp, esp
         0x81, 0xec  // sub esp, ...
     }},

    // This one is common on Windows
    {5,
     {
         0x8b, 0xff, // mov edi, edi
         0x55,       // push ebp
         0x8b, 0xec, // mov ebp, esp
     }},

    {3,
     {
         0x55,       // push ebp
         0x8b, 0xec, // mov ebp, esp
     }},
    {0, {}}};

const FunctionAddresses &ExecutableFile::guessFunctionAddresses() const {
    if (m_functionsInited) {
        return m_functions;
    }

    for (auto &s : getSections()) {
        if (!s.executable) {
            continue;
        }

        for (auto i = 0; i < s.size; ++i) {
            uint8_t buffer[MAX_PATTERN_SIZE];
            auto size = sizeof(buffer);
            if (read(buffer, size, s.start + i) != size) {
                break;
            }

            for (auto p = &s_prologs[0]; p->size; ++p) {
                if (!memcmp(buffer, p->pattern, p->size)) {
                    m_functions.push_back(s.start + i);
                    i += p->size - 1;
                    break;
                }
            }
        }
    }

    m_functionsInited = true;
    return m_functions;
}

} // namespace vmi
