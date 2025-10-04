/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2017, Cyberhaven
 * Copyright (c) 2012, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef KLEE_ConcreteBuffer_H
#define KLEE_ConcreteBuffer_H

#include <klee/Common.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <boost/intrusive_ptr.hpp>
#include <string.h>

#include <klee/util/PtrUtils.h>

#include <klee/util/PagePool.h>

namespace klee {

class ConcreteBuffer;
typedef boost::intrusive_ptr<ConcreteBuffer> ConcreteBufferPtr;

/**
 * Stores a reference-counted concrete buffer.
 * Allows to share a common concrete buffer between different
 * ObjectStates (e.g., when splitting a big object into
 * smaller ones).
 */
class ConcreteBuffer : public RefCount {
    uint8_t *m_buffer;
    unsigned m_size;

    uint8_t *osAlloc(unsigned size) const {
        void *ret = (uint8_t *) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ret == MAP_FAILED) {
            *klee_warning_stream << "Memory allocation failed: " << errno << "\n";
            return nullptr;
        }
        return (uint8_t *) ret;
    }

    void osFree(void *region, unsigned size) const {
        munmap(region, size);
    }

    uint8_t *allocateBuffer(unsigned size) {
        if (size == PAGE_SIZE) {
            return PagePool::get()->alloc();
        } else if ((size % PAGE_SIZE) == 0) {
            uint8_t *ret = osAlloc(size);
            if (!ret) {
                exit(-1);
            }
            return ret;
        } else {
            return new uint8_t[size];
        }
    }

    ConcreteBuffer(size_t size) : m_buffer(allocateBuffer(size)), m_size(size) {
        memset(m_buffer, 0, size);
    }

    ConcreteBuffer(const ConcreteBufferPtr &b) : m_buffer(allocateBuffer(b->m_size)), m_size(b->m_size) {
        memcpy(m_buffer, b->m_buffer, b->m_size);
    }

    ~ConcreteBuffer() {
        if (m_size == PAGE_SIZE) {
            PagePool::get()->free(m_buffer);
        } else if ((m_size % PAGE_SIZE) == 0) {
            osFree(m_buffer, m_size);
        } else {
            delete[] m_buffer;
        }
    }

public:
    static const unsigned PAGE_SIZE = 0x1000;

    static ConcreteBufferPtr create(size_t size) {
        return ConcreteBufferPtr(new ConcreteBuffer(size));
    }

    static ConcreteBufferPtr create(const ConcreteBufferPtr &b) {
        return ConcreteBufferPtr(new ConcreteBuffer(b));
    }

    inline uint8_t *get() const {
        return m_buffer;
    }

    unsigned size() const {
        return m_size;
    }
};

} // namespace klee

#endif
