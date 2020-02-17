///
/// Copyright (C) 2011-2016, Dependable Systems Laboratory, EPFL
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

#ifndef S2E_SYNCHRONIZATION_H
#define S2E_SYNCHRONIZATION_H

#include <inttypes.h>
#include <string>

namespace s2e {

class S2ESynchronizedObjectInternal {
private:
    uint8_t *m_sharedBuffer;
    unsigned m_size;
    unsigned m_headerSize;
    int m_fd;

    S2ESynchronizedObjectInternal() {
        m_sharedBuffer = nullptr;
        m_size = 0;
        m_headerSize = 0;
        m_fd = -1;
    }

protected:
    int getFd() const {
        return m_fd;
    }

public:
    S2ESynchronizedObjectInternal(unsigned size, const char *name);
    ~S2ESynchronizedObjectInternal();

    void lock();
    void release();
    void *acquire();
    void *tryAcquire();

    // Unsynchronized function to get the buffer
    void *get() const {
        return ((uint8_t *) m_sharedBuffer) + m_headerSize;
    }
};

/**
 *  This class creates a shared memory buffer on which
 *  all S2E processes can perform read/write requests.
 */
template <class T> class S2ESynchronizedObject {
private:
    S2ESynchronizedObjectInternal sync;

public:
    S2ESynchronizedObject(const char *name = nullptr) : sync(S2ESynchronizedObjectInternal(sizeof(T), name)) {
        new (sync.get()) T();
    }

    ~S2ESynchronizedObject() {
        T *t = (T *) sync.get();
        t->~T();
    }

    T *acquire() {
        return (T *) sync.acquire();
    }

    // Returns null if could not lock the object
    T *tryAcquire() {
        return (T *) sync.tryAcquire();
    }

    void release() {
        sync.release();
    }

    T *get() const {
        return (T *) sync.get();
    }
};
} // namespace s2e

#endif
