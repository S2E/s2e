///
/// Copyright (C) 2011-2016, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
        m_sharedBuffer = NULL;
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
    S2ESynchronizedObject(const char *name = NULL) : sync(S2ESynchronizedObjectInternal(sizeof(T), name)) {
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
}

#endif
