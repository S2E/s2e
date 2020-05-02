///
/// Copyright (C) 2020, Vitaly Chipounov
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

#ifndef KLEE_UTIL_PAGEPOOL_H
#define KLEE_UTIL_PAGEPOOL_H

#include <atomic>
#include <boost/intrusive_ptr.hpp>
#include <map>
#include <unordered_map>
#include <unordered_set>

#include <klee/util/BitArray.h>
#include <klee/util/PtrUtils.h>

namespace klee {

class Pages;
typedef boost::intrusive_ptr<Pages> PagesPtr;

class Pages {
    static unsigned const PAGE_SIZE = 0x1000;
    std::atomic<uint32_t> m_refCount;
    BitArrayPtr m_pageStatus;
    uint8_t *m_buffer;
    size_t m_size;

private:
    Pages(unsigned numPages);
    ~Pages();

public:
    static PagesPtr create(unsigned numPages) {
        return PagesPtr(new Pages(numPages));
    }

    inline uint8_t *getBuffer() const {
        return m_buffer;
    }

    uint8_t *alloc();

    void free(uint8_t *addr);

    inline bool empty() const {
        return m_pageStatus->isAllOnes();
    }

    inline bool full() const {
        return m_pageStatus->isAllZeros();
    }

    inline unsigned getFreePagesCount() const {
        return m_pageStatus->getSetBitCount();
    }

    INTRUSIVE_PTR_FRIENDS(Pages)
};

INTRUSIVE_PTR_ADD_REL(Pages)

struct PagePoolDesc {
    static const uint64_t POOL_PAGE_COUNT;
    static const uint64_t POOL_PAGE_SIZE;

    uintptr_t addr;

    PagePoolDesc() : addr(0) {
    }

    bool operator()(uintptr_t a, uintptr_t b) const {
        return a + POOL_PAGE_SIZE <= b;
    }
};

class PagePool;
typedef boost::intrusive_ptr<PagePool> PagePoolPtr;

///
/// \brief The PagePool class manages a pool of 4KB pages
/// that can be allocated individually.
///
/// Calling mmap for single pages is inefficient. Instead, this
/// class uses mmap to allocate larger chunks at once and maintains
/// a bitmap to return individual pages to callers.
///
class PagePool {
    std::atomic<uint32_t> m_refCount;
    std::map<uintptr_t, PagesPtr, PagePoolDesc> m_map;
    std::unordered_map<uintptr_t, PagesPtr> m_freePages;
    PagesPtr m_cachedPages;

    static PagePoolPtr s_pool;

    PagePool() : m_refCount(0) {
    }

    PagesPtr allocatePages();

public:
    static PagePoolPtr create() {
        return PagePoolPtr(new PagePool());
    }

    uint8_t *alloc();

    void free(uint8_t *_ptr);

    static PagePoolPtr get() {
        return s_pool;
    }

    inline int getPoolCount() const {
        return m_map.size();
    }

    unsigned getFreePages() const;

    INTRUSIVE_PTR_FRIENDS(PagePool)
};

INTRUSIVE_PTR_ADD_REL(PagePool)

} // namespace klee

#endif
