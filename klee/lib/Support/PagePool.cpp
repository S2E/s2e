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

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <klee/util/PagePool.h>

namespace klee {

PagePoolPtr PagePool::s_pool = PagePool::create();

const uint64_t PagePoolDesc::POOL_PAGE_COUNT = 2 * 1024 * 1024 / 4096;
const uint64_t PagePoolDesc::POOL_PAGE_SIZE = PagePoolDesc::POOL_PAGE_COUNT * 4096;

Pages::Pages(unsigned numPages) : m_refCount(0), m_buffer(nullptr), m_size(0) {
    assert(numPages > 0);
    m_size = numPages * PAGE_SIZE;
    m_buffer = (uint8_t *) mmap(NULL, m_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m_buffer == MAP_FAILED) {
        throw std::bad_alloc();
    }
    m_pageStatus = BitArray::create(numPages, true);
}

Pages::~Pages() {
    munmap(m_buffer, m_size);
}

uint8_t *Pages::alloc() {
    unsigned index;
    if (!m_pageStatus->findFirstSet(index)) {
        return nullptr;
    }

    m_pageStatus->unset(index);
    auto ret = getBuffer() + index * PAGE_SIZE;
    assert(ret >= getBuffer());
    return ret;
}

void Pages::free(uint8_t *addr) {
    assert(addr >= getBuffer() && addr < getBuffer() + m_size);
    ptrdiff_t offset = addr - getBuffer();
    auto page = offset / PAGE_SIZE;
    assert(!m_pageStatus->get(page));
    m_pageStatus->set(page);
}

PagesPtr PagePool::allocatePages() {
    auto pages = Pages::create(PagePoolDesc::POOL_PAGE_COUNT);
    auto start = (uintptr_t) pages->getBuffer();
    m_map[start] = pages;
    m_freePages[start] = pages;
    return pages;
}

uint8_t *PagePool::alloc() {
    PagesPtr pages;
    auto fp = m_freePages.begin();
    if (fp == m_freePages.end()) {
        pages = allocatePages();
    } else {
        pages = fp->second;
    }

    auto ret = pages->alloc();
    if (pages->full()) {
        m_freePages.erase((uintptr_t) pages->getBuffer());
    }
    return ret;
}

void PagePool::free(uint8_t *_ptr) {
    PagesPtr page;
    uintptr_t start;

    if (m_cachedPages) {
        auto buffer = m_cachedPages->getBuffer();
        if (_ptr >= buffer && _ptr < buffer + PagePoolDesc::POOL_PAGE_SIZE) {
            page = m_cachedPages;
            start = (uintptr_t) m_cachedPages->getBuffer();
        }
    }

    if (!page) {
        auto it = m_map.find((uintptr_t) _ptr);
        assert(it != m_map.end());
        start = it->first;
        page = it->second;
        m_cachedPages = page;
    }

    auto full = page->full();
    page->free(_ptr);

    if (page->empty()) {
        m_freePages.erase(start);
        m_map.erase(start);
    } else {
        if (full) {
            m_freePages[start] = page;
        }
    }
}

unsigned PagePool::getFreePages() const {
    auto ret = 0u;
    for (auto &it : m_map) {
        auto pages = it.second;
        ret += pages->getFreePagesCount();
    }
    return ret;
}

} // namespace klee
