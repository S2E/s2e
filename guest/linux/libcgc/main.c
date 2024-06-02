/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2024 Vitaly Chipounov
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

#include <libcgc.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

int transmit(int fd, const void *buf, size_t count, size_t *tx_bytes) {
    int ret = 0;

    ssize_t sz = write(fd, buf, count);
    if (sz >= 0) {
        if (tx_bytes) {
            *tx_bytes = sz;
        }
        ret = 0;
        goto out;
    }

    ret = (int) sz;

out:
    return ret;
}

int receive(int fd, void *buf, size_t count, size_t *rx_bytes) {
    int ret = 0;
    ssize_t sz = read(fd, buf, count);
    if (sz >= 0) {
        *rx_bytes = sz;
        goto out;
    }
    ret = (int) sz;
out:
    return ret;
}

int fdwait(int nfds, fd_set *readfds, fd_set *writefds, const struct timeval *timeout, int *readyfds) {
    struct timeval tm = *timeout;
    int ret = select(nfds, readfds, writefds, NULL, &tm);
    if (ret >= 0) {
        *readyfds = ret;
        ret = 0;
    }

    return ret;
}

int allocate(size_t length, int is_X, void **addr) {
    int prot = PROT_READ | PROT_WRITE;
    if (is_X) {
        prot |= PROT_EXEC;
    }
    void *ret_addr = mmap(NULL, length, prot, MAP_ANON | MAP_PRIVATE, 0, 0);
    if (ret_addr == MAP_FAILED) {
        return -EFAULT;
    } else {
        *addr = ret_addr;
        return 0;
    }
}

int deallocate(void *addr, size_t length) {
    return munmap(addr, length);
}

void delay(unsigned int msec) {
    struct timeval timeout;
    timeout.tv_sec = msec / 1000;
    timeout.tv_usec = (msec % 1000) * 1000;
    fdwait(0, NULL, NULL, &timeout, NULL);
}
