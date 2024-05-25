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

/// Adapted from https://github.com/CyberGrandChallenge/libpov
/// https://github.com/CyberGrandChallenge/libpov/blob/22648e2489145dfa431b0674a03959489a5c0fac/debian/copyright
/// Copyright: Under 17 U.S.C § 105 US Government Works are not subject to domestic copyright protection.
/// License: None

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libcgc.h>
#include <libpov.h>

int type_negotiate(int fd, type_request *req) {
    int res = read(fd, &req->povType, sizeof(req->povType));
    if (res != sizeof(req->povType)) {
        return -1;
    }

    if (req->povType == 2) {
        return 0;
    }

    if (req->povType == 1) {
        res = read(fd, &req->type1.ipmask, sizeof(req->type1.ipmask));
        if (res != sizeof(req->type1.ipmask)) {
            return -1;
        }

        res = read(fd, &req->type1.regmask, sizeof(req->type1.regmask));
        if (res != sizeof(req->type1.regmask)) {
            return -1;
        }

        res = read(fd, &req->type1.regnum, sizeof(req->type1.regnum));
        if (res != sizeof(req->type1.regnum)) {
            return -1;
        }
    }

    return 0;
}

/*
 * Negotiate a type 1 pov. Caller specifies an ip bit mask, a register bit mask
 * and a general purpose register number (see the list below).
 *
   0 - eax
   1 - ecx
   2 - edx
   3 - ebx
   4 - esp
   5 - ebp
   6 - esi
   7 - edi
 *
 * Returns 0 on success. On success, the t1vals structure holds required IP
 * and register values that must be found when the target CB crashes. At the
 * time of the crash the following must hold:
 *  (crash_eip & ipmask) == t1vals->ipval
 *  (crash_REG & regmask) == t1vals->regval
 */
int type1_negotiate(unsigned int ipmask, unsigned int regmask, unsigned int regnum, type1_vals *t1vals) {
    uint32_t povType = 1;
    if (transmit_all(NEG_FD, &povType, sizeof(povType)) || transmit_all(NEG_FD, &ipmask, sizeof(ipmask)) ||
        transmit_all(NEG_FD, &regmask, sizeof(regmask)) || transmit_all(NEG_FD, &regnum, sizeof(regnum))) {
        return -1;
    }
    if (length_read(NEG_FD, (unsigned char *) t1vals, sizeof(type1_vals)) != sizeof(type1_vals)) {
        return -1;
    }
    return 0;
}

/*
 * Negotiate a type 2 pov.
 * Returns 0 on success. On success, the t2vals structure holds the address
 * (t2vals->region_addr) and size of a memory region (t2vals->region_size)
 * from which the POV must leak a specific number of bytes (t2vals->read_size).
 */
int type2_negotiate(type2_vals *t2vals) {
    uint32_t povType = 2;
    if (transmit_all(NEG_FD, &povType, sizeof(povType))) {
        return -1;
    }
    if (length_read(NEG_FD, (unsigned char *) t2vals, sizeof(type2_vals)) != sizeof(type2_vals)) {
        return -1;
    }
    return 0;
}

/*
 * Submit the len bytes in the val buffer as the results of a type 2 POV
 * Returns 0 on success
 */
int type2_submit(const unsigned char *val, size_t len) {
    return transmit_all(NEG_FD, val, len);
}

int length_read(int fd, unsigned char *buf, unsigned int len) {
    unsigned int total = 0;
    while (total < len) {
        unsigned int need = len - total;
        size_t rlen;
        if (buf != NULL) {
            // read directly into caller buffer
            if (buffered_receive(fd, buf + total, need, &rlen) != 0 || rlen == 0) {
                // error or eof but might have had some data
                break;
            }
        } else {
            // caller supplied no buffer so just read len bytes
            // and discard
            unsigned char dbuf[512];
            if (need > sizeof(dbuf)) {
                need = sizeof(dbuf);
            }
            if (buffered_receive(fd, dbuf, need, &rlen) != 0 || rlen == 0) {
                // error or eof but might have had some data
                break;
            }
        }
        total += rlen;
    }
    return (int) total;
}

int transmit_all(int fd, const void *buf, const size_t size) {
    size_t sent = 0;
    size_t sent_now = 0;
    int ret;

    if (!buf)
        return 1;

    if (!size)
        return 2;

    while (sent < size) {
        ret = transmit(fd, sent + (char *) buf, size - sent, &sent_now);
        if (ret != 0) {
            return 3;
        }
        sent += sent_now;
    }

    return 0;
}

void receive_all(int fd, void *buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        size_t s = 0;
        receive(fd, buf + total, count - total, &s);
        total += s;
    }
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void receive_null(int fd, size_t count) {
    uint8_t buf[256];
    while (count) {
        size_t s = MIN(count, sizeof(buf));
        receive_all(fd, buf, s);
        count -= s;
    }
}

typedef struct _read_buffer {
    uint32_t iptr;
    uint32_t eptr;
    uint8_t buf[4096];
} read_buffer;

static read_buffer *ibufs[16];

int buffered_receive(int fd, void *buf, size_t count, size_t *rx_bytes) {
    if (fd > 15) {
        return receive(fd, buf, count, rx_bytes);
    }
    read_buffer *rb = ibufs[fd];
    if (rb == NULL) {
        rb = (read_buffer *) malloc(sizeof(read_buffer));
        rb->iptr = rb->eptr = 0;
        ibufs[fd] = rb;
    }

    if (rx_bytes != NULL) {
        *rx_bytes = 0;
    }

    int res = 0;
    while (1) {
        uint32_t avail = rb->eptr - rb->iptr;
        if (avail > 0) {
            if (avail >= count) {
                // we have enough data buffered to satisfy request
                memcpy(buf, rb->buf + rb->iptr, count);
                rb->iptr += count;
                if (rx_bytes != NULL) {
                    *rx_bytes += count;
                }
                return 0;
            } else {
                // avail < len some data buffered but not enough
                memcpy(buf, rb->buf + rb->iptr, avail);
                buf = avail + (char *) buf;
                count -= avail;
                if (rx_bytes != NULL) {
                    *rx_bytes += avail;
                }
            }
        }
        size_t rxb;
        rb->iptr = rb->eptr = 0;
        res = receive(fd, rb->buf, sizeof(rb->buf), &rxb);
        if (res != 0 || rxb == 0) {
            break;
        }
        rb->eptr = rxb;
    }
    return res;
}
