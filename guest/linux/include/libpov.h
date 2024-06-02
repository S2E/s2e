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

#ifndef LIBPOV_H

#define LIBPOV_H

#include <inttypes.h>
#include <stddef.h>

#define NEG_FD 3

typedef struct type_request {
    uint32_t povType;
    struct {
        uint32_t ipmask;
        uint32_t regmask;
        uint32_t regnum;
    } type1;
} type_request;

/*
 * The following functions are available to POV authors to support
 * POV type negotiations.
 */

typedef struct type1_vals_ {
    unsigned int ipval;
    unsigned int regval;
} type1_vals;

typedef struct type2_vals_ {
    unsigned int region_addr;
    unsigned int region_size;
    unsigned int read_size;
} type2_vals;

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
int type1_negotiate(unsigned int ipmask, unsigned int regmask, unsigned int regnum, type1_vals *t1vals);

/*
 * Negotiate a type 2 pov.
 * Returns 0 on success. On success, the t2vals structure holds the address
 * (t2vals->region_addr) and size of a memory region (t2vals->region_size)
 * from which the POV must leak a specific number of bytes (t2vals->read_size).
 */
int type2_negotiate(type2_vals *t2vals);

/*
 * Submit the len bytes in the val buffer as the results of a type 2 POV
 * Returns 0 on success
 */
int type2_submit(const unsigned char *val, size_t len);

int length_read(int fd, unsigned char *buf, unsigned int len);
int transmit_all(int fd, const void *buf, const size_t size);
void receive_all(int fd, void *buf, size_t count);
void receive_null(int fd, size_t count);
int buffered_receive(int fd, void *buf, size_t count, size_t *rx_bytes);
void delay(unsigned int msec);

#define GET_BYTE(v, i) ((((uint32_t) (v)) >> ((i) *8)) & 0xFF)

/// @brief Read the negotiation parameters from the POV binary.
int type_negotiate(int fd, type_request *req);

#endif