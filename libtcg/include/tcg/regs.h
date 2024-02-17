/*
 * i386 virtual CPU header
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _TCG_REGS_H_

#define _TCG_REGS_H_

#include <fpu/softfloat.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// XXX: this is in softfloat.
typedef uint32_t float32;
typedef uint64_t float64;

typedef union MMXReg {
    uint8_t _b[8];
    uint16_t _w[4];
    uint32_t _l[2];
    float32 _s[2];
    uint64_t q;
} MMXReg;

typedef union XMMReg {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
    float32 _s[4];
    float64 _d[2];
} XMMReg;

typedef union YMMReg {
    uint64_t _q_YMMReg[256 / 64];
    XMMReg _x_YMMReg[256 / 128];
} YMMReg;

typedef union ZMMReg {
    uint8_t _b_ZMMReg[512 / 8];
    uint16_t _w_ZMMReg[512 / 16];
    uint32_t _l_ZMMReg[512 / 32];
    uint64_t _q_ZMMReg[512 / 64];
    float16 _h_ZMMReg[512 / 16];
    float32 _s_ZMMReg[512 / 32];
    float64 _d_ZMMReg[512 / 64];
    XMMReg _x_ZMMReg[512 / 128];
    YMMReg _y_ZMMReg[512 / 256];
} ZMMReg;

#ifdef __cplusplus
}
#endif

#endif
