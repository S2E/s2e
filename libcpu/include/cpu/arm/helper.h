/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016  Cyberhaven
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.
///
#ifndef __LIBCPU_ARM_HELPER_H__

#define __LIBCPU_ARM_HELPER_H__
#define _M_CF (1 << 1)
#define _M_VF (1 << 2)
#define _M_NF (1 << 3)
#define _M_ZF (1 << 4)
#define _M_R0 (1 << 5)
#define _M_R1 (1 << 6)
#define _M_R2 (1 << 7)
#define _M_R3 (1 << 8)
#define _M_R4 (1 << 9)
#define _M_R5 (1 << 10)
#define _M_R6 (1 << 11)
#define _M_R7 (1 << 12)
#define _M_R8 (1 << 13)
#define _M_R9 (1 << 14)
#define _M_R10 (1 << 15)
#define _M_R11 (1 << 16)
#define _M_R12 (1 << 17)
#define _M_R13 (1 << 18)
#define _M_R14 (1 << 19)
#define _M_SPSR (1 << 20)
#define _M_BANKED_SPSR ((unsigned long int) (63) << 21)
#define _M_BANKED_R13 ((unsigned long int) (63) << 27)
#define _M_BANKED_R14 ((unsigned long int) (63) << 33)
#define _M_USR_REGS ((unsigned long int) (32) << 39)
#define _M_REGS (32768 << 5)
#define _M_ALL ~((unsigned long int) (0) << 39)
#endif
