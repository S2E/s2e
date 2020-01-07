// Helper macros for pointer arithmetic.
//
// Contains code derived from these sources:
// https://github.com/lattera/glibc/blob/master/include/libc-pointer-arith.h

// Copyright (C) 2012-2019 Free Software Foundation, Inc.
// This file is part of the GNU C Library.
//
// The GNU C Library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// The GNU C Library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with the GNU C Library; if not, see
// <http://www.gnu.org/licenses/>.

#ifndef LIBTCG_ROUNDING

#define LIBTCG_ROUNDING

// Round number down to multiple
#define ALIGN_DOWN(base, size) ((base) / (size) * (size))

// Align a value by rounding up to closest size.
// E.g. Using size of 4096, we get this behavior:
//    {4095, 4096, 4097} = {4096, 4096, 8192}.
// Note: The size argument has side effects (expanded multiple times).
#define ALIGN_UP(base, size) ALIGN_DOWN((base) + (size) -1, (base))

// Same as ALIGN_DOWN(), but automatically casts when base is a pointer
#define ALIGN_PTR_DOWN(base, size) ((typeof(base)) ALIGN_DOWN((uintptr_t)(base), (size)))

// Same as ALIGN_UP(), but automatically casts when base is a pointer
#define ALIGN_PTR_UP(base, size) ((typeof(base)) ALIGN_UP((uintptr_t)(base), (size)))

// Round number up to multiple.
// Requires that size be a power of 2.
#ifndef ROUND_UP
#define ROUND_UP(base, size) (((base) + (size) -1) & -(size))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(base, size) (((base) + (size) -1) / (size))
#endif

#endif
