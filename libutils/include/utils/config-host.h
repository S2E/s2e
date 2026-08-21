/// Copyright (c) 2026 Vitaly Chipounov
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef S2E_UTILS_CONFIG_HOST_H
#define S2E_UTILS_CONFIG_HOST_H

// Host configuration for the vendored QEMU utilities. Upstream gets these from
// meson through qemu/osdep.h; here they derive from compiler builtins so that
// every translation unit that includes a utils header, in any component and
// under any build rule (including the clang -emit-llvm bitcode rules), sees the
// same definitions. Struct layouts in int128.h and qtree.h depend on them.

// Upstream CONFIG_INT128: the compiler has __int128.
#ifdef __SIZEOF_INT128__
#define CONFIG_INT128 1
#endif

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define HOST_BIG_ENDIAN 1
#else
#define HOST_BIG_ENDIAN 0
#endif

// Always use QEMU's own QTree rather than aliasing it to GTree. Upstream
// switches on the glib version; keeping one implementation avoids a behavior
// change when the host glib is upgraded.
#define HAVE_GLIB_WITH_SLICE_ALLOCATOR 1

// CONFIG_CPUID_H is deliberately left undefined. With it, cpuinfo-i386.c
// detects BMI/POPCNT/LZCNT/AVX and the TCG backend then advertises andc, ctz,
// clz, ctpop and vector ops, which tcg-llvm.cpp does not translate. The TCG op
// set has to stay at the baseline until the LLVM translator covers them.

#endif
