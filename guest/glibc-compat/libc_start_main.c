///
/// Copyright (C) 2022 Vitaly Chipounov
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

#include <link.h>

struct startup_info {
    void *sda_base;
    int (*main)(int, char **, char **, void *);
    int (*init)(int, char **, char **, void *);
    void (*fini)(void);
};

extern int __libc_start_main(int argc, char **argv, char **ev, ElfW(auxv_t) * auxvec, void (*rtld_fini)(void),
                             struct startup_info *stinfo, char **stack_on_entry);

#if defined __i386__
__asm__(".symver __libc_start_main,__libc_start_main@GLIBC_2.0");
#elif defined __x86_64__
__asm__(".symver __libc_start_main,__libc_start_main@GLIBC_2.2.5");
#else
#error Unsupported architecture
#endif

int __wrap___libc_start_main(int argc, char **argv, char **ev, ElfW(auxv_t) * auxvec, void (*rtld_fini)(void),
                             struct startup_info *stinfo, char **stack_on_entry) {
    return __libc_start_main(argc, argv, ev, auxvec, rtld_fini, stinfo, stack_on_entry);
}
