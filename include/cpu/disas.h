/// Copyright (C) 2017  Cyberhaven
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

#ifndef _LIBCPU_DISAS_H
#define _LIBCPU_DISAS_H

#include <cpu/types.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void host_disas(FILE *out, void *pc, size_t size);

void target_disas(void *env, FILE *out, target_ulong code, target_ulong size, int flags);

typedef int (*fprintf_function_t)(FILE *f, const char *fmt, ...);
void target_disas_ex(void *env, FILE *out, fprintf_function_t func, uintptr_t code, size_t size, int flags);

#ifdef __cplusplus
}
#endif

#endif /* _LIBCPU_DISAS_H */
