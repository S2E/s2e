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

#include <errno.h>
#include <string.h>

#include <cpu/config.h>
#include <cpu/i386/cpu.h>

#include <cpu/disas.h>

///
/// \brief target_disas_ex disassembles a chunk of guest code
/// \param out   the output stream where to print the disassembly
/// \param func  the printing function
/// \param pc    the guest program counter where to start
/// \param size  the size of the chunk to disassemble
/// \param flags i386: 2 => 64-bit, 1 => 16-bit, 0 => 32-bit
///
void target_disas_ex(FILE *out, fprintf_function_t func, target_ulong pc, target_ulong size, int flags) {
    func(out, "Disassembly not supported\n");
}

void target_disas(FILE *out, target_ulong pc, target_ulong size, int flags) {
    target_disas_ex(out, fprintf, pc, size, flags);
}
