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
#include <cpu/memdbg.h>

#include <capstone/capstone.h>

///
/// \brief target_disas_ex disassembles a chunk of guest code
/// \param out   the output stream where to print the disassembly
/// \param func  the printing function
/// \param pc    the guest program counter where to start
/// \param size  the size of the chunk to disassemble
/// \param flags i386: 2 => 64-bit, 1 => 16-bit, 0 => 32-bit
///
void target_disas_ex(void *env, FILE *out, fprintf_function_t func, uintptr_t pc, size_t size, int flags) {
    csh handle;
    cs_insn *insn;
    size_t count;
    cs_mode mode;

    switch (flags) {
        case 0:
            mode = CS_MODE_32;
            break;
        case 1:
            mode = CS_MODE_16;
            break;
        case 2:
            mode = CS_MODE_64;
            break;
        default:
            func(out, "Invalid mode %d\n", flags);
            return;
    }

    if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
        func(out, "Could not open disassembler\n");
        return;
    }

    uint8_t buffer[size];
    if (env) {
        cpu_memory_rw_debug(env, (target_ulong) pc, buffer, size, 0);
    } else {
        memcpy(buffer, (void *) pc, size);
    }

    for (unsigned i = 0; i < size; ++i) {
        func(out, "%#02x ", buffer[i]);
    }
    func(out, "\n");

    count = cs_disasm(handle, buffer, size, pc, 0, &insn);

    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            func(out, "0x%" PRIx64 ":  %-7s %s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    } else {
        func(out, "ERROR: Failed to disassemble given code!\n");
    }

    cs_close(&handle);
}

void target_disas(void *env, FILE *out, target_ulong pc, target_ulong size, int flags) {
    target_disas_ex(env, out, fprintf, pc, size, flags);
}

void host_disas(FILE *out, void *pc, size_t size) {
    target_disas_ex(NULL, out, fprintf, (uintptr_t) pc, size, 2);
}
