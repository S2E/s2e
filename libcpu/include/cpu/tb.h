/// Copyright (C) 2003  Fabrice Bellard
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

#ifndef __LIBCPU_TB_H__

#define __LIBCPU_TB_H__

#include <stdbool.h>

#include <cpu/se_libcpu_config.h>
#include <cpu/types.h>
#include <tcg/exec/translation-block.h>

#ifdef __cplusplus
extern "C" {
#endif

///
/// \brief tb_get_instruction_size returns the size of the guest machine
/// instruction starting at the given address and belonging to the given
/// translation block. Useful for variable-length instruction sets.
///
/// \param tb the translation block in which the instruction is located
/// \param addr the absolute virtual address at which the instruction starts
/// \returns the size of the instruction in bytes, or 0 if no instruction
/// starting at the given address is found in the translation block
///
int tb_get_instruction_size(TranslationBlock *tb, uint64_t pc);

///
/// \brief cpu_restore_state restores the CPU state of the guest instruction
/// that was running at a host address inside generated code.
///
/// \param cpu the CPU to restore
/// \param host_pc the host address
/// \returns true if the state was restored, false if host_pc is not in generated code
///
bool cpu_restore_state(CPUState *cpu, uintptr_t host_pc);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCPU_TB_H__ */
