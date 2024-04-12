/// Copyright (c) 2010, Dependable Systems Laboratory, EPFL
/// Copyright (c) 2016, Cyberhaven, Inc
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are met:
///
///    * Redistributions of source code must retain the above copyright
///      notice, this list of conditions and the following disclaimer.
///
///    * Redistributions in binary form must reproduce the above copyright
///      notice, this list of conditions and the following disclaimer in the
///      documentation and/or other materials provided with the distribution.
///
///    * Neither the names of the copyright holders, nor the
///      names of its contributors may be used to endorse or promote products
///      derived from this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
/// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
/// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
/// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
/// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
/// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
/// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef S2E_OPCODES_H
#define S2E_OPCODES_H

#ifdef __cplusplus
extern "C" {
#endif

// clang-format off

#define OPCODE_SIZE (2 + 8)

// Central opcode repository for plugins that implement micro-operations
#define RAW_MONITOR_OPCODE                  0xAA
#define STATE_MANAGER_OPCODE                0xAD

#define HOST_FILES_OPCODE                   0xEE
#define HOST_FILES_OPEN_OPCODE              0x00
#define HOST_FILES_CLOSE_OPCODE             0x01
#define HOST_FILES_READ_OPCODE              0x02
#define HOST_FILES_CREATE_OPCODE            0x03
#define HOST_FILES_WRITE_OPCODE             0x04

// Expression evaluates to true if the custom instruction operand contains the
// specified opcode
#define OPCODE_CHECK(operand, opcode) ((((operand) >> 8) & 0xFF) == (opcode))

// Get an 8-bit function code from the operand.
//
// This may or may not be used depending on how a plugin expects an operand to
// look like
#define OPCODE_GETSUBFUNCTION(operand) (((operand) >> 16) & 0xFF)

#define BASE_S2E_CHECK          0x00
#define BASE_S2E_MAKE_SYMBOLIC  0x03
#define BASE_S2E_IS_SYMBOLIC    0x04
#define BASE_S2E_GET_PATH_ID    0x05
#define BASE_S2E_KILL_STATE     0x06
#define BASE_S2E_PRINT_EXPR     0x07
#define BASE_S2E_PRINT_MEM      0x08
#define BASE_S2E_ENABLE_FORK    0x09
#define BASE_S2E_DISABLE_FORK   0x0A
#define BASE_S2E_INVOKE_PLUGIN  0x0B
#define BASE_S2E_ASSUME         0x0C
#define BASE_S2E_ASSUME_DISJ    0x0D
#define BASE_S2E_ASSUME_RANGE   0x0E
#define BASE_S2E_YIELD          0x0F
#define BASE_S2E_PRINT_MSG      0x10
#define BASE_S2E_MAKE_CONCOLIC  0x11 // Keep this for backwards compatibility, behaves like s2e_make_symbolic
#define BASE_S2E_BEGIN_ATOMIC   0x12
#define BASE_S2E_END_ATOMIC     0x13
#define BASE_S2E_IS_FORKING_ENABLED 0x14
#define BASE_S2E_CONCRETIZE     0x20
#define BASE_S2E_EXAMPLE        0x21
#define BASE_S2E_STATE_COUNT    0x30
#define BASE_S2E_INSTANCE_COUNT 0x31
#define BASE_S2E_SLEEP          0x32
#define BASE_S2E_WRITE_BUFFER   0x33
#define BASE_S2E_GET_RANGE      0x34
#define BASE_S2E_CONSTR_CNT     0x35
#define BASE_S2E_HEX_DUMP       0x36
#define BASE_S2E_CHECK_PLUGIN   0x40
#define BASE_S2E_SET_TIMER_INT  0x50
#define BASE_S2E_SET_APIC_INT   0x51
#define BASE_S2E_GET_OBJ_SZ     0x52
#define BASE_S2E_CLEAR_TEMPS    0x53
#define BASE_S2E_FORK_COUNT     0x54
#define BASE_S2E_FLUSH_TBS      0x55

// Maximum S2E opcode allowed
#define BASE_S2E_MAX_OPCODE     0x70

// clang-format on

#ifdef __cplusplus
}
#endif

#endif
