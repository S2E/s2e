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

#ifndef __LIBCPU_INTERRUPT_H__

#define __LIBCPU_INTERRUPT_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Flags for use in ENV->INTERRUPT_PENDING.

   The numbers assigned here are non-sequential in order to preserve
   binary compatibility with the vmstate dump.  Bit 0 (0x0001) was
   previously used for CPU_INTERRUPT_EXIT, and is cleared when loading
   the vmstate dump.  */

/* External hardware interrupt pending.  This is typically used for
   interrupts from devices.  */
#define CPU_INTERRUPT_HARD 0x0002

/* Exit the current TB.  This is typically used when some system-level device
   makes some change to the memory mapping.  E.g. the a20 line change.  */
#define CPU_INTERRUPT_EXITTB 0x0004

/* Halt the CPU.  */
#define CPU_INTERRUPT_HALT 0x0020

/* Debug event pending.  */
#define CPU_INTERRUPT_DEBUG 0x0080

/* Several target-specific external hardware interrupts.  Each target/cpu.h
   should define proper names based on these defines.  */
#define CPU_INTERRUPT_TGT_EXT_0 0x0008
#define CPU_INTERRUPT_TGT_EXT_1 0x0010
#define CPU_INTERRUPT_TGT_EXT_2 0x0040
#define CPU_INTERRUPT_TGT_EXT_3 0x0200
#define CPU_INTERRUPT_TGT_EXT_4 0x1000

/* Several target-specific internal interrupts.  These differ from the
   preceding target-specific interrupts in that they are intended to
   originate from within the cpu itself, typically in response to some
   instruction being executed.  These, therefore, are not masked while
   single-stepping within the debugger.  */
#define CPU_INTERRUPT_TGT_INT_0 0x0100
#define CPU_INTERRUPT_TGT_INT_1 0x0400
#define CPU_INTERRUPT_TGT_INT_2 0x0800
#define CPU_INTERRUPT_TGT_INT_3 0x2000

/* First unused bit: 0x4000.  */

/* The set of all bits that should be masked when single-stepping.  */
#define CPU_INTERRUPT_SSTEP_MASK                                                                        \
    (CPU_INTERRUPT_HARD | CPU_INTERRUPT_TGT_EXT_0 | CPU_INTERRUPT_TGT_EXT_1 | CPU_INTERRUPT_TGT_EXT_2 | \
     CPU_INTERRUPT_TGT_EXT_3 | CPU_INTERRUPT_TGT_EXT_4)

#define EXCP_INTERRUPT 0x10000 /* async interruption */
#define EXCP_HLT 0x10001       /* hlt instruction reached */
#define EXCP_DEBUG 0x10002     /* cpu stopped after a breakpoint or singlestep */
#define EXCP_HALTED 0x10003    /* cpu is halted (waiting for external event) */
#ifdef CONFIG_SYMBEX
#define EXCP_SE 0x10004 /* Symbex engine requested exiting cpu loop */
#endif

#ifdef __cplusplus
}
#endif

#endif
