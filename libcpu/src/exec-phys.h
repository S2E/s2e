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

#ifndef __EXEC_PHYS_H__

#define __EXEC_PHYS_H__

#include <cpu/memory.h>
#include <inttypes.h>

extern const uint16_t phys_section_unassigned;
extern const uint16_t phys_section_notdirty;
extern const uint16_t phys_section_rom;
extern const uint16_t phys_section_watch;

void phys_register_section(unsigned index, const struct MemoryDescOps *ops);

#endif
