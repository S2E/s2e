# S2E Selective Symbolic Execution Platform
#
# Copyright (c) 2013 Dependable Systems Laboratory, EPFL
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

all: build-all

quiet-command = $(if $(V),$1,$(if $(2),@echo $2 && $1, @$1))

ASM=nasm
S2EBIOS=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TOOLS_DIR=$(S2EBIOS)/..
VPATH=$(S2EBIOS)
INCLUDES=-I$(TOOLS_DIR)/common/include -I$(S2EBIOS)/include -I$(S2EBIOS)

BIOS_CFLAGS := -std=c99 -O3 -g -ffreestanding  -nostdlib -nostdinc -fno-omit-frame-pointer -mno-red-zone $(INCLUDES)
BIOS_CFLAGS += -fno-exceptions -fno-asynchronous-unwind-tables

S2E_BIOS_C_UTILS=libc/string.c utils/interrupt.c libc/printf.c
S2E_BIOS_C_HW=hw/pci.c hw/ioapic.c hw/apic.c
S2E_BIOS_C_TESTS=tests/maze.c tests/range.c tests/selfmod.c tests/symbhw.c
S2E_BIOS_ASM_TESTS=
S2E_BIOS_C=s2e-bios-low.c main.c
S2E_BIOS_C_SOURCE=$(S2E_BIOS_C) $(S2E_BIOS_C_UTILS) $(S2E_BIOS_C_TESTS) $(S2E_BIOS_C_HW)

ifeq ($(BITS),64)
BIOS_CFLAGS+=-m64 -D__WORD_SIZE=64
LD_SCRIPT="$(S2EBIOS)/bios64.ld"
BIOS_ASM_SOURCE=$(S2EBIOS)/s2e-bios-64.asm
ASM_FMT=elf64
S2E_BIOS_ASM_TESTS=tests/tests64.asm utils/arch64.asm
S2E_BIOS_C_SOURCE:=$(S2E_BIOS_C_SOURCE) vmm/vmm64.c
else
BIOS_CFLAGS+=-m32 -D__WORD_SIZE=32
LD_SCRIPT="$(S2EBIOS)/bios.ld"
BIOS_ASM_SOURCE=$(S2EBIOS)/s2e-bios-32.asm
ASM_FMT=elf32
S2E_BIOS_ASM_TESTS=utils/arch32.asm
S2E_BIOS_C_SOURCE:=$(S2E_BIOS_C_SOURCE) vmm/vmm32.c
endif

S2E_BIOS_C_OBJ=$(S2E_BIOS_C_SOURCE:.c=.o) $(S2E_BIOS_ASM_TESTS:.asm=.o)

.PHONY : all clean build-all

build-all: s2e-bios.bin

%.o: %.c
	@mkdir -p $$(dirname $@)
	$(call quiet-command,$(CC) $(BIOS_CFLAGS) -O0 -c -o $@ $^,"  Building $(TARGET_DIR)$@")

%.o: %.asm
	@mkdir -p $$(dirname $@)
	$(ASM) -o $@ -f $(ASM_FMT) $^

s2e-bios-up.bin : $(BIOS_ASM_SOURCE)
	$(call quiet-command,$(ASM) -O1 -i$(S2EBIOS)/ -f bin -o $@ $(BIOS_ASM_SOURCE),"  Building $(TARGET_DIR)$@")

s2e-bios-low-c: $(S2E_BIOS_C_OBJ)
	$(LD) -T $(LD_SCRIPT)  -o $@ $^

s2e-bios-low-c.bin: s2e-bios-low-c
	objcopy -O binary --rename-section .data=.rodata,alloc,load,data,contents,readonly $^ $@

s2e-bios.bin: s2e-bios-up.bin s2e-bios-low-c.bin
	dd if=s2e-bios-low-c.bin of=$@ bs=65536 count=1
	dd if=s2e-bios-up.bin of=$@ bs=65536 count=1 seek=1

clean:
	rm -f *.bin *.o s2e-bios-low-c
