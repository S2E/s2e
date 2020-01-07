# Copyright (c) 2019, Cyberhaven
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

TARGET=basic6-funcmon
SOURCE=main.c

GCC_LINUX=gcc
GCC_WINDOWS64=x86_64-w64-mingw32-gcc
GCC_WINDOWS32=i686-w64-mingw32-gcc

CFLAGS:=-O3 -g -Wall -std=c99 $(CFLAGS)

linux64-$(TARGET): $(SOURCE)
	$(GCC_LINUX) -m64 $(CFLAGS) -o "$@" "$^"

linux32-$(TARGET): $(SOURCE)
	$(GCC_LINUX) -m32 $(CFLAGS) -o "$@" "$^"

windows64-$(TARGET).exe: $(SOURCE)
	$(GCC_WINDOWS64) -m64 $(CFLAGS) -o "$@" "$^"

windows32-$(TARGET).exe: $(SOURCE)
	$(GCC_WINDOWS32) -m32 $(CFLAGS) -o "$@" "$^"

TARGETS=linux64-$(TARGET) linux32-$(TARGET) windows64-$(TARGET).exe windows32-$(TARGET).exe

all: $(TARGETS)
clean:
	rm -f $(TARGETS)
