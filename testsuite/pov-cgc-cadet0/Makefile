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

CB=CADET_00001
SOURCE=main.c

BUILD_SCRIPTS_SRC:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

RUN_DOCKER = docker run -ti --rm -w $(BUILD_SCRIPTS_SRC) -e NO_CB_EXTENDED_APP=1 -v $(BUILD_SCRIPTS_SRC):$(BUILD_SCRIPTS_SRC) linux-build-i386cgc /run_as.sh $(shell id -u) $(shell id -g) make -C CADET_00001 $(1)

$(CB)/bin/$(CB): $(CB)/src/service.c
	cd $(BUILD_SCRIPTS_SRC) && $(call RUN_DOCKER,build)

TARGETS=$(CB)/bin/$(CB)

all: $(TARGETS)

clean:
	$(call RUN_DOCKER,clean)
