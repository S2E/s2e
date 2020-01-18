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


# Env vars:
# WINDOWS_BUILD_HOST=192.168.187.140
# WINDOWS_BUILD_USER=s2e
# S2ESRC=/path/to/s2e/src


DRIVER32=./scanner/filter/Debug/scanner.sys
DRIVER64=./scanner/filter/x64/Debug/scanner.sys

REMOTE_BUILD=$(S2ESRC)/scripts/windows/remote-msbuild.sh

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(shell ls $(REMOTE_BUILD) 2>&1),$(REMOTE_BUILD))
$(error Could not find $(REMOTE_BUILD), please check that S2ESRC is set properly!)
endif

ifeq ($(WINDOWS_BUILD_HOST),)
$(error Please set WINDOWS_BUILD_HOST to the address of the Windows build machine)
endif

ifeq ($(WINDOWS_BUILD_USER),)
$(error Please set WINDOWS_BUILD_USER to the user of the Windows build machine)
endif
endif

$(DRIVER32):
	REMOTE_HOST=$(WINDOWS_BUILD_HOST) REMOTE_USER=$(WINDOWS_BUILD_USER) REMOTE_FOLDER=faultinj-scannersys VS_PLATFORM=Win32 VS_CONFIG=Debug $(REMOTE_BUILD) scanner
	cp ./scanner/scanner.inf ./scanner/filter/Debug
	cp ./scanner/user/Debug/*.exe* ./scanner/filter/Debug

# Serialize the build, parallel won't work
$(DRIVER64): $(DRIVER32)
	REMOTE_HOST=$(WINDOWS_BUILD_HOST) REMOTE_USER=$(WINDOWS_BUILD_USER) REMOTE_FOLDER=faultinj-scannersys VS_PLATFORM=x64 VS_CONFIG=Debug $(S2ESRC)/scripts/windows/remote-msbuild.sh scanner
	cp ./scanner/scanner.inf ./scanner/filter/x64/Debug
	cp ./scanner/user/x64/Debug/*.exe* ./scanner/filter/x64/Debug

TARGETS=$(DRIVER32) $(DRIVER64)

all: $(TARGETS)
clean:
	rm -rf ./scanner/*/Debug ./scanner/*/x64
