///
/// Copyright (C) 2018-2020, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include "pdbparser.h"

// Print the syscall table
void DumpSyscalls(
    const SymbolInfo &Symbols, HANDLE Process,
    const std::string &ImagePath, ULONG64 ModuleBase,
    UINT64 NativeLoadBase, bool Is64
)
{
    PLOADED_IMAGE Img = nullptr;

    // 1. look for the syscall table boundary
    UINT64 KiServiceTable, KiServiceLimit;

    if (!GetSymbolAddress(Symbols, "KiServiceTable", KiServiceTable)) {
        fprintf(stderr, "Could not find KiServiceTable\n");
        goto err;
    }

    if (!GetSymbolAddress(Symbols, "KiServiceLimit", KiServiceLimit)) {
        fprintf(stderr, "Could not find KiServiceLimit\n");
        goto err;
    }

    UINT64 PtrSize = Is64 ? 8 : 4;

    // 2. Load the image
    Img = ImageLoad((PSTR)ImagePath.c_str(), NULL);
    if (!Img) {
        fprintf(stderr, "Could not load image\n");
        goto err;
    }

    UINT32 SyscallCount;
    if (!ReadPe(Img, NativeLoadBase, KiServiceLimit, &SyscallCount)) {
        fprintf(stderr, "Could not ready syscall count\n");
        goto err;
    }

    // 3. Read the array of syscall pointers
    // TODO: use safe pointer
    UINT64 *SyscallPtrs = new UINT64[SyscallCount];
    for (UINT i = 0; i < SyscallCount; ++i) {
        bool Result;

        if (Is64) {
            UINT32 Ret;
            Result = ReadPe(Img, NativeLoadBase, KiServiceTable + i * sizeof(UINT32), &Ret);
            SyscallPtrs[i] = NativeLoadBase + Ret;
        } else {
            UINT32 Ret;
            Result = ReadPe(Img, NativeLoadBase, KiServiceTable + i * sizeof(UINT32), &Ret);
            SyscallPtrs[i] = Ret;
        }

        auto it = Symbols.ByAddress.find(SyscallPtrs[i]);
        if (it != Symbols.ByAddress.end()) {
            auto symbolName = (*it).second;
            printf("%d %#llx %s\n", i, SyscallPtrs[i], symbolName.c_str());
        }

        if (!Result) {
            printf("Syscall extraction failed\n");
            goto err;
        }
    }

err:
    if (Img) {
        ImageUnload(Img);
    }
}
