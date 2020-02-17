///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
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

#ifndef _KERNEL_STRUCTS_H_

#define _KERNEL_STRUCTS_H_

typedef struct KERNEL_STRUCTS
{
    RTL_OSVERSIONINFOEXW Version;

    /**
    * Address of the Kernel debugger data block
    * decryption routine.
    */
    UINT64 KdCopyDataBlock;

    /**
    * Pointer to the kernel variable that stores
    * the encryption status of the the kernel
    * debugger data block.
    */
    UINT64 KdpDataBlockEncoded;

    PVOID PRCBProcessorStateOffset;

    PLIST_ENTRY PsActiveProcessHead;
    UINT64 EProcessActiveProcessLinkOffset;
    UINT64 EProcessThreadListHeadOffset;
    UINT64 EThreadThreadListEntry;

    UINT64 ObpCreateHandle;
    UINT64 MmAccessFault;
    UINT64 NtAllocateVirtualMemory;
    UINT64 NtFreeVirtualMemory;
    UINT64 NtProtectVirtualMemory;
    UINT64 NtMapViewOfSection;
    UINT64 NtUnmapViewOfSectionEx;
    UINT64 NtUnmapViewOfSection;
    UINT64 MiUnmapViewOfSection;
} KERNEL_STRUCTS;

extern KERNEL_STRUCTS g_kernelStructs;

#endif
