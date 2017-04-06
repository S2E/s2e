///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _KERNEL_STRUCTS_H_

#define _KERNEL_STRUCTS_H_

typedef struct KERNEL_STRUCTS
{
    UINT32 Version;

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
