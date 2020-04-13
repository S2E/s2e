///
/// Copyright (C) 2014-2020, Cyberhaven
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
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

BOOL OurGetFileSize(const char *pFileName, DWORD *pFileSize)
{
    BOOLEAN Ret = FALSE;
    HANDLE hFile = CreateFile(pFileName, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        goto err0;
    }

    *pFileSize = GetFileSize(hFile, NULL);
    if (*pFileSize == INVALID_FILE_SIZE) {
        goto err1;
    }

    Ret = TRUE;

err1: CloseHandle(hFile);
err0: return Ret;
}

_Success_(return)

BOOL GetImageInfo(
    _In_ const char *FileName,
    _Out_ ULONG64 *LoadBase,
    _Out_ DWORD *CheckSum,
    _Out_ bool *Is64
)
{
    FILE *fp = nullptr;
    BOOL Ret = FALSE;
    IMAGE_DOS_HEADER Header;

    union
    {
        IMAGE_NT_HEADERS32 Headers32;
        IMAGE_NT_HEADERS64 Headers64;
    } Headers;

    if (fopen_s(&fp, FileName, "rb") || !fp) {
        fprintf(stderr, "Could not open %s\n", FileName);
        goto err;
    }

    if (fread(&Header, sizeof(Header), 1, fp) != 1) {
        fprintf(stderr, "Could not read DOS header for %s\n", FileName);
        goto err;
    }

    if (Header.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Incorrect magic for %s\n", FileName);
        goto err;
    }

    if (fseek(fp, Header.e_lfanew, SEEK_SET) < 0) {
        fprintf(stderr, "Could not seek to NT header %s\n", FileName);
        goto err;
    }

    if (fread(&Headers.Headers64, sizeof(Headers.Headers64), 1, fp) != 1) {
        fprintf(stderr, "Could not read NT headers for %s\n", FileName);
        goto err;
    }

    switch (Headers.Headers32.FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386: {
            *LoadBase = Headers.Headers32.OptionalHeader.ImageBase;
            *CheckSum = Headers.Headers32.OptionalHeader.CheckSum;
            *Is64 = false;
        }
        break;
        case IMAGE_FILE_MACHINE_AMD64: {
            *LoadBase = Headers.Headers64.OptionalHeader.ImageBase;
            *CheckSum = Headers.Headers64.OptionalHeader.CheckSum;
            *Is64 = true;
        }
        break;

        default: {
            fprintf(stderr, "Unsupported architecture %x for %s\n", Headers.Headers32.FileHeader.Machine, FileName);
            goto err;
        }
    }

    Ret = TRUE;

err:
    if (fp) {
        fclose(fp);
    }

    return Ret;
}
