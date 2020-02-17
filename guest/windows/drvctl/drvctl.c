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

#define USER_APP
#pragma warning(disable:4201)

#include <windows.h>
#include <winreg.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <s2e/s2e.h>
#include <s2e/WindowsCrashMonitor.h>

#include <s2ectl.h>
#include "drvctl.h"

#define LOG(x, ...) S2EMessageFmt("drvctl.exe: " ## x, __VA_ARGS__)

typedef int (*cmd_handler_t)(const char **args);

typedef struct _cmd_t
{
    char *name;
    cmd_handler_t handler;
    int args_count;
    const char *description;
    const char *arg_desc[4];
} cmd_t;

INT S2EGetVersionSafe(VOID)
{
    /* Avoid crashing with illegal instruction when
     * running outside S2E */
    __try {
        return S2EGetVersion();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

LPSTR GetErrorString(DWORD ErrorCode)
{
    LPSTR Msg;
    DWORD Ret = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        ErrorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // default language
        (LPSTR)&Msg,
        0,
        NULL
    );

    if (!Ret) {
        return NULL;
    }

    return Msg;
}

int handler_register(const char **args)
{
    int Ret = -1;
    PCSTR ModuleName = args[0];

    HANDLE Handle = S2EOpenDriver(S2EDriverDevice);
    if (Handle == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Could not open %s\n"), S2EDriverDevice);
        goto err;
    }

    LOG("Registering %s...\n", ModuleName);
    if (!S2EIoCtl(Handle, IOCTL_S2E_REGISTER_MODULE, (PVOID)ModuleName, (DWORD)(strlen(ModuleName) + 1))) {
        LOG("S2EIoCtl failed (%#x)\n", GetLastError());
        goto err;
    }

    Ret = 0;

err:
    if (Handle != INVALID_HANDLE_VALUE) {
        CloseHandle(Handle);
    }

    return Ret;
}

// Stop complaining about GetVersionEx being deprecated
#pragma warning(disable : 4996)

static BOOL IsWindowsXp()
{
    OSVERSIONINFO OSVersion;
    OSVersion.dwOSVersionInfoSize = sizeof(OSVersion);
    if (!GetVersionEx(&OSVersion)) {
        LOG("could not determine OS version\n");
        goto err;
    }

    return OSVersion.dwMajorVersion == 5 && OSVersion.dwMinorVersion == 1;

err:
    return FALSE;
}

INT S2EInvokeWindowsCrashMonitor(S2E_WINDOWS_CRASH_COMMAND *Command)
{
    HANDLE Driver;
    UINT8 *Buffer;
    PCSTR String;
    size_t BufferSize, StringSize;
    DWORD IoCtlCode;

    Command->Dump.Buffer = 0;
    Command->Dump.Size = 0;

    // Windows XP: invoke the plugin directly, because it can generate
    // crash dump info by itself. Later versions need support from s2e.sys.
    if (IsWindowsXp()) {
        if (Command->Command == WINDOWS_USERMODE_CRASH) {
            __s2e_touch_string((PCSTR)(UINT_PTR)Command->UserModeCrash.ProgramName);
        } else {
            LOG("invalid command for WindowsCrashMonitor: %#x\n", Command->Command);
            return -1;
        }

        S2EInvokePlugin("WindowsCrashMonitor", Command, sizeof(*Command));
        // Not supposed to return
        return 0;
    }

    Driver = S2EOpenDriver(S2EDriverDevice);
    if (Driver == INVALID_HANDLE_VALUE) {
        LOG("could not open %s\n", S2EDriverDevice);
        goto err;
    }

    if (Command->Command != WINDOWS_USERMODE_CRASH) {
        goto err;
    }

    String = (PCSTR)(UINT_PTR)Command->UserModeCrash.ProgramName;
    Command->UserModeCrash.ProgramName = sizeof(*Command);
    IoCtlCode = IOCTL_S2E_WINDOWS_USERMODE_CRASH;

    StringSize = (strlen(String) + 1) * sizeof(String[0]);
    BufferSize = sizeof(*Command) + StringSize;
    Buffer = (UINT8 *)malloc(BufferSize);
    if (!Buffer) {
        goto err;
    }

    memcpy(Buffer + sizeof(*Command), String, StringSize);
    memcpy(Buffer, Command, sizeof(*Command));

    if (!S2EIoCtl(Driver, IoCtlCode, Buffer, (DWORD)BufferSize)) {
        LOG("S2EIoCtl failed (%#x)\n", GetLastError());
        goto err;
    }

err:
    free(Buffer);
    if (Driver != INVALID_HANDLE_VALUE) {
        CloseHandle(Driver);
    }
    return 0;
}

// Use the HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
// key to invoke s2edbg.exe.
//
// Add or edit the Debugger value, using a REG_SZ string that specifies the
// command line for the debugger.
//
// "C:\test\drvctl.exe" %ld %ld
//
// s2edbg.exe -p pid -e eventhandle
int handler_debug(const char **args)
{
    long pid = strtol(args[0], NULL, 0);
    long event_id = strtol(args[1], NULL, 0);

    LOG("Program with pid %d crashed (event id: %#x)\n", pid, event_id);

    DebugApp(pid, event_id);
    return 0;
}

static int register_debug(const char *AeDebugKey)
{
    HMODULE Module;
    CHAR Path[MAX_PATH];
    CHAR Value[MAX_PATH];
    HKEY Key = NULL;
    LPSTR ErrMsg = NULL;

    LSTATUS Status = RegCreateKeyA(HKEY_LOCAL_MACHINE, AeDebugKey, &Key);
    if (Status != ERROR_SUCCESS) {
        LOG("Could not open key %s (%#x)\n", AeDebugKey, Status);
        goto err;
    }

    Module = GetModuleHandle(NULL);
    GetModuleFileNameA(Module, Path, MAX_PATH);
    LOG("Setting JIT debugger to %s\n", Path);

    sprintf_s(Value, sizeof(Value), "\"%s\" debug %%ld %%ld", Path);
    LOG("Writing registry key value %s\n", Value);

    Status = RegSetValueExA(Key, "Debugger", 0, REG_SZ, (const BYTE*)Value, (DWORD)strlen(Value));
    if (Status != ERROR_SUCCESS) {
        ErrMsg = GetErrorString(Status);
        LOG("Could not register %s as a JIT debugger (%#x - %s)\n", AeDebugKey, Status, ErrMsg);
        goto err;
    }

    Status = RegSetValueExA(Key, "Auto", 0, REG_SZ, (const BYTE*)"1", 1);
    if (Status != ERROR_SUCCESS) {
        char *ErrMsg = GetErrorString(Status);
        LOG("Could not enable autostart for JIT debugger (%p - %#x %s)\n", AeDebugKey, Status, ErrMsg);
        goto err;
    }

err:
    if (ErrMsg) {
        LocalFree(ErrMsg);
    }

    if (Key != NULL) {
        RegCloseKey(Key);
    }

    return 0;
}

static void disable_windows_error_reporting()
{
    LPSTR ErrMsg = NULL;
    LPCSTR WerPath = "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting";
    HKEY Key = NULL;

    LSTATUS Status = RegCreateKeyA(HKEY_LOCAL_MACHINE, WerPath, &Key);
    if (Status != ERROR_SUCCESS) {
        LOG("Could not open key %s (%#x)\n", WerPath, Status);
        goto err;
    }

    Status = RegSetValueExA(Key, "DontShowUI", 0, REG_SZ, (const BYTE*)"1", 1);
    if (Status != ERROR_SUCCESS) {
        char *ErrMsg = GetErrorString(Status);
        LOG("Could not disable WER (%p - %#x - %s)\n", WerPath, Status, ErrMsg);
        goto err;
    }

err:
    if (ErrMsg) {
        LocalFree(ErrMsg);
    }

    if (Key) {
        RegCloseKey(Key);
    }
}

int handler_register_debug(const char **args)
{
    UNREFERENCED_PARAMETER(args);

    LPCSTR Path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug";
#if defined(_AMD64_)
    LPCSTR WowPath = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug";
#endif

    register_debug(Path);

#if defined(_AMD64_)
    register_debug(WowPath);
#endif

    LOG("Disabling WER...\n");
    disable_windows_error_reporting();

    return 0;
}

int handler_crash(const char **args)
{
    UNREFERENCED_PARAMETER(args);
    *(char *)0 = 0;
    return 0;
}

int handler_kernel_crash(const char **args)
{
    UNREFERENCED_PARAMETER(args);

    HANDLE Driver = S2EOpenDriver(S2EDriverDevice);
    if (Driver == INVALID_HANDLE_VALUE) {
        LOG("could not open %s\n", S2EDriverDevice);
        goto err;
    }

    S2EMessage("crashing the kernel...");
    if (!S2EIoCtl(Driver, IOCTL_S2E_CRASH_KERNEL, NULL, 0)) {
        LOG("S2EIoCtl failed (%#x)\n", GetLastError());
        goto err;
    }

err:
    if (Driver != INVALID_HANDLE_VALUE) {
        CloseHandle(Driver);
    }
    return 0;
}

int handler_wait(const char **args)
{
    HANDLE Driver;
    UNREFERENCED_PARAMETER(args);

    while (1) {
        LOG("waiting for the s2e driver...");
        Driver = S2EOpenDriver(S2EDriverDevice);
        if (Driver != INVALID_HANDLE_VALUE) {
            break;
        }

        Sleep(1000);
    }

    CloseHandle(Driver);
    LOG("s2e driver loaded");
    return 0;
}

int handler_set_config(const char **args)
{
    HANDLE Driver = INVALID_HANDLE_VALUE;
    LPCSTR ConfigName = args[0];
    UINT64 ConfigValue = strtoll(args[1], NULL, 0);
    S2E_IOCTL_SET_CONFIG *Config = NULL;

    Driver = S2EOpenDriver(S2EDriverDevice);
    if (Driver == INVALID_HANDLE_VALUE) {
        LOG("Could not open %s\n", S2EDriverDevice);
        goto err;
    }

    LOG("Setting %s=%#llx\n", ConfigName, ConfigValue);

    Config = S2ESerializeIoctlSetConfig(ConfigName, ConfigValue);
    if (!Config) {
        LOG("Could not allocate memory\n");
        goto err;
    }

    if (!S2EIoCtl(Driver, IOCTL_S2E_SET_CONFIG, Config, Config->Size)) {
        LOG("S2EIoCtl failed (%#x)\n", GetLastError());
    }

err:
    free(Config);

    if (Driver != INVALID_HANDLE_VALUE) {
        CloseHandle(Driver);
    }

    return 0;
}

int handler_invoke_plugin(const char **args)
{
    HANDLE Driver = INVALID_HANDLE_VALUE;
    LPCSTR PluginName = args[0];
    LPCSTR Data = args[1];
    UINT DataSize = strlen(Data) + 1;

    S2E_IOCTL_INVOKE_PLUGIN *Plugin = NULL;

    // Does not need to be freed
    PVOID Output = NULL;

    Driver = S2EOpenDriver(S2EDriverDevice);
    if (Driver == INVALID_HANDLE_VALUE) {
        LOG("Could not open %s\n", S2EDriverDevice);
        goto err;
    }

    LOG("Invoking plugin %s with data \"%s\"\n", PluginName, Data);

    Plugin = S2ESerializeIoctlInvokePlugin(PluginName, Data, DataSize, &Output);
    if (!Plugin) {
        LOG("Could not allocate memory\n");
        goto err;
    }

    Plugin->Result = 0xdeadbeef;
    if (!S2EIoCtlOut(Driver, IOCTL_S2E_INVOKE_PLUGIN, Plugin, Plugin->Size)) {
        LOG("S2EIoCtl failed (%#x)\n", GetLastError());
        goto err;
    }

    LOG("Result: %#x\n", Plugin->Result);

err:
    free(Plugin);

    if (Driver != INVALID_HANDLE_VALUE) {
        CloseHandle(Driver);
    }

    return 0;
}

int handler_fork(const char **args)
{
    HANDLE Driver = INVALID_HANDLE_VALUE;
    LPCSTR VariableName = args[0];
    UINT DataSize = strtol(args[1], NULL, 0);
    PCHAR Data = NULL;

    if (!DataSize) {
        goto err;
    }

    Driver = S2EOpenDriver(S2EDriverDevice);
    if (Driver == INVALID_HANDLE_VALUE) {
        LOG("Could not open %s\n", S2EDriverDevice);
        goto err;
    }

    Data = calloc(1, DataSize);
    if (!Data) {
        goto err;
    }

    if (!S2EIoctlMakeSymbolic(Driver, VariableName, Data, DataSize)) {
        LOG("Could not make data symbolic\n");
        goto err;
    }

    if (Data[0]) {
        LOG("fork: true");
    } else {
        LOG("fork: false");
    }

err:
    free(Data);

    if (Driver != INVALID_HANDLE_VALUE) {
        CloseHandle(Driver);
    }

    return 0;
}

int handler_pathid(const char **args)
{
    UNREFERENCED_PARAMETER(args);
    HANDLE Driver = INVALID_HANDLE_VALUE;
    UINT64 PathId;

    Driver = S2EOpenDriver(S2EDriverDevice);
    if (Driver == INVALID_HANDLE_VALUE) {
        LOG("Could not open %s\n", S2EDriverDevice);
        goto err;
    }

    if (!S2EIoctlGetPathId(Driver, &PathId)) {
        fprintf(stderr, "Could not get path id");
        goto err;
    }

    printf("%lld\n", PathId);

err:

    if (Driver != INVALID_HANDLE_VALUE) {
        CloseHandle(Driver);
    }

    return 0;
}

#define COMMAND(c, args, desc, ...) { #c, handler_##c, args, desc, {__VA_ARGS__} }

// Note: some of these commands duplicate those in s2ecmd.
// This is to illustrate the use of s2e.sys to run S2E instructions,
// see s2ectl.h for more details.
static cmd_t s_commands[] = {
    COMMAND(register, 1, "Register a driver that is already loaded.",
        "Name of the driver (e.g., driver.sys)."),

    COMMAND(crash, 0, "Just crashes", NULL),
    COMMAND(kernel_crash, 0, "Crashes the kernel", NULL),
    COMMAND(wait, 0, "Waits for the s2e driver to finish loading", NULL),
    COMMAND(set_config, 2, "Sets s2e driver configuration (name=value)", NULL),
    COMMAND(invoke_plugin, 2, "Invokes the specified plugin with the given data", NULL),
    COMMAND(fork, 2, "Forks the current state, takes a variable name and size", NULL),
    COMMAND(pathid, 0, "Prints the current path id", NULL),

    COMMAND(debug, 2, "Handle debug request from Windows",
        "Pid of the program that crashed",
        "Event handle"),

    COMMAND(register_debug, 0, "Registers drvctl as a Windows JIT debugger.", NULL),

    { NULL, NULL, 0, NULL }
};

static void print_commands(void)
{
    unsigned i = 0;
    unsigned j = 0;
    LOG("%-15s  %s %s\n\n", "Command name", "Argument count", "Description");
    while (s_commands[i].handler) {
        LOG("%-15s  %d              %s\n", s_commands[i].name,
            s_commands[i].args_count, s_commands[i].description);

        for (j = 0; s_commands[i].arg_desc[j]; ++j) {
            LOG("                                arg %d: %s\n", j, s_commands[i].arg_desc[j]);
        }

        ++i;
    }
}

static int find_command(const char *cmd)
{
    unsigned i = 0;
    while (s_commands[i].handler) {
        if (!strcmp(s_commands[i].name, cmd)) {
            return i;
        }
        ++i;
    }
    return -1;
}

int __cdecl main(int argc, const char **argv)
{
    const char *cmd;
    int cmd_index;

    if (argc < 2) {
        print_commands();
        return -1;
    }

    cmd = argv[1];
    cmd_index = find_command(cmd);

    if (cmd_index == -1) {
        LOG("Command %s not found\n", cmd);
        return -1;
    }

    argc -= 2;
    ++argv;
    ++argv;

    if (argc != s_commands[cmd_index].args_count) {
        LOG("Invalid number of arguments supplied (%d instead of %d)\n",
            argc, s_commands[cmd_index].args_count);
        return -1;
    }

    return s_commands[cmd_index].handler(argv);
}
