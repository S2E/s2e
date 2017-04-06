/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017 Cyberhaven
/// Copyright (c) 2013 Dependable Systems Lab, EPFL
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

#ifndef _S2E_KVS_H_

#define _S2E_KVS_H_

#include "s2e.h"
#pragma warning(disable:4201) //nonstandard extension used : nameless struct/union

__declspec(align(8))
typedef enum _S2E_KVSTORE_PLUGIN_COMMANDS
{
    KVS_PUT_STRING, KVS_GET_STRING,
    KVS_PUT_INT, KVS_GET_INT,
    KVS_LOCK, KVS_UNLOCK,
    KVS_INTEGER_KEY = 0x80000000
} S2E_KVSTORE_PLUGIN_COMMANDS;

__declspec(align(8))
typedef struct _S2E_KVSTORE_PLUGIN_COMMAND
{
    S2E_KVSTORE_PLUGIN_COMMANDS Command;

    union
    {
 /* Pointer to the string that will be used as a key */
        UINT64 KeyAddress;

        /* Integer key */
        UINT64 IntegerKey;
    };

    /* Key/Value should be put in the current state */
    UINT64 Local;

    /* Guest address where to store/get the value */
    union
    {
        UINT64 ValueAddress;
        UINT64 IntegerValue;
    };

    /* Size of the value in bytes */
    UINT64 ValueSize;

    /* Results */

    /* Key did not exist before */
    UINT64 NewKey;

    /* Success status of the command */
    UINT64 Success;
} S2E_KVSTORE_PLUGIN_COMMAND;

CCASSERT(sizeof(S2E_KVSTORE_PLUGIN_COMMAND) == 56);

static BOOLEAN S2EKVSSetValueEx(PCSTR Key, UINT64 Value, BOOLEAN *NewKey, BOOLEAN Local)
{
    S2E_KVSTORE_PLUGIN_COMMAND Command;

    Command.Command = KVS_PUT_INT;
    Command.KeyAddress = (UINT_PTR)Key;
    Command.Local = Local;
    Command.IntegerValue = Value;
    Command.NewKey = 0;
    Command.Success = 0;
    Command.ValueSize = 0;

    S2EInvokePlugin("KeyValueStore", &Command, sizeof(Command));

    if (NewKey) {
        *NewKey = (BOOLEAN)Command.NewKey;
    }

    return (BOOLEAN)Command.Success;
}

static BOOLEAN S2EKVSSetValueIntKeyEx(UINT64 Key, UINT64 Value, BOOLEAN *NewKey, BOOLEAN Local)
{
    S2E_KVSTORE_PLUGIN_COMMAND Command;

    Command.Command = KVS_PUT_INT | KVS_INTEGER_KEY;
    Command.IntegerKey = (UINT_PTR)Key;
    Command.Local = Local;
    Command.IntegerValue = Value;
    Command.NewKey = 0;
    Command.Success = 0;
    Command.ValueSize = 0;

    S2EInvokePlugin("KeyValueStore", &Command, sizeof(Command));

    if (NewKey) {
        *NewKey = (BOOLEAN)Command.NewKey;
    }

    return (BOOLEAN)Command.Success;
}

static BOOLEAN S2EKVSSetValue(PCSTR Key, UINT64 Value, BOOLEAN *NewKey)
{
    return S2EKVSSetValueEx(Key, Value, NewKey, FALSE);
}

static BOOLEAN S2EKVSSetValueIntKey(UINT64 Key, UINT64 Value, BOOLEAN *NewKey)
{
    return S2EKVSSetValueIntKeyEx(Key, Value, NewKey, FALSE);
}

static BOOLEAN S2EKVSGetValueEx(PCSTR Key, UINT64 *Value, BOOLEAN Local)
{
    S2E_KVSTORE_PLUGIN_COMMAND Command;

    Command.Command = KVS_GET_INT;
    Command.KeyAddress = (UINT_PTR)Key;
    Command.Local = Local;
    Command.NewKey = 0;
    Command.Success = 0;
    Command.ValueAddress = 0;
    Command.ValueSize = 0;

    S2EInvokePlugin("KeyValueStore", &Command, sizeof(Command));

    *Value = Command.IntegerValue;
    return (BOOLEAN)Command.Success;
}

static BOOLEAN S2EKVSGetValueIntKeyEx(UINT64 Key, UINT64 *Value, BOOLEAN Local)
{
    S2E_KVSTORE_PLUGIN_COMMAND Command;

    Command.Command = KVS_GET_INT | KVS_INTEGER_KEY;
    Command.IntegerKey = (UINT_PTR)Key;
    Command.Local = Local;
    Command.NewKey = 0;
    Command.Success = 0;
    Command.ValueAddress = 0;
    Command.ValueSize = 0;

    S2EInvokePlugin("KeyValueStore", &Command, sizeof(Command));

    *Value = Command.IntegerValue;
    return (BOOLEAN)Command.Success;
}

static BOOLEAN S2EKVSGetValue(PCSTR Key, UINT64 *Value)
{
    return S2EKVSGetValueEx(Key, Value, FALSE);
}

static BOOLEAN S2EKVSGetValueIntKey(UINT64 Key, UINT64 *Value)
{
    return S2EKVSGetValueIntKeyEx(Key, Value, FALSE);
}

#endif
