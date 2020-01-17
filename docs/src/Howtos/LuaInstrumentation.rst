=================================
Instrumenting guest code with Lua
=================================

S2E comes with several plugins that expose its monitoring and instrumentation capabilities to scripts written in the
`Lua <http://lua.org>`__ programming language. This lets users create lightweight scripts without having to write and
build C++ plugins.

There are currently two instrumentation plugins:

* ``LuaFunctionInstrumentation``: for function call instrumentation
* ``LuaInstructionInstrumentation``: for instrumentation of individual instructions

Instrumenting function calls and returns
========================================

The ``LuaFunctionInstrumentation`` plugin allows instrumenting function calls and returns. It works by monitoring
machine ``call`` and ``ret`` instructions. When execution reaches a call instruction, the plugin saves the stack pointer
that references the return address, so that when a return instruction is called, the plugin can match the stack pointer
with the corresponding call instruction. This way, users only need to specify the address of the function and need not
worry about instrumenting every return instruction of that function.

Suppose that you want to instrument a function in ``mydll.dll``, which is loaded in a process called ``my.exe``.
The address of the function (as set by the linker) is ``0x4001050``. Your ``s2e-config.lua`` would contain the
following definitions:


.. code-block:: lua

    -- s2e-env configures this plugin when creating a new project for the binary my.exe.
    -- If you need to monitor functions from another process, make sure that the name
    -- of that process is defined here. If you forget to define it, your instrumentation
    -- will not be called.
    add_plugin("ProcessExecutionDetector")
    pluginsConfig.ProcessExecutionDetector = {
        moduleNames = {
            "my.exe"
        },
    }

    ...

    -- Manually enable FunctionMonitor and LuaFunctionInstrumentation plugins.
    -- They are not automatically included when creating a new project.
    add_plugin("FunctionMonitor")
    add_plugin("LuaFunctionInstrumentation")

    -- This is the configuration for LuaFunctionInstrumentation
    pluginsConfig.LuaFunctionInstrumentation = {
        -- For each function to instrument, provide an entry in the "instrumentation" table
        instrumentation = {
            -- Define an instrumentation called "my_instrumentation".
            -- This may be any string you want.
            my_instrumentation = {
                -- The name of the module to instrument.
                -- This module can either be the name of a process specified
                -- in ProcessExecutionDetector, or a dynamic library that is loaded
                -- in the address space of that process.
                module_name = "mylibrary.dll",

                -- The name of the Lua function to call when the guest function is called.
                -- The Lua function is defined later in this script.
                name = "instrumentation_func",

                -- The virtual address of the guest function to instrument.
                -- You can find this address using a disassembler (e.g., IDA or objdump).
                pc = 0x4001050,

                -- Number of parameters that the guest function takes.
                -- This parameter may be zero unless you want to access parameters
                -- from the annotation or skip the execution of
                -- an stdcall function (parameters popped by the callee).
                param_count = 2,

                -- Set to "true" to fork a new state when this instrumentation is triggered.
                -- This can be useful, e.g., to have one state run the original function
                -- and another state skip that function and replace it with a faster
                -- model to speed up symbolic execution.
                fork = false,

                -- Calling convention of the function. Either "cdecl" or "stdcall".
                convention = "cdecl",
            },
        }
    }

    -- The instrumentation code goes here
    function instrumentation_func(state, instrumentation_state, is_call, param1, param2)
        if is_call then
            -- Handle the function call
            g_s2e:debug("function called!")
        else
            -- Handle the function return
            g_s2e:debug("function returned!")
        end
    end

An instrumentation function has the following arguments:

1. A ``LuaS2EExecutionState`` object.
   Gives access to the execution state. It is the equivalent of ``S2EExecutionState`` in C++ plugins.
   You can use this object to read/write registers/memory or kill the state.

2. A ``LuaInstrumentationState`` object.
   Controls the behavior of the instrumentation. For example, you can instruct S2E to skip the function call
   altogether. You can read more about it later in this document.

3. A boolean value indicating whether the function is being called or is returning.

In addition, an instrumentation function may have one or more additional parameters, each containing the address of
a guest function argument on the stack. Note that this will only work for calling conventions that use the stack
to pass their arguments.


Instrumenting instructions
==========================

Suppose you are at a "Capture the Flag" (CTF) competition and are given a binary that contains an encrypted flag. To get
that flag, you need to give a correct password on the command line. The binary is obfuscated, and you cannot extract this
flag easily, so you decide to try symbolic execution. Unfortunately, this causes quite a bit of path explosion
out-of-the-box, so you still cannot get the flag. So, you look at the binary and identify two interesting program
counters: the first one is reached when the password is correct, while the second one is executed as soon as there is an
invalid character in the password. You can use this knowledge to speed up symbolic execution. When the correct program
counter is reached, you can kill all paths and exit S2E immediately. When the bad program counter is reached, however,
you can terminate the execution path in order to avoid wasting time. For this, you could configure the
``LuaInstructionInstrumentation`` plugin as follows:

.. code-block:: lua

    add_plugin("ProcessExecutionDetector")
    pluginsConfig.ProcessExecutionDetector = {
        moduleNames = {
            "ctf-challenge-binary"
        },
    }

    pluginsConfig.LuaInstructionInstrumentation = {
        -- For each instruction to instrument, provide an entry in the "instrumentation" table
        instrumentation = {
            -- Defines an instrumentation called "success"
            success = {
                -- The name of the module that we are interested in
                module_name = "ctf-challenge-binary",

                -- The name of the Lua function to call when the guest executes the instruction
                name = "on_success",

                -- The virtual address of the instruction in the given module
                pc = 0x800123,
            },

            -- Defines an instrumentation called "failure"
            failure = {
                module_name = "ctf-challenge",
                name = "on_failure",
                pc = 0x800565,
            }
        }
    }

    -- An instruction instrumentation takes
    -- a LuaS2EExecutionState object and a LuaInstrumentationState object.
    function on_success(state, instrumentation_state)
        -- Do something in the success state
        g_s2e:debug("Found secret!")

        -- No need to continue running S2E - terminate
        g_s2e:exit(0)
    end

    function on_failure(state, instrumentation_state)
        -- There is no reason to continue execution any further because any other paths
        -- that will fork from here will not lead to success.
        state:kill(1, "Dead-end path")
    end

This is a common pattern used by other symbolic execution engines (e.g. Angr, Manticore, etc.) for solving Capture
the Flag (CTF) challenges. This pattern allows users to specify:

1. Program path(s) that indicate the successful capture of the flag; and
2. Program path(s) to **avoid** (e.g., because they lead to some kind of failure state).

The above Lua code defines the ``success`` and ``failure`` instrumentation. The ``success`` instrumentation calls the
``on_success`` function when the instruction at ``0x800123`` is executed in the module ``ctf-challenge`` (and
likewise for the ``failure`` instrumentation).


.. note::

    For a concrete demonstration of ``LuaInstructionInstrumentation`` and ``LuaFunctionInstrumentation``, refer to
    the S2E `testsuite <../Testsuite.rst>`__, which contains an
    `example <https://github.com/S2E/s2e/tree/master/testsuite/basic7-instmon>`__ of how to instrument a sample CTF
    challenge.



API Reference
=============

As mentioned previously, all instrumentation functions take the following two arguments:

1. A ``LuaS2EExecutionState`` object, containing the current execution state; and
2. A ``LuaInstrumentationState`` object, containing the current state of the instrumentation.

LuaS2EExecutionState
--------------------

An execution state object is a wrapper around the ``S2EExecutionState`` class. It provides the following methods:

**mem()**
    Returns the current memory state in a ``LuaS2EExecutionStateMemory`` object.

**regs()**
    Returns the current register state in a ``LuaS2EExecutionStateRegisters`` object.

**createSymbolicValue(name, size)**
    Creates a new symbolic value with the given name and size (in bytes). The symbolic value is returned as a
    ``LuaExpression`` object.

**kill(status, message)**
    Kills the current state with the given status code (an integer) and message.

**getPluginProperty(plugin_name, property_name)**
    Retrieves a property from the given plugin and returns it as a string.

**setPluginProperty(plugin_name, property_name, value)**
    Sets a plugin property with the given string value.

**debug(message)**
    Writes the given message string to the debug log.


LuaS2EExecutionStateMemory
--------------------------

This is a wrapper around the ``S2EExecutionStateMemory`` class.

**readPointer(address)**
    Read a (concrete) pointer at the given address.

**readBytes(address, size)**
    Read a string of (concrete) bytes from the given address.

**write(address, expr)**
    Write a ``LuaExpression`` object at the given address.

**write(address, value, size)**
    Write the given ``value`` at the specified ``address``.

**makeSymbolic(address, size, name)**
    Make a region of memory symbolic.

LuaS2EExecutionStateRegisters
-----------------------------

This is a wrapper around the ``S2EExecutionStateRegisters`` class.

**getPc()**
    Return the current program counter.

**getSp()**
    Return the current stack pointer.

**read(pointer, size)**
    Read the register offset by ``pointer``.

**write(pointer, expr)**
    Write the ``LuaExpression`` object at the register offset by ``pointer``.

**write(pointer, value, size)**
    Write the given value at the register offset by ``pointer``.

LuaFunctionInstrumentationState
-------------------------------

An object of this type provides the following methods:

**skipFunction(skip)**
    Set ``skip`` to ``true`` in order to skip the function call.

**isChild()**
    Returns ``true`` if the instrumentation state is a forked child. This is used when ``fork = true`` is set
    in the configuration.

**setExitCpuLoop(exit)**
    Set ``skip`` to ``true`` in order to exit the CPU loop when the instrumentation returns.
    This may be useful if you modify the program counter in your instrumentation code.

LuaInstructionInstrumentationState
----------------------------------

An object of this type provides the following methods:

**skipInstruction(skip)**
    Set ``skip`` to ``true`` in order to skip the instruction after the Lua function returns.

**setExitCpuLoop(exit)**
    Set ``skip`` to ``true`` in order to exit the CPU loop when the instrumentation returns.
    This may be useful if you modify the program counter in your instrumentation code.


LuaExpression
-------------

This wrapper around a ``klee::Expr`` object.

.. warning::

    Symbolic expression support in Lua scripts is currently experimental and limited.


The ``g_s2e`` object
--------------------

Finally, the global ``g_s2e`` object is available throughout `s2e-config.lua`. It provides the following methods:

**debug(message)**
    Write the given message string to the debug log.

**info(message)**
    Write the given message string to the info log.

**warning(message)**
    Write the given message string to the warning log.

**exit(return_code)**
    Exit S2E with the given return code.

**getPlugin(plugin_name)**
    Return a reference to the specified plugin. This allows Lua scripts to interact with compatible C++ S2E plugins.

.. note::

    Only a fraction of the APIs available to C++ plugins are exposed to Lua. If you find that an API is missing,
    add it by modifying the corresponding ``LuaXXX.cpp`` file.
