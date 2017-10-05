===========
Annotations
===========

The annotation plugins combine monitoring and instrumentation capabilities to let users annotate either individual
instructions or entire function calls. The user writes the annotation directly inside the S2E configuration file using
the `Lua <http://lua.org>`_ programming language.

There are two types of annotation plugins:

* ``LuaFunctionAnnotation``: Instrument function calls
* ``LuaInstructionAnnotation``: Instrument individual instructions

Both will be discussed in turn.

LuaFunctionAnnotation
---------------------

The ``LuaFunctionAnnotation`` plugin requires the following plugins to be enabled:

* ``LuaBindings``
* ``OSMonitor``
* ``ModuleExecutionDetector``
* ``FunctionMonitor``
* ``KeyValueStore``

A function annotation is defined as follows:

.. code-block:: lua

    pluginsConfig.LuaFunctionAnnotation = {
        -- For each function to annotate, provide an entry in the "annotations" table
        annotations = {
            -- define an annotation called "my_annotation"
            my_annotation = {
                -- The name of the module that we are interested in
                module_name = "module_name",
                -- The name of the Lua function to call when this annotation is triggered
                name = "annotation_func",
                -- The virtual address of a function in the given module that will trigger the annotation
                pc = 0x12345678,
                -- Number of parameters that the function at "pc" takes
                param_count = 2,
                -- Set to "true" to fork a new state when this annotation is triggered
                fork = false,
                -- Calling convention of the function at "pc". Either "cdecl" or "stdcall"
                convention = "cdecl",
            },
        }
    }

    function annotation_func(state, annotation_state, is_call, param1, param2)
        if is_call then
            -- Handle the function call
        else
            -- Handle the function return
        end
    end

The number of parameters that the Lua function takes varies depending on ``param_count``. A function annotation always
takes the following parameters:

1. A ``LuaS2EExecutionState`` object
2. A ``LuaAnnotationState`` object
3. A boolean value indicating whether the function is being called (``is_call`` is ``true``) or is returning
   (``is_call`` is ``false``).

It also takes an additional ``param_count`` arguments, each containing the address of a function argument on the stack.

LuaInstructionAnnotation
------------------------

The ``LuaInstructionAnnotation`` plugin requires the following plugins to be enabled:

* ``LuaBindings``
* ``ProcessExecutionDetector``
* ``ModuleMap``

An instruction annotation is very similar to an instruction annotation. An example of an instruction annotation is
given below.

.. code-block:: lua

    pluginsConfig.LuaInstructionAnnotation = {
        -- For each instruction to annotate, provide an entry in the "annotations" table
        annotations = {
            -- Defines an annotation called "success"
            success = {
                -- The name of the module that we are interested in
                module_name = "ctf-challenge",
                -- The name of the Lua function to call when this annotation is triggered
                name = "on_success",
                -- The virtual address of an instruction in the module that will trigger the annotation
                pc = 0x12345678,
            },

            failure = {
                module_name = "ctf-challenge",
                name = "on_failure",
                pc = 0xdeadbeef,
            }
        }
    }

    function on_success(state, annotation_state)
        -- Do something in the success state

        -- No need to continue running S2E - terminate
        g_s2e:exit()
    end

    function on_failure(state, annotation_state)
        -- There is no reason to continue execution any further. So kill the state
        state:kill(1, "Invalid path")
    end

This is a very common pattern used by other symbolic execution engines (e.g. Angr, Manticore, etc.) for solving Capture
the Flag (CTF) challenges. This pattern allows the user to specify:

1. Program path(s) that indicate the successful capture of the flag; and
2. Program path(s) to **avoid** (e.g. because they lead to some kind of failure state).

The above Lua code defines the ``success`` and ``failure`` annotations. The ``success`` annotation calls the
``on_success`` function when the instruction at ``0x12345678`` is executed in the module ``ctf-challenge`` (and
likewise for the ``failure`` annotation).

Instruction annotations always take two arguments - a ``LuaS2EExecutionState`` object and a ``LuaAnnotationState``
object.

Lua API
-------

As stated previously, all annotations take the following two arguments:

1. A ``LuaS2EExecutionState`` object, containing the current execution state; and
2. A ``LuaAnnotationState`` object, containing the current state of the annotation.

``LuaS2EExecutionState``
~~~~~~~~~~~~~~~~~~~~~~~~

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

``LuaAnnotationState``
~~~~~~~~~~~~~~~~~~~~~~

A ``LuaAnnotationState`` object provides the following methods:

**setSkip(skip)**
    Available in function annotations. Set ``skip`` to ``true`` to skip the function call.

**isChild()**
    Returns ``true`` if the annotation state is a forked child. This is used when ``fork = true`` in a function
    annotation.

**setExitCpuLoop()**
    Sets the exit CPU loop to ``true``. This will cause the CPU to exit when the annotation returns.

``LuaS2EExecutionStateMemory``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A ``LuaS2EExecutionStateMemory`` object provides a wrapper around the ``S2EExecutionStateMemory`` class.

**readPointer(address)**
    Read a (concrete) pointer at the given address.

**readBytes(address, size)**
    Read a string of (concrete) bytes from the given address.

**write(address, expr)**
    Write a ``LuaExpression`` object at the given address.

**makeSymbolic(address, size, name)**
    Make a region of memory symbolic.

**makeConcolic(address, size, name)**
    Make a region of memory concolic.

``LuaS2EExecutionStateRegisters``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Likewise a ``LuaS2EExecutionStateRegisters`` object provides a wrapper around the ``S2EExecutionStateRegisters`` class.

**getPc()**
    Return the current program counter.

**read(pointer, size)**
    Read the register offset by ``pointer``.

**write(pointer, expr)**
    Write the ``LuaExpression`` object at the register offset by ``pointer``.

**write(pointer, value, size)**
    Write the given value at the register offset by ``pointer``.

``LuaExpression``
~~~~~~~~~~~~~~~~~

Wrapper around a ``klee::Expr`` object.

The ``g_s2e`` object
~~~~~~~~~~~~~~~~~~~~

Finally, the ``g_s2e`` object is available in all annotations. It provides the following methods:

**debug(message)**
    Write the given message string to the debug log.

**info(message)**
    Write the given message string to the info log.

**warning(message)**
    Write the given message string to the warning log.

**exit(return_code)**
    Exit S2E with the given return code.
