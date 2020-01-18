================
BaseInstructions
================

S2E provides a means for guest code code to communicate with plugins by providing a special machine instruction.
S2E extends the x86 instruction set with a custom instruction. When guest code executes this instruction, S2E
invokes plugins that listen for that instruction (using the ``CorePlugin::onCustomInstruction`` event).
The instruction has the following format:

::

   # S2E custom instruction format
   0f 3f XX XX YY YY YY YY YY YY

   XX: 16-bit instruction code. Each plugin should have a unique one.
   YY: 6-bytes operands. Freely defined by the instruction code.

The ``BaseInstructions`` plugin uses the above format to implement basic functionality (e.g., creating symbolic
variables, get current state id, check if a memory location is symbolic, etc.). Refer to
``guest/common/include/s2e/s2e.h`` for a complete set of APIs.

Plugins should not define new custom instruction codes. There are two problems with this format:
(1) one needs to manually allocate plugin-specific opcodes and (2) each plugin is forced to listen to all S2E
instruction invocations and filter out those of no interest.

Instead, plugins should implement the ``IPluginInvoker`` interface. This interface provides a method that
the ``BaseInstructions`` plugin calls when the guest invokes the ``s2e_invoke_plugin()`` API. This API lets guest
code pass arbitrary data to specific plugins. Each plugin can define its own data format.

.. code-block:: c

    # Definition in s2e.h
    static inline int s2e_invoke_plugin(const char *pluginName, void *data, uint32_t dataSize);

    ...

    s2e_invoke_plugin("MyPlugin", &command, sizeof(command));



See the `source code <https://github.com/S2E/s2e/blob/master/guest/common/include/s2e/s2e.h>`__ for more information
about custom instructions.
