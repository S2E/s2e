================
BaseInstructions
================

This plugin implements various custom instructions to control the behavior of symbolic execution from within the guest
OS. S2E extends the x86 instruction set with custom opcodes. This opcode takes an 8-bytes operand that is passed to
plugins that listen for custom instructions. The content of the operand is plugin specific.

::

   # S2E custom instruction format
   0f 3f XX XX YY YY YY YY YY YY

   XX: 16-bit instruction code. Each plugin should have a unique one.
   YY: 6-bytes operands. Freely defined by the instruction code.

``guest/common/include/s2e/s2e.h`` defines a basic set of custom instructions. The preferred method for extending this
functionality is by using the ``s2e_invoke_plugin`` function to send arbitrary data to a plugin. Another option is to
assign an unused instruction code to your custom instruction. S2E does not track instruction code allocation. S2E calls
all the plugins that listen for a custom opcode (i.e. those that implement the
``BaseInstructionsPluginInvokerInterface`` interface) in the order of their registration.

s2e.h is well documented, so see the `source code
<https://github.com/S2E/guest-tools/blob/master/common/include/s2e/s2e.h>`_ for more information on what instructions exist.
