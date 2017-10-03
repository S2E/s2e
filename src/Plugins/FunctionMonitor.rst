===============
FunctionMonitor
===============

The ``FunctionMonitor`` plugin catches the call/return machine instructions and invokes the corresponding handlers.

Suppose that you want to monitor the call to a function that starts at address ``0xC00F0120`` in kernel space. You also
wish to monitor all the returns from that function.

Proceed as follows:

1. Write a plugin starting from the ``Example`` plugin in the S2E package.
2. Obtain the instance of the ``FunctionMonitor`` plugin in the ``initialize()``  method of your plugin
3. Connect a handler H to any meaningful signal that exports an ``S2EExecutionState``  as a parameter. Any signal from
   ``CorePlugin`` will do. You may also want to connect to the ``onModuleLoad`` signal of an ``Interceptor`` plugin.
   This is the ideal place if you want to hook some  functions exported by a module.
4. In your handler H, obtain the addresses of the functions you want to monitor. E.g., you can parse the symbols of the
   module, or read the addresses from the configuration file.
5. Once you have the addresses, register the call handler. Make sure you register it only once, unless you want the
   handler to be called multiple times consecutively on the same call instruction.
6. In your call handler, register the return handler, if necessary.

The following part shows the code that implements the steps explained above.

.. code-block:: cpp

    // 1. Write a new analysis plugin (e.g., based on the Example plugin)
    void Example::initialize() {
        // 2. Get an instance of the FunctionMonitor plugin
        FunctionMonitor *m_monitor = s2e()->getPlugin<FunctionMonitor>();

        // 3. Monitor the translation of each translation block
        s2e()->getCorePlugin()->onTranslateBlockStart.connect(
                sigc::mem_fun(*this, &Example::slotTranslateBlockStart));

    }

For example, to monitor the kernel-mode function located at ``0xC00F012``, specify, issue a call as follows:

.. code-block:: cpp

    void Example::slotTranslateBlockStart(ExecutionSignal *signal,
                                          S2EExecutionState *state,
                                          TranslationBlock *tb,
                                          uint64_t pc) {
        // 4. Obtain the address of the function to be monitored
        // The hard-coded value can be specified in the configuration file your plugin
        uint64_t functionAddress = 0xC00F0120;

        // 5. Register a function call monitor at program counter 0xC00F0120.
        // This is done in two steps:
        //  a. Register a call signal for the specified address
        //  b. Connect as many signal handlers as needed

        if (m_registered) {
            //You must make sure that you do not register the same handler more than
            //once, unless you want it to be called multiple times.
            return;
        }

        // a. Register a call signal for address 0xC00F0120
        FunctionMonitor::callSignal *callSignal = m_monitor->getCallSignal(state, functionAddress, -1);

        // b. Register one signal handler for the function call.
        // Whenever a call instruction whose target is 0xC00F0120 is detected, FunctionMonitor
        // will invoke myFunctionCallMonitor
        callSignal->connect(sigc::mem_fun(*this, &Example::myFunctionCallMonitor));
    }

The ``FunctionMonitor`` plugin has one important methods that returns a call descriptor tied to the specified program
counter/process id:

.. code-block:: cpp

    FunctionMonitor::CallSignal*
        FunctionMonitor::getCallSignal(
            S2EExecutionState *state,
            uint64_t eip,
            uint64_t cr3);

* ``state``: the execution state in which to register the function handler
* ``eip``: the virtual address of the function to monitor (-1 to monitor all function calls)
* ``cr3``: the process id (page directory pointer) to which ``eip`` belongs (-1 to monitor all address spaces).

The call handler looks as follows:

.. code-block:: cpp

    // This handler is called after the call instruction is executed, and before the first instruction
    // of the called function is run.
    void Example::myFunctionCallMonitor(S2EExecutionState* state, FunctionMonitorState *fns) {
        getDebugStream(state) << "My function handler is called\n";

        // ...
        // Perform here any analysis or state manipulation you wish
        // ...

        // 6. Register the return handler
        // The FunctionMonitor plugin invokes this method whenever the return instruction corresponding
        // to this call is executed.
        FUNCMON_REGISTER_RETURN(state, fns, Example::myFunctionRetMonitor)
    }

Finally, the return handler looks as follows:

.. code-block:: cpp

    // FunctionMonitor invokes this handler right after the return instruction is executed, and
    // before the next instruction is run.
    void Example::myFunctionRetMonitor(S2EExecutionState *state) {
        // ...
        // Perform here any analysis or state manipulation you wish
        // ...
    }

Call/return handlers are paired: ``FunctionMonitor`` tracks stack pointers. Whenever the return instruction is executed
and the  stack pointer corresponds to the one at the call instruction, the return handler tied to that call is
executed.

You can pass as many parameters as you wish to your call handlers. You are not limited to the default
``S2EExecutionState`` and ``FunctionMonitorState``. For this, you can use the ``fsigc++``  ``bind`` feature.
