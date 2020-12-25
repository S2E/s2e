==========================
How to Write an S2E plugin
==========================

In this tutorial, we show step-by-step how to write a complete plugin that uses most of the features of the S2E plugin
infrastructure. We take the example of a plugin that counts how many times a specific instruction has been executed.
Users of that plugin can specify the instruction to watch in the S2E configuration file. We will also show how to build
the plugin so that it can communicate with other plugins and expose reusable functionality.

Starting with an empty plugin
=============================

In this tutorial, we will create a plugin that counts executed instructions.
After setting up your S2E environment, run the following command:

.. code-block:: bash

    $ s2e new_plugin InstructionTracker

This creates the required boilerplate for an S2E plugin:

    * The plugin source: ``$S2EENV/source/s2e/libs2eplugins/src/s2e/Plugins/InstructionTracker.cpp``
    * The plugin header: ``$S2EENV/source/s2e/libs2eplugins/src/s2e/Plugins/InstructionTracker.h``
    * An entry in the makefile to build the plugin: ``$S2EENV/source/s2e/libs2eplugins/src/CMakeLists.txt``


Reading configuration parameters
================================

To let users specify which instruction to monitor, the plugin needs a configuration variable that
stores the address of that instruction. To create one, add the following to your ``s2e-config.lua`` file:

.. code-block:: lua

    add_plugin("InstructionTracker")
    pluginsConfig.InstructionTracker = {
        -- The address we want to track
        addressToTrack = 0x12345,
    }

For now, this will do nothing. We need to instruct the plugin to read this configuration, e.g., during
initialization. Open the plugin's source file and add the following code to the ``initialize`` method:

.. code-block:: cpp

    void InstructionTracker::initialize() {
        m_address = (uint64_t) s2e()->getConfig()->getInt(getConfigKey() + ".addressToTrack");
    }

Do not forget to add ``uint64_t m_address;`` as a private members of class ``InstructionTracker`` in
``InstructionTracker.h``.


Instrumenting instructions
==========================

To instrument an instruction, an S2E plugin registers to the ``onTranslateInstructionStart`` core event. There are
many other core events to which a plugin can register. These events are defined in ``CorePlugin.h`` in the
`libs2ecore <https://github.com/S2E/s2e/tree/master/libs2ecore>`__ directory.

Extend your code as follows. Do not forget to add all new member functions to the (private) section of the class
declaration.

.. code-block:: cpp

    // From libs2ecore. Provides the hexval function
    #include <s2e/Utils.h>

    void InstructionTracker::initialize() {
        m_address = (uint64_t) s2e()->getConfig()->getInt(getConfigKey() + ".addressToTrack");

        // This indicates that our plugin is interested in monitoring instruction translation.
        // For this, the plugin registers a callback with the onTranslateInstruction signal.
        s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
            sigc::mem_fun(*this, &InstructionTracker::onTranslateInstruction));
    }

    void InstructionTracker::onTranslateInstruction(ExecutionSignal *signal,
                                                    S2EExecutionState *state,
                                                    TranslationBlock *tb,
                                                    uint64_t pc) {
        if (m_address == pc) {
            // When we find an interesting address, ask S2E to invoke our callback when the address is actually
            // executed
            signal->connect(sigc::mem_fun(*this, &InstructionTracker::onInstructionExecution));
        }
    }

    // This callback is called only when the instruction at our address is executed.
    // The callback incurs zero overhead for all other instructions
    void InstructionTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
        s2e()->getDebugStream() << "Executing instruction at " << hexval(pc) << '\n';
        // The plugins can arbitrarily modify/observe the current execution state via the execution state pointer.
        // Plugins can also call the s2e() method to use the S2E API
    }


.. warning::

    Do not confuse ``onTranslate`` events and ``onInstructionExecution`` handlers. The former is called during
    instruction translation, the latter when the instruction is executed, and only if the handler has been registered
    during translation. The translation vs. execution difference is due to how dynamic binary translators work.
    If you increment during translation, you will get incorrect results. For example, a loop body
    would typically be translated once and executed several times, so your counter will not be incremented as expected.


Counting instructions
=====================

We would like to count how many times that particular instruction is executed. There are two options:

1. Count how many times it was executed across all paths
2. Count how many times it was executed in each path

The first option is easy to implement. Simply add an additional member to the class and increment it every time the
``onInstructionExecution`` callback is invoked.

The second option requires keeping per-state plugin information. S2E plugins manage per-state information in a class
that derives from ``PluginState``. This class must implement a ``factory`` method that returns a new instance of the
class when S2E starts symbolic execution. The ``clone`` method is used to fork the plugin state. Both ``factory`` and
``clone`` **must** be implemented.

Here is how ``InstructionTracker`` could implement the plugin state. Note that the plugin boilerplate already contains
all the required declarations. All you need to do is to fill them in. You can also delete them if your plugin does
not need to store per-state information.

.. code-block:: cpp

    class InstructionTrackerState : public PluginState {
    private:
        int m_count;

    public:
        InstructionTrackerState() {
            m_count = 0;
        }

        virtual ~InstructionTrackerState() {}

        static PluginState *factory(Plugin*, S2EExecutionState*) {
            return new InstructionTrackerState();
        }

        InstructionTrackerState *clone() const {
            return new InstructionTrackerState(*this);
        }

        void increment() {
            ++m_count;
        }

        int get() {
            return m_count;
        }
    };

Plugin code can refer to this state using the ``DECLARE_PLUGINSTATE`` macro:

.. code-block:: cpp

    void InstructionTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
        // This macro declares the plgState variable of type InstructionTrackerState.
        // It automatically takes care of retrieving the right plugin state attached to the specified execution state
        DECLARE_PLUGINSTATE(InstructionTrackerState, state);

        s2e()->getDebugStream() << "Executing instruction at " << hexval(pc) << '\n';

        // Increment the count
        plgState->increment();
    }


Exporting events
================

All S2E plugins can define custom events. Other plugins can in turn connect to them and also export their own events.
This scheme is at the center of the S2E plugin infrastructure. For example, the `LinuxMonitor <../Plugins/Linux/LinuxMonitor.rst>`__
plugin exports a number of events (e.g. segmentation fault, module load, etc.) that can be intercepted by your own
plugins.

In this tutorial, we show how ``InstructionTracker`` can expose an event and trigger it when the monitored instruction
is executed ten times.

First, we declare the signal as a ``public`` field of the ``InstructionTracker`` class. It is important that the field
be public, otherwise other plugins will not be able to register.

.. code-block:: cpp

    class InstructionTracker : public Plugin {
        // ...

        public:
            sigc::signal<void,
                         S2EExecutionState *, // The first parameter of the callback is the state
                         uint64_t             // The second parameter is an integer representing the program counter
                        > onPeriodicEvent;

        //...
    }

Second, we add some logic to trigger the event and invoke the registered callbacks.

.. code-block:: cpp

    void InstructionTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
        DECLARE_PLUGINSTATE(InstructionTrackerState, state);

        s2e()->getDebugStream() << "Executing instruction at " << hexval(pc) << '\n';

        plgState->increment();

        // Trigger the event
        if ((plgState->get() % 10) == 0) {
            onPeriodicEvent.emit(state, pc);
        }
    }

That is all we need to define and trigger an event. To register for this event, a plugin invokes
``s2e()->getPlugin<PluginName>()``, where ``PluginName`` is the name of the plugin as defined in the
``S2E_DEFINE_PLUGIN`` macro. In our case, a plugin named ``MyClient`` would do something like this in its
initialization routine:

.. code-block:: cpp

    // Include the plugin's header file
    #include <s2e/Plugins/InstructionCounter.h>

    // Specify dependencies
    S2E_DEFINE_PLUGIN(MyClient, "We use InstructionTracker", "MyClient", "InstructionTracker");

    void MyClient::initialize() {
        // Get the instance of the plugin
        Instructiontracker *tracker = s2e()->getPlugin<InstructionTracker>();

        // Register to custom events
        tracker->onPeriodicEvent.connect(/* Connect a handler method */);
    }

Note that S2E enforces the plugin dependencies specified in the ``S2E_DEFINE_PLUGIN`` macro. If a dependency is not
satisfied (e.g., the plugin is not enabled in the configuration file or is not compiled in S2E), S2E will not start and
emit an error message instead.

It is not always necessary to specify the dependencies. For example, a plugin may want to work with reduced
functionality if a dependent plugin is missing. Attempting to call ``s2e()->getPlugin()`` returns ``nullptr`` if
the requested plugin is missing.


Guest-plugin communication
==========================

Guest code can send commands to plugins. S2E uses this extensively. For example, the Windows and Linux monitoring
plugins notify other plugins about loaded modules, processes, and threads by receiving this information from a guest
driver. The driver extract this information using the guest OS APIs, then sends it to the appropriate plugins.

In this part of the tutorial, we will modify the ``InstructionTracker`` plugin so that guest code can configure
which address to monitor. This can be useful, e.g., in case the address to track is not known before S2E starts
(ASLR, dynamically loaded modules, etc.).

Guest code uses the ``s2e_invoke_plugin`` function to call a plugin. This call takes a pointer to a plugin-specific
data structure that contains the command to run and execute. The following example shows how to send a command
to the ``InstructionTracker`` plugin:

.. code-block:: cpp

    #include <s2e/s2e.h>

    enum S2E_INSTRUCTIONTRACKER_COMMANDS {
        SET_ADDRESS
    };

    struct S2E_INSTRUCTIONTRACKER_COMMAND {
        S2E_TESTPLUGIN_COMMANDS Command;

        union {
            // Command parameters go here
            uint64_t address;
        };
    };

    int main(int argc, char **argv) {
        struct S2E_INSTRUCTIONTRACKER_COMMAND cmd;
        cmd.Command = SET_ADDRESS;
        cmd.address = 0x12345;

        s2e_invoke_plugin("InstructionTracker", &cmd, sizeof(cmd));
        return 0;
    }


This code invokes the ``handleOpcodeInvocation`` method in the ``InstructionTracker`` plugin. You will need to modify
it so that it accepts the command:

.. code-block:: cpp

    void InstructionTracker::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize)
    {
        S2E_INSTRUCTIONTRACKER_COMMAND command;

        if (guestDataSize != sizeof(command)) {
            getWarningsStream(state) << "mismatched S2E_INSTRUCTIONTRACKER_COMMAND size\n";
            return;
        }

        if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
            getWarningsStream(state) << "could not read transmitted data\n";
            return;
        }

        switch (command.Command) {
            case SET_ADDRESS:
                m_address = command.address;
                break;
            default:
                getWarningsStream(state) << "Unknown command " << command.Command << "\n";
                break;
        }
    }

You will also need to update the ``InstructionTracker.h`` header with the proper structure definitions.

.. note::

    S2E does not enforce the data format between the guest code and the associated plugins. The template shown above
    is merely a suggestion. You can simplify it if needed. For example, if you know that your plugin has only
    one command, you could just call ``s2e_invoke_plugin`` with null arguments.