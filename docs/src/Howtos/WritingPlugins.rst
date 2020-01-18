==========================
How to Write an S2E plugin
==========================

In this tutorial, we show step-by-step how to write a complete plugin that uses most of the features of the S2E plugin
infrastructure. We take the example of a plugin that counts how many times a specific instruction has been executed.
Users of that plugin can specify the instruction to watch in the S2E configuration file. We will also show how to build
the plugin so that it can communicate with other plugins and expose reusable functionality.

Starting with an Empty Plugin
=============================

The first thing to do is to name the plugin and create boilerplate code. Let us name the plugin ``InstructionTracker``.
You can copy/paste the ``Example`` plugin that ships with S2E (in the `libs2eplugins
<https://github.com/S2E/s2e/tree/master/libs2eplugins>`__ directory).

Create a file named ``InstructionTracker.h`` in ``$S2EDIR/libs2eplugins/src/s2e/Plugins`` with the following content:

.. code-block:: cpp

    #ifndef S2E_PLUGINS_INSTRTRACKER_H
    #define S2E_PLUGINS_INSTRTRACKER_H

    // These header files are located in libs2ecore
    #include <s2e/Plugin.h>
    #include <s2e/CorePlugin.h>
    #include <s2e/S2EExecutionState.h>

    namespace s2e {
    namespace plugins {

    class InstructionTracker : public Plugin {
        S2E_PLUGIN

    public:
        InstructionTracker(S2E *s2e) : Plugin(s2e) {}

        void initialize();
    };

    } // namespace plugins
    } // namespace s2e

    #endif

Then, create the corresponding ``InstructionTracker.cpp`` file in the same directory:

.. code-block:: cpp

    #include <s2e/S2E.h>

    #include "InstructionTracker.h"

    namespace s2e {
    namespace plugins {

    // Define a plugin whose class is InstructionTracker and called "InstructionTracker"
    S2E_DEFINE_PLUGIN(InstructionTracker,                   // Plugin class
                      "Tutorial - Tracking instructions",   // Description
                      "InstructionTracker",                 // Plugin function name
                      // Plugin dependencies would normally go here. However this plugin does not have any dependencies
                      );

    void InstructionTracker::initialize() {
    }

    } // namespace plugins
    } // namespace s2e

Finally, we need to compile the plugin with the rest of S2E. For this, add the following line to
``$S2EDIR/libs2eplugins/src/CMakeLists.txt``, near the other plugin declarations::

    s2e/Plugins/InstructionTracker.cpp

Reading Configuration Parameters
================================

We would like to let the user specify which instruction to monitor. For this, we create a configuration variable that
stores the address of that instruction. Every plugin can have an entry in the S2E configuration file. The entry for our
plugin would look like this:

.. code-block:: lua

    pluginsConfig.InstructionTracker = {
        -- The address we want to track
        addressToTrack = 0x12345,
    }

We also need to add our plugin to the ``Plugins`` table. This can be done one of two ways:

* If using ``s2e-env``, add a call to ``add_plugin`` to ``s2e-config.lua``.

.. code-block:: lua

    add_plugin("InstructionTracker")

* If not using ``s2e-env``, you will have to create the ``Plugins`` table yourself:

.. code-block:: lua

    Plugins = {
        -- List other plugins here
        "InstructionTracker",
    }

If we run the plugin as it is now, nothing will happen. S2E ignores any unknown configuration value. We need a
mechanism to explicitly retrieve the configuration value. In S2E, plugins can retrieve the configuration at any time.
In our case, we do it during the initialization phase.

.. code-block:: cpp

    // From libs2ecore. We need this to read configuration files
    #include <s2e/ConfigFile.h>

    // ...

    void InstructionTracker::initialize() {
        m_address = (uint64_t) s2e()->getConfig()->getInt(getConfigKey() + ".addressToTrack");
    }

Do not forget to add ``uint64_t m_address;`` as a private members of class ``InstructionTracker`` in
``InstructionTracker.h``.

Instrumenting Instructions
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
        if(m_address == pc) {
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

Counting Instructions
=====================

We would like to count how many times that particular instruction is executed. There are two options:

1. Count how many times it was executed across all paths
2. Count how many times it was executed in each path

The first option is trivial to implement. Simply add an additional member to the class and increment it every time the
``onInstructionExecution`` callback is invoked.

The second option requires to keep per-state plugin information. S2E plugins manage per-state information in a class
that derives from ``PluginState``. This class must implement a ``factory`` method that returns a new instance of the
class when S2E starts symbolic execution. The ``clone`` method is used to fork the plugin state. Both ``factory`` and
``clone`` **must** be implemented.

Here is how ``InstructionTracker`` could implement the plugin state.

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

Exporting Events
================

All S2E plugins can define custom events. Other plugins can in turn connect to them and also export their own events.
This scheme is heavily used by stock S2E plugins. For example, the `LinuxMonitor <../Plugins/Linux/LinuxMonitor.rst>`__
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
