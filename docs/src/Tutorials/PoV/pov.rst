========================================================
Automated Generation of Proofs of Vulnerability with S2E
========================================================

In this tutorial, we will show you how to use the S2E analysis platform to automatically find vulnerable spots in
binaries and generate proofs of the existence of the vulnerabilities. These proofs can then be used by developers to
easily reproduce, understand, and fix the bugs that lead to the vulnerabilities.

S2E is a platform for in-vivo analysis of software systems that combines a virtual machine with symbolic execution.
Users install and run in S2E any x86 or ARM software stack, including programs, libraries, the OS kernel, and drivers.
S2E comes with a comprehensive set of plugins to perform various types of analyses, such as bug finding, performance
profiling, reverse engineering, and of course vulnerability analysis as well as proof of vulnerabilitiy (PoV)
generation. Attackers exploit binaries by supplying carefully-crafted inputs that force the program to execute malicious
code or leak confidential data out of the program's memory. An attacker typically feeds programs abnormally large
strings in an attempt to gain control of the program counter. The attacker would choose the input data such that the
corrupted program counter points to the location of the malicious payload, e.g., the attacker's shellcode.

Automating this can be decomposed in two parts: finding the vulnerable program location and generating the proof of
vulnerability (PoV). In this tutorial, we will assume that the vulnerable instruction has been found and will
focus on explaining how to generate the PoV.

.. note::

    Although not required, we recommend that you get familiar with the DARPA CyberGrandChallenge (CGC) in order to have
    a better understanding of this tutorial. The CGC documentation is on
    `Github <https://github.com/CyberGrandChallenge/cgc-release-documentation>`__
    and details about the event are `here <http://archive.darpa.mil/cybergrandchallenge/>`__.

    DARPA's `Cyber Grand Challenge <http://archive.darpa.mil/cybergrandchallenge/>`__ (CGC) was the world's first
    all-machine hacking tournament. S2E was a key component in CodeJitsu's Cyber Reasoning System (CRS) and was used to
    automatically to find vulnerabilities and exploit them. This tutorial walks you through the theory behind automated
    PoV generation. After you are done reading it, you can get your hands dirty in this `follow-up <index.rst>`__.


Understanding the Execution of a Vulnerable Program
===================================================

Consider the following program. It receives data from the network and stores it into a buffer. The buffer has a length
of 4 bytes and the receive function tries to write 12 bytes into it, causing a buffer overflow.

.. code-block:: c
    :number-lines:

    int main(int argc, char **argv)
    {
        char buf[4];
        receive(buf, 12);
        return 0;
    }


Since the processor executes machine instructions, we must reason about the binary form of this program. Here is how the
assembly code for this program could look like, with the most important instructions explained.

.. code-block:: none
    :number-lines:

    push    ebp
    mov     ebp, esp
    sub     esp, 4         ; Allocate 4 bytes on the stack for buf
    lea     eax, [ebp-4]   ; Compute address of buf
    push    12             ; Push 12 for 2nd parameter of receive
    push    eax            ; Push address of buf for 1st param of receive
    call    receive
    xor     eax, eax       ; Set return value to 0
    leave                  ; Clean the stack frame
    ret                    ; Return from the main function

Let's now see what the program would execute if the attacker sends the string ``AAAABBBBCCCC``. Assume that the stack
pointer register is ``0xf0`` at instruction 1 and the frame pointer is ``0x1000``. After executing instruction 6 and
right before calling receive, the program stack could look like this:

.. code-block:: none

    0xf8: 0xabc0    ; argv
    0xf4: 0xdef0    ; argc
    0xf0: 0x800231  ; return address
    0xec: 0x1000    ; saved frame pointer
    0xe8: buf       ; space for the buffer (allocated at line 3)
    0xe4: 12        ; size of the parameter passed to receive
    0xe0: 0xe8      ; address of the buffer on the stack

After calling receive, the stack looks like this:

.. code-block:: none

    0xf8: 0xabc0    ; argv
    0xf4: 0xdef0    ; argc
    0xf0: CCCC      ; return address
    0xec: BBBB      ; saved frame pointer
    0xe8: AAAA      ; space for the buffer (allocated at line 3)
    0xe4: 12        ; size of the parameter passed to receive
    0xe0: 0xe8      ; address of the buffer on the stack


As you can see, the receive call overwrote the neighbouring memory locations, corrupting the original frame pointer and
the return address. The return instruction at line 10 will jump straight to the address ``CCCC``, fully controlled by
the attacker. All the attacker needs to do here is to figure out what bytes of the inputs end up in the program counter.

An automated PoV generator would have to do here is to detect when the input reaches the program counter, figure out
which bytes of the input end up in the program counter, and compute the actual input byte values so that the program
counter has the desired address.


Using Symbolic Execution to Generate PoVs
-----------------------------------------

Performing this mapping can be done with a simple technique called symbolic execution. In normal execution (aka
"concrete" execution), the program gets concrete inputs (e.g., ``1``, ``2``, ``"abc"``, etc.), performs computations on
them, and produces concrete outputs. In symbolic execution, the program gets "symbolic" inputs instead (e.g., λ\
:sub:`0`\ λ\ :sub:`1`\ λ\ :sub:`2`\ λ\ :sub:`3`\ ). These symbolic inputs propagate through the program and build
mathematical formulas ("symbolic expressions" or "symbolic values") as execution progresses.

Symbolic values coexist side-by-side with concrete values, and just like concrete values, can be read and written to
memory and processor registers. Moreover, at any point of execution, it is possible to plug any such mathematical
formula into a solver in order to compute concrete inputs, e.g., to generate a PoV.

Executing a program symbolically requires a symbolic execution engine. You can think of it as an emulator that
continuously fetches binary instructions, decodes them, checks if the operands contain symbolic data, and if so creates
a symbolic expression out of the operands, and otherwise computes the result concretely as usual. The engine extends the
register file and the memory with an array of pointers that store a reference to the symbolic expression or null if the
location is concrete. When the system starts, there is no symbolic data in the system and everything runs concretely. In
order to initiate symbolic execution, the engine therefore needs to provide a mechanism  to create fresh symbolic
variables and write them to the desired memory location. S2E, which is based on virtualization, conveniently provides a
custom machine instruction (e.g., a special x86 instruction for x86 targets) that can be used from inline assembly.


In order to run the program above symbolically, one needs to define a source of symbolic values. This source is the
receive system call. The symbolic execution engine would need to somehow intercept the call to ``receive`` and replace
it with a custom implementation that injects symbolic values into the buffer instead of reading concrete data from the
network. When using S2E, this can be easily done with ``LD_PRELOAD`` or, for static binaries, by tweaking the receive
syscall in the Linux kernel. S2E provides a custom x86 instruction to create symbolic values. For the example above,
this can be as simple as transforming receive into:

.. code-block:: c
    :number-lines:

    int receive(void *buf, size_t size)
    {
        s2e_make_symbolic(buf, size, "input_buffer");
        return size;
    }

``s2e_make_symbolic`` is nothing more than a function written in assembly that contains a hard-coded sequence of bytes
for the custom x86 opcode that instructs the symbolic execution engine to write a fresh symbolic value to the desired
memory location. Each symbolic variable gets a name (e.g., ``"input_buffer"``) in order to simplify test case
generation. When running the previous example inside a symbolic execution engine, the stack would look like this when
receive returns:

.. code-block:: none

    0xf8: 0xabc0     ; argv
    0xf4: 0xdef0     ; argc
    0xf0: λ11λ10λ9λ8 ; input_buffer[8..11]
    0xec: λ7λ6λ5λ4   ; input_buffer[4..7]
    0xe8: λ3λ2λ1λ0   ; input_buffer[0..3]
    0xe4: 12         ; size of the parameter passed to receive
    0xe0: 0xe8       ; address of the buffer on the stack

The symbolic execution engine eventually reaches the return instruction at line 10, at which point it tries to write the
symbolic value at address 0xe8 into the program counter. The engine detects that the value is symbolic and stops
execution. The engine cannot continue execution at this stage because it does not know the target of a symbolic program
counter. A symbolic program counter could point to any memory location and the analysis engine would have a pretty hard
time choosing on its own a concrete value that makes sense.

This is where S2E analysis plugins come into play. Plugins hook into the execution engine and react to various events of
interest. The S2E engine exposes dozens of events, allowing developers to implement powerful analysis tools. For
example, plugins could observe the instruction stream and react to symbolic pointers. This is useful for PoV generation,
as symbolic pointers that end up in critical registers (like a program counter) are often an indication of a
vulnerability. Plugins could also look at which instructions were executed, in order to compute code coverage, etc.

S2E uses the ``Recipe`` plugin in order to determine whether an instruction can be exploited and generate inputs for the
PoV. The recipe plugin takes as input a set of pre-computed constraints for registers (the "recipe"). When a potentially
vulnerable spot is reached, the plugin appends the recipe constraints to the current set of path constraints, then asks
the solver to compute concrete inputs. If the solver succeeds in computing the inputs, the plugin found a PoV. If not,
the recipe plugin resumes execution, looking for other vulnerable spots. In the example above, suppose that the recipe
states that the program counter must be equal to ``0x801002`` and the frame pointer must be set to ``0xdeadbeef`` in
order to demonstrate the vulnerability. When execution reaches the return instruction, the solver will be fed additional
constraints λ\ :sub:`11`\ λ\ :sub:`10`\ λ\ :sub:`9`\ λ\ :sub:`8`\  == 0x00801002 and λ\ :sub:`7`\ λ\ :sub:`6`\ λ\
:sub:`5`\ λ\ :sub:`4`\  == 0xdeadbeef.  The solver will determine that this is feasible, and will then return the
following concrete input bytes: ``ff ff ff ff ef be ad de 02 10 80 00``. Values for λ\ :sub:`3`\ λ\ :sub:`2`\ λ\
:sub:`1`\ λ\ :sub:`0`\  are not important (i.e., they have no constraints), so the solver can choose anything for them
(here ``0xffffffff``).

The following is the simplest possible recipe accepted by the ``Recipe`` plugin. It specifies a ``Type 1``
vulnerability, in which the attacker can control the program counter (EIP register), as well as a general purpose
register (here, it is ``EAX``). The mask specifies which bits of these registers the attacker can control. The lines of
the form ``EIP[0] == $pc[0]`` represent constraints on the symbolic registers. The left hand side is the register, the
right hand side is a variable that represents a concrete value negotiated with the CGC framework (the framework chooses
a random ``EIP`` value to check that the exploit works for any ``EIP`` value).

.. note::

    We use the DARPA CyberGrandChallenge terminology, which defines ``Type 1`` and ``Type 2`` vulnerabilities.
    Refer to the CGC `documentation <https://github.com/CyberGrandChallenge/cgc-release-documentation/blob/master/walk-throughs/understanding-cfe-povs.md>`__ for more details.

.. code-block:: none

    :type=1
    :arch=i386
    :platform=generic
    :gp=EAX
    :reg_mask=0xffffffff
    :pc_mask=0xffffffff
    EIP[0] == $pc[0]
    EIP[1] == $pc[1]
    EIP[2] == $pc[2]
    EIP[3] == $pc[3]
    EAX[0] == $gp[0]
    EAX[1] == $gp[1]
    EAX[2] == $gp[2]
    EAX[3] == $gp[3]

The following is a more complex recipe that contains shellcode. The lines of the form ``[EIP+XXX] == YY`` represent a
constraint on a memory location at address ``EIP + XXX``. For example, ``EIP+0`` must be equal to ``0xb8``. When the
symbolic execution engine encounters a symbolic program counter, it checks that the recipe constraints can be satisfied,
and if so, generates the PoV.

.. code-block:: none

    # Set GP and EIP with shellcode
    # mov eax $gp
    # mov ebx, $pc
    # jmp ebx
    :type 1
    :reg_mask=0xffffffff
    :pc_mask=0xffffffff
    :gp=EAX
    :exec_mem=EIP
    [EIP+0] == 0xb8
    [EIP+1] == $gp[0]
    [EIP+2] == $gp[1]
    [EIP+3] == $gp[2]
    [EIP+4] == $gp[3]
    [EIP+5] == 0xbb
    [EIP+6] == $pc[0]
    [EIP+7] == $pc[1]
    [EIP+8] == $pc[2]
    [EIP+9] == $pc[3]
    [EIP+10] == 0xff
    [EIP+11] == 0xe3

Identifying Advanced Vulnerability Patterns with S2E
====================================================

In the previous sections, we explained how to detect basic return address overwrites and generate simple PoVs. The idea
was to use symbolic execution in order to track the flow of symbolic input data into sensitive registers, such as the
program counter, then use the constraint solver in order to generate valid PoVs according to pre-computed recipes. PoV
generation leverages the ability of S2E to detect memory accesses through symbolic pointers, detect changes of control
flow to a symbolic address, and detect function calls with symbolic parameters. When S2E detects these events, it
notifies the recipe plugin. The plugin then goes through the set of recipes and if one of them satisfies the current
path constraints, generates a PoV. This is sufficient to exploit stack/heap overflows, arbitrary memory writes, lack of
input validation, etc.

In this section, we will look into more advanced vulnerability patterns that S2E can detect. All these patterns are
based on the ability of S2E to detect uses of symbolic pointers, like assignment to program counter or simple
dereference. We will see how to detect and exploit function pointer overwrites, reads and writes to arbitrary memory
locations, as well as function calls that have symbolic parameters.

Function Pointer Overwrite
--------------------------

In the following example, ``f_ptr`` is overwritten by the receive function. So instead of calling ``f_ptr``, the program
ends up calling a pointer set by the attacker.

.. code-block:: c
    :number-lines:

    int main(int argc, char **argv)
    {
        int (*f_ptr)(void);
        char buffer[32];
        f_ptr = f; // f is a function defined elsewhere in the program
        receive(buffer, sizeof(buffer) + 4);
        return f_ptr();
    }

When ``f_ptr`` is called, S2E detects the attempt to set ``EIP`` to a symbolic value and tries every available recipe.
This is very similar to the case of return address overwrites, in which the return instruction fetches the symbolic
value stored on the stack and attempts to assign it to the program counter. Here, we have a call (or jump) instruction
that computes the target (e.g., by getting it from a register or from a memory location specified by the operand) before
writing it to the program counter. The recipe plugin catches the write and tries to figure out if there is a recipe that
can force the program counter to go to an interesting address.

Arbitrary Writes
----------------

The code snippet below contains an arbitrary write vulnerability. It exemplifies a situation that commonly occurs with
heap overflow vulnerabilities. An attacker may overwrite the memory location specified by input bytes ``[32:35]`` with
the value specified by input bytes ``[0:3]``.

.. code-block:: c
    :number-lines:

    int main(int argc, char **argv)
    {
        // Initialize a with the address of a legitimate global variable
        int *a = &g_my_var;
        char buffer[32];

        receive(buffer, sizeof(buffer) + 4);
        *a = *(int *)buffer;
        return *a;
    }

The trick to exploit such vulnerabilities automatically is to collect addresses of all sorts of interesting targets
during execution. Such targets include locations of return addresses on the stack, various code pointers, etc. When S2E
finds an arbitrary write, the recipe plugin uses that write to overwrite every potential target with attacker-controlled
data. Later on, as S2E continues execution, it will detect the use of the overwritten return address and handle it as
the common case of return address / code pointer overwrite.

The recipe plugin instruments call and ret instructions to keep a LIFO structure for locations of return addresses to be
used as potential targets for arbitrary writes. This is a best effort attempt at exploitation: if the binary interrupts
execution between the arbitrary write vulnerability and the following return instruction (e.g., by means of an exit),
the exploitation attempt will fail. We discuss later ways to identify more potential targets to improve the chances of
successfully exploiting arbitrary writes.

Arbitrary Reads
---------------

S2E also supports exploitation of arbitrary memory reads. The following code snippet has a pointer ``a`` to a structure
that contains a function pointer ``f_ptr``. The program dereferences ``a`` and then calls ``f_ptr``. The attacker can
overwrite ``a`` to point to the buffer buffer, which would allow setting ``f_ptr`` to an arbitrary value and thus
execute arbitrary code.

.. code-block:: c
    :number-lines:

    struct test {
        int abcd;
        int (*f_ptr)(void);
    };

    struct test g_test1 = {0, my_func1};
    int main(int argc, char **argv)
    {
        // Initialize a with the address of a legitimate global variable
        struct test *a = &g_test1;
        char buffer[32];

        // This receive overflows by 4 bytes, overwriting pointer a
        // with attacker-controlled data.
        receive(buffer, sizeof(buffer) + 4);

        // Reads attacker-controller pointer value from a,
        // then reads the address of a function stored in f_ptr
        // (also attacker controlled), and finally calls that function.
        a->f_ptr();
        return 0;
    }

When S2E identifies an arbitrary read, the recipe plugin looks for memory locations (e.g., ``buffer``) that contain
symbolic data (i.e., derived from user input). The plugin forces constraints on the target of the read operation (e.g.,
``a``) to make it point to one of these locations, and let execution go forward. By doing so, if any of the values read
from symbolic memory are used, e.g., as target of a write operation, or of an indirect control instruction, the plugin
can detect and exploit it as explained in previous scenarios.  The line invoking the function pointer ``a->f_ptr()``
triggers the arbitrary read vulnerability. S2E automatically overwrites pointer ``a`` with the address of buffer, so
that ``f_ptr`` tries to invoke symbolic bytes at ``buffer[4:7]``. This is then handled as a function pointer overwrite
case.

Function Calls with Symbolic Parameters
---------------------------------------

There are cases where the ability to pass arbitrary arguments to certain functions can be exploited to exfiltrate data.
The following example transmits 128 bytes stored at the memory location pointed to by ``a``. Unfortunately, this
location can be controlled by the attacker through a buffer overflow. The attacker can therefore set it to any address
and exfiltrate pretty much anything from the address space of the binary, such as encryption keys, passwords, or other
secrets.

.. code-block:: c
    :number-lines:

    char g_long_string[128] = "...";
    int main(int argc, char **argv)
    {
        // Initialize a to the address of a legitimate string
        char *a = g_a_string;
        char buffer[32];

        // Overflow 4 bytes past the buffer
        receive(0, buffer, sizeof(buffer) + 4);

        // a contains attacker-controlled data, allowing to exfiltrate
        // any data in the address space.
        transmit(a, 128);
        return 0;
    }

Detecting such cases for S2E is straightforward. The recipe plugin instruments every critical function (e.g.,
``transmit()``) to check whether any of the critical parameters can be made to point to interesting data. It then
applies recipes to produce a ``Type`2`` PoV which aims to leak a flag in the secret page. The challenge is to
automatically identify such functions (not only ``transmit()``) inside the CGC binaries. Before starting the analysis of
the binary, S2E disassembles it, extracts all function addresses, then invokes every function with canned parameters. If
the function produces the expected output, identification succeeded.



    S2E uses `RevGen <https://github.com/S2E/s2e/tree/master/tools/tools/revgen32>`__, an x86-to-LLVM translator,
    in order to extract function types from the binary before analyzing it.


Generating Replayable PoVs
==========================

In the CGC framework, a PoV is a normal program that communicates with the vulnerable binary in order to exploit it.
Communication can be done through a pipe or a network. A PoV can send data to the binary and receive data that the
binary outputs. PoVs are free to make computations on the data they get from the challenge binary in order to generate
input for the binary that will lead to exploitation.

The example below shows a simple PoV that sends a long string that triggers a buffer overflow in the challenge binary.
Note that even if data sent by the binary is not used, it must still be consumed by the PoV, otherwise the binary could
block when its transmit buffer is full.

.. raw:: html

    <table>
    <tr><th>PoV</th><th>Challenge Binary</th></tr>
    <tr>
        <td>

.. code-block:: c
    :number-lines:

    int main(...) {
        transmit(
           "aaaaaaaaaaaaaaaa"
           "bbbbbbbbbbbbbbbb"
           "cccccccc", 40
        );

        char buffer[4];
        receive(buffer, 4);
    }

.. raw:: html

        </td>
        <td>

.. code-block:: c
    :number-lines:

    int main(...) {
        char buffer[32];

        receive(buffer, sizeof(buffer) + 8);

        transmit("done", 4);
    }


.. raw:: html

    </td>
    </tr>
    </table>

In this section, we will discuss some of the challenges that symbolic execution engines face in order to generate
correct and reliable PoVs.

S2E generates a PoV for the above example as follows. First, S2E instruments the program to monitor calls to the receive
and transmit functions. S2E makes the contents of the receive buffer symbolic and records what the binary writes through
the transmit function. It maintains an ordered list of these calls. When a path terminates and is exploitable, S2E
generates concrete inputs and attaches them to the corresponding receive entry in the list. Second, for every receive
invoked by the binary, S2E generates a corresponding write in the PoV. This write contains the concrete data computed by
the solver. Likewise, S2E generates a receive operation for every transmit done by the binary. In its simplest form, the
PoV ignores the contents sent by the binary.

The complexity of generating a PoV depends on whether the challenge binary is deterministic or not, and whether it
requires the PoV to perform computations. A deterministic binary is one that does not use randomness, making PoV
generation easy. When the symbolic execution engine detects a vulnerable point, it calls the constraint solver in order
to get concrete inputs. These concrete inputs can then be used to exploit the binary. Moreover, they are guaranteed to
work on every exploitation attempt.

Generating PoVs for non-deterministic input is much harder than for deterministic ones. Non-determinism occurs when the
challenge binary relies on random data to implement its functionality. This often happens in challenge-response
algorithms, where a program sends a random value to the client and expects the client to reply with a correct response
based on some computation on that random value. A simplified version of this is when a program generates a random value
(or "cookie"), sends that cookie to the client, then expects the client to send that cookie back unmodified on the next
request in order to operate properly.

S2E handles non-deterministic binaries that use simple cookies. Consider the following scenario. A challenge binary
calls the random number generator, records the random number, then transmits it. It then expects to receive that number
from the remote host in order to continue with execution. S2E has no trouble making the random value symbolic and
getting to the vulnerability. The problem is that by default, the generated PoV is invalid: the constraint solver does
not know that the received value has any connection to the written value and as a result generates a bogus concrete
value that does not match the random data. Moreover, the random value will be different on every run, so it is
impossible to hard-code a fixed value in the PoV. The following code snippet shows such a case.

.. code-block:: c
    :number-lines:

    int main(int argc, char **argv)
    {
        int data;
        // S2E returns a symbolic value instead of the original concrete value
        int cookie = random();
        // The binary sends the random value to the client
        transmit(&cookie, sizeof(cookie));
        // S2E creates a fresh symbolic value for data
        receive(&data, sizeof(data));
        // data is not constrained, so S2E can explore both outcomes of the if
        if (data != cookie) {
          return 0;
        }
        // When arriving here, S2E generates an unreplayable PoV because
        // it did not realize that data and cookie are connected together
        vulnerable_code();
    }

    void naive_pov()
    {
      int data0;
      // The POV expects to read 4 bytes of data written by the program.
      receive(&data, sizeof(data));
      // 1234 is a random value chosen by the solver for the cookie. It was
      // valid only for one path and is unlikely to be useful in the next run.
      int data1 = 1234;
      transmit(&data1, sizeof(data1));
    }


A correct PoV would look like this:

.. code-block:: c
    :number-lines:

    void correct_pov()
    {
      int data0;
      receive(&data0, sizeof(data0));
      int data1 = data0;
      // Transmit the previously received data
      transmit(&data1, sizeof(data1));
    }

To generate a correct PoV, S2E looks at all branch conditions and looks for cases where the content of a receive buffer
is compared with a symbolic value derived from the random number generator. Once it found such a comparison, it can
easily generate the correct PoV code by mapping the symbolic value created in the receive call to the symbolic value
written by the transmit function.

A much harder case happens when the PoV needs to perform computations. Consider the slightly modified above example:

.. code-block:: c
    :number-lines:

    int main(int argc, char **argv)
    {
        int data;
        int cookie = random();
        transmit(&cookie, sizeof(cookie));
        receive(&data, sizeof(data));
        if (data * 8 != cookie) {
          return 0;
        }
        vulnerable_code();
    }

A valid PoV would look something like this:

.. code-block:: c
    :number-lines:

    void correct_pov()
    {
      int data0;
      receive(&data0, sizeof(data0));
      int data1 = data0 / 8;
      // Transmit the previously received data
      transmit(&data1, sizeof(data1));
    }

Generating a valid PoV in the general case where computations on transmitted data are involved requires embedding a
constraint solver directly inside the PoV itself. The PoV would have to solve the equation (``date * 8 == cookie``) in
order to exploit the binary. For some simple cases like here, it may be possible to invert the equation, though in
general, conditions are of the form ``f(x,y,...)=0``, making this task practically impossible without running the actual
solver. The following snippet shows how would an automatically generated PoV with an embedded solver look like.

.. code-block:: c
    :number-lines:

    void correct_pov_with_solver()
    {
      int data0, data1;
      receive(&data0, sizeof(data0));
      // pseudo code that takes data0 as input and computes data1
      solve("%s * 8 == %s", &data0, &data1);
      // Transmit the previously received data
      transmit(&data1, sizeof(data1));
    }

Unfortunately, we ran out of time and didn't have time to implement this solution. The main challenge was to fit an
entire solver within the size and memory limits of a PoV, as well as modifying the solver to accommodate a very
restricted runtime environment, that has primitive memory allocation, no standard library, etc.

Conclusion
==========

In this tutorial, you have learnt the theory behind automated PoV generation as well as various practical
issues that arise when building a robust PoV generator. Now it is a good time to get your hands dirty
by actually `generating <index.rst>`__ PoVs for a few vulnerable binaries.
