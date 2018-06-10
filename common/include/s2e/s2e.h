///
/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2010-2017, Dependable Systems Laboratory, EPFL
/// Copyright (c) 2017, Cyberhaven
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are met:
///     * Redistributions of source code must retain the above copyright
///       notice, this list of conditions and the following disclaimer.
///     * Redistributions in binary form must reproduce the above copyright
///       notice, this list of conditions and the following disclaimer in the
///       documentation and/or other materials provided with the distribution.
///     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
///       names of its contributors may be used to endorse or promote products
///       derived from this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
/// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
/// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
/// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
/// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
/// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
/// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef S2E_CUSTOM_INSTRUCTIONS_H
#define S2E_CUSTOM_INSTRUCTIONS_H

#include <stdarg.h>
#include <stdio.h>

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <inttypes.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "opcodes.h"

// clang-format off

#define _S2E_INSTRUCTION_COMPLEX(val1, val2)            \
    ".byte 0x0F, 0x3F\n"                                \
    ".byte 0x00, " #val1 ", " #val2 ", 0x00\n"          \
    ".byte 0x00, 0x00, 0x00, 0x00\n"

// This layer of indirection is required so that the arguments are expanded
// before being "stringified"
#define S2E_INSTRUCTION_COMPLEX(val1, val2)             \
    _S2E_INSTRUCTION_COMPLEX(val1, val2)

#define S2E_INSTRUCTION_SIMPLE(val)                     \
    _S2E_INSTRUCTION_COMPLEX(val, 0x00)

#ifdef __x86_64__
#define S2E_INSTRUCTION_REGISTERS_COMPLEX(val1, val2)   \
    "push %%rbx\n"                                      \
    "mov %%rdx, %%rbx\n"                                \
    _S2E_INSTRUCTION_COMPLEX(val1, val2)                \
    "pop %%rbx\n"
#else
#define S2E_INSTRUCTION_REGISTERS_COMPLEX(val1, val2)   \
    "pushl %%ebx\n"                                     \
    "movl %%edx, %%ebx\n"                               \
    _S2E_INSTRUCTION_COMPLEX(val1, val2)                \
    "popl %%ebx\n"
#endif

#define S2E_INSTRUCTION_REGISTERS_SIMPLE(val)           \
    S2E_INSTRUCTION_REGISTERS_COMPLEX(val, 0x00)

///
/// \brief Forces a read of each byte in the specified string
///
/// This ensures that the memory pages occupied by the string are paged in memory before passing them to S2E, which
/// cannot page in memory by itself.
///
/// \param[in] string String to page into memory
///
static inline void __s2e_touch_string(volatile const char *string) {
    while (*string) {
        ++string;
    }
}

///
/// \brief Forces a read of each byte in the specified buffer
///
/// This ensures that the memory pages occupied by the buffer are paged in memory before passing them to S2E, which
/// cannot page in memory by itself.
///
/// \param[in] buffer Buffer to page into memory
/// \param[in] size Number of bytes in the buffer
///
static inline void __s2e_touch_buffer(volatile void *buffer, unsigned size) {
    unsigned i;
    unsigned t __attribute__((unused));
    volatile char *b = (volatile char *) buffer;
    for (i = 0; i < size; ++i) {
	t = *b;
	++b;
    }
}

///
/// \brief Get the S2E version
///
/// \return The S2E version or 0 when running without S2E
///
static inline int s2e_check(void) {
    int version;
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_CHECK)
        : "=a" (version)  : "a" (0)
    );
    return version;
}

//
// These functions allow you to print messages and symbolic values to the S2E log file. This is useful for debugging
//

///
/// \brief Print a message to the S2E log
///
/// \param[in] message The message to print
///
static inline void s2e_message(const char *message) {
    __s2e_touch_string(message);
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_PRINT_MSG)
        : : "a" (message)
    );
}

///
/// \brief Print a format string as an S2E message
///
/// \param[in] format The format string
/// \param[in] ... Arguments to the format string
/// \return The number of characters printed
///
static inline int s2e_printf(const char *format, ...) {
    char buffer[512];
    va_list args;
    int ret;

    va_start(args, format);
    ret = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    s2e_message(buffer);

    return ret;
}

///
/// \brief Print a warning message to the S2E log and S2E stdout
///
/// \param[in] message The message to print
///
static inline void s2e_warning(const char *message) {
    __s2e_touch_string(message);
    __asm__ __volatile__(
        S2E_INSTRUCTION_COMPLEX(BASE_S2E_PRINT_MSG, 0x01)
        : : "a" (message)
    );
}

///
/// \brief Print a symbolic expression to the S2E log
///
/// \param[in[ name The expression name
/// \param[in] expression The symbolic expression
///
static inline void s2e_print_expression(const char *name, int expression) {
    __s2e_touch_string(name);
    __asm__ __volatile__(
        S2E_INSTRUCTION_COMPLEX(BASE_S2E_PRINT_EXPR, 0x01)
        : : "a" (expression), "c" (name)
    );
}

//
// These functions control symbolic and concolic values, allowing you to create symbolic values and concretize them
//

///
/// \brief Fill a buffer with unconstrained symbolic values
///
/// \param[out] buf The buffer to make symbolic
/// \param[in] size The buffer's size
/// \param[in] name A descriptive name for the buffer
///
static inline void s2e_make_symbolic(void *buf, int size, const char *name) {
    __s2e_touch_string(name);
    __s2e_touch_buffer(buf, size);
    __asm__ __volatile__(
        S2E_INSTRUCTION_REGISTERS_SIMPLE(BASE_S2E_MAKE_SYMBOLIC)
        : : "a" (buf), "d" (size), "c" (name) : "memory"
    );
}

///
/// \brief Fill buffer with unconstrained symbolic valies without discarding concrete data
///
/// \param[out] buf The buffer to make concolic
/// \param[in] size The buffer's size
/// \param[in] name A descriptive name for the buffer
///
static inline void s2e_make_concolic(void *buf, int size, const char *name) {
    __s2e_touch_string(name);
    __s2e_touch_buffer(buf, size);
    __asm__ __volatile__(
        S2E_INSTRUCTION_REGISTERS_SIMPLE(BASE_S2E_MAKE_CONCOLIC)
        : : "a" (buf), "d" (size), "c" (name) : "memory"
    );
}

///
/// \brief Returns \c true if the given pointer points to symbolic memory
///
/// \param[in] ptr Pointer to check
/// \param[in] size The pointer's size
///
/// \return 1 if the pointer points to symbolic memory, or 0 otherwise
///
static inline int s2e_is_symbolic(void *ptr, size_t size) {
    int result;
    __s2e_touch_buffer(ptr, 1);
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_IS_SYMBOLIC)
        : "=a" (result) : "a" (size), "c" (ptr)
    );
    return result;
}

///
/// \brief Concretize the given expression
///
/// \param[out] buf The buffer to concretize
/// \param[in] size The buffer's size
///
static inline void s2e_concretize(void *buf, int size) {
    __s2e_touch_buffer(buf, size);
    __asm__ __volatile__(
        S2E_INSTRUCTION_REGISTERS_SIMPLE(BASE_S2E_CONCRETIZE)
        : : "a" (buf), "d" (size) : "memory"
    );
}

///
/// \brief Generate a concrete value based on the current path constraints
///
/// This example value is generated without adding state constraints.
///
/// \param[out] buf The example value
/// \param[in] size The size of the buffer to write the example value to
///
static inline void s2e_get_example(void *buf, int size) {
    __s2e_touch_buffer(buf, size);
    __asm__ __volatile__(
        S2E_INSTRUCTION_REGISTERS_SIMPLE(BASE_S2E_EXAMPLE)
        : : "a" (buf), "d" (size) : "memory"
    );
}

///
/// \brief Generate a bounded, concrete value based on the current path constraints
///
/// This example value is generated without adding state constraints.
///
/// \param[out] expr The example value
/// \param[out] low The lower bound
/// \param[out] high The upper bound
///
static inline void s2e_get_range(uintptr_t expr, uintptr_t *low, uintptr_t *high) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_REGISTERS_SIMPLE(BASE_S2E_GET_RANGE)
        : : "a" (expr), "c" (low), "d" (high)
    );
}

///
/// \brief Get the number of constraints for the given expression
///
/// \param[in] expr The expression to count constraints for
/// \return The number of constraints
///
static inline unsigned s2e_get_constraint_count(uintptr_t expr) {
    unsigned result;
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_CONSTR_CNT)
        : "=a" (result) : "a" (expr)
    );
    return result;
}

///
/// \brief Generate a concrete value based on the given expression
///
/// The example value is generated without adding state constraints. This is a convenience function to be used in
/// printfs.
///
/// \param[in] val The expression to generate a concrete value for
/// \return A concrete value
///
static inline unsigned s2e_get_example_uint(unsigned val) {
    unsigned buf = val;
    __asm__ __volatile__(
        S2E_INSTRUCTION_REGISTERS_SIMPLE(BASE_S2E_EXAMPLE)
        : : "a" (&buf), "d" (sizeof(buf)) : "memory"
    );
    return buf;
}

//
// These functions control the path exploration from within the guest. The guest can enable/disable forking as well as
// kill states at any point in the code. When forking is disabled, S2E follows only one branch outcome, even if both
// outcomes are feasible
//

///
/// \brief Enable forking on symbolic conditions
///
static inline void s2e_enable_forking(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_ENABLE_FORK)
    );
}

///
/// \brief Disable forking on symbolic conditions
///
static inline void s2e_disable_forking(void)
{
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_DISABLE_FORK)
    );
}

///
/// \brief Forks the given number of times without adding constraints
///
/// \param[in] count The number of times to fork
/// \param[in] name Label
/// \return ???
///
static inline int s2e_fork(int count, const char *name) {
    unsigned result = 0;
    __s2e_touch_string(name);
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_FORK_COUNT)
        : "=a" (result) : "a" (count), "c" (name)
    );

    s2e_concretize(&result, sizeof(result));

    return result;
}

///
/// \brief Terminate the currently-executing state
///
/// \param[in] status Exit code
/// \param[in] message The message to print upon exiting
///
static inline void s2e_kill_state(int status, const char *message) {
    __s2e_touch_string(message);
    __asm__ __volatile__(
        S2E_INSTRUCTION_REGISTERS_SIMPLE(BASE_S2E_KILL_STATE)
        : : "a" (status), "d" (message)
    );
}

///
/// \brief Terminate the currently-executing state and print a formatted string as an S2E message
///
/// \param[in] status Exit code
/// \param[in] message Format string of message to print
/// \param[in] ... Arguments to the format string
///
static inline void s2e_kill_state_printf(int status, const char *message, ...) {
    char buffer[512];
    va_list args;
    va_start(args, message);
    vsnprintf(buffer, sizeof(buffer), message, args);
    va_end(args);
    s2e_kill_state(status, buffer);
}

///
/// \brief Yield the current state
///
static inline void s2e_yield(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_YIELD)
    );
}

///
/// \brief Get the current execution path/state ID
///
/// \return The current execution path/state ID
///
static inline unsigned s2e_get_path_id(void) {
    unsigned id;
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_GET_PATH_ID)
        : "=a" (id)
    );
    return id;
}

///
/// \brief Prevent the searcher from switching states unless the current state dies
///
/// \c s2e_end_atomic should be called to reenable the searcher to switch states.
///
static inline void s2e_begin_atomic(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_BEGIN_ATOMIC)
    );
}

///
/// \brief Reenable the searcher to switch states
///
/// Used together with \c s2e_begin_atomic
///
static inline void s2e_end_atomic(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_END_ATOMIC)
    );
}

///
/// \brief Adds a constraint to the current state
///
/// The constraint must be satisfiable.
///
/// \param[in] expression A satisfiable constraint
///
static inline void s2e_assume(int expression) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_ASSUME)
        : : "a" (expression)
    );
}

///
/// \brief Adds a bounded constraint to the current state
///
/// The constraint must be satisfiable.
///
/// \param[in] expression A bounded, satisfiable constraint
/// \param[in] lower The constraint's lower bound
/// \param[in] upper The constraint's upper bound
///
static inline void s2e_assume_range(unsigned int expression, unsigned int lower, unsigned int upper) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_ASSUME_RANGE)
        : :  "a" (expression), "c" (lower), "d" (upper)
    );
}

///
/// \brief Returns a symbolic value in a given range
///
/// \param[in] start Lower bound
/// \param[in] end Upper bound
/// \param[in] name Symbolic value's name
/// \return The symbolic value
///
static inline int s2e_range(int start, int end, const char *name) {
    int x = -1;

    if (start >= end) {
        s2e_kill_state(1, "s2e_range: invalid range");
    }

    if (start + 1 == end) {
        return start;
    } else {
        s2e_make_symbolic(&x, sizeof x, name);

        /* Make nicer constraint when simple... */
        if (start == 0) {
            if ((unsigned) x >= (unsigned) end) {
                s2e_kill_state(0, "s2e_range creating a constraint...");
            }
        } else {
            if (x < start || x >= end) {
                s2e_kill_state(0, "s2e_range creating a constraint...");
            }
        }

        return x;
    }
}

///
/// \brief Enable timer interrupts in the VM
///
static inline void s2e_enable_timer_interrupt(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_SET_TIMER_INT)
    );
}

///
/// \brief Disable timer interrupts in the guest
///
static inline void s2e_disable_timer_interrupt(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_COMPLEX(BASE_S2E_SET_TIMER_INT, 0x01)
    );
}

///
/// \brief Enable all APIC interrupts in the guest
///
static inline void s2e_enable_all_apic_interrupts(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_SET_APIC_INT)
    );
}

///
/// \brief Disable all APIC interrupts in the guest
///
static inline void s2e_disable_all_apic_interrupts(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_COMPLEX(BASE_S2E_SET_APIC_INT, 0x01)
    );
}

///
/// \brief Get the size of a RAM object in bits
///
/// \return The value of \c SE_RAM_OBJECT_BITS
///
static inline int s2e_get_ram_object_bits(void) {
    int bits;
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_GET_OBJ_SZ)
        : "=a" (bits)  : "a" (0)
    );
    return bits;
}

///
/// \brief Open a file on the host
///
/// Requires that the \c HostFiles plugin is enabled.
///
/// \param[in] fname Path to the host file. This path must be relative to the \c HostFiles plugin base directory
/// \return File descriptor for the host file
///
static inline int s2e_open(const char *fname) {
    int fd;
    __s2e_touch_string(fname);
    __asm__ __volatile__(
        S2E_INSTRUCTION_COMPLEX(HOST_FILES_OPCODE, HOST_FILES_OPEN_OPCODE)
        : "=a" (fd) : "a"(-1), "b" (fname), "c" (0)
    );
    return fd;
}

///
/// \brief Close a file on the host
///
/// Requires that the \c HostFiles plugin is enabled.
///
/// \param[in] fd File descriptor for the host file
/// \return result of close operation
///
static inline int s2e_close(int fd) {
    int res;
    __asm__ __volatile__(
        S2E_INSTRUCTION_COMPLEX(HOST_FILES_OPCODE, HOST_FILES_CLOSE_OPCODE)
        : "=a" (res) : "a" (-1), "b" (fd)
    );
    return res;
}

///
/// \brief Read the contents of a file from the host
///
/// Requires that the \c HostFiles plugin is enabled.
///
/// \param[in] fd File descriptor for the host file
/// \param[out] buf Buffer to read the file contents into
/// \param[int] count Number of bytes to read
/// \return The actual number of bytes read
///
static inline int s2e_read(int fd, char *buf, int count) {
    int res;
    __s2e_touch_buffer(buf, count);
    __asm__ __volatile__(
#ifdef __x86_64__
        "push %%rbx\n"
        "mov %%rsi, %%rbx\n"
#else
        "pushl %%ebx\n"
        "movl %%esi, %%ebx\n"
#endif
        S2E_INSTRUCTION_COMPLEX(HOST_FILES_OPCODE, HOST_FILES_READ_OPCODE)
#ifdef __x86_64__
        "pop %%rbx\n"
#else
        "popl %%ebx\n"
#endif
        : "=a" (res) : "a" (-1), "S" (fd), "c" (buf), "d" (count)
    );
    return res;
}

///
/// \brief Create a file on the host
///
/// Requires that the \c HostFiles plugin is enabled.
///
/// \param[in] fname Name of the file to create
/// \return File descriptor of the file
///
static inline int s2e_create(const char *fname) {
    int fd;
    __s2e_touch_string(fname);
    __asm__ __volatile__(
        S2E_INSTRUCTION_COMPLEX(HOST_FILES_OPCODE, HOST_FILES_CREATE_OPCODE)
        : "=a" (fd) : "a"(-1), "b" (fname), "c" (0)
    );
    return fd;
}

///
/// \brief Write file content to the host
///
/// Requires that the \c HostFiles plugin is enabled.
///
/// \param[in] fd File descriptor for the host file
/// \param[in] buf Data to write
/// \param[in] count Number of bytes to write
/// \return The actual number of bytes to write
///
static inline int s2e_write(int fd, char *buf, int count) {
    int res;
    __s2e_touch_buffer(buf, count);
    __asm__ __volatile__(
#ifdef __x86_64__
        "push %%rbx\n"
        "mov %%rsi, %%rbx\n"
#else
        "pushl %%ebx\n"
        "movl %%esi, %%ebx\n"
#endif
        S2E_INSTRUCTION_COMPLEX(HOST_FILES_OPCODE, HOST_FILES_WRITE_OPCODE)
#ifdef __x86_64__
        "pop %%rbx\n"
#else
        "popl %%ebx\n"
#endif
        : "=a" (res) : "a" (-1), "S" (fd), "c" (buf), "d" (count)
    );
    return res;
}

///
/// \brief Enable memory tracing
///
static inline void s2e_memtracer_enable(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(MEMORY_TRACER_OPCODE)
    );
}

///
/// \brief Disable memory tracing
///
static inline void s2e_memtracer_disable(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_COMPLEX(MEMORY_TRACER_OPCODE, 0x01)
    );
}

///
/// \brief Programmatically add a new configuration entry to the \c ModuleExecutionDetector plugin
///
/// \param[in] moduleId The module's ID
/// \param[in] moduleName The module's name
/// \param[in] kernelMode Set to 1 if the module is in the kernel, or 0 otherwise
///
static inline void s2e_moduleexec_add_module(const char *moduleId, const char *moduleName, int kernelMode) {
    __s2e_touch_string(moduleId);
    __s2e_touch_string(moduleName);
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(MODULE_EXECUTION_DETECTOR_OPCODE)
            : : "c" (moduleId), "a" (moduleName), "d" (kernelMode)
    );
}

///
/// \brief Terminate the currently-executing state if \c b is zero
///
/// \param[in] b boolean value to determine whether to terminate the current state
/// \param[in] expression Message to print upon state termination
///
static inline void _s2e_assert(int b, const char *expression) {
    if (!b) {
        s2e_kill_state(0, expression);
    }
}

#define s2e_assert(expression) _s2e_assert(expression, "Assertion failed: "  #expression)

///
/// \brief Check if a plugin has been loaded
///
/// \param[in] pluginName Name of the plugin to check
/// \return 1 if the plugin is loaded, 0 otherwise
///
static inline int s2e_plugin_loaded(const char *pluginName) {
    int result;
    __s2e_touch_string(pluginName);
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_CHECK_PLUGIN)
        : "=a" (result) : "a" (pluginName)
    );

    return result;
}

///
/// \brief Send data to a given plugin
///
/// \param[in] pluginName The plugin to send the data to
/// \param[in] data The data to send
/// \param[in] dataSize Number of bytes to send
/// \return 0 on success or an error code on failure
///
static inline int s2e_invoke_plugin(const char *pluginName, void *data, uint32_t dataSize) {
    int result;
    __s2e_touch_string(pluginName);
    __s2e_touch_buffer(data, dataSize);
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_INVOKE_PLUGIN)
        : "=a" (result) : "a" (pluginName), "c" (data), "d" (dataSize) : "memory"
    );

    return result;
}

///
/// \brief Send data to the given plugin
///
/// This function ensures that the CPU state is concrete before invoking the plugin.
///
/// \param[in] The plugin to send the data to
/// \param[in] data The data to send
/// \param[in] dataSize Number of bytes to send
/// \return 0 on success or an error code on failure
///
static inline int s2e_invoke_plugin_concrete(const char *pluginName, void *data, uint32_t dataSize) {
    int result;
    __s2e_touch_string(pluginName);
    __s2e_touch_buffer(data, dataSize);

    __asm__ __volatile__(
        #ifdef __x86_64__
        "push %%rbx\n"
        "push %%rsi\n"
        "push %%rdi\n"
        "push %%rbp\n"
        "push %%r8\n"
        "push %%r9\n"
        "push %%r10\n"
        "push %%r11\n"
        "push %%r12\n"
        "push %%r13\n"
        "push %%r14\n"
        "push %%r15\n"

        "xor  %%rbx, %%rbx\n"
        "xor  %%rsi, %%rsi\n"
        "xor  %%rdi, %%rdi\n"
        "xor  %%rbp, %%rbp\n"
        "xor  %%r8, %%r8\n"
        "xor  %%r9, %%r9\n"
        "xor  %%r10, %%r10\n"
        "xor  %%r11, %%r11\n"
        "xor  %%r12, %%r12\n"
        "xor  %%r13, %%r13\n"
        "xor  %%r14, %%r14\n"
        "xor  %%r15, %%r15\n"
        #else
        "push %%ebx\n"
        "push %%ebp\n"
        "push %%esi\n"
        "push %%edi\n"
        "xor %%ebx, %%ebx\n"
        "xor %%ebp, %%ebp\n"
        "xor %%esi, %%esi\n"
        "xor %%edi, %%edi\n"
        #endif

        // Clear temp flags
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_CLEAR_TEMPS)

        // Force concrete mode
        "jmp __sip1\n"
        "__sip1:\n"

        S2E_INSTRUCTION_SIMPLE(BASE_S2E_INVOKE_PLUGIN)

#ifdef __x86_64__
        "pop %%r15\n"
        "pop %%r14\n"
        "pop %%r13\n"
        "pop %%r12\n"
        "pop %%r11\n"
        "pop %%r10\n"
        "pop %%r9\n"
        "pop %%r8\n"
        "pop %%rbp\n"
        "pop %%rdi\n"
        "pop %%rsi\n"
        "pop %%rbx\n"
#else
        "pop %%edi\n"
        "pop %%esi\n"
        "pop %%ebp\n"
        "pop %%ebx\n"
#endif

            : "=a" (result) : "a" (pluginName), "c" (data), "d" (dataSize) : "memory"
    );

    return result;
}

typedef struct _merge_desc_t {
    uint64_t start;
} merge_desc_t;

///
/// \brief Merges the states that are generated between this function and \c s2e_merge_group_end into one path
///
static inline void s2e_merge_group_begin(void) {
    merge_desc_t desc;
    desc.start = 1;
    s2e_invoke_plugin("MergingSearcher", &desc, sizeof(desc));
}

///
/// \brief Merges the states that are generated between \c s2e_merge_group_begin and this function into one path
///
static inline void s2e_merge_group_end(void) {
    merge_desc_t desc;
    desc.start = 0;
    s2e_invoke_plugin_concrete("MergingSearcher", &desc, sizeof(desc));
}

///
/// \brief Display a hex dump of memory
///
/// \param[in] name Label the hex dump
/// \param[in] Address Start address of memory to dump
/// \param[in] size Number of bytes to dump from memory
///
static inline void s2e_hex_dump(const char *name, void *addr, unsigned size) {
    __s2e_touch_string(name);
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_HEX_DUMP)
        :: "a"(addr), "b" (size), "c" (name)
    );
}

///
/// \brief Flush the CPU translation block cache
///
static inline void s2e_flush_tbs(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_FLUSH_TBS)
    );
}

// clang-format on

#ifdef __cplusplus
}
#endif

#endif
