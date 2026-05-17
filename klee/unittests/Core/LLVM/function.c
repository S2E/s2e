///
/// Functions exercising: function calls, returns, switch statements,
/// integer truncation, pointer-integer conversions, and function pointers.
///
/// No standard-library headers are included; unsigned long is used as a
/// pointer-sized integer (64-bit on Linux x86-64).
///

/// Helper called by call_chain – exercises Instruction::Call internally.
static int double_it(int x) {
    return x * 2;
}

/// Calls double_it and adds an offset.
/// Exercises Instruction::Call and the matching Instruction::Ret paths.
int call_chain(int x) {
    return double_it(x) + 1;
}

/// Multi-way branch – exercises Instruction::Switch.
/// Returns 10/20/30 for cases 0/1/2 and -1 for the default arm.
int classify(int x) {
    switch (x) {
        case 0:
            return 10;
        case 1:
            return 20;
        case 2:
            return 30;
        default:
            return -1;
    }
}

/// Truncate i32 → i8 – exercises Instruction::Trunc.
unsigned char trunc_to_u8(unsigned int x) {
    return (unsigned char) x;
}

/// Truncate i32 → i16 – exercises Instruction::Trunc.
unsigned short trunc_to_u16(unsigned int x) {
    return (unsigned short) x;
}

/// Convert pointer to integer – exercises Instruction::PtrToInt.
unsigned long ptr_to_int(void *p) {
    return (unsigned long) p;
}

/// Convert integer to pointer – exercises Instruction::IntToPtr.
void *int_to_ptr(unsigned long x) {
    return (void *) x;
}

/// Call fn(x) through a function pointer – exercises an indirect
/// Instruction::Call where the callee is a non-constant SSA value.
///
/// The caller must supply a concrete (non-symbolic) function pointer so
/// that the executor can resolve the callee at interpretation time.
int apply(int (*fn)(int), int x) {
    return fn(x);
}
