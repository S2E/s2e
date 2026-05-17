///
/// A pure computation function used to exercise the KLEE interpreter.
///
/// The function reads from *in and writes results to *out. It uses no
/// standard library and has no other side effects.
///

typedef struct {
    int values[8];  /// Input array (up to 8 elements)
    int n;          /// Number of valid elements (clamped to [0,8])
    unsigned flags; /// Bitmask combined with all elements via AND
} Input;

typedef struct {
    int sum;             /// Sum of all elements
    int min_val;         /// Minimum element (0 if n==0)
    int max_val;         /// Maximum element (0 if n==0)
    unsigned xor_all;    /// XOR of all elements
    unsigned and_masked; /// flags & values[0] & values[1] & ...
    int alternating;     /// values[0] - values[1] + values[2] - ...
    int dot_self;        /// Sum of values[i] * values[i]
} Output;

/// Compute aggregate statistics over the integer array in *in.
///
/// Exercises: loops, conditional branches, phi nodes, GEP (struct and array),
/// load/store, add/sub/mul, xor/and, shl/ashr, icmp (slt/sgt/eq),
/// select, sext/zext/trunc.
void compute(const Input *in, Output *out) {
    /// Clamp n to [0, 8] using conditional branches.
    int n = in->n;
    if (n < 0)
        n = 0;
    if (n > 8)
        n = 8;

    int sum = 0;
    int min_val = 0x7fffffff;
    int max_val = -0x7fffffff - 1;
    unsigned xor_all = 0u;
    unsigned and_masked = in->flags;
    int alternating = 0;
    int dot_self = 0;

    /// Main loop: exercises phi nodes, GEP with variable index, select.
    for (int i = 0; i < n; i++) {
        int v = in->values[i];

        sum += v;

        /// min/max via ternary (select instruction).
        min_val = v < min_val ? v : min_val;
        max_val = v > max_val ? v : max_val;

        /// Bitwise: XOR accumulator, AND with flags.
        xor_all ^= (unsigned) v;
        and_masked &= (unsigned) v;

        /// Alternating sum: even indices add, odd indices subtract.
        /// Uses bitwise AND to test parity, then select.
        int sign = (i & 1) ? -1 : 1;
        alternating += sign * v;

        /// Dot product with itself: exercises MUL.
        dot_self += v * v;
    }

    /// Reset min/max to zero for empty input.
    if (n == 0) {
        min_val = 0;
        max_val = 0;
    }

    /// Shift-based post-processing: exercises SHL and ASHR.
    int shifted_sum = sum << 2;       /// sum * 4
    int recovered = shifted_sum >> 2; /// should equal sum (arithmetic shift)

    /// Mix shifted results back in to keep the compiler from optimising out.
    out->sum = recovered;
    out->min_val = min_val;
    out->max_val = max_val;
    out->xor_all = xor_all;
    out->and_masked = and_masked;
    out->alternating = alternating;
    out->dot_self = dot_self;
}
