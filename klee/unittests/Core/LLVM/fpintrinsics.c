///
/// Copyright (C) 2026, Vitaly Chipounov
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

// Floating point intrinsics that clang emits for the hard float fast paths of
// softfloat: llvm.is.fpclass for the class predicates, llvm.fma for the fused
// multiply-add, llvm.rint for the rounding helpers and llvm.fmuladd for a
// contractable a * b + c.
//
// Must be compiled at -O0: at -O1 and above clang folds most of the class
// predicates into plain comparisons and the intrinsics disappear.

int is_signaling_d(double x) {
    return __builtin_issignaling(x);
}

int is_nan_d(double x) {
    return __builtin_isnan(x);
}

int is_inf_d(double x) {
    return __builtin_isinf(x);
}

int is_finite_d(double x) {
    return __builtin_isfinite(x);
}

int is_normal_d(double x) {
    return __builtin_isnormal(x);
}

int is_subnormal_d(double x) {
    return __builtin_issubnormal(x);
}

int is_zero_d(double x) {
    return __builtin_iszero(x);
}

int is_normal_f(float x) {
    return __builtin_isnormal(x);
}

double fma_d(double a, double b, double c) {
    return __builtin_fma(a, b, c);
}

float fma_f(float a, float b, float c) {
    return __builtin_fmaf(a, b, c);
}

double rint_d(double x) {
    return __builtin_rint(x);
}

double muladd_d(double a, double b, double c) {
    return a * b + c;
}
