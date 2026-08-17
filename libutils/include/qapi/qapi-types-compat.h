/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * Schema-defined QAPI types
 *
 * Copyright IBM, Corp. 2011
 * Copyright (c) 2013-2018 Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#ifndef QAPI_TYPES_COMPAT_H
#define QAPI_TYPES_COMPAT_H

#include "qapi/qapi-builtin-types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum CompatPolicyInput {
    COMPAT_POLICY_INPUT_ACCEPT,
    COMPAT_POLICY_INPUT_REJECT,
    COMPAT_POLICY_INPUT_CRASH,
    COMPAT_POLICY_INPUT__MAX,
} CompatPolicyInput;

#define CompatPolicyInput_str(val) qapi_enum_lookup(&CompatPolicyInput_lookup, (val))

extern const QEnumLookup CompatPolicyInput_lookup;

typedef enum CompatPolicyOutput {
    COMPAT_POLICY_OUTPUT_ACCEPT,
    COMPAT_POLICY_OUTPUT_HIDE,
    COMPAT_POLICY_OUTPUT__MAX,
} CompatPolicyOutput;

#define CompatPolicyOutput_str(val) qapi_enum_lookup(&CompatPolicyOutput_lookup, (val))

extern const QEnumLookup CompatPolicyOutput_lookup;

typedef struct CompatPolicy CompatPolicy;

struct CompatPolicy {
    bool has_deprecated_input;
    CompatPolicyInput deprecated_input;
    bool has_deprecated_output;
    CompatPolicyOutput deprecated_output;
    bool has_unstable_input;
    CompatPolicyInput unstable_input;
    bool has_unstable_output;
    CompatPolicyOutput unstable_output;
};

void qapi_free_CompatPolicy(CompatPolicy *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(CompatPolicy, qapi_free_CompatPolicy)

#ifdef __cplusplus
}
#endif

#endif /* QAPI_TYPES_COMPAT_H */
