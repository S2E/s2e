/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Helper file for declaring TCG helper functions.
 * This one expands prototypes for the helper functions.
 */

#ifndef HELPER_PROTO_H
#define HELPER_PROTO_H

#include "helper-proto-common.h"

#define HELPER_H "tcg/helper.h"
#include "helper-proto.h.inc"
#undef HELPER_H

#endif /* HELPER_PROTO_H */
