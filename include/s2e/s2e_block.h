///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _S2E_BLOCK_H_

#define _S2E_BLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct S2EBlockDevice;

/* Disk-related copy on write */
int s2e_bdrv_read(struct S2EBlockDevice *bs, int64_t sector_num, uint8_t *buf, int nb_sectors);

int s2e_bdrv_write(struct S2EBlockDevice *bs, int64_t sector_num, const uint8_t *buf, int nb_sectors);

void s2e_bdrv_fail();

extern struct S2EExecutionState **g_block_s2e_state;

#ifdef __cplusplus
}
#endif

#endif
