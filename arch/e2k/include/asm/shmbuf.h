/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _E2K_ASM_SHMBUF_H_
#define _E2K_ASM_SHMBUF_H_

#include <uapi/asm/shmbuf.h>

#if defined(CONFIG_PROTECTED_MODE)
/* Outputs shared segment size for the given ID: */
unsigned long get_shm_segm_size(int shmid);
#endif

#endif /* _E2K_ASM_SHMBUF_H_ */
