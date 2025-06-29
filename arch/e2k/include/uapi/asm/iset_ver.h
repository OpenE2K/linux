/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_UAPI_ISET_VER_H_
#define _E2K_UAPI_ISET_VER_H_

#ifndef __ASSEMBLY__

/*
 * IMPORTANT: instruction sets are numbered in increasing order,
 * each next iset being backwards compatible with all the
 * previous ones.
 */
typedef enum e2k_iset_ver {
	E2K_ISET_GENERIC,
	E2K_ISET_V3 = 3,
	E2K_ISET_V4 = 4,
	E2K_ISET_V5 = 5,
	E2K_ISET_V6 = 6,
	E2K_ISET_V7 = 7,
} e2k_iset_ver_t;

#define E2K_ISET_V3_MASK	(1 << E2K_ISET_V3)
#define E2K_ISET_V4_MASK	(1 << E2K_ISET_V4)
#define E2K_ISET_V5_MASK	(1 << E2K_ISET_V5)
#define E2K_ISET_V6_MASK	(1 << E2K_ISET_V6)
#define E2K_ISET_V7_MASK	(1 << E2K_ISET_V7)

#define E2K_ISET_SINCE_V3_MASK	(-1)
#define E2K_ISET_SINCE_V4_MASK	(E2K_ISET_SINCE_V3_MASK & ~E2K_ISET_V3_MASK)
#define E2K_ISET_SINCE_V5_MASK	(E2K_ISET_SINCE_V4_MASK & ~E2K_ISET_V4_MASK)
#define E2K_ISET_SINCE_V6_MASK	(E2K_ISET_SINCE_V5_MASK & ~E2K_ISET_V5_MASK)
#define E2K_ISET_SINCE_V7_MASK	(E2K_ISET_SINCE_V6_MASK & ~E2K_ISET_V6_MASK)

enum {
	ELBRUS_GENERIC_ISET = E2K_ISET_GENERIC,
	ELBRUS_2S_ISET = E2K_ISET_V3,
	ELBRUS_8C_ISET = E2K_ISET_V4,
	ELBRUS_1CP_ISET = E2K_ISET_V4,
	ELBRUS_8C2_ISET = E2K_ISET_V5,
	ELBRUS_12C_ISET = E2K_ISET_V6,
	ELBRUS_16C_ISET = E2K_ISET_V6,
	ELBRUS_2C3_ISET = E2K_ISET_V6,
	ELBRUS_48C_ISET = E2K_ISET_V7,
	ELBRUS_8V7_ISET = E2K_ISET_V7,
};

#endif	/* !__ASSEMBLY__ */

#endif /* !_E2K_UAPI_ISET_VER_H_ */
