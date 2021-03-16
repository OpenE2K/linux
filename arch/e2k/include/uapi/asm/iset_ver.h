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
	E2K_ISET_V2 = 2,
	E2K_ISET_V3 = 3,
	E2K_ISET_V4 = 4,
	E2K_ISET_V5 = 5,
	E2K_ISET_V6 = 6,
} e2k_iset_ver_t;

#define E2K_ISET_V2_MASK	(1 << E2K_ISET_V2)
#define E2K_ISET_V3_MASK	(1 << E2K_ISET_V3)
#define E2K_ISET_V4_MASK	(1 << E2K_ISET_V4)
#define E2K_ISET_V5_MASK	(1 << E2K_ISET_V5)
#define E2K_ISET_V6_MASK	(1 << E2K_ISET_V6)

#define E2K_ISET_SINCE_V2_MASK	(-1)
#define E2K_ISET_SINCE_V3_MASK	(E2K_ISET_SINCE_V2_MASK & ~E2K_ISET_V2_MASK)
#define E2K_ISET_SINCE_V4_MASK	(E2K_ISET_SINCE_V3_MASK & ~E2K_ISET_V3_MASK)
#define E2K_ISET_SINCE_V5_MASK	(E2K_ISET_SINCE_V4_MASK & ~E2K_ISET_V4_MASK)
#define E2K_ISET_SINCE_V6_MASK	(E2K_ISET_SINCE_V5_MASK & ~E2K_ISET_V5_MASK)

enum {
	/* generic e2k iset */
	ELBRUS_GENERIC_ISET = E2K_ISET_GENERIC,
	/* Cubic, Turmalin */
	ELBRUS_S_ISET = E2K_ISET_V2,
	/* E2S (E4C) */
	ELBRUS_2S_ISET = E2K_ISET_V3,
	/* E8C */
	ELBRUS_8C_ISET = E2K_ISET_V4,
	/* E1C+ */
	ELBRUS_1CP_ISET = E2K_ISET_V4,
	/* E8C2 */
	ELBRUS_8C2_ISET = E2K_ISET_V5,
	/* E12C */
	ELBRUS_12C_ISET = E2K_ISET_V6,
	/* E16C */
	ELBRUS_16C_ISET = E2K_ISET_V6,
	/* E2C3 */
	ELBRUS_2C3_ISET = E2K_ISET_V6,
};

#endif	/* !__ASSEMBLY__ */

#endif /* !_E2K_UAPI_ISET_VER_H_ */
