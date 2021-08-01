#ifndef _E2K_MAS_H_
#define _E2K_MAS_H_

#include <asm/types.h>

#include <uapi/asm/mas.h>

#ifndef __ASSEMBLY__

/* new in iset v6 */
typedef union {
	struct {
		u8 mod : 3;
		u8 opc : 4;
		u8     : 1;
	} masf1;
	struct {
		u8 mod   : 3;
		u8 be    : 1;
		u8 m1    : 1 /* == 0 */;
		u8 dc_ch : 2;
		u8       : 1;
	} masf2;
	struct {
		u8 mod : 3 /* == 3,7 */;
		u8 be  : 1;
		u8 m1  : 1 /* == 1 */;
		u8 m3  : 1;
		u8 mt  : 1;
		u8     : 1;
	} masf3;
	struct {
		u8 m2    : 2;
		u8 ch1   : 1;
		u8 be    : 1;
		u8 m1    : 1 /* == 1 */;
		u8 dc_ch : 2;
		u8       : 1;
	} masf4;
	u8 word;
} e2k_v6_mas_t;

# define MAS_MT_0 0
# define MAS_MT_1 1

# define MAS_STORE_RELEASE_V6(_mt) \
({ \
	e2k_v6_mas_t __mas = { \
		.masf3.mod = 3, \
		.masf3.be = 0, \
		.masf3.m1 = 1, \
		.masf3.m3 = 0, \
		.masf3.mt = (_mt) \
	}; \
	__mas.word; \
})

# define MAS_LOAD_ACQUIRE_V6(_mt) \
({ \
	e2k_v6_mas_t __mas = { \
		.masf3.mod = 3, \
		.masf3.be = 0, \
		.masf3.m1 = 1, \
		.masf3.m3 = 0, \
		.masf3.mt = (_mt) \
	}; \
	__mas.word; \
})

# define MAS_LOAD_ACQUIRE_V6(_mt) \
({ \
	e2k_v6_mas_t __mas = { \
		.masf3.mod = 3, \
		.masf3.be = 0, \
		.masf3.m1 = 1, \
		.masf3.m3 = 0, \
		.masf3.mt = (_mt) \
	}; \
	__mas.word; \
})

/* Only ALC0 or ALC0/ALC2 for quadro */
# define MAS_WATCH_FOR_MODIFICATION_V6 \
({ \
	e2k_v6_mas_t __mas = { \
		.masf4.m1 = 1, \
		.masf4.m2 = 1 \
	}; \
	__mas.word; \
})

/* Note that 'root', 'spec' and 'store' must also be checked */
static inline bool is_mas_secondary_lock_trap_on_store(unsigned int mas)
{
	return (mas & 3) == 1;
}

/* Note that 'root', 'spec' and 'store' must also be checked */
static inline bool is_mas_secondary_lock_trap_on_load_store(unsigned int mas)
{
	return (mas & 3) == 2;
}

/* Note that 'chan', 'spec' and 'store' must also be checked */
static inline bool is_mas_special_mmu_aau(unsigned int mas)
{
	return (mas & 7) == 7;
}

/* mas is conflict check between ld and st */
static inline bool is_mas_check(unsigned int mas)
{
	unsigned int m1 = (mas >> 3) & 0x2;
	unsigned int big_endian = (mas >> 3) & 0x1;
	unsigned int mod = mas & 0x7;

	return m1 == 0x0 && mod == 0x2 && !big_endian;
}

/* mas is conflict check with unlock between ld and st */
static inline bool is_mas_check_unlock(unsigned int mas)
{
	unsigned int m1 = (mas >> 3) & 0x2;
	unsigned int big_endian = (mas >> 3) & 0x1;
	unsigned int mod = mas & 0x7;

	return m1 == 0x0 && mod == 0x3 && !big_endian;
}

/* mas is semi-speculative conflict lock check between ld and st */
static inline bool is_mas_lock_check(unsigned int mas)
{
	unsigned int m1 = (mas >> 3) & 0x2;
	unsigned int big_endian = (mas >> 3) & 0x1;
	unsigned int mod = mas & 0x7;
	unsigned int m2 = mas & 0x3;

	return (m1 == 0x0 && mod == 0x4 || m1 == 0x1 && m2 == 0x1) &&
		!big_endian;
}

/* mas is speculative conflict lock check between ld and st */
static inline bool is_mas_spec_lock_check(unsigned int mas)
{
	unsigned int m1 = (mas >> 3) & 0x2;
	unsigned int big_endian = (mas >> 3) & 0x1;
	unsigned int mod = mas & 0x7;
	unsigned int m2 = mas & 0x3;

	return (m1 == 0x0 && mod == 0x7 || m1 == 0x1 && m2 == 0x3) &&
		!big_endian;
}

#endif

#endif /* _E2K_MAS_H_ */
