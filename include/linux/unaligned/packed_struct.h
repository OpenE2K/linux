#ifndef _LINUX_UNALIGNED_PACKED_STRUCT_H
#define _LINUX_UNALIGNED_PACKED_STRUCT_H

#include <linux/types.h>

struct __una_u16 { u16 x; } __packed;
struct __una_u32 { u32 x; } __packed;
struct __una_u64 { u64 x; } __packed;

#if defined CONFIG_E2K && (defined CONFIG_CPU_E8V7)
/* rm 26193 - CPU_HWBUG_UNALIGNED_LOADS workaround, mark unaligned loads with volatile.
 * Avoid dynamic checks cause they would be more costly then the workaround. */
# define UNALIGNED_LD volatile
#else
# define UNALIGNED_LD
#endif

static inline u16 __get_unaligned_cpu16(const void *p)
{
	UNALIGNED_LD const struct __una_u16 *ptr = (UNALIGNED_LD const struct __una_u16 *)p;
	return ptr->x;
}

static inline u32 __get_unaligned_cpu32(const void *p)
{
	UNALIGNED_LD const struct __una_u32 *ptr = (UNALIGNED_LD const struct __una_u32 *)p;
	return ptr->x;
}

static inline u64 __get_unaligned_cpu64(const void *p)
{
	UNALIGNED_LD const struct __una_u64 *ptr = (UNALIGNED_LD const struct __una_u64 *)p;
	return ptr->x;
}

static inline void __put_unaligned_cpu16(u16 val, void *p)
{
	struct __una_u16 *ptr = (struct __una_u16 *)p;
	ptr->x = val;
}

static inline void __put_unaligned_cpu32(u32 val, void *p)
{
	struct __una_u32 *ptr = (struct __una_u32 *)p;
	ptr->x = val;
}

static inline void __put_unaligned_cpu64(u64 val, void *p)
{
	struct __una_u64 *ptr = (struct __una_u64 *)p;
	ptr->x = val;
}

#endif /* _LINUX_UNALIGNED_PACKED_STRUCT_H */
