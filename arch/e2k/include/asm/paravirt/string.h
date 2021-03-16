#ifndef _ASM_E2K_PARAVIRT_STRING_H
#define _ASM_E2K_PARAVIRT_STRING_H

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

#ifndef	CONFIG_BOOT_E2K
static inline unsigned long
pv_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return pv_cpu_ops.fast_tagged_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
boot_pv_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return BOOT_PARAVIRT_GET_CPU_FUNC(fast_tagged_memory_copy)(dst, src,
				len, strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
pv_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	return pv_cpu_ops.fast_tagged_memory_set(addr, val,
						 tag, len, strd_opcode);
}
static inline void
boot_pv_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	BOOT_PARAVIRT_GET_CPU_FUNC(fast_tagged_memory_set)(addr, val, tag, len,
								strd_opcode);
}
#endif	/* ! CONFIG_BOOT_E2K */

static inline unsigned long
pv_extract_tags_32(u16 *dst, const void *src)
{
	return pv_cpu_ops.extract_tags_32(dst, src);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is native guest kernel (not paravirtualized based on pv_ops) */

#ifndef	CONFIG_BOOT_E2K
static inline unsigned long
fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return pv_fast_tagged_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
boot_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return boot_pv_fast_tagged_memory_copy(dst, src,
				len, strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	return pv_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
}
static inline void
boot_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	boot_pv_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
}
#endif	/* CONFIG_BOOT_E2K */

static inline unsigned long
extract_tags_32(u16 *dst, const void *src)
{
	return pv_extract_tags_32(dst, src);
}
#endif	/* ! CONFIG_PARAVIRT_GUEST */

#endif /* _ASM_E2K_PARAVIRT_STRING_H */

