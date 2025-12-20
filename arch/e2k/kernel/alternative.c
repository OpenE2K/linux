/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <asm/alternative.h>
#include <asm/machdep.h>

#define ADDR_TO_PHYS_CACHE_INIT ((struct addr_to_phys_cache) { .vfn = -1UL })
struct addr_to_phys_cache {
	phys_addr_t phys_addr;
	unsigned long vfn;
};

static void addr_to_phys_cache_update(struct addr_to_phys_cache *cache,
		const void *vaddr, phys_addr_t phys_addr)
{
	cache->vfn = (unsigned long) vaddr >> PAGE_SHIFT;
	cache->phys_addr = phys_addr & PAGE_MASK;
}

static void *lm_alias_node(int node, const void *addr,
		struct addr_to_phys_cache *cache)
{
	phys_addr_t phys_addr;

	/* Check cached value first */
	if ((unsigned long) addr >> PAGE_SHIFT == cache->vfn)
		return __va(cache->phys_addr + ((unsigned long) addr & ~PAGE_MASK));

	/* Do page table lookup */
	phys_addr = node_kernel_address_to_phys(node, (unsigned long) addr);
	if (IS_ERR_VALUE(phys_addr)) {
		WARN_ONCE(1, "could not apply alternative instruction on node %d vaddr 0x%lx, skipping patching\n",
				node, (unsigned long) addr);
		return ERR_PTR(phys_addr);
	}

	addr_to_phys_cache_update(cache, addr, phys_addr);
	return __va(phys_addr);
}

static inline size_t tail_bytes(void *addr)
{
	if (PAGE_ALIGNED(addr))
		return PAGE_SIZE;

	return PAGE_ALIGN((unsigned long) addr) - (unsigned long) addr;
}

static int __init_or_module add_padding(void *insns, size_t len,
		int node, void *ip, struct addr_to_phys_cache *cache)
{
	void *dst_va;

	/* Initialize the whole area with zeroes */
	void *addr_to_clear = insns;
	size_t left_to_clear = len;
	while (left_to_clear) {
		dst_va = lm_alias_node(node, addr_to_clear, cache);
		if (IS_ERR(dst_va))
			return -EINVAL;

		size_t clear_size = min(left_to_clear, tail_bytes(dst_va));
		memset(dst_va, 0, clear_size);

		left_to_clear -= clear_size;
		addr_to_clear += clear_size;
	}

	/* Mark wide instructions beginnings */

	while (len >= 64) {
		dst_va = lm_alias_node(node, insns, cache);
		if (IS_ERR(dst_va))
			return -EINVAL;

		*(u32 *) dst_va = 0x00000070;
		insns += 64;
		len -= 64;
	}

	dst_va = lm_alias_node(node, insns, cache);
	if (IS_ERR(dst_va))
		return -EINVAL;

	switch (len) {
	case 56:
		*(u32 *) dst_va = 0x00000060;
		break;
	case 48:
		*(u32 *) dst_va = 0x00000050;
		break;
	case 40:
		*(u32 *) dst_va = 0x00000040;
		break;
	case 32:
		*(u32 *) dst_va = 0x00000030;
		break;
	case 24:
		*(u32 *) dst_va = 0x00000020;
		break;
	case 16:
		*(u32 *) dst_va = 0x00000010;
		break;
	case 8:
	case 0:
		break;
	default:
		panic("Bad altinstr padding length %ld at %px\n", len, ip);
	}

	return 0;
}

static int copy_instr(void *dst, int dst_node, void *src,
		size_t len, struct addr_to_phys_cache *cache)
{
	while (len) {
		void *dst_va = lm_alias_node(dst_node, dst, cache);
		if (IS_ERR(dst_va))
			return -EINVAL;

		size_t copy_size = min(len, tail_bytes(dst_va));
		memcpy(dst_va, src, copy_size);
		flush_icache_range((unsigned long) dst_va,
				   (unsigned long) dst_va + copy_size);

		len -= copy_size;
		src += copy_size;
		dst += copy_size;
	}

	return 0;
}

void __init_or_module apply_alternatives(struct alt_instr *start,
					 struct alt_instr *end)
{
	struct alt_instr *a;
	u8 *instr, *replacement;

	/*
	 * The scan order should be from start to end. A later scanned
	 * alternative code can overwrite previously scanned alternative code.
	 */
	for (a = start; a < end; a++) {
		int node;

		if (!cpu_has_by_value(a->facility))
			continue;

		instr = (u8 *) &a->instr_offset + a->instr_offset;
		replacement = (u8 *) &a->repl_offset + a->repl_offset;

		if (unlikely(a->instrlen % 8 || a->replacementlen % 8)) {
			WARN_ONCE(1, "alternative instructions length is not divisible by 8, skipping patching\n");
			continue;
		}

		for_each_node_has_dup_kernel(node) {
			struct addr_to_phys_cache cache = ADDR_TO_PHYS_CACHE_INIT;

			if (copy_instr(instr, node, replacement,
					a->replacementlen, &cache)) {
				continue;
			}

			if (a->instrlen > a->replacementlen &&
			    add_padding(instr + a->replacementlen,
					a->instrlen - a->replacementlen,
					node, instr, &cache)) {
				continue;
			}

			/* Modules are not duplicated */
			if (!is_duplicated_code((unsigned long) instr))
				break;
		}
	}
}

extern struct alt_instr __alt_instructions[], __alt_instructions_end[];
void __init apply_alternative_instructions(void)
{
	apply_alternatives(__alt_instructions, __alt_instructions_end);
}
