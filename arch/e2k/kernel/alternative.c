#include <linux/module.h>
#include <asm/alternative.h>
#include <asm/machdep.h>

static void __init_or_module add_padding(void *insns,
					 unsigned int len, void *ip)
{
	memset(insns, 0, len);

	while (len >= 64) {
		*(u32 *) insns = 0x00000070;
		insns += 64;
		len -= 64;
	}

	switch (len) {
	case 56:
		*(u32 *) insns = 0x00000060;
		break;
	case 48:
		*(u32 *) insns = 0x00000050;
		break;
	case 40:
		*(u32 *) insns = 0x00000040;
		break;
	case 32:
		*(u32 *) insns = 0x00000030;
		break;
	case 24:
		*(u32 *) insns = 0x00000020;
		break;
	case 16:
		*(u32 *) insns = 0x00000010;
		break;
	case 8:
	case 0:
		break;
	default:
		panic("Bad altinstr padding length %d at %px\n", len, ip);
	}
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
			unsigned long instr_phys;
			u8 *instr_va;

			instr_phys = node_kernel_address_to_phys(node,
					(unsigned long) instr);
			if (IS_ERR_VALUE(instr_phys)) {
				WARN_ONCE(1, "could not apply alternative instruction on node %d, skipping patching\n", node);
				continue;
			}

			instr_va = (u8 *) __va(instr_phys);
			memcpy(instr_va, replacement, a->replacementlen);

			if (a->instrlen > a->replacementlen)
				add_padding(instr_va + a->replacementlen,
					    a->instrlen - a->replacementlen, instr);

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
