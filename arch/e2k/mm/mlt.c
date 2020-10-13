/*
 * $Id: mlt.c,v 1.18 2009/11/09 15:53:35 kravtsunov_e Exp $
 */
#include <asm/mlt.h>
#include <asm/secondary_space.h>
#include <asm/uaccess.h>

#define	DEBUG_MLT_MODE		0
#define	DebugMLT		if (DEBUG_MLT_MODE) printk

#define REG_MLT_N_SHIFT		7
#define	REG_MLT_PART_SHIFT	5
#define	REG_MLT_TYPE_SHIFT	0

#define MLT_PAGE_SHIFT	12
#define MLT_WORD_SHIFT	3

#define REG_MLT_TYPE	5

const e2k_addr_t	reg_addr_part1 = (REG_MLT_TYPE << REG_MLT_TYPE_SHIFT);
const e2k_addr_t	reg_addr_part2 = (1 << REG_MLT_PART_SHIFT) |
				(REG_MLT_TYPE << REG_MLT_TYPE_SHIFT);
const e2k_addr_t	reg_addr_part3 = (2 << REG_MLT_PART_SHIFT) | 
				(REG_MLT_TYPE << REG_MLT_TYPE_SHIFT);

static inline int
read_MLT_entry(e2k_mlt_entry_t *mlt, int entry_num)
{
	AS_WORD(mlt->first_part) = E2K_READ_MLT_REG((reg_addr_part1 |
					(entry_num << REG_MLT_N_SHIFT)));
	if (!AS_STRUCT(mlt->first_part).val) {
		return 0;
	}
	AS_WORD(mlt->second_part) = E2K_READ_MLT_REG((reg_addr_part2 |
					(entry_num << REG_MLT_N_SHIFT)));
	AS_WORD(mlt->third_part) = E2K_READ_MLT_REG((reg_addr_part3 |
					(entry_num << REG_MLT_N_SHIFT)));
		
	DebugMLT(" ------- mlt reg %d first word 0x%lx\n",
		entry_num, AS_WORD(mlt->first_part));
	DebugMLT(" ------- mlt reg %d second word 0x%lx\n",
		entry_num, AS_WORD(mlt->second_part));
	DebugMLT(" ------- mlt reg %d third word 0x%lx\n",
		entry_num, AS_WORD(mlt->third_part));
	return 1;
}

static inline void
invalidate_MLT_entry(e2k_mlt_entry_t *mlt)
{
	ldst_rec_op_t opc = {
				.fields = {
					.fmt = 1,
					.mas = MAS_MLT_NOP_UNLOCK,
				}
			};
	e2k_addr_t addr = (e2k_addr_t) &opc;

	if (machine.iset_ver >= E2K_ISET_V3) {
		/*
		 * Starting with E2S, MLT works only for secondary space.
		 */
		AS(opc).root = 1;
		AS(opc).mas = MAS_MLT_SEC_NOP_UNLOCK;
	}

	AS_STRUCT(opc).rg = AS_STRUCT(mlt->first_part).rg;
	E2K_RECOVERY_STORE((addr), 0x0, AS_WORD(opc), 2);
}

void
invalidate_MLT_context(void)
{
	e2k_mlt_entry_t mlt;
	int i;

	for (i = 0; i < E2K_MLT_SIZE; i++) {
		if (!read_MLT_entry(&mlt, i))
			continue;
		invalidate_MLT_entry(&mlt);
		DebugMLT("invalidate_MLT_context() entry #%d first "
			"0x%lx second 0x%lx third 0x%lx\n",
			i, AS_WORD(mlt.first_part),
			AS_WORD(mlt.second_part),
			AS_WORD(mlt.third_part));
	}
}

void
get_and_invalidate_MLT_context(e2k_mlt_t *mlt_state)
{
	unsigned long addr;
	int i;

	mlt_state->num = 0;

	for (i = 0; i < E2K_MLT_SIZE; i++) {
		/* reading mlt reg */
		e2k_mlt_entry_t *mlt = &mlt_state->mlt[mlt_state->num];

		if (!read_MLT_entry(mlt, i))
			continue;

		invalidate_MLT_entry(mlt);

		addr = (u64)((AS_STRUCT(mlt->second_part).virt_page <<
							MLT_PAGE_SHIFT) |
			(AS_STRUCT(mlt->second_part).word <<
							MLT_WORD_SHIFT) |
			(AS_STRUCT(mlt->second_part).byte));
		if (IS_MACHINE_E3M && ADDR_IN_SS(addr)) {
			printk("get_MLT_context() ignore MLT entry #%d from "
				"primary space, addr 0x%lx should be below "
				"0x%llx\n",
				mlt_state->num, addr, SS_ADDR_START);
		} else if (!IS_MACHINE_E3M && !ADDR_IN_SS(addr)) {
			printk("get_MLT_context() ignore MLT entry #%d from "
				"primary space, addr 0x%lx should be higher "
				"0x%llx\n",
				mlt_state->num, addr, SS_ADDR_START);
		} else {
			mlt_state->num ++;
			DebugMLT("get_MLT_context() entry #%d  virtual addr "
				"0x%lx, page 0x%x rg 0x%02x\n",
				i, addr,
				AS_STRUCT(mlt->first_part).page,
				AS_STRUCT(mlt->first_part).rg);
		}
	}
}
