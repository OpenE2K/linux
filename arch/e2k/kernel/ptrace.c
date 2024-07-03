/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/context_tracking.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/errno.h>
#include <linux/hw_breakpoint.h>
#include <linux/ptrace.h>
#include <linux/user.h>
#include <linux/pagemap.h>
#include <linux/perf_event.h>
#include <linux/signal.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/pgtable.h>
#include <linux/sched/mm.h>
#include <linux/compat.h>

#include <asm/compat.h>
#include <asm/gregs.h>
#include <linux/uaccess.h>
#include <asm/system.h>
#include <asm/e2k_ptypes.h>
#include <asm/process.h>
#include <asm/regs_state.h>
#include <asm/e2k_debug.h>
#ifdef CONFIG_USE_AAU
#include <asm/aau_context.h>
#endif
#include <asm/traps.h>

#include <linux/tracehook.h>

#include <trace/syscall.h>

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

/* #define DEBUG_PTRACE		0 */
#define	NEED_CUI_COMPUTING

#undef	DEBUG_PT_MODE
#undef	DebugPT
#define	DEBUG_PT_MODE		0	/* Compilation unit debugging */
#define DebugPT(...)		DebugPrint(DEBUG_PT_MODE, ##__VA_ARGS__)

#undef	DEBUG_CUI_MODE
#undef	DebugCUI
#define	DEBUG_CUI_MODE		0	/* Compilation unit debugging */
#define DebugCUI(...)		DebugPrint(DEBUG_CUI_MODE, ##__VA_ARGS__)

#undef	DEBUG_TRACE
#undef	DebugTRACE
#define	DEBUG_TRACE		0
#define DebugTRACE(...)		DebugPrint(DEBUG_TRACE, ##__VA_ARGS__)


/**
 * regs_query_register_offset() - query register offset from its name
 * @name:	the name of a register
 *
 * regs_query_register_offset() returns the offset of a register in struct
 * pt_regs from its name. If the name is invalid, this returns -EINVAL;
 */
int regs_query_register_offset(const char *name)
{
	int reg_num, offset;

	if (name[0] == '\0' || (name[0] != 'r' && name[0] != 'b' &&
				strncmp(name, "pred", 4) &&
				strncmp(name, "ret_ip", 6)))
		return INT_MIN;

	if (!strncmp(name, "ret_ip", 6)) {
		offset = REGS_TIR1_REGISTER_FLAG;
	} else if (name[0] == 'r') {
		/* '%r' register */
		if (kstrtoint(name + 1, 10, &reg_num))
			return INT_MIN;

		if (reg_num < 0 || reg_num >= E2K_MAXSR_d)
			return INT_MIN;

		offset = (reg_num & ~1) * 16;
		if (reg_num & 1) {
			if (machine.native_iset_ver < E2K_ISET_V5)
				offset += 8;
			else
				offset += 16;
		}
	} else if (name[0] == 'b') {
		/* '%b' register */
		if (kstrtoint(name + 1, 10, &reg_num))
			return INT_MIN;

		if (reg_num < 0 || reg_num >= 128)
			return INT_MIN;

		offset = reg_num | REGS_B_REGISTER_FLAG;
	} else {
		/* '%pred' register */
		if (kstrtoint(name + 4, 10, &reg_num))
			return INT_MIN;

		if (reg_num < 0 || reg_num >= 32)
			return INT_MIN;

		offset = reg_num | REGS_PRED_REGISTER_FLAG;
	}

	return offset;
}

static char *r_reg_name[E2K_MAXSR_d] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
	"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
	"r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
	"r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",
	"r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47",
	"r48", "r49", "r50", "r51", "r52", "r53", "r54", "r55",
	"r56", "r57", "r58", "r59", "r60", "r61", "r62", "r63",
	"r64", "r65", "r66", "r67", "r68", "r69", "r70", "r71",
	"r72", "r73", "r74", "r75", "r76", "r77", "r78", "r79",
	"r80", "r81", "r82", "r83", "r84", "r85", "r86", "r87",
	"r88", "r89", "r90", "r91", "r92", "r93", "r94", "r95",
	"r96", "r97", "r98", "r99", "r100", "r101", "r102", "r103",
	"r104", "r105", "r106", "r107", "r108", "r109", "r110", "r111",
	"r112", "r113", "r114", "r115", "r116", "r117", "r118", "r119",
	"r120", "r121", "r122", "r123", "r124", "r125", "r126", "r127",
	"r128", "r129", "r130", "r131", "r132", "r133", "r134", "r135",
	"r136", "r137", "r138", "r139", "r140", "r141", "r142", "r143",
	"r144", "r145", "r146", "r147", "r148", "r149", "r150", "r151",
	"r152", "r153", "r154", "r155", "r156", "r157", "r158", "r159",
	"r160", "r161", "r162", "r163", "r164", "r165", "r166", "r167",
	"r168", "r169", "r170", "r171", "r172", "r173", "r174", "r175",
	"r176", "r177", "r178", "r179", "r180", "r181", "r182", "r183",
	"r184", "r185", "r186", "r187", "r188", "r189", "r190", "r191",
	"r192", "r193", "r194", "r195", "r196", "r197", "r198", "r199",
	"r200", "r201", "r202", "r203", "r204", "r205", "r206", "r207",
	"r208", "r209", "r210", "r211", "r212", "r213", "r214", "r215",
	"r216", "r217", "r218", "r219", "r220", "r221", "r222", "r223"
};

static char *b_reg_name[128] = {
	"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
	"b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15",
	"b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
	"b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31",
	"b32", "b33", "b34", "b35", "b36", "b37", "b38", "b39",
	"b40", "b41", "b42", "b43", "b44", "b45", "b46", "b47",
	"b48", "b49", "b50", "b51", "b52", "b53", "b54", "b55",
	"b56", "b57", "b58", "b59", "b60", "b61", "b62", "b63",
	"b64", "b65", "b66", "b67", "b68", "b69", "b70", "b71",
	"b72", "b73", "b74", "b75", "b76", "b77", "b78", "b79",
	"b80", "b81", "b82", "b83", "b84", "b85", "b86", "b87",
	"b88", "b89", "b90", "b91", "b92", "b93", "b94", "b95",
	"b96", "b97", "b98", "b99", "b100", "b101", "b102", "b103",
	"b104", "b105", "b106", "b107", "b108", "b109", "b110", "b111",
	"b112", "b113", "b114", "b115", "b116", "b117", "b118", "b119",
	"b120", "b121", "b122", "b123", "b124", "b125", "b126", "b127"
};

static char *pred_reg_name[32] = {
	"pred0", "pred1", "pred2", "pred3", "pred4", "pred5", "pred6", "pred7",
	"pred8", "pred9", "pred10", "pred11", "pred12", "pred13", "pred14", "pred15",
	"pred16", "pred17", "pred18", "pred19", "pred20", "pred21", "pred22", "pred23",
	"pred24", "pred25", "pred26", "pred27", "pred28", "pred29", "pred30", "pred31"
};


/**
 * regs_query_register_name() - query register name from its offset
 * @offset:	the offset of a register in struct pt_regs.
 *
 * regs_query_register_name() returns the name of a register from its
 * offset in struct pt_regs. If the @offset is invalid, this returns NULL;
 */
const char *regs_query_register_name(unsigned int offset)
{
	unsigned int reg_num;

	if (offset & REGS_TIR1_REGISTER_FLAG)
		return "ret_ip";

	if (offset & REGS_PRED_REGISTER_FLAG)
		return pred_reg_name[offset & ~REGS_PRED_REGISTER_FLAG];

	if (offset & REGS_B_REGISTER_FLAG)
		return b_reg_name[offset & ~REGS_B_REGISTER_FLAG];

	reg_num = 2 * (offset / 32);
	if (offset % 32)
		++reg_num;

	if (reg_num >= E2K_MAXSR_d)
		return NULL;

	return r_reg_name[reg_num];
}

/**
 * regs_get_register() - get register value from its offset
 * @regs:       pt_regs from which register value is gotten.
 * @offset:     offset number of the register.
 *
 * regs_get_register returns the value of a register. The @offset is the
 * offset of the register in struct pt_regs address which specified by @regs.
 * If @offset is bigger than MAX_REG_OFFSET, this returns 0.
 */
unsigned long regs_get_register(const struct pt_regs *regs, unsigned int offset)
{
	e2k_psp_lo_t psp_lo = regs->stacks.psp_lo;
	e2k_psp_hi_t cur_psp_hi, psp_hi = regs->stacks.psp_hi;
	e2k_cr0_lo_t cr0_lo = regs->crs.cr0_lo;
	e2k_cr1_lo_t cr1_lo = regs->crs.cr1_lo;
	e2k_cr1_hi_t cr1_hi = regs->crs.cr1_hi;
	unsigned long base, spilled, size;
	u64 value;
	u8 tag;

	if (unlikely((signed int) offset < 0))
		return 0xdead;

	if (offset & REGS_TIR1_REGISTER_FLAG) {
		struct trap_pt_regs *trap = regs->trap;

		if (!trap || trap->nr_TIRs <= 0)
			return 0xdead;

		return trap->TIRs[1].TIR_lo.TIR_lo_ip;
	}

	if (offset & REGS_PRED_REGISTER_FLAG) {
		u64 pf, pval, ptag;
		int pred, psz, pcur;

		pred = offset & ~REGS_PRED_REGISTER_FLAG;

		psz = AS(cr1_hi).psz;
		pcur = AS(cr1_hi).pcur;

		if (pcur && pred <= psz) {
			pred = pred + pcur;
			if (pred > psz)
				pred -= psz + 1;
		}

		pf = AS(cr0_lo).pf;

		pval = (pf & (1ULL << 2 * pred)) >> 2 * pred;
		ptag = (pf & (1ULL << (2 * pred + 1))) >> (2 * pred + 1);

		return (ptag << 1) | pval;
	}

	cur_psp_hi = READ_PSP_HI_REG();

	if (offset & REGS_B_REGISTER_FLAG) {
		int qr, r, br, rbs, rsz, rcur;

		rbs = AS(cr1_hi).rbs;
		rsz = AS(cr1_hi).rsz;
		rcur = AS(cr1_hi).rcur;

		br = offset & ~REGS_B_REGISTER_FLAG;

		qr = br / 2 + rcur;
		if (qr > rsz)
			qr -= rsz + 1;
		qr += rbs;

		r = 2 * qr;
		if (br & 1)
			++r;

		offset = 16 * (r & ~1);
		if (r & 1) {
			if (machine.native_iset_ver < E2K_ISET_V5)
				offset += 8;
			else
				offset += 16;
		}
	}

	size = AS(cr1_lo).wbs * EXT_4_NR_SZ;
	base = AS(psp_lo).base + AS(psp_hi).ind - size;

	spilled = AS(psp_lo).base + AS(cur_psp_hi).ind;

	if (unlikely(offset + 8 > size))
		return 0xdead;

	if (base + offset >= spilled)
		E2K_FLUSHR;

	load_value_and_tagd((void *) base + offset, &value, &tag);

	return value;
}

/* User's "struct user_regs_struct" may be smaller than kernel one */
static inline int get_user_regs_struct_size(
		struct user_regs_struct __user *uregs, long *size)
{
	unsigned long val;
	int ret;

	ret = get_user(val, &uregs->sizeof_struct);
	if (!ret) {
		*size = val;
		if (val < offsetof(struct user_regs_struct, idr))
			ret = -EPERM;
	}

	if (!ret && (cpu_has(CPU_FEAT_QPREG) &&
		     *size < offsetofend(struct user_regs_struct, gext_tag_v5) ||
		     cpu_has(CPU_FEAT_ISET_V6) &&
		     *size < offsetofend(struct user_regs_struct, ctpr3_hi)))
		pr_info_ratelimited("%s [%d] sys_ptrace: size of user_regs_struct is too small to keep all registers. Are you using an old version of profiler or gdb?\n",
				current->comm, current->pid);

	return ret;
}

/*	psl field value in usd_lo variable, which is stored in the kernel,
*	differs from the real user value by 1
*	according to the instruction set - any call increases this field by 1
*	and any return reduces by 1
*/
static void change_psl_field(unsigned long *pnt, int value)
{
	e2k_rwsap_lo_struct_t	lo;
	lo.word = *pnt;
	/* only for protected mode */
	if (!lo.E2K_RUSD_lo_p)
		return;
	lo.fields.psl += value;
	*pnt = lo.word;
}
/* The value of user gd & cud registers are in memory
	they would be executed in done and return commands
	Current gd & cud registers are pointed to kernel address

	cut_entry = mem[CUTD.base + cuir.[15:0]*32];
	CUD.base = cut_entry.cud.base;
	CUD.size = cut_entry.cud.size;
	CUD.c = cut_entry.cud.c;
	GD.base = cut_entry.gd.base;
	GD.size = cut_entry.gd.size;
*/
static int execute_user_gd_cud_regs(struct task_struct *child,
				    struct user_regs_struct *user_regs)
{
	e2k_cutd_t cutd;
	e2k_cute_t cute;
	e2k_cute_t *p_cute = &cute;
	unsigned long pnt_cut_entry, ts_flag;
	size_t copied;

	/* index checkup */
	if (!(user_regs->cuir >> (CR1_lo_cuir_size)))
		return 0;
	cutd.word = user_regs->cutd;
	pnt_cut_entry = cutd.CUTD_base + 32 * (user_regs->cuir & CUIR_mask);
	if (pnt_cut_entry + sizeof(cute) > PAGE_OFFSET)
		return 0;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	copied = access_process_vm(child, pnt_cut_entry, &cute,
				   sizeof(cute), 0);
	clear_ts_flag(ts_flag);
	if (copied != sizeof(cute)) {
		pr_info("%s[PID=0x%x]:: bad pnt_cut_entry=0x%lx : copied(%zd) !=  sizeof(cute)=%ld\n",
			__func__, child->pid, pnt_cut_entry, copied, sizeof(e2k_cute_t));
		return -ENODATA;
	}
	user_regs->gd_lo = p_cute->gd_base;
	user_regs->gd_hi = p_cute->gd_size;
	user_regs->cud_lo = p_cute->cud_base;
	user_regs->cud_hi = p_cute->cud_size;
	return 0;
}

static void save_dam(struct user_regs_struct *user_regs, const struct task_struct *task)
{
	if (task->ptrace) {
		BUILD_BUG_ON(sizeof(task->thread.dam) != sizeof(user_regs->dam));
		memcpy(user_regs->dam, task->thread.dam, sizeof(task->thread.dam));
	} else {
		memset(user_regs->dam, 0, sizeof(user_regs->dam));
	}
}

void core_pt_regs_to_user_regs (struct pt_regs *pt_regs,
				struct user_regs_struct *user_regs)
{
	struct trap_pt_regs *trap;
        long size = sizeof(struct user_regs_struct);
        int i;
	struct thread_info *ti = current_thread_info();
#ifdef CONFIG_GREGS_CONTEXT
	struct e2k_global_regs gregs;
#endif
#ifdef CONFIG_USE_AAU
	e2k_aau_t aau_regs;
	e2k_aasr_t aasr;
#endif /* CONFIG_USE_AAU */

	DebugTRACE("%s: current->pid=%d(%s)\n", __func__, current->pid, current->comm);

        memset(user_regs, 0, size);

#ifdef CONFIG_GREGS_CONTEXT
	machine.save_gregs(&gregs);
	copy_k_gregs_to_gregs(&gregs, &ti->k_gregs);
	GET_GREGS_FROM_THREAD(user_regs->g, user_regs->gtag, gregs.g);
	for (i = 0; i < 32; i++)
		user_regs->gext[i] = (u16) gregs.g[i].ext;
	if (machine.native_iset_ver >= E2K_ISET_V5)
		GET_GREGS_FROM_THREAD(user_regs->gext_v5,
				user_regs->gext_tag_v5, &gregs.g[0].ext);
	user_regs->bgr = AW(gregs.bgr);
#endif /* CONFIG_GREGS_CONTEXT */

	user_regs->upsr = AW(ti->upsr);

	/* user_regs->oscud_lo = READ_OSCUD_LO_REG_VALUE(); internal kernel info */
	/* user_regs->oscud_hi = READ_OSCUD_HI_REG_VALUE(); internal kernel info */
	/* user_regs->osgd_lo = READ_OSGD_LO_REG_VALUE(); internal kernel info */
	/* user_regs->osgd_hi = READ_OSGD_HI_REG_VALUE(); internal kernel info */
	/* user_regs->osem = READ_OSEM_REG_VALUE(); internal kernel info */
	user_regs->osr0 = READ_CURRENT_REG_VALUE();

	user_regs->pfpfr = READ_PFPFR_REG_VALUE();
	user_regs->fpcr = READ_FPCR_REG_VALUE();
	user_regs->fpsr = READ_FPSR_REG_VALUE();

	user_regs->cs_lo = READ_CS_LO_REG_VALUE();
	user_regs->cs_hi = READ_CS_HI_REG_VALUE();
	user_regs->ds_lo = READ_DS_LO_REG_VALUE();
	user_regs->ds_hi = READ_DS_HI_REG_VALUE();
	user_regs->es_lo = READ_ES_LO_REG_VALUE();
	user_regs->es_hi = READ_ES_HI_REG_VALUE();
	user_regs->fs_lo = READ_FS_LO_REG_VALUE();
	user_regs->fs_hi = READ_FS_HI_REG_VALUE();
	user_regs->gs_lo = READ_GS_LO_REG_VALUE();
	user_regs->gs_hi = READ_GS_HI_REG_VALUE();
	user_regs->ss_lo = READ_SS_LO_REG_VALUE();
	user_regs->ss_hi = READ_SS_HI_REG_VALUE();

#ifdef CONFIG_USE_AAU
	memset(&aau_regs, 0, sizeof(aau_regs));

	aasr = read_aasr_reg();
	aau_regs.aafstr = read_aafstr_reg_value();
	read_aaldm_reg(&aau_regs.aaldm);
	read_aaldv_reg(&aau_regs.aaldv);
	machine.get_aau_context(&aau_regs, aasr);
	SAVE_AADS(&aau_regs);

	machine.save_aaldi(user_regs->aaldi);
	SAVE_AALDA(user_regs->aalda);

	for (i = 0; i < 32; i++) {
		user_regs->aad[2*i] = AW(aau_regs.aads[i]).lo;
		user_regs->aad[2*i+1] = AW(aau_regs.aads[i]).hi;
	}

	if (machine.native_iset_ver < E2K_ISET_V5) {
		for (i = 0; i < 16; i++)
			user_regs->aaind[i] = (u32) aau_regs.aainds[i];

		for (i = 0; i < 8; i++)
			user_regs->aaincr[i] = (u32) aau_regs.aaincrs[i];

		for (i = 0; i < 16; i++)
			user_regs->aasti[i] = (u32) aau_regs.aastis[i];
	} else {
		for (i = 0; i < 16; i++)
			user_regs->aaind[i] = aau_regs.aainds[i];

		for (i = 0; i < 8; i++)
			user_regs->aaincr[i] = aau_regs.aaincrs[i];

		for (i = 0; i < 16; i++)
			user_regs->aasti[i] = aau_regs.aastis[i];
	}

	user_regs->aaldv = AW(aau_regs.aaldv);
	user_regs->aaldm = AW(aau_regs.aaldm);

	user_regs->aasr = AW(aasr);
	user_regs->aafstr = (unsigned long long) aau_regs.aafstr;
#endif /* CONFIG_USE_AAU */

	user_regs->clkr = 0;

	user_regs->dibcr = READ_DIBCR_REG_VALUE();
	user_regs->ddbcr = READ_DDBCR_REG_VALUE();
	user_regs->dibsr =  READ_DIBSR_REG_VALUE();
	user_regs->dibar[0] = READ_DIBAR0_REG_VALUE();
	user_regs->dibar[1] = READ_DIBAR1_REG_VALUE();
	user_regs->dibar[2] = READ_DIBAR2_REG_VALUE();
	user_regs->dibar[3] = READ_DIBAR3_REG_VALUE();
	user_regs->ddbar[0] = READ_DDBAR0_REG_VALUE();
	user_regs->ddbar[1] = READ_DDBAR1_REG_VALUE();
	user_regs->ddbar[2] = READ_DDBAR2_REG_VALUE();
	user_regs->ddbar[3] = READ_DDBAR3_REG_VALUE();
	user_regs->dimcr = READ_DIMCR_REG_VALUE();
	user_regs->ddmcr = READ_DDMCR_REG_VALUE();
	user_regs->dimar[0] = READ_DIMAR0_REG_VALUE();
	user_regs->dimar[1] = READ_DIMAR1_REG_VALUE();
	user_regs->ddmar[0] = READ_DDMAR0_REG_VALUE();
	user_regs->ddmar[1] = READ_DDMAR1_REG_VALUE();
	user_regs->ddbsr = READ_DDBSR_REG_VALUE();
	if (machine.save_dimtp) {
		e2k_dimtp_t dimtp;
		machine.save_dimtp(&dimtp);
		user_regs->dimtp_lo = dimtp.lo;
		user_regs->dimtp_hi = dimtp.hi;
	}

	/* user_regs->rpr = ; */
	user_regs->rpr_lo = READ_RPR_LO_REG_VALUE();
	user_regs->rpr_hi = READ_RPR_HI_REG_VALUE();

	/*   DAM  */
	save_dam(user_regs, current);

	user_regs->chain_stack_base = (u64) GET_PCS_BASE(&ti->u_hw_stack);
	user_regs->proc_stack_base = (u64) GET_PS_BASE(&ti->u_hw_stack);

	user_regs->idr = READ_IDR_REG_VALUE();
	user_regs->core_mode = READ_CORE_MODE_REG_VALUE();

	user_regs->sizeof_struct = sizeof(struct user_regs_struct);

	if (!pt_regs)
		return;

	user_regs->cutd = READ_CUTD_REG_VALUE();
	user_regs->cuir = (machine.native_iset_ver < E2K_ISET_V6) ?
				AS(pt_regs->crs.cr1_lo).cuir :
				AS(pt_regs->crs.cr1_lo).cui;

	trap = pt_regs->trap;

	user_regs->usbr = pt_regs->stacks.top;
	user_regs->usd_lo = AW(pt_regs->stacks.usd_lo);
	user_regs->usd_hi = AW(pt_regs->stacks.usd_hi);
	change_psl_field((unsigned long *)&user_regs->usd_lo, -1);

	user_regs->psp_lo = AW(pt_regs->stacks.psp_lo);
	user_regs->psp_hi = AW(pt_regs->stacks.psp_hi);
	user_regs->pshtp = AW(pt_regs->stacks.pshtp);

	user_regs->cr0_lo = AW(pt_regs->crs.cr0_lo);
	user_regs->cr0_hi = AW(pt_regs->crs.cr0_hi);
	user_regs->cr1_lo = AW(pt_regs->crs.cr1_lo);
	user_regs->cr1_hi = AW(pt_regs->crs.cr1_hi);

	/*
	 *  new ip - the crash ip
	 *  Gdb shows last command from chain
	 */
	user_regs->pcsp_lo = AW(pt_regs->stacks.pcsp_lo);
	user_regs->pcsp_hi = AW(pt_regs->stacks.pcsp_hi);
	user_regs->pcshtp = pt_regs->stacks.pcshtp;

	user_regs->wd = AW(pt_regs->wd);

	user_regs->br = AS(pt_regs->crs.cr1_hi).br;

	/* user_regs->eir = ; */

	user_regs->lsr = pt_regs->lsr;
	user_regs->ilcr = pt_regs->ilcr;
	if (machine.native_iset_ver >= E2K_ISET_V5) {
		user_regs->lsr1 = pt_regs->lsr1;
		user_regs->ilcr1 = pt_regs->ilcr1;
	}

	if (trap) {
		u64 data;
		u8 tag;

		user_regs->ctpr1 = AW(pt_regs->ctpr1);
		user_regs->ctpr2 = AW(pt_regs->ctpr2);
		user_regs->ctpr3 = AW(pt_regs->ctpr3);
		if (machine.native_iset_ver >= E2K_ISET_V6) {
			user_regs->ctpr1_hi = AW(pt_regs->ctpr1_hi);
			user_regs->ctpr2_hi = AW(pt_regs->ctpr2_hi);
			user_regs->ctpr3_hi = AW(pt_regs->ctpr3_hi);
		}

		/* MLT */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		/* FIXME: it need implement for guest */
		if (!paravirt_enabled() && trap->mlt_state.num)
			memcpy(user_regs->mlt, trap->mlt_state.mlt,
				sizeof(e2k_mlt_entry_t) * trap->mlt_state.num);
#endif

		/* TC */
		for (i = 0; i < min(MAX_TC_SIZE, HW_TC_SIZE); i++) {
			user_regs->trap_cell_addr[i] = trap->tcellar[i].address;
			user_regs->trap_cell_info[i] =
					AW(trap->tcellar[i].condition);
			load_value_and_tagd(&trap->tcellar[i].data,
					&data, &tag);
			user_regs->trap_cell_val[i] = data;
			user_regs->trap_cell_tag[i] = tag;
		}

		/* TIR */
		for (i = 0; i <= trap->nr_TIRs; i++) {
			user_regs->tir_hi[i] = trap->TIRs[i].TIR_hi.TIR_hi_reg;
			user_regs->tir_lo[i] = trap->TIRs[i].TIR_lo.TIR_lo_reg;
		}

		/* SBBP */
		if (trap->sbbp)
			memcpy(user_regs->sbbp, trap->sbbp,
					sizeof(user_regs->sbbp));
	}
	(void) execute_user_gd_cud_regs(current, user_regs);
}

#ifdef CONFIG_HAVE_HW_BREAKPOINT
/*
 * Handle hitting a HW-breakpoint.
 */
static void ptrace_hbp_triggered(struct perf_event *bp,
		struct perf_sample_data *data, struct pt_regs *regs)
{
	struct thread_struct *thread = &current->thread;
	struct arch_hw_breakpoint *hw = counter_arch_bp(bp);
	kernel_siginfo_t info;
	int i, is_data_bp;

	is_data_bp = hw_breakpoint_type(bp) & HW_BREAKPOINT_RW;

	for (i = 0; i < HBP_NUM; ++i) {
		if (is_data_bp && bp == thread->debug.hbp_data[i]) {
			AW(thread->sw_regs.ddbsr) &= ~E2K_DDBSR_MASK(i);
			AW(thread->sw_regs.ddbsr) |=
				READ_DDBSR_REG_VALUE() & E2K_DDBSR_MASK(i);
			break;
		}

		if (!is_data_bp && bp == thread->debug.hbp_instr[i]) {
			AW(thread->sw_regs.dibsr) &= ~E2K_DIBSR_MASK(i);
			AW(thread->sw_regs.dibsr) |=
				READ_DIBSR_REG_VALUE() & E2K_DIBSR_MASK(i);
			break;
		}
	}

	info.si_signo = SIGTRAP;
	info.si_errno = i;
	info.si_code = TRAP_HWBKPT;
	info.si_addr = (void __user *) (hw->address);

	force_sig_info(&info);
}

static int register_ptrace_breakpoint(struct task_struct *child,
		unsigned long bp_addr, int bp_len, int bp_type,
		int idx, int enabled)
{
	struct perf_event_attr attr;
	struct perf_event *event;
	int ret;

	if (bp_type & HW_BREAKPOINT_RW)
		event = child->thread.debug.hbp_data[idx];
	else
		event = child->thread.debug.hbp_instr[idx];

	if (!event) {
		if (!enabled)
			return 0;

		ptrace_breakpoint_init(&attr);
		attr.bp_addr = bp_addr;
		attr.bp_len = bp_len;
		attr.bp_type = bp_type;

		event = register_user_hw_breakpoint(&attr,
				ptrace_hbp_triggered, NULL, child);
		if (IS_ERR(event))
			return PTR_ERR(event);

		if (bp_type & HW_BREAKPOINT_RW)
			child->thread.debug.hbp_data[idx] = event;
		else
			child->thread.debug.hbp_instr[idx] = event;

		ret = 0;
	} else {
		attr = event->attr;
		attr.bp_addr = bp_addr;
		attr.bp_len = bp_len;
		attr.bp_type = bp_type;
		attr.disabled = !enabled;

		ret = modify_user_hw_breakpoint(event, &attr);
	}

	return ret;
}
#endif

static inline int get_hbp_len(int lng)
{
	return 1 << (lng - 1);
}

static inline int get_hbp_type(int rw)
{
	int bp_type = 0;

	if (rw & 1)
		bp_type |= HW_BREAKPOINT_W;
	if (rw & 2)
		bp_type |= HW_BREAKPOINT_R;

	return bp_type;
}

static int ptrace_write_hbp_registers(struct task_struct *child,
		struct user_regs_struct *user_regs)
{
	struct thread_struct *thread = &child->thread;
	e2k_dibcr_t dibcr;
	e2k_ddbcr_t ddbcr;
	e2k_dibsr_t dibsr;
	e2k_ddbsr_t ddbsr;
	int ret;

	AW(dibcr) = user_regs->dibcr;
	AW(ddbcr) = user_regs->ddbcr;
	AW(dibsr) = user_regs->dibsr;
	AW(ddbsr) = user_regs->ddbsr;

	ret = 0;
	ret = ret ?: register_ptrace_breakpoint(child,
			user_regs->dibar[0], HW_BREAKPOINT_LEN_8,
			HW_BREAKPOINT_X, 0, dibcr.v0 && !dibsr.b0);
	ret = ret ?: register_ptrace_breakpoint(child,
			user_regs->dibar[1], HW_BREAKPOINT_LEN_8,
			HW_BREAKPOINT_X, 1, dibcr.v1 && !dibsr.b1);
	ret = ret ?: register_ptrace_breakpoint(child,
			user_regs->dibar[2], HW_BREAKPOINT_LEN_8,
			HW_BREAKPOINT_X, 2, dibcr.v2 && !dibsr.b2);
	ret = ret ?: register_ptrace_breakpoint(child,
			user_regs->dibar[3], HW_BREAKPOINT_LEN_8,
			HW_BREAKPOINT_X, 3, dibcr.v3 && !dibsr.b3);
	ret = ret ?: register_ptrace_breakpoint(child,
			user_regs->ddbar[0], get_hbp_len(ddbcr.lng0),
			get_hbp_type(ddbcr.rw0), 0, ddbcr.v0 && !ddbsr.b0);
	ret = ret ?: register_ptrace_breakpoint(child,
			user_regs->ddbar[1], get_hbp_len(ddbcr.lng1),
			get_hbp_type(ddbcr.rw1), 1, ddbcr.v1 && !ddbsr.b1);
	ret = ret ?: register_ptrace_breakpoint(child,
			user_regs->ddbar[2], get_hbp_len(ddbcr.lng2),
			get_hbp_type(ddbcr.rw2), 2, ddbcr.v2 && !ddbsr.b2);
	ret = ret ?: register_ptrace_breakpoint(child,
			user_regs->ddbar[3], get_hbp_len(ddbcr.lng3),
			get_hbp_type(ddbcr.rw3), 3, ddbcr.v3 && !ddbsr.b3);
	if (ret)
		return ret;

	AW(thread->sw_regs.dibsr) = user_regs->dibsr;
	AW(thread->sw_regs.ddbsr) = user_regs->ddbsr;

	AW(thread->debug.regs.dibcr) = user_regs->dibcr;
	AW(thread->debug.regs.ddbcr) = user_regs->ddbcr;
	thread->debug.regs.dibar0 = user_regs->dibar[0];
	thread->debug.regs.dibar1 = user_regs->dibar[1];
	thread->debug.regs.dibar2 = user_regs->dibar[2];
	thread->debug.regs.dibar3 = user_regs->dibar[3];
	thread->debug.regs.ddbar0 = user_regs->ddbar[0];
	thread->debug.regs.ddbar1 = user_regs->ddbar[1];
	thread->debug.regs.ddbar2 = user_regs->ddbar[2];
	thread->debug.regs.ddbar3 = user_regs->ddbar[3];

	return 0;
}

static int pt_regs_to_user_regs(struct task_struct *child,
			 struct user_regs_struct *user_regs, long size)
{
	struct thread_info *ti = task_thread_info(child);
	struct thread_struct *thread = &child->thread;
	struct pt_regs *pt_regs = ti->pt_regs;
	struct trap_pt_regs *trap;
	struct sw_regs *sw_regs = &child->thread.sw_regs;
#ifdef CONFIG_USE_AAU
	e2k_aau_t *aau_regs;
#endif /* CONFIG_USE_AAU*/
        int i;

        memset(user_regs, 0, size);
	DebugTRACE("%s: current->pid=%d(%s) child->pid=%d\n",
		   __func__, current->pid, current->comm, child->pid);

	if (!pt_regs)
		return -1;

#ifdef CONFIG_USE_AAU
	aau_regs = pt_regs->aau_context;
#endif /* CONFIG_USE_AAU*/

	trap = pt_regs->trap;

#ifdef CONFIG_GREGS_CONTEXT
	copy_k_gregs_to_gregs(&sw_regs->gregs, &ti->k_gregs);
	GET_GREGS_FROM_THREAD(user_regs->g, user_regs->gtag, sw_regs->gregs.g);
	for (i = 0; i < 32; i++)
		user_regs->gext[i] = (u16) sw_regs->gregs.g[i].ext;
	if (machine.native_iset_ver >= E2K_ISET_V5) {
		if (size >= offsetofend(struct user_regs_struct, gext_v5) &&
		    size >= offsetofend(struct user_regs_struct, gext_tag_v5)) {
			GET_GREGS_FROM_THREAD(user_regs->gext_v5,
					      user_regs->gext_tag_v5,
					      &sw_regs->gregs.g[0].ext);
		}
	}
        user_regs->bgr = AW(sw_regs->gregs.bgr);
#endif /* CONFIG_GREGS_CONTEXT */

	user_regs->upsr = AW(ti->upsr);

	/* user_regs->oscud_lo = READ_OSCUD_LO_REG_VALUE(); internal kernel info */
	/* user_regs->oscud_hi = READ_OSCUD_HI_REG_VALUE(); internal kernel info */
	/* user_regs->osgd_lo = READ_OSGD_LO_REG_VALUE(); internal kernel info */
	/* user_regs->osgd_hi = READ_OSGD_HI_REG_VALUE(); internal kernel info */
	/* user_regs->osem = READ_OSEM_REG_VALUE(); internal kernel info */
	user_regs->osr0 = READ_CURRENT_REG_VALUE();

	user_regs->pfpfr = AW(sw_regs->fpu.pfpfr);
	user_regs->fpcr = AW(sw_regs->fpu.fpcr);
	user_regs->fpsr = AW(sw_regs->fpu.fpsr);

	user_regs->usbr = pt_regs->stacks.top;
	user_regs->usd_lo = AW(pt_regs->stacks.usd_lo);
	user_regs->usd_hi = AW(pt_regs->stacks.usd_hi);
	change_psl_field((unsigned long *)&user_regs->usd_lo, -1);

	user_regs->psp_lo = AW(pt_regs->stacks.psp_lo);
	user_regs->psp_hi = AW(pt_regs->stacks.psp_hi);
	user_regs->pshtp = AW(pt_regs->stacks.pshtp);

	user_regs->cr0_lo = AW(pt_regs->crs.cr0_lo);
	user_regs->cr0_hi = AW(pt_regs->crs.cr0_hi);
	user_regs->cr1_lo = AW(pt_regs->crs.cr1_lo);
	user_regs->cr1_hi = AW(pt_regs->crs.cr1_hi);

	user_regs->ip = (pt_regs->crs.cr0_hi.CR0_hi_ip << 3);

	user_regs->pcsp_lo = AW(pt_regs->stacks.pcsp_lo);
	user_regs->pcsp_hi = AW(pt_regs->stacks.pcsp_hi);
	user_regs->pcshtp = pt_regs->stacks.pcshtp;

	user_regs->cs_lo = sw_regs->cs_lo;
	user_regs->cs_hi = sw_regs->cs_hi;
	user_regs->ds_lo = sw_regs->ds_lo;
	user_regs->ds_hi = sw_regs->ds_hi;
	user_regs->es_lo = sw_regs->es_lo;
	user_regs->es_hi = sw_regs->es_hi;
	user_regs->fs_lo = sw_regs->fs_lo;
	user_regs->fs_hi = sw_regs->fs_hi;
	user_regs->gs_lo = sw_regs->gs_lo;
	user_regs->gs_hi = sw_regs->gs_hi;
	user_regs->ss_lo = sw_regs->ss_lo;
	user_regs->ss_hi = sw_regs->ss_hi;

#ifdef CONFIG_USE_AAU
	user_regs->aasr = AW(pt_regs->aasr);
	if (aau_regs) {
		for (i = 0; i < 32; i++) {
			user_regs->aad[2*i] = AW(aau_regs->aads[i]).lo;
			user_regs->aad[2*i+1] = AW(aau_regs->aads[i]).hi;
		}

		if (machine.native_iset_ver < E2K_ISET_V5) {
			for (i = 0; i < 16; i++)
				user_regs->aaind[i] = (u32) aau_regs->aainds[i];

			for (i = 0; i < 8; i++)
				user_regs->aaincr[i] = (u32) aau_regs->aaincrs[i];

			for (i = 0; i < 64; i++)
				user_regs->aaldi[i] = (u32) aau_regs->aaldi[i];

			for (i = 0; i < 16; i++)
				user_regs->aasti[i] = (u32) aau_regs->aastis[i];
		} else {
			for (i = 0; i < 16; i++)
				user_regs->aaind[i] = aau_regs->aainds[i];

			for (i = 0; i < 8; i++)
				user_regs->aaincr[i] = aau_regs->aaincrs[i];

			for (i = 0; i < 64; i++)
				user_regs->aaldi[i] = aau_regs->aaldi[i];

			for (i = 0; i < 16; i++)
				user_regs->aasti[i] = aau_regs->aastis[i];
		}

		user_regs->aaldv = AW(aau_regs->aaldv);

		for (i = 0; i < 64; i++)
			user_regs->aalda[i] = AW(ti->aalda[i]);

		user_regs->aaldm = AW(aau_regs->aaldm);
		user_regs->aafstr = (unsigned long long) aau_regs->aafstr;
	}
#endif /* CONFIG_USE_AAU */

	user_regs->clkr = 0;

	user_regs->dibcr = AW(thread->debug.regs.dibcr);
	user_regs->ddbcr = AW(thread->debug.regs.ddbcr);
	user_regs->dibar[0] = thread->debug.regs.dibar0;
	user_regs->dibar[1] = thread->debug.regs.dibar1;
	user_regs->dibar[2] = thread->debug.regs.dibar2;
	user_regs->dibar[3] = thread->debug.regs.dibar3;
	user_regs->ddbar[0] = thread->debug.regs.ddbar0;
	user_regs->ddbar[1] = thread->debug.regs.ddbar1;
	user_regs->ddbar[2] = thread->debug.regs.ddbar2;
	user_regs->ddbar[3] = thread->debug.regs.ddbar3;
	user_regs->dibsr = AW(sw_regs->dibsr);
	user_regs->ddbsr = AW(sw_regs->ddbsr);
	user_regs->dimcr = AW(sw_regs->dimcr);
	user_regs->ddmcr = AW(sw_regs->ddmcr);
	user_regs->dimar[0] = sw_regs->dimar0;
	user_regs->dimar[1] = sw_regs->dimar1;
	user_regs->ddmar[0] = sw_regs->ddmar0;
	user_regs->ddmar[1] = sw_regs->ddmar1;
	if (machine.native_iset_ver >= E2K_ISET_V6 &&
			size >= offsetofend(struct user_regs_struct, dimtp_hi)) {
		user_regs->dimtp_lo = sw_regs->dimtp.lo;
		user_regs->dimtp_hi = sw_regs->dimtp.hi;
	}

	user_regs->wd = AW(pt_regs->wd);

	user_regs->br = AS(pt_regs->crs.cr1_hi).br;

        /* user_regs->eir = ; */

        user_regs->cutd = AW(sw_regs->cutd);
	user_regs->cuir = (machine.native_iset_ver < E2K_ISET_V6) ?
				AS(pt_regs->crs.cr1_lo).cuir :
				AS(pt_regs->crs.cr1_lo).cui;

	if (size >= offsetofend(struct user_regs_struct, idr))
		user_regs->idr = READ_IDR_REG_VALUE();

	if (size >= offsetofend(struct user_regs_struct, core_mode))
		user_regs->core_mode = READ_CORE_MODE_REG_VALUE();

	user_regs->lsr = pt_regs->lsr;
	user_regs->ilcr = pt_regs->ilcr;
	if (machine.native_iset_ver >= E2K_ISET_V5) {
		if (size >= offsetofend(struct user_regs_struct, lsr1))
			user_regs->lsr1 = pt_regs->lsr1;
		if (size >= offsetofend(struct user_regs_struct, ilcr1))
			user_regs->ilcr1 = pt_regs->ilcr1;
	}

 	user_regs->rpr_lo = sw_regs->rpr_lo;
	user_regs->rpr_hi = sw_regs->rpr_hi;

	if (trap) {
		u64 data;
		u8 tag;

		user_regs->ctpr1 = AW(pt_regs->ctpr1);
		user_regs->ctpr2 = AW(pt_regs->ctpr2);
		user_regs->ctpr3 = AW(pt_regs->ctpr3);
		if (machine.native_iset_ver >= E2K_ISET_V6 &&
				size >= offsetofend(struct user_regs_struct, ctpr3_hi)) {
			user_regs->ctpr1_hi = AW(pt_regs->ctpr1_hi);
			user_regs->ctpr2_hi = AW(pt_regs->ctpr2_hi);
			user_regs->ctpr3_hi = AW(pt_regs->ctpr3_hi);
		}

		/* MLT */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		/* FIXME: it need implement for guest */
		if (!paravirt_enabled() && trap->mlt_state.num)
			memcpy(user_regs->mlt, trap->mlt_state.mlt,
				sizeof(e2k_mlt_entry_t) * trap->mlt_state.num);
#endif

		/* TC */
		for (i = 0; i < min(MAX_TC_SIZE, HW_TC_SIZE); i++) {
			user_regs->trap_cell_addr[i] = trap->tcellar[i].address;
			user_regs->trap_cell_info[i] =
					trap->tcellar[i].condition.word;
			load_value_and_tagd(&trap->tcellar[i].data,
					&data, &tag);
			user_regs->trap_cell_val[i] = data;
			user_regs->trap_cell_tag[i] = tag;
		}

		/* TIR */
		for (i = 0; i <= trap->nr_TIRs; i++) {
			user_regs->tir_hi[i] = trap->TIRs[i].TIR_hi.TIR_hi_reg;
			user_regs->tir_lo[i] = trap->TIRs[i].TIR_lo.TIR_lo_reg;
		}

		/* SBBP */
		if (trap->sbbp)
			memcpy(user_regs->sbbp, trap->sbbp,
					sizeof(user_regs->sbbp));

		user_regs->sys_num  = -1UL;
	} else {
		user_regs->arg1     = pt_regs->args[1];
		user_regs->arg2     = pt_regs->args[2];
		user_regs->arg3     = pt_regs->args[3];
		user_regs->arg4     = pt_regs->args[4];
		user_regs->arg5     = pt_regs->args[5];
		user_regs->arg6     = pt_regs->args[6];
#ifdef CONFIG_PROTECTED_MODE
		if ((pt_regs->kernel_entry == 8)
			&& (size >= offsetofend(struct user_regs_struct, arg12))) {
			user_regs->arg7     = pt_regs->args[7];
			user_regs->arg8     = pt_regs->args[8];
			user_regs->arg9     = pt_regs->args[9];
			user_regs->arg10    = pt_regs->args[10];
			user_regs->arg11    = pt_regs->args[11];
			user_regs->arg12    = pt_regs->args[12];
			if (size >= offsetofend(struct user_regs_struct, arg_tags)) {
				user_regs->arg_tags = pt_regs->tags;
				user_regs->sys_rval_lo = pt_regs->rval1;
				user_regs->sys_rval_hi = pt_regs->rval2;
				user_regs->sys_rval_tag = pt_regs->rv1_tag |
							(pt_regs->rv2_tag << 4);
				user_regs->flags = TASK_IS_PROTECTED(child) ?
						USER_REGS_FLAG_PROTECTED_MODE : 0;
				if (pt_regs->return_desk)
					user_regs->flags |= USER_REGS_FLAG_RETURN_DESCRIPTOR;
			}
		}
#endif /* CONFIG_PROTECTED_MODE */
		user_regs->sys_rval = pt_regs->sys_rval;
		user_regs->sys_num  = (s64) (s32) pt_regs->sys_num;
	}

	/*   DAM  */
	save_dam(user_regs, child);

	if (size >= offsetofend(struct user_regs_struct, proc_stack_base)) {
		user_regs->proc_stack_base = (u64) GET_PS_BASE(&ti->u_hw_stack);
		user_regs->chain_stack_base =
				(u64) GET_PCS_BASE(&ti->u_hw_stack);
	}

	/*
	 * gdb uses (sizeof_struct != 0) check to test for
	 * errors, so don't clear this field.
	 */
	user_regs->sizeof_struct = size;

	return execute_user_gd_cud_regs(child, user_regs);
}

/* Check if ctpr doesn't contain privilidged label */
static bool is_priv_or_inv_ctpr(e2k_ctpr_t ctpr, u64 oscud_lo)
{
	e2k_cud_lo_t oscud_lo_d = {
		.word = oscud_lo
	};


	/* These opcode and tags greater than CTPSL_CT_TAG are reserved */
	if (ctpr.CTPR_opc == 2 || ctpr.CTPR_ta_tag > CTPSL_CT_TAG)
		return true;

	/* System label should be properly aligned and point to kernel entry */
	if (ctpr.CTPR_ta_tag == CTPSL_CT_TAG) {
		u64 cud_offset = ctpr.CTPR_ta_base -
					oscud_lo_d.E2K_RUSD_lo_base;

		if (cud_offset % 0x800)
			return true;

		if (cud_offset / 0x800 > 31)
			return true;
	}

	/* All other ctpr must not be privilidged descriptors */
	if (ctpr.CTPR_ta_base >= current_thread_info()->addr_limit.seg &&
			(ctpr.CTPR_ta_tag == CTPLL_CT_TAG ||
			ctpr.CTPR_ta_tag == CTPPL_CT_TAG ||
			ctpr.CTPR_ta_tag == CTPNL_CT_TAG))
		return true;

	return false;
}

/*
 * Check that it val_lo, val_hi, tag don't constitute
 * descriptor pointing to privilidged area
 */
static bool is_priv_desc(u64 val_lo, u64 val_hi, u32 tag)
{
	u64 desc_base, desc_size, func_base;
	e2k_ptr_lo_t ptr_lo = {
		.word = val_lo
	};
	e2k_ptr_hi_t ptr_hi = {
		.word = val_hi
	};

	desc_base = ptr_lo.base;
	desc_size = ptr_hi.size;
	func_base = ((e2k_pl_lo_t *) &val_lo)->target;

	return ((tag == ETAGAPQ && desc_base + desc_size >=
			current_thread_info()->addr_limit.seg) ||
			(tag == ETAGPLQ && func_base >=
			current_thread_info()->addr_limit.seg));
}

/*
 * Check if aad doesn't constitute AP-type descriptor,
 * pointing to privilidged area
 */
bool is_priv_aad(unsigned int aad_lo, unsigned long aad_hi)
{
	unsigned long addr_limit = current_thread_info()->addr_limit.seg;

	if (aad_lo & (7ULL << 54) == 0x4) {
		unsigned long base = aad_lo & 0xffffffffffff;
		unsigned int size = aad_hi & 0xffffffff;

		if (base >= addr_limit || base + size >= addr_limit)
			return true;
	}

	return false;
}

static int check_permissions(struct user_regs_struct *user_regs, long size,
				e2k_aau_t *aau_regs)
{
	e2k_ctpr_t ctpr1, ctpr2, ctpr3;
	e2k_dibcr_t dibcr;
	e2k_dimcr_t dimcr;
	e2k_ddmcr_t ddmcr;
	int i;

	if (capable(CAP_SYS_ADMIN))
		return 0;

	AW(dibcr) = user_regs->dibcr;
	AW(dimcr) = user_regs->dimcr;
	AW(ddmcr) = user_regs->ddmcr;
	AW(ctpr1) = user_regs->ctpr1;
	AW(ctpr2) = user_regs->ctpr2;
	AW(ctpr3) = user_regs->ctpr3;

	/* Sanity check (breakpoints are checked
	 * in arch_check_bp_in_kernelspace()). */
	if (AS(dimcr)[0].system && AS(dimcr)[0].trap ||
		      AS(dimcr)[1].system && AS(dimcr)[1].trap ||
		      AS(ddmcr)[0].system && AS(ddmcr)[0].trap ||
		      AS(ddmcr)[1].system && AS(ddmcr)[1].trap)
		return -EIO;

	if (dibcr.stop)
		return -EIO;

	if (machine.native_iset_ver >= E2K_ISET_V6) {
		/*
		 * Prohibit user changing of monitor registers
		 */
		if (dimcr.u_m_en)
			return -EIO;

		if (size >= offsetofend(struct user_regs_struct, dimtp_hi)) {
			e2k_dimtp_t dimtp = {
				.lo = user_regs->dimtp_lo,
				.hi = user_regs->dimtp_hi
			};

			/*
			 * Disallow setting up buffer in kernel
			 */
			if (!access_ok((void __user *) dimtp.base, dimtp.size))
				return -EIO;
		}
	}

	/* Check, that all ctprs contain only user-space labels */
	if (is_priv_or_inv_ctpr(ctpr1, user_regs->oscud_lo) ||
			is_priv_or_inv_ctpr(ctpr2, user_regs->oscud_lo) ||
			is_priv_or_inv_ctpr(ctpr3, user_regs->oscud_lo))
		return -EPERM;

	/*
	 * Check, that there are no privilidged descriptors in global regs
	 * (descriptors, which point to kernel space)
	 */
	for (i = 0; i < 32; i += 2) {
		if (is_priv_desc(user_regs->g[i],
				user_regs->g[i + 1],
				user_regs->gtag[i] |
				(user_regs->gtag[i + 1] << 4)))
			return -EPERM;
	}

	/* Check that aad don't contain privilidged descs */
	if (aau_regs) {
		for (i = 0; i < 2*32; i += 2) {
			if (is_priv_aad(user_regs->aad[i],
					user_regs->aad[i + 1]))
				return -EPERM;
		}
	}

	return 0;
}

static int user_regs_to_pt_regs(struct user_regs_struct *user_regs,
			   struct task_struct *child, long size)
{
	struct thread_info *ti = task_thread_info(child);
	struct pt_regs *pt_regs = ti->pt_regs;
	struct trap_pt_regs *trap;
	struct sw_regs *sw_regs = &child->thread.sw_regs;
#ifdef CONFIG_USE_AAU
	e2k_aau_t *aau_regs;
#endif /* CONFIG_USE_AAU */
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	int ret, i;

	DebugTRACE("%s: current->pid=%d(%s) child->pid=%d BINCO(child) is %s\n",
		__func__, current->pid, current->comm, child->pid,
		TASK_IS_BINCO(child) ? "true" : "false");

	/* Sanity check; note that 'pt_regs' may be empty at this point. */
	ret = check_permissions(user_regs, size,
				pt_regs ? pt_regs->aau_context : NULL);
	if (ret)
		return ret;

	ret = ptrace_write_hbp_registers(child, user_regs);
	if (ret)
		return ret;

#ifdef	CONFIG_GREGS_CONTEXT
	/* FIXME: guest kernel sw_regs have not right values of global */
	/* registers. Right values save/restore/keep host into gthread_info */
	/* structure for this guest process */
	/* FIXME: it need implement for guest, but why do copying of */
	/* separate word, extention, tag so complex, using LDRD operations */
	SET_GREGS_TO_THREAD(sw_regs->gregs.g, user_regs->g, user_regs->gtag);
	for (i = 0; i < 32; i++)
		sw_regs->gregs.g[i].ext = (u64) user_regs->gext[i];
	if (machine.native_iset_ver >= E2K_ISET_V5) {
		if (size >= offsetofend(struct user_regs_struct, gext_v5) &&
		    size >= offsetofend(struct user_regs_struct, gext_tag_v5)) {
			SET_GREGS_TO_THREAD(&sw_regs->gregs.g[0].ext,
				    user_regs->gext_v5, user_regs->gext_tag_v5);
		}
	}
	get_k_gregs_from_gregs(&ti->k_gregs, &sw_regs->gregs);

	AW(sw_regs->gregs.bgr) = user_regs->bgr;
#endif /* CONFIG_GREGS_CONTEXT */

	AW(ti->upsr) = user_regs->upsr;

	/* WRITE_OSCUD_LO_REG_VALUE(user_regs->oscud_lo); unsecure to update descriptor */
	/* WRITE_OSCUD_HI_REG_VALUE(user_regs->oscud_hi); unsecure to update descriptor */
	/* WRITE_OSGD_LO_REG_VALUE(user_regs->osgd_lo); unsecure to update descriptor */
	/* WRITE_OSGD_HI_REG_VALUE(user_regs->osgd_hi); unsecure to update descriptor */
	/* WRITE_OSEM_REG_VALUE(user_regs->osem); unsecure: internal kernel info */
	/* WRITE_CURRENT_REG_VALUE(user_regs->osr0); unsecure: internal kernel info */

	AW(sw_regs->fpu.pfpfr) = user_regs->pfpfr;
	AW(sw_regs->fpu.fpcr) = user_regs->fpcr;
	AW(sw_regs->fpu.fpsr) = user_regs->fpsr;

	sw_regs->cs_lo = user_regs->cs_lo;
	sw_regs->cs_hi = user_regs->cs_hi;
	sw_regs->ds_lo = user_regs->ds_lo;
	sw_regs->ds_hi = user_regs->ds_hi;
	sw_regs->es_lo = user_regs->es_lo;
	sw_regs->es_hi = user_regs->es_hi;
	sw_regs->fs_lo = user_regs->fs_lo;
	sw_regs->fs_hi = user_regs->fs_hi;
	sw_regs->gs_lo = user_regs->gs_lo;
	sw_regs->gs_hi = user_regs->gs_hi;
	sw_regs->ss_lo = user_regs->ss_lo;
	sw_regs->ss_hi = user_regs->ss_hi;

	AW(sw_regs->dimcr) = user_regs->dimcr;
	AW(sw_regs->ddmcr) = user_regs->ddmcr;
	sw_regs->dimar0 = user_regs->dimar[0];
	sw_regs->dimar1 = user_regs->dimar[1];
	sw_regs->ddmar0 = user_regs->ddmar[0];
	sw_regs->ddmar1 = user_regs->ddmar[1];
	if (machine.native_iset_ver >= E2K_ISET_V6 &&
			size >= offsetofend(struct user_regs_struct, dimtp_hi)) {
		sw_regs->dimtp.lo = user_regs->dimtp_lo;
		sw_regs->dimtp.hi = user_regs->dimtp_hi;
	}

	AW(sw_regs->cutd) = user_regs->cutd;
	/*  = user_regs->cuir; */

	/*  = user_regs->rpr; */
	sw_regs->rpr_lo = user_regs->rpr_lo;
	sw_regs->rpr_hi = user_regs->rpr_hi;

	if (!pt_regs)
		return 0;

	/*  = user_regs->usbr; */
	AW(pt_regs->stacks.usd_lo) = user_regs->usd_lo;
	AW(pt_regs->stacks.usd_hi) = user_regs->usd_hi;
	change_psl_field((unsigned long *)&pt_regs->stacks.usd_lo, 1);

	AW(cr0_hi) = user_regs->cr0_hi;
	AW(cr1_lo) = user_regs->cr1_lo;
	AW(cr1_hi) = user_regs->cr1_hi;

	AW(pt_regs->crs.cr0_lo) = user_regs->cr0_lo;
	AS(pt_regs->crs.cr0_hi).ip = AS(cr0_hi).ip;
	AS(pt_regs->crs.cr1_lo).cui = AS(cr1_lo).cui;
	if (machine.native_iset_ver < E2K_ISET_V6)
		AS(pt_regs->crs.cr1_lo).ic = AS(cr1_lo).ic;
	AS(pt_regs->crs.cr1_lo).ss = AS(cr1_lo).ss;
	AS(pt_regs->crs.cr1_hi).ussz = AS(cr1_hi).ussz;
	AS(pt_regs->crs.cr1_hi).wdbl = AS(cr1_hi).wdbl;
	AS(pt_regs->crs.cr1_hi).br = AS(cr1_hi).br;

#ifdef CONFIG_USE_AAU
	AW(pt_regs->aasr) = user_regs->aasr;
	aau_regs = pt_regs->aau_context;
	/*
	 * Skip copying aaldi/aalda since they are recalculated anyway
	 */
	if (aau_regs) {
		for (i = 0; i < 32; i++) {
			AW(aau_regs->aads[i]).lo = user_regs->aad[2*i];
			AW(aau_regs->aads[i]).hi = user_regs->aad[2*i+1];
		}

		for (i = 0; i < 16; i++)
			aau_regs->aainds[i] = user_regs->aaind[i];

		for (i = 0; i < 8; i++)
			aau_regs->aaincrs[i] = user_regs->aaincr[i];

		AW(aau_regs->aaldv) = user_regs->aaldv;
		AW(aau_regs->aaldm) = user_regs->aaldm;

		aau_regs->aafstr = user_regs->aafstr;

		for (i = 0; i < 16; i++)
			aau_regs->aastis[i] = user_regs->aasti[i];
	}
#endif /* CONFIG_USE_AAU */

        AW(pt_regs->wd) = user_regs->wd;

	AS(pt_regs->crs.cr1_hi).br = user_regs->br;

	AW(pt_regs->ctpr1) = user_regs->ctpr1;
	AW(pt_regs->ctpr2) = user_regs->ctpr2;
	AW(pt_regs->ctpr3) = user_regs->ctpr3;

        /*  = user_regs->eir; */

	pt_regs->lsr = user_regs->lsr;
	pt_regs->ilcr = user_regs->ilcr;
	if (machine.native_iset_ver >= E2K_ISET_V5) {
		if (size >= offsetofend(struct user_regs_struct, lsr1))
			pt_regs->lsr1 = user_regs->lsr1;
		if (size >= offsetofend(struct user_regs_struct, ilcr1))
			pt_regs->ilcr1 = user_regs->ilcr1;
	}

	trap = pt_regs->trap;
	/* NB> The stuff below can be set ONLY IN REGULAR MODE */
	if (!trap && !TASK_IS_PROTECTED(child)) {
		pt_regs->args[1]    = user_regs->arg1;
		pt_regs->args[2]    = user_regs->arg2;
		pt_regs->args[3]    = user_regs->arg3;
		pt_regs->args[4]    = user_regs->arg4;
		pt_regs->args[5]    = user_regs->arg5;
		pt_regs->args[6]    = user_regs->arg6;
		pt_regs->sys_rval   = user_regs->sys_rval;
		pt_regs->sys_num    = user_regs->sys_num;
	}

        /* copy MLT */
	/* Unsupported */

	return 0;
}

/*
 * Called by kernel/ptrace.c when detaching..
 *
 * Make sure the single step bit is not set.
 */
void ptrace_disable(struct task_struct *child)
{
	user_disable_single_step(child);
}

static int arch_ptrace_peek(struct task_struct *child,
		 unsigned long addr, unsigned long data, bool tag, bool user)
{
	struct thread_info *ti = task_thread_info(child);
	volatile unsigned long tmp; /* volatile because it contains tag */
	unsigned long value;
	int copied;
	bool privileged_access = range_intersects(addr, sizeof(tmp),
			USER_ADDR_MAX, PAGE_OFFSET - USER_ADDR_MAX);
	bool tag_unaligned = false;

	if (!user && data < PAGE_OFFSET)
		return -EINVAL;

	if (tag && !IS_ALIGNED(addr, 8)) {
		if (!IS_ALIGNED(addr, 4))
			return -EINVAL;

		addr = round_down(addr, 8);
		tag_unaligned = true;
	}

	if (privileged_access) {
		unsigned long ts_flag;

		/* Only allow access to CUT and hw stacks */
		if (!range_includes(USER_HW_STACKS_BASE, E2K_ALL_STACKS_MAX_SIZE,
				addr, sizeof(tmp)) &&
		    !range_includes(USER_CUT_AREA_BASE, USER_CUT_AREA_SIZE,
				    addr, sizeof(tmp)))
			return -EPERM;

		/* Chain stack access works only with aligned dwords.
		 * Also this allows for the security check below. */
		if (!IS_ALIGNED(addr, 8))
			return -EINVAL;

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		copied = ptrace_access_vm(child, addr, (unsigned long *) &tmp,
				sizeof(tmp), FOLL_FORCE);
		clear_ts_flag(ts_flag);
	} else {
		copied = ptrace_access_vm(child, addr, (unsigned long *) &tmp,
				sizeof(tmp), FOLL_FORCE);
	}
	if (copied != sizeof(tmp))
		return -EIO;

	if (tag) {
		u64 unused;
		u8 tag;

		load_value_and_tagd((void *) &tmp, &unused, &tag);
		value = (tag_unaligned) ? (tag >> 2) : (tag & 0x3);
	} else {
		value = tmp;
	}

	if (user) {
		/* Ugly, but it seems like backwards
		 * compatibility requires this... */
		if (tag && is_compat_task())
			return put_user((compat_ulong_t) value,
					(compat_ulong_t __user *) data);
		else
			return put_user(value, (unsigned long __user *) data);
	} else {
		if (tag)
			*(u8 *) data = value;
		else
			*(unsigned long *) data = value;
		return 0;
	}
}

#ifdef	CONFIG_PROTECTED_MODE
static int arch_ptrace_peek_pl(struct task_struct *child,
				unsigned long addr, unsigned long data)
{
	e2k_pl_lo_t pl;
	long resdata = -1L;
	int ret = -EIO;

	if (arch_ptrace_peek(child, addr, (unsigned long) &pl, false, false))
		return ret;

	if (pl.itag == E2K_PL_ITAG) {
		resdata = pl.target;
		ret = put_user(resdata, (unsigned long __user *)data);
#ifdef	DEBUG_PTRACE
		pr_info("%s: result 0x%016lx\n", __func__, resdata);
#endif	/* DEBUG_PTRACE */
	} else {
		/* TD not supported */
#ifdef	DEBUG_PTRACE
		pr_info("%s: TD not supported\n", __func__);
#endif	/* DEBUG_PTRACE */
	}
	return ret;
}
#endif	/* CONFIG_PROTECTED_MODE */

struct poke_work_args {
	unsigned long addr;
	unsigned long data;
	u8 tag;
	struct callback_head callback;
};

static void poke_work_fn(struct callback_head *head)
{
	unsigned long pcs_base, pcs_used_top, ps_base, ps_used_top;
	struct pt_regs *regs = current_pt_regs();
	struct poke_work_args *args =
			container_of(head, struct poke_work_args, callback);
	unsigned long addr = args->addr, data = args->data;
	u8 tag = args->tag;
	volatile unsigned long value; /* volatile because it contains tag */

	kfree(args);
	args = NULL;

	/*
	 * Calculate stack frame addresses
	 */
	pcs_base = (unsigned long) CURRENT_PCS_BASE();
	ps_base = (unsigned long) CURRENT_PS_BASE();

	pcs_used_top = AS(regs->stacks.pcsp_lo).base +
		       AS(regs->stacks.pcsp_hi).ind;
	ps_used_top = AS(regs->stacks.psp_lo).base + AS(regs->stacks.psp_hi).ind;

	store_tagged_dword((u64 *) &value, data, tag);

	if (addr >= pcs_base && addr + sizeof(value) <= pcs_used_top) {
		write_current_chain_stack(addr, (void __user *) &value, sizeof(value));
	} else if (addr >= ps_base && addr + sizeof(value) <= ps_used_top) {
		copy_current_proc_stack((void __user *) &value, (void __user *) addr,
				sizeof(value), true, ps_used_top);
	} else {
		/* Writing of signal stack and CUT is prohibited */
		return;
	}
}

static int arch_ptrace_poke(struct task_struct *child,
		 unsigned long addr, unsigned long data, u8 tag)
{
	struct thread_info *ti = task_thread_info(child);
	bool privileged_access = range_intersects(addr, sizeof(data),
			USER_ADDR_MAX, PAGE_OFFSET - USER_ADDR_MAX);
	volatile unsigned long value;	/* volatile because it contains tag */

	/* Only allow access to hw stacks */
	if (privileged_access) {
		struct poke_work_args *poke_work;

		if (!range_includes(USER_HW_STACKS_BASE, E2K_ALL_STACKS_MAX_SIZE,
				addr, sizeof(value)))
			return -EPERM;

		/* Chain stack access works only with aligned dwords */
		if (!IS_ALIGNED(addr, 8))
			return -EINVAL;

		poke_work = kmalloc(sizeof(*poke_work), GFP_KERNEL);
		if (!poke_work)
			return -ENOMEM;

		poke_work->addr = addr;
		poke_work->data = data;
		poke_work->tag = tag;
		init_task_work(&poke_work->callback, poke_work_fn);
		return task_work_add(child, &poke_work->callback, true);
	} else {
		int copied;

		store_tagged_dword((u64 *) &value, data, tag);

		copied = ptrace_access_vm(child, addr, (void *) &value,
				sizeof(value), FOLL_FORCE | FOLL_WRITE);
		return (copied == sizeof(value)) ? 0 : -EIO;
	}
}


/* This is PEEKUSER if (peek_reg==true); POKEUSER otherwise */
static int arch_ptrace_peek_poke_user(struct task_struct *child,
				      unsigned long offset, unsigned long data,
				      bool peek_reg)
{
	struct thread_info *ti = task_thread_info(child);
	struct pt_regs *pt_regs = ti->pt_regs;

#define MIN_USER_AREA_OFFSET offsetof(struct user, regs.g[0])
#define MAX_USER_AREA_OFFSET offsetof(struct user, regs.arg12)
#define END_OF_REGS_USER_AREA_OFFSET U_TSIZE_UAREA_OFFSET
#define U_TSIZE_UAREA_OFFSET offsetof(struct user, u_tsize)
#define REGS_ARGX_SIZE (sizeof(((struct user *)NULL)->regs.arg1))

	DebugTRACE("%s  current->pid=%d(%s) child->pid=%d\n",
		   __func__, current->pid, current->comm, child->pid);

	if (!pt_regs)
		return -EIO;

	if (unlikely(offset < MIN_USER_AREA_OFFSET) ||
			offset > END_OF_REGS_USER_AREA_OFFSET)
		return -EIO;

	switch (offset) {
	case offsetof(struct user, regs.upsr):
		if (peek_reg)
			return put_user(AW(ti->upsr), (unsigned long __user *)data);
		AW(ti->upsr) = data;
		return 0;
	case offsetof(struct user, regs.usbr):
		if (peek_reg)
			return put_user(pt_regs->stacks.top, (unsigned long __user *)data);
		return -EIO;
	case offsetof(struct user, regs.usd_lo):
		if (peek_reg)
			return put_user(AW(pt_regs->stacks.usd_lo), (unsigned long __user *)data);
		return -EIO;
	case offsetof(struct user, regs.usd_hi):
		if (peek_reg)
			return put_user(AW(pt_regs->stacks.usd_hi), (unsigned long __user *)data);
		return -EIO;

	case offsetof(struct user, regs.sys_rval):
		if (peek_reg)
			return put_user(pt_regs->sys_rval, (unsigned long __user *)data);
		pt_regs->sys_rval = data;
		return 0;
	case offsetof(struct user, regs.sys_num):
		if (peek_reg)
			return put_user(pt_regs->sys_num, (unsigned long __user *)data);
		pt_regs->sys_num = data;
		return 0;

	case offsetof(struct user, regs.arg1):
		if (peek_reg)
			return put_user(pt_regs->args[1], (unsigned long __user *)data);
		else
			/* NB> We don't allow updating protected syscall arguments */
			break;
		return 0;
	case offsetof(struct user, regs.arg2):
		if (peek_reg)
			return put_user(pt_regs->args[2], (unsigned long __user *)data);
		else
			break;
	case offsetof(struct user, regs.arg3):
		if (peek_reg)
			return put_user(pt_regs->args[3], (unsigned long __user *)data);
		else
			break;
	case offsetof(struct user, regs.arg4):
		if (peek_reg)
			return put_user(pt_regs->args[4], (unsigned long __user *)data);
		else
			break;
	case offsetof(struct user, regs.arg5):
		if (peek_reg)
			return put_user(pt_regs->args[5], (unsigned long __user *)data);
		else
			break;
	case offsetof(struct user, regs.arg6):
		if (peek_reg)
			return put_user(pt_regs->args[6], (unsigned long __user *)data);
		else
			break;

#ifdef CONFIG_PROTECTED_MODE
		/* NB> We don't allow updating protected syscall arguments */
	case offsetof(struct user, regs.arg7):
		if (peek_reg)
			return put_user(pt_regs->args[7], (unsigned long __user *)data);
		else
			break;
	case offsetof(struct user, regs.arg8):
		if (peek_reg)
			return put_user(pt_regs->args[8], (unsigned long __user *)data);
		else
			break;
	case offsetof(struct user, regs.arg9):
		if (peek_reg)
			return put_user(pt_regs->args[9], (unsigned long __user *)data);
		else
			break;
	case offsetof(struct user, regs.arg10):
		if (peek_reg)
			return put_user(pt_regs->args[10], (unsigned long __user *)data);
		else
			break;
	case offsetof(struct user, regs.arg11):
		if (peek_reg)
			return put_user(pt_regs->args[11], (unsigned long __user *)data);
		else
			break;
	case offsetof(struct user, regs.arg12):
		if (peek_reg)
			return put_user(pt_regs->args[12], (unsigned long __user *)data);
		else
			break;
#endif /* CONFIG_PROTECTED_MODE */
	}

	return -EIO;
}

long common_ptrace(struct task_struct *child, long request, unsigned long addr,
		   unsigned long data, bool compat)
{
	struct user_regs_struct local_user_regs;
	long ret;
#ifdef CONFIG_PROTECTED_MODE
	u8 tag;
	long resdata = -1L;
	int itag;
#endif /* CONFIG_PROTECTED_MODE */

#ifdef DEBUG_PTRACE
	pr_info("%s: request=0x%lx\n", __func__, request);
#endif /* DEBUG_PTRACE */

	switch (request) {
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		ret = arch_ptrace_peek(child, addr, data, false, true);
		break;

	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		ret = arch_ptrace_poke(child, addr, data, 0);
		break;

	/* read the word at location addr in the USER area. */
	case PTRACE_PEEKUSR:
		ret = arch_ptrace_peek_poke_user(child, addr, data, true);
		break;

	case PTRACE_POKEUSR: /* write the word at location addr in the */
			     /* USER area */
		ret = arch_ptrace_peek_poke_user(child, addr, data, false);
		break;

	case PTRACE_PEEKTAG:
		ret = arch_ptrace_peek(child, addr, data, true, true);
		break;

	case PTRACE_POKETAG:
		/* not implemented yet. */
		ret = -EIO;
#ifdef DEBUG_PTRACE
		pr_info("%s: PTRACE_POKETAG not implemented yet\n", __func__);
#endif /* DEBUG_PTRACE */
		break;

#ifdef CONFIG_PROTECTED_MODE
        case PTRACE_PEEKPTR:
		ret = -EIO;

		/* Address should be aligned at least 8 bytes */
		if ((addr & 0x7) != 0)
			break;

		if (arch_ptrace_peek(child, addr, (unsigned long) &tag,
				     true, false))
			break;
#ifdef DEBUG_PTRACE
		pr_info("%s: tag=0x%x\n", __func__, tag);
#endif /* DEBUG_PTRACE */
		if (tag == E2K_AP_LO_ETAG) {
			/* C. 4.6.1. tag.lo = 1111 - AP, OD or PL
			* Address should be aligned at 16 bytes */
			if ((addr & 15) != 0)
				break;

			if (arch_ptrace_peek(child, addr + 8,
					(unsigned long) &tag, true, false))
				break;
#ifdef DEBUG_PTRACE
			pr_info("%s: tag=0x%x\n", __func__, tag);
#endif /* DEBUG_PTRACE */
			if (tag == E2K_AP_HI_ETAG) {
				/* AP  */
				e2k_ptr_t ap;

				if (arch_ptrace_peek(child, addr,
					  (unsigned long) &ap.lo, false, false))
					break;
				if (arch_ptrace_peek(child, addr + 8,
					  (unsigned long) &ap.hi, false, false))
					break;

                                itag = ap.itag;

                                if (itag == E2K_AP_ITAG) {
                                        /* AP */
                                        resdata = ap.base + ap.curptr;
				} else {
                                        resdata = -1;
#ifdef DEBUG_PTRACE
					pr_info("%s: unknown itag 0x%x\n", __func__, itag);
#endif /* DEBUG_PTRACE */
                                }

                		ret = put_user(resdata,(unsigned long __user *) data);
#ifdef DEBUG_PTRACE
				pr_info("%s: result 0x%016lx\n", __func__, resdata);
#endif /* DEBUG_PTRACE */
			} else if (tag == E2K_PLHI_ETAG) {
				ret = arch_ptrace_peek_pl(child, addr, data);
			} else {
				/* OD not supported. */
#ifdef	DEBUG_PTRACE
				pr_info("%s: OD not supported\n", __func__);
#endif	/* DEBUG_PTRACE */
				break;
			}
		} else if (tag == E2K_PL_ETAG) {
			ret = arch_ptrace_peek_pl(child, addr, data);
		} else {
			/* Unknown tag */
#ifdef	DEBUG_PTRACE
			pr_info("%s: unknown tag 0x%x\n", __func__, tag);
#endif	/* DEBUG_PTRACE */
			break;
		}
		break;

        case PTRACE_POKEPTR: {

		/* We arrive as follows:
		 * data - the address WHICH we want to write
		 * addr - the address, a software to WHICH we want to write
		 *
		 * If gd_base < = data < gd_base + gd_size, we will create
		 * AP descriptor also we will write it as structure to the
		 * address ADDR, then we will add tags
		 *
		 * FIXME
		 * Descriptor as <size> we will prescribe the area size to
		 * the addresses gd_base + gd_addr (because it isn't clear,
		 * what size to register), as <curptr> we create 0.
		 * as rw - E2_RWAR_RW_ENABLE
		 *
		 * If usd_base < = data < usd_base + usd_size, we will create
		 * descriptor of SAP
		 *
		 * If cud_base < = data < cud_base + cud_size, we will create
		 * PL descriptor */

		struct pt_regs *pt_regs = task_thread_info(child)->pt_regs;
		struct sw_regs *sw_regs = &child->thread.sw_regs;
		e2k_cutd_t cutd = sw_regs->cutd;
		e2k_pusd_lo_t pusd_lo;
		e2k_pusd_hi_t pusd_hi;
		e2k_cute_t cute;
		int cui = USER_CODES_PROT_INDEX; /* FIXME In a kernel it
							* isn't realized yet */
		long cute_entry_addr, stack_bottom;
		long pusd_base, pusd_size, gd_base, gd_size, cud_base, cud_size;
		unsigned long ts_flag;
		size_t copied;

		ret = -EIO;

		/* Address should be aligned at least 8 bytes */
		if ((addr & 7) != 0)
			break;


		/* Read register %pusd */
		AW(pusd_lo) = AW(pt_regs->stacks.usd_lo);
		AW(pusd_hi) = AW(pt_regs->stacks.usd_hi);
		pusd_base = pusd_lo.PUSD_lo_base;
		pusd_size = pusd_hi.PUSD_hi_size;

                /*                            usd.size
                 *                            <------>
                 *                              USER_P_STACK_SIZE <- FIXME
                 *                            <------------------->
                 * 0x0 |......................|...................| 0xfff...
                 *                                ^               ^
                 *                                usd.base        stack_bottom */
                stack_bottom = pusd_base + 0x2000 /* FIXME */;

		/* In %cutd the table address is written,
		 * in %cui - an index in the table is written.
		 * we calculate the address of entry necessary to us */
		cute_entry_addr = cutd.E2K_RWP_base + cui * sizeof (e2k_cute_t);

#ifdef DEBUG_PTRACE
		pr_info("do_ptrace: cutd.base = 0x%llx, cui = 0x%x, cute_entry_addr = 0x%lx\n",
			cutd.E2K_RWP_base, cui, cute_entry_addr);
		pr_info("do_ptrace: pusd.base = 0x%lx, pusd.size = 0x%lx\n", pusd_base, pusd_size);
#endif /* DEBUG_PTRACE */

		if (cute_entry_addr + sizeof(cute) > PAGE_OFFSET)
			break;
		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		copied = access_process_vm(child, cute_entry_addr, &cute,
				sizeof(cute), 0);
		clear_ts_flag(ts_flag);
		if (copied != sizeof(cute))
			break;

		gd_base = cute.gd_base;
		gd_size = cute.gd_size;
		cud_base = cute.cud_base;
		cud_size = cute.cud_size;

#ifdef DEBUG_PTRACE
		pr_info("do_ptrace: gd.base = 0x%lx, gd.size = 0x%lx\n"
			"do_ptrace: cud.base = 0x%lx, cud.size = 0x%lx\n",
			gd_base, gd_size, cud_base, cud_size);
#endif /* DEBUG_PTRACE */

		if ((gd_base <= data && data < (gd_base + gd_size)) ||
			((pusd_base <= data && data < stack_bottom))) {
			/* AP descriptor needed */
			e2k_ptr_t ap = {.hi = 0 };

			/* Address should be aligned at 16 bytes */
			if ((addr & 15) != 0)
				break;

			ap.base = data;
			ap.rw = E2_RWAR_RW_ENABLE;
			ap.itag = E2K_AP_ITAG;
			ap.curptr = 0;
			ap.size = gd_base + gd_size - data;

			if (arch_ptrace_poke(child, addr,
					ap.lo, E2K_AP_LO_ETAG))
				break;
			if (arch_ptrace_poke(child, addr + 8,
					ap.hi, E2K_AP_HI_ETAG))
				break;

			ret = 0;
#ifdef DEBUG_PTRACE
			pr_info("do_ptrace: AP written\n");
#endif /* DEBUG_PTRACE */
                } else if (cud_base <= data && data < (cud_base + cud_size)) {
			/* PL descriptor needed */
			e2k_pl_t pl;

			if (cpu_has(CPU_FEAT_ISET_V6)) {
				pl = MAKE_PL_V6(data, cui);
				if (arch_ptrace_poke(child, addr,
						AW(pl.lo), E2K_PLLO_ETAG))
					break;
				if (arch_ptrace_poke(child, addr + 8,
						AW(pl.hi), E2K_PLHI_ETAG))
					break;
			} else {
				pl = MAKE_PL_V3(data);
				if (arch_ptrace_poke(child, addr,
						AW(pl.lo), E2K_PL_ETAG))
					break;
			}

			ret = 0;
#ifdef DEBUG_PTRACE
			pr_info("%s: PL written\n", __func__);
#endif /* DEBUG_PTRACE */
		} else {
#ifdef DEBUG_PTRACE
			pr_info("%s: incorrect ptr\n", __func__);
#endif /* DEBUG_PTRACE */
		}
		break;
	}
#endif /* CONFIG_PROTECTED_MODE */

	case PTRACE_EXPAND_STACK: {
		/*
		 * This was created to prevent SIGSEGV when trying
		 * to PTRACE_POKEDATA below the allocated data stack
		 * area, but it is no longer needed: get_user_pages()
		 * calls into find_extend_vma() which automatically
		 * expands user's data stack
		 */
		ret = 0;
		break;
	}

	case PTRACE_GETREGS: {
		long size;

#ifdef DEBUG_PTRACE
	pr_info("%s: request=0x%lx[PTRACE_GETREGS]\n", __func__, request);
#endif /* DEBUG_PTRACE */
		ret = get_user_regs_struct_size(
				(struct user_regs_struct __user *) data, &size);
		if (ret) {
			unsigned long long zero = 0;
			if (copy_to_user((void __user *) data, &zero,
					 sizeof(zero)));
			break;
		}
		ret = pt_regs_to_user_regs (child, &local_user_regs, size);
		if (ret) {
			/*
			 * gdb expects result to be 0.
			 */
			ret = 0;
			memset(&local_user_regs, 0, size);
			/*
			 * gdb uses (sizeof_struct != 0) check to test for
			 * errors, so don't clear this field.
			 */
			local_user_regs.sizeof_struct = size;
		}

		ret = copy_to_user((void __user *) data,
				&local_user_regs, size);
		break;
	}

	case PTRACE_SETREGS: { /* Set all gp regs in the child. */
		long size;

#ifdef DEBUG_PTRACE
	pr_info("%s: request=0x%lx[PTRACE_SETREGS]\n", __func__, request);
#endif /* DEBUG_PTRACE */
		ret = get_user_regs_struct_size(
				(struct user_regs_struct __user *) data, &size);
		if (ret)
			break;

		ret = copy_from_user(&local_user_regs,
				(void __user *) data, size);
		if (ret)
			break;

		ret = user_regs_to_pt_regs(&local_user_regs, child, size);
		break;
	}

	case PTRACE_SINGLESTEP: {
		struct thread_info *ti = task_thread_info(child);

		if (!ti->pt_regs) {
			ret = -EPERM;
			break;
		}
		/* Fall through.  */
	}

	default:
		ret =
#ifdef CONFIG_COMPAT
			(compat) ? compat_ptrace_request(child, request, addr, data) :
#endif
			ptrace_request(child, request, addr, data);
		break;
	}
#ifdef DEBUG_PTRACE
	if (ret < 0)
		pr_info("do_ptrace: FAIL: ret=%ld\n", ret);
#endif /* DEBUG_PTRACE */
	return ret;
}

long arch_ptrace(struct task_struct *child, long request,
		 unsigned long addr, unsigned long data)
{
	return common_ptrace(child, request, addr, data, false);
}

void user_enable_single_step(struct task_struct *child)
{
	struct thread_info *ti = task_thread_info(child);

	set_ti_status_flag(ti, TS_SINGLESTEP_USER);
	if (!AS(ti->pt_regs->crs.cr1_lo).pm)
		AS(ti->pt_regs->crs.cr1_lo).ss = 1;
}

void user_disable_single_step(struct task_struct *child)
{
	struct thread_info *ti = task_thread_info(child);

	clear_ti_status_flag(ti, TS_SINGLESTEP_USER);
	if (ti->pt_regs)
		AS(ti->pt_regs->crs.cr1_lo).ss = 0;
}


int syscall_trace_entry(struct pt_regs *regs)
{
	int ret = 0;

	/* For compatibility with Intel. It can be used to distinguish
		syscall entry from syscall exit */
	regs->sys_rval = -ENOSYS;

	if (test_thread_flag(TIF_NOHZ))
		user_exit();

	if (test_thread_flag(TIF_SYSCALL_TRACE)) {
		ret = tracehook_report_syscall_entry(regs);
		if (ret)
			return ret;
	}

#ifdef CONFIG_HAVE_ARCH_SECCOMP_FILTER
	/* do the secure computing check after ptrace */
	ret = secure_computing();
	if (ret < 0)
		return ret;
#endif

	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_enter(regs, regs->sys_num);

	audit_syscall_entry(regs->sys_num, regs->args[1],
			    regs->args[2], regs->args[3], regs->args[4]);

	return ret;
}

void syscall_trace_leave(struct pt_regs *regs)
{
	audit_syscall_exit(regs);

	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_exit(regs, regs->sys_rval);

	if (test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall_exit(regs, 0);

	if (test_thread_flag(TIF_NOHZ))
		user_enter();

	rseq_syscall(regs);
}

