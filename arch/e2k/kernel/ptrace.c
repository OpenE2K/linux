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
#include <linux/elf.h>
#include <linux/regset.h>
#include <linux/seccomp.h>
#include <linux/pgtable.h>
#include <linux/sched/mm.h>
#include <linux/compat.h>
#include <linux/task_work.h>

#include <asm/check_hw_ctx.h>
#include <asm/compat.h>
#include <asm/gregs.h>
#include <linux/uaccess.h>
#include <asm/system.h>
#include <asm/e2k_ptypes.h>
#include <asm/process.h>
#include <asm/regs_state.h>
#include <asm/e2k_debug.h>
#include <asm/aau_context.h>
#include <asm/traps.h>
#include <asm/ptrace.h>

#include <trace/syscall.h>

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

/* #define DEBUG_PTRACE		0 */
#define	NEED_CUI_COMPUTING

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
	e2k_psp_t psp = regs->stacks.psp;
	e2k_psp_t cur_psp;
	e2k_cr1_t cr1 = regs->crs.cr1;
	unsigned long base, spilled, size;
	u64 value;
	u8 tag;

	if (unlikely((signed int) offset < 0))
		return 0xdead;

	if (offset & REGS_TIR1_REGISTER_FLAG) {
		struct trap_pt_regs *trap = regs->trap;

		if (!trap || trap->nr_TIRs <= 0)
			return 0xdead;

		return trap->TIRs[1].ip;
	}

	if (offset & REGS_PRED_REGISTER_FLAG) {
		u64 pf, pval, ptag;
		int pred, psz, pcur;

		pred = offset & ~REGS_PRED_REGISTER_FLAG;

		psz = cr1.psz;
		pcur = cr1.pcur;

		if (pcur && pred <= psz) {
			pred = pred + pcur;
			if (pred > psz)
				pred -= psz + 1;
		}

		pf = regs->crs.cr0.pf;

		pval = (pf & (1ULL << 2 * pred)) >> 2 * pred;
		ptag = (pf & (1ULL << (2 * pred + 1))) >> (2 * pred + 1);

		return (ptag << 1) | pval;
	}

	cur_psp = read_PSP_reg();

	if (offset & REGS_B_REGISTER_FLAG) {
		int qr, r, br, rbs, rsz, rcur;

		rbs = cr1.rbs;
		rsz = cr1.rsz;
		rcur = cr1.rcur;

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

	size = cr1.wbs * EXT_4_NR_SZ;
	base = PSP_PTR(psp) - size;

	spilled = PSP_BASE(psp) + PSP_IND(cur_psp);

	if (unlikely(offset + 8 > size))
		return 0xdead;

	if (base + offset >= spilled)
		E2K_FLUSHR;

	load_value_and_tagd((void *) base + offset, &value, &tag);

	return value;
}

static void user_regs_struct_size_checks(long size)
{
	bool size_is_small = cpu_has(CPU_FEAT_ISET_V5) &&
			     size < offsetofend(struct user_regs_struct, gext_tag_v5) ||
			     cpu_has(CPU_FEAT_ISET_V6) &&
			     size < offsetofend(struct user_regs_struct, ctpr3_hi) ||
			     cpu_has(CPU_FEAT_ISET_V7) &&
			     size < offsetofend(struct user_regs_struct, dimar3);

	if (size_is_small)
		pr_info_ratelimited("%s [%d] sys_ptrace: size of user_regs_struct is too small to keep all registers. Are you using an old version of profiler or gdb?\n",
				    current->comm, current->pid);
}

static void debug_regs_struct_size_checks(unsigned long long size)
{
	bool size_is_small = machine.native_iset_ver >= E2K_ISET_V6 &&
			     size < offsetofend(struct e2k_debug_regs, dimtp_hi) ||
			     machine.native_iset_ver >= E2K_ISET_V7 &&
			     size < offsetofend(struct e2k_debug_regs, dimar3);

	if (size_is_small)
		pr_info_ratelimited("%s [%d] sys_ptrace: size of e2k_debug_regs is too small to keep all registers. Are you using an old version of profiler or gdb?\n",
				    current->comm, current->pid);
}

/* User's "struct user_regs_struct" may be smaller than kernel one */
static inline int get_user_regs_struct_size(struct user_regs_struct __user *uregs,
					    long *size)
{
	unsigned long val;
	int ret;

	ret = get_user(val, &uregs->sizeof_struct);
	if (!ret) {
		if (val > sizeof(struct user_regs_struct))
			val = sizeof(struct user_regs_struct);
		*size = val;
		if (val < offsetof(struct user_regs_struct, idr))
			ret = -EPERM;

		/* do not allow to set arrays gext_v5 and gext_tag_v5 partially */
		if (val > offsetof(struct user_regs_struct, gext_v5[0]) &&
		    val < offsetofend(struct user_regs_struct, gext_tag_v5[31]))
			ret = -EPERM;
	}

	if (!ret)
		user_regs_struct_size_checks(*size);

	return ret;
}

/*	psl field value in usd_lo variable, which is stored in the kernel,
*	differs from the real user value by 1
*	according to the instruction set - any call increases this field by 1
*	and any return reduces by 1
*/
static void change_psl_field(e2k_usd_t *usd, int value)
{
	if (USD_P(*usd))
		usd->Psl += value;
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
	e2k_cute_t cute;
	e2k_cuir_t cuir;
	unsigned long pnt_cut_entry, ts_flag;
	size_t copied;

	/* index checkup */
	AW(cuir) = (u32) user_regs->cuir;
	if (machine.native_iset_ver < E2K_ISET_V6 && !cuir.checkup)
		return 0;
	pnt_cut_entry = user_regs->cutd.base + 32 * cuir.index;
	if (pnt_cut_entry + sizeof(cute) > PAGE_OFFSET)
		return 0;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	copied = access_process_vm(child, pnt_cut_entry, &cute,
				   sizeof(cute), 0);
	clear_ts_flag(ts_flag);
	if (copied != sizeof(cute)) {
		pr_info(" %s[PID=0x%x]:: bad pnt_cut_entry=0x%lx : copied(%zd) !=  sizeof(cute)=%ld\n",
			 __func__, child->pid, pnt_cut_entry, copied, sizeof(e2k_cute_t));
		return -ENODATA;
	}
	user_regs->gd = cute.gd;
	user_regs->cud = cute.cud;
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

void core_pt_regs_to_user_regs(struct pt_regs *pt_regs,
				struct user_regs_struct *user_regs)
{
	struct trap_pt_regs *trap;
	long size = sizeof(struct user_regs_struct);
	int i;
	struct thread_info *ti = current_thread_info();
	volatile struct global_gregs g_gregs;
	e2k_aau_t aau_regs;
	e2k_aasr_t aasr;

	DebugTRACE("%s: current->pid=%d(%s)\n", __func__, current->pid, current->comm);

	memset(user_regs, 0, size);

	machine.save_global_gregs((struct global_gregs *) &g_gregs);
	get_gregs_from_thread(user_regs, (struct global_gregs *) &g_gregs,
			      &current->thread.u_gregs);

	user_regs->upsr = AW(ti->upsr);

	/* user_regs->oscud_lo = READ_OSCUD_LO_REG_VALUE(); internal kernel info */
	/* user_regs->oscud_hi = READ_OSCUD_HI_REG_VALUE(); internal kernel info */
	/* user_regs->osgd_lo = READ_OSGD_LO_REG_VALUE(); internal kernel info */
	/* user_regs->osgd_hi = READ_OSGD_HI_REG_VALUE(); internal kernel info */
	/* user_regs->osem = READ_OSEM_REG_VALUE(); internal kernel info */
	/* user_regs->osr0 = READ_CURRENT_REG_VALUE(); */

	user_regs->pfpfr = AW(read_PFPFR_reg());
	user_regs->fpcr = AW(read_FPCR_reg());
	user_regs->fpsr = AW(read_FPSR_reg());

	user_regs->cs = (e2k_qreg_t) { .lo = READ_CS_LO_REG_VALUE(), .hi = READ_CS_HI_REG_VALUE() };
	user_regs->ds = (e2k_qreg_t) { .lo = READ_DS_LO_REG_VALUE(), .hi = READ_DS_HI_REG_VALUE() };
	user_regs->es = (e2k_qreg_t) { .lo = READ_ES_LO_REG_VALUE(), .hi = READ_ES_HI_REG_VALUE() };
	user_regs->fs = (e2k_qreg_t) { .lo = READ_FS_LO_REG_VALUE(), .hi = READ_FS_HI_REG_VALUE() };
	user_regs->gs = (e2k_qreg_t) { .lo = READ_GS_LO_REG_VALUE(), .hi = READ_GS_HI_REG_VALUE() };
	user_regs->ss = (e2k_qreg_t) { .lo = READ_SS_LO_REG_VALUE(), .hi = READ_SS_HI_REG_VALUE() };

	memset(&aau_regs, 0, sizeof(aau_regs));

	aasr = read_aasr_reg();
	aau_regs.aafstr = read_aafstr_reg_value();
	read_aaldm_reg(&aau_regs.aaldm);
	read_aaldv_reg(&aau_regs.aaldv);
	machine.get_aau_context(&aau_regs, aasr);
	SAVE_AADS(&aau_regs);

	machine.save_aaldi(user_regs->aaldi);
	SAVE_AALDA(user_regs->aalda);

	BUILD_BUG_ON(AADS_REGS_NUM != 32 || AAINDS_REGS_NUM != 16 ||
		     AAINCRS_REGS_NUM != 8 || AALDIS_REGS_NUM != 64 ||
		     AALDAS_REGS_NUM != 64 || AASTIS_REGS_NUM != 16);

	memcpy(user_regs->aad, aau_regs.aads, sizeof(aau_regs.aads));
	memcpy(user_regs->aaind, aau_regs.aainds, sizeof(aau_regs.aainds));
	memcpy(user_regs->aasti, aau_regs.aastis, sizeof(aau_regs.aastis));

	if (machine.native_iset_ver < E2K_ISET_V5) {
		for (i = 0; i < AAINCRS_REGS_NUM; i++)
			user_regs->aaincr[i] = (u32) aau_regs.aaincrs[i];
	} else {
		memcpy(user_regs->aaincr, aau_regs.aaincrs, sizeof(aau_regs.aaincrs));
	}

	user_regs->aaldv = AW(aau_regs.aaldv);
	user_regs->aaldm = AW(aau_regs.aaldm);

	user_regs->aasr = AW(aasr);
	user_regs->aafstr = (unsigned long long) aau_regs.aafstr;

	user_regs->clkr = 0;

	user_regs->dibcr = AW(read_DIBCR_reg());
	user_regs->ddbcr = READ_DDBCR_REG_VALUE();
	user_regs->dibsr = AW(read_DIBSR_reg());
	user_regs->dibar[0] = read_DIBAR0_reg();
	user_regs->dibar[1] = read_DIBAR1_reg();
	user_regs->dibar[2] = read_DIBAR2_reg();
	user_regs->dibar[3] = read_DIBAR3_reg();
	user_regs->ddbar[0] = READ_DDBAR0_REG();
	user_regs->ddbar[1] = READ_DDBAR1_REG();
	user_regs->ddbar[2] = READ_DDBAR2_REG();
	user_regs->ddbar[3] = READ_DDBAR3_REG();
	user_regs->dimcr = AW(read_DIMCR_reg());
	user_regs->ddmcr = READ_DDMCR_REG_VALUE();
	if (machine.native_iset_ver >= E2K_ISET_V7) {
		user_regs->ddmcr1 = READ_DDMCR1_REG_VALUE();
		user_regs->ddmar2 = READ_DDMAR2_REG();
		user_regs->ddmar3 = READ_DDMAR3_REG();
		if (!cpu_has(CPU_HWBUG_DIMCR1)) {
			user_regs->dimcr1 = AW(read_DIMCR1_reg());
			user_regs->dimar2 = read_DIMAR2_reg();
			user_regs->dimar3 = read_DIMAR3_reg();
		}
	}
	user_regs->dimar[0] = read_DIMAR0_reg();
	user_regs->dimar[1] = read_DIMAR1_reg();
	user_regs->ddmar[0] = READ_DDMAR0_REG();
	user_regs->ddmar[1] = READ_DDMAR1_REG();
	user_regs->ddbsr = READ_DDBSR_REG_VALUE();

	user_regs->dimtp = read_DIMTP_reg();

	user_regs->rpr = read_RPR_reg();
	user_regs->rndpr = AW(pt_regs->rndpr);

	/*   DAM  */
	save_dam(user_regs, current);

	*((void __priv **)&user_regs->chain_stack_base) = GET_PCS_BASE(&ti->u_hw_stack);
	*((void __priv **)&user_regs->proc_stack_base) = GET_PS_BASE(&ti->u_hw_stack);

	user_regs->idr = AW(read_IDR_reg());
	user_regs->core_mode = AW(read_CORE_MODE_reg());

	user_regs->sizeof_struct = sizeof(struct user_regs_struct);

	if (!pt_regs)
		return;

	user_regs->cutd = read_CUTD_reg();
	user_regs->cuir = (machine.native_iset_ver < E2K_ISET_V6) ?
				pt_regs->crs.cr1.cuir : pt_regs->crs.cr1.cui;

	trap = pt_regs->trap;

	user_regs->usbr = pt_regs->stacks.top;
	user_regs->usd = pt_regs->stacks.usd;
	change_psl_field(&user_regs->usd, -1);

	user_regs->psp = pt_regs->stacks.psp;
	user_regs->pshtp = AW(pt_regs->stacks.pshtp);

	user_regs->cr0 = pt_regs->crs.cr0;
	user_regs->cr1 = pt_regs->crs.cr1;

	user_regs->ip = get_cr0_ip(pt_regs->crs.cr0);

	user_regs->pcsp = pt_regs->stacks.pcsp;
	user_regs->pcshtp = AW(pt_regs->stacks.pcshtp);

	user_regs->wd = AW(pt_regs->wd);

	user_regs->br = pt_regs->crs.cr1.br;

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

		user_regs->ctpr1 = LO(pt_regs->ctpr1);
		user_regs->ctpr2 = LO(pt_regs->ctpr2);
		user_regs->ctpr3 = LO(pt_regs->ctpr3);
		if (machine.native_iset_ver >= E2K_ISET_V6) {
			user_regs->ctpr1_hi = HI(pt_regs->ctpr1);
			user_regs->ctpr2_hi = HI(pt_regs->ctpr2);
			user_regs->ctpr3_hi = HI(pt_regs->ctpr3);
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
			user_regs->trap_cell_info[i] = AW(trap->tcellar[i].condition);
			load_value_and_tagd(&trap->tcellar[i].data,
					    &data, &tag);
			user_regs->trap_cell_val[i] = data;
			user_regs->trap_cell_tag[i] = tag;
		}

		/* TIR */
		for (i = 0; i <= trap->nr_TIRs; i++) {
			user_regs->tir[i] = trap->TIRs[i];
		}

		/* SBBP */
		memcpy(user_regs->sbbp, trap->sbbp, sizeof(user_regs->sbbp));
	} else {
		user_regs->arg1     = pt_regs->dargs[0];
		user_regs->arg2     = pt_regs->dargs[1];
		user_regs->arg3     = pt_regs->dargs[2];
		user_regs->arg4     = pt_regs->dargs[3];
		user_regs->arg5     = pt_regs->dargs[4];
		user_regs->arg6     = pt_regs->dargs[5];
#ifdef CONFIG_PROTECTED_MODE
		if (pt_regs->kernel_entry == 8
			&& (size >= offsetofend(struct user_regs_struct, arg12))) {
			user_regs->arg7     = pt_regs->dargs[6];
			user_regs->arg8     = pt_regs->dargs[7];
			user_regs->arg9     = pt_regs->dargs[8];
			user_regs->arg10    = pt_regs->dargs[9];
			user_regs->arg11    = pt_regs->dargs[10];
			user_regs->arg12    = pt_regs->dargs[11];
			if (size >= offsetofend(struct user_regs_struct, flags)) {
				user_regs->flags = USER_REGS_FLAG_PROTECTED_MODE;
				user_regs->arg_tags = pt_regs->tags;
				if (pt_regs->return_desk) {
					user_regs->sys_rval_lo = pt_regs->rval1;
					user_regs->sys_rval_hi = pt_regs->rval2;
					user_regs->sys_rval_tag = pt_regs->rv1_tag |
								(pt_regs->rv2_tag << 4);
					user_regs->flags |= USER_REGS_FLAG_RETURN_DESCRIPTOR;
				}
			}
		}
#endif /* CONFIG_PROTECTED_MODE */
		user_regs->sys_rval = pt_regs->sys_rval;
		user_regs->sys_num  = (s64) (s32) pt_regs->sys_num;
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
				AW(read_DIBSR_reg()) & E2K_DIBSR_MASK(i);
			break;
		}
	}

	info.si_signo = SIGTRAP;
	info.si_errno = i;
	info.si_code = TRAP_HWBKPT;
	info.si_addr = (void __user *) (hw->address);

	force_sig_info(&info);
}

static int register_ptrace_breakpoint(struct task_struct *child, bool is_data_bp,
				      unsigned long bp_addr, int bp_len,
				      int bp_type, int idx, int enabled)
{
	struct perf_event_attr attr;
	struct perf_event *event;

	if (is_data_bp)
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

		event = register_user_hw_breakpoint(&attr, ptrace_hbp_triggered,
						    NULL, child);
		if (IS_ERR(event))
			return PTR_ERR(event);

	} else {
		if (enabled) {
			attr = event->attr;
			attr.bp_addr = bp_addr;
			attr.bp_len = bp_len;
			attr.bp_type = bp_type;
			attr.disabled = 0;

			return modify_user_hw_breakpoint(event, &attr);
		}

		unregister_hw_breakpoint(event);
		event = NULL;
	}

	if (is_data_bp)
		child->thread.debug.hbp_data[idx] = event;
	else
		child->thread.debug.hbp_instr[idx] = event;

	return 0;
}
#else /* CONFIG_HAVE_HW_BREAKPOINT */
static inline int register_ptrace_breakpoint(struct task_struct *child, bool is_data_bp,
					     unsigned long bp_addr, int bp_len,
					     int bp_type, int idx, int enabled)
{
	/* Not supported */
	return -ENODEV;
}
#endif /* CONFIG_HAVE_HW_BREAKPOINT */

static inline int get_hbp_len(int lng)
{
	if (lng >= 1 && lng <= 5)
		return 1 << (lng - 1);
	/* Values 0, 6 and 7 are reserved */
	return 0;
}

static inline int get_hbp_type(int rw)
{
	int bp_type = HW_BREAKPOINT_EMPTY;

	if (rw & 1)
		bp_type |= HW_BREAKPOINT_W;
	if (rw & 2)
		bp_type |= HW_BREAKPOINT_R;

	return bp_type;
}

static int ptrace_write_hbp_registers(struct task_struct *child,
				      const e2k_dibcr_t dibcr,
				      const e2k_ddbcr_t ddbcr,
				      const e2k_dibsr_t dibsr,
				      const e2k_ddbsr_t ddbsr,
				      const unsigned long long dibars[4],
				      const unsigned long long ddbars[4])
{
	struct thread_struct *thread = &child->thread;
	int i, ret = 0;

	/* Attention: if one of these calls fails, all the previous calls should be rewinded */
	ret = ret ?: register_ptrace_breakpoint(child, false,
			dibars[0], HW_BREAKPOINT_LEN_8,
			HW_BREAKPOINT_X, 0, dibcr.v0 && !dibsr.b0);
	ret = ret ?: register_ptrace_breakpoint(child, false,
			dibars[1], HW_BREAKPOINT_LEN_8,
			HW_BREAKPOINT_X, 1, dibcr.v1 && !dibsr.b1);
	ret = ret ?: register_ptrace_breakpoint(child, false,
			dibars[2], HW_BREAKPOINT_LEN_8,
			HW_BREAKPOINT_X, 2, dibcr.v2 && !dibsr.b2);
	ret = ret ?: register_ptrace_breakpoint(child, false,
			dibars[3], HW_BREAKPOINT_LEN_8,
			HW_BREAKPOINT_X, 3, dibcr.v3 && !dibsr.b3);
	ret = ret ?: register_ptrace_breakpoint(child, true,
			ddbars[0], get_hbp_len(ddbcr.lng0),
			get_hbp_type(ddbcr.rw0), 0, ddbcr.v0 && !ddbsr.b0);
	ret = ret ?: register_ptrace_breakpoint(child, true,
			ddbars[1], get_hbp_len(ddbcr.lng1),
			get_hbp_type(ddbcr.rw1), 1, ddbcr.v1 && !ddbsr.b1);
	ret = ret ?: register_ptrace_breakpoint(child, true,
			ddbars[2], get_hbp_len(ddbcr.lng2),
			get_hbp_type(ddbcr.rw2), 2, ddbcr.v2 && !ddbsr.b2);
	ret = ret ?: register_ptrace_breakpoint(child, true,
			ddbars[3], get_hbp_len(ddbcr.lng3),
			get_hbp_type(ddbcr.rw3), 3, ddbcr.v3 && !ddbsr.b3);
	if (ret)
		return ret;

	thread->sw_regs.dibsr = dibsr;
	thread->sw_regs.ddbsr = ddbsr;

	thread->debug.regs.dibcr = dibcr;
	thread->debug.regs.ddbcr = ddbcr;
	for (i = 0; i < 4; i++) {
		thread->debug.regs.dibar[i] = dibars[i];
		thread->debug.regs.ddbar[i] = ddbars[i];
	}

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
	e2k_aau_t *aau_regs;
	int i;

	/* just in case clear the whole structure (not first 'size' bytes) */
	memset(user_regs, 0, sizeof(struct user_regs_struct));

	DebugTRACE("%s: current->pid=%d(%s) child->pid=%d\n",
		   __func__, current->pid, current->comm, child->pid);

	if (!pt_regs)
		return -1;

	aau_regs = pt_regs->aau_context;
	trap = pt_regs->trap;

	get_gregs_from_thread(user_regs, &sw_regs->u_gregs,
			      &child->thread.u_gregs);

	user_regs->upsr = AW(ti->upsr);

	/* user_regs->oscud_lo = READ_OSCUD_LO_REG_VALUE(); internal kernel info */
	/* user_regs->oscud_hi = READ_OSCUD_HI_REG_VALUE(); internal kernel info */
	/* user_regs->osgd_lo = READ_OSGD_LO_REG_VALUE(); internal kernel info */
	/* user_regs->osgd_hi = READ_OSGD_HI_REG_VALUE(); internal kernel info */
	/* user_regs->osem = READ_OSEM_REG_VALUE(); internal kernel info */
	/* user_regs->osr0 = READ_CURRENT_REG_VALUE(); */

	user_regs->pfpfr = AW(sw_regs->fpu.pfpfr);
	user_regs->fpcr = AW(sw_regs->fpu.fpcr);
	user_regs->fpsr = AW(sw_regs->fpu.fpsr);

	user_regs->usbr = pt_regs->stacks.top;
	user_regs->usd = pt_regs->stacks.usd;
	change_psl_field(&user_regs->usd, -1);

	user_regs->psp = pt_regs->stacks.psp;
	user_regs->pshtp = AW(pt_regs->stacks.pshtp);

	user_regs->cr0 = pt_regs->crs.cr0;
	user_regs->cr1 = pt_regs->crs.cr1;

	user_regs->ip = get_cr0_ip(pt_regs->crs.cr0);

	user_regs->pcsp = pt_regs->stacks.pcsp;
	user_regs->pcshtp = AW(pt_regs->stacks.pcshtp);

	user_regs->cs = sw_regs->cs;
	user_regs->ds = sw_regs->ds;
	user_regs->es = sw_regs->es;
	user_regs->fs = sw_regs->fs;
	user_regs->gs = sw_regs->gs;
	user_regs->ss = sw_regs->ss;

	user_regs->aasr = AW(pt_regs->aasr);
	if (aau_regs) {
		BUILD_BUG_ON(AADS_REGS_NUM != 32 || AAINDS_REGS_NUM != 16 ||
			     AAINCRS_REGS_NUM != 8 || AALDIS_REGS_NUM != 64 ||
			     AALDAS_REGS_NUM != 64 || AASTIS_REGS_NUM != 16);

		memcpy(user_regs->aad, aau_regs->aads, sizeof(aau_regs->aads));
		memcpy(user_regs->aaind, aau_regs->aainds, sizeof(aau_regs->aainds));
		memcpy(user_regs->aaldi, aau_regs->aaldi, sizeof(aau_regs->aaldi));
		memcpy(user_regs->aasti, aau_regs->aastis, sizeof(aau_regs->aastis));

		if (machine.native_iset_ver < E2K_ISET_V5) {
			for (i = 0; i < AAINCRS_REGS_NUM; i++)
				user_regs->aaincr[i] = (u32) aau_regs->aaincrs[i];
		} else {
			memcpy(user_regs->aaincr, aau_regs->aaincrs, sizeof(aau_regs->aaincrs));
		}

		user_regs->aaldv = AW(aau_regs->aaldv);

		for (i = 0; i < AALDAS_REGS_NUM; i++)
			user_regs->aalda[i] = AW(ti->aalda[i]);

		user_regs->aaldm = AW(aau_regs->aaldm);
		user_regs->aafstr = (unsigned long long) aau_regs->aafstr;
	}

	user_regs->clkr = 0;

	user_regs->dibcr = AW(thread->debug.regs.dibcr);
	user_regs->ddbcr = AW(thread->debug.regs.ddbcr);
	for (i = 0; i < 4; i++) {
		user_regs->dibar[i] = thread->debug.regs.dibar[i];
		user_regs->ddbar[i] = thread->debug.regs.ddbar[i];
	}
	user_regs->dibsr = AW(sw_regs->dibsr);
	user_regs->ddbsr = AW(sw_regs->ddbsr);
	user_regs->dimcr = AW(sw_regs->dimcr);
	user_regs->ddmcr = AW(sw_regs->ddmcr);
	user_regs->dimar[0] = sw_regs->dimar[0];
	user_regs->dimar[1] = sw_regs->dimar[1];
	user_regs->ddmar[0] = sw_regs->ddmar[0];
	user_regs->ddmar[1] = sw_regs->ddmar[1];
	if (machine.native_iset_ver >= E2K_ISET_V7) {
		user_regs->ddmcr1 = AW(sw_regs->ddmcr1);
		user_regs->ddmar2 = sw_regs->ddmar[2];
		user_regs->ddmar3 = sw_regs->ddmar[3];
		if (!cpu_has(CPU_HWBUG_DIMCR1)) {
			user_regs->dimcr1 = AW(sw_regs->dimcr1);
			user_regs->dimar2 = sw_regs->dimar[2];
			user_regs->dimar3 = sw_regs->dimar[3];
		}
	}

	if (machine.native_iset_ver >= E2K_ISET_V6)
		user_regs->dimtp = sw_regs->dimtp;

	user_regs->wd = AW(pt_regs->wd);

	user_regs->br = pt_regs->crs.cr1.br;

	user_regs->cutd = sw_regs->cutd;
	user_regs->cuir = (machine.native_iset_ver < E2K_ISET_V6) ?
				pt_regs->crs.cr1.cuir : pt_regs->crs.cr1.cui;

	/*
	 * It is wrong to obtain IDR value via read_IDR_reg(), because
	 * it provides the IDR of the tracer's cpu (not the tracee's,
	 * whose IDR is of interest). Futhermore, the tracer's IDR may
	 * change between subsequent calls to ptrace() if the tracer
	 * migrated to another cpu, even though the tracee was stopped
	 * all that time.
	 *
	 * So, use the value previously saved in sw_regs.
	 */
	user_regs->idr = AW(sw_regs->idr);
	user_regs->core_mode = AW(read_CORE_MODE_reg());

	user_regs->lsr = pt_regs->lsr;
	user_regs->ilcr = pt_regs->ilcr;
	if (machine.native_iset_ver >= E2K_ISET_V5) {
		user_regs->lsr1 = pt_regs->lsr1;
		user_regs->ilcr1 = pt_regs->ilcr1;
	}

	user_regs->rpr = sw_regs->rpr;
	user_regs->rndpr = AW(pt_regs->rndpr);

	if (trap) {
		u64 data;
		u8 tag;

		user_regs->ctpr1 = LO(pt_regs->ctpr1);
		user_regs->ctpr2 = LO(pt_regs->ctpr2);
		user_regs->ctpr3 = LO(pt_regs->ctpr3);
		if (machine.native_iset_ver >= E2K_ISET_V6) {
			user_regs->ctpr1_hi = HI(pt_regs->ctpr1);
			user_regs->ctpr2_hi = HI(pt_regs->ctpr2);
			user_regs->ctpr3_hi = HI(pt_regs->ctpr3);
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
			user_regs->trap_cell_info[i] = trap->tcellar[i].condition.word;
			load_value_and_tagd(&trap->tcellar[i].data,
					    &data, &tag);
			user_regs->trap_cell_val[i] = data;
			user_regs->trap_cell_tag[i] = tag;
		}

		/* TIR */
		for (i = 0; i <= trap->nr_TIRs; i++) {
			user_regs->tir[i] = trap->TIRs[i];
		}

		/* SBBP */
		memcpy(user_regs->sbbp, trap->sbbp, sizeof(user_regs->sbbp));

		user_regs->sys_num = -1UL;
	} else {
		user_regs->arg1    = pt_regs->dargs[0];
		user_regs->arg2    = pt_regs->dargs[1];
		user_regs->arg3    = pt_regs->dargs[2];
		user_regs->arg4    = pt_regs->dargs[3];
		user_regs->arg5    = pt_regs->dargs[4];
		user_regs->arg6    = pt_regs->dargs[5];
#ifdef CONFIG_PROTECTED_MODE
		if ((pt_regs->kernel_entry == 8)
			&& (size >= offsetofend(struct user_regs_struct, arg12))) {
			user_regs->arg7     = pt_regs->dargs[6];
			user_regs->arg8     = pt_regs->dargs[7];
			user_regs->arg9     = pt_regs->dargs[8];
			user_regs->arg10    = pt_regs->dargs[9];
			user_regs->arg11    = pt_regs->dargs[10];
			user_regs->arg12    = pt_regs->dargs[11];
			if (size >= offsetofend(struct user_regs_struct, flags)) {
				user_regs->flags = USER_REGS_FLAG_PROTECTED_MODE;
				user_regs->arg_tags = pt_regs->tags;
				if (pt_regs->return_desk) {
					user_regs->sys_rval_lo = pt_regs->rval1;
					user_regs->sys_rval_hi = pt_regs->rval2;
					user_regs->sys_rval_tag = pt_regs->rv1_tag |
								(pt_regs->rv2_tag << 4);
					user_regs->flags |= USER_REGS_FLAG_RETURN_DESCRIPTOR;
				}
			}
		}
#endif /* CONFIG_PROTECTED_MODE */
		user_regs->sys_rval = pt_regs->sys_rval;
		user_regs->sys_num = (s64) (s32) pt_regs->sys_num;
	}

	/*   DAM  */
	save_dam(user_regs, child);

	*((void __priv **)&user_regs->chain_stack_base) = GET_PCS_BASE(&ti->u_hw_stack);
	*((void __priv **)&user_regs->proc_stack_base) = GET_PS_BASE(&ti->u_hw_stack);

	/*
	 * gdb uses (sizeof_struct != 0) check to test for
	 * errors, so don't clear this field.
	 */
	user_regs->sizeof_struct = size;

	return execute_user_gd_cud_regs(child, user_regs);
}

/* Check if ctpr doesn't contain privileged label */
static bool is_priv_or_inv_ctpr(e2k_ctpr_t ctpr, e2k_cud_t oscud)
{
	u64 opc = ctpr_opc(ctpr);
	u64 ta_tag = ctpr_ta_tag(ctpr);

	/* These opcode and tags greater than CTPSL_CT_TAG are reserved */
	if (opc == 2 || ta_tag > CTPSL_CT_TAG)
		return true;

	/* System label should be properly aligned and point to kernel entry */
	if (ta_tag == CTPSL_CT_TAG) {
		u64 cud_offset = ctpr.ta_base - CUD_BASE(oscud);

		if (cud_offset % 0x800)
			return true;

		if (cud_offset / 0x800 > 31)
			return true;
	}

	/* All other ctpr must not be privileged descriptors */
	if (ctpr.ta_base >= USER_ADDR_MAX &&
	    (ta_tag == CTPLL_CT_TAG || ta_tag == CTPPL_CT_TAG || ta_tag == CTPNL_CT_TAG))
		return true;

	return false;
}

/*
 * Check if aad doesn't constitute AP-type descriptor,
 * pointing to a privileged area.
 */
static bool is_priv_aad(e2k_aadj_t aad)
{
	if (AAD_IS_AP(aad)) {
		u64 base = AAD_BASE(aad);
		u64 size = AAD_SIZE(aad);

		if (base >= USER_ADDR_MAX || base + size >= USER_ADDR_MAX)
			return true;
	}

	if (AAD_IS_SAP(aad))
		return true;

	return false;
}

static int check_debug_regs(const e2k_dibcr_t *dibcr, const e2k_dimcr_t *dimcr,
			    const e2k_dimcr_t *dimcr1, const e2k_ddmcr_t *ddmcr,
			    const e2k_ddmcr_t *ddmcr1)
{
	/* Sanity check (breakpoints are checked
	 * in arch_check_bp_in_kernelspace()). */
	if (dimcr->dimar[0].system && dimcr->dimar[0].trap ||
	    dimcr->dimar[1].system && dimcr->dimar[1].trap ||
	    dimcr1->dimar[0].system && dimcr1->dimar[0].trap ||
	    dimcr1->dimar[1].system && dimcr1->dimar[1].trap ||
	    ddmcr->ddmar[0].system && ddmcr->ddmar[0].trap ||
	    ddmcr->ddmar[1].system && ddmcr->ddmar[1].trap ||
	    ddmcr1->ddmar[0].system && ddmcr1->ddmar[0].trap ||
	    ddmcr1->ddmar[1].system && ddmcr1->ddmar[1].trap)
		return -EIO;

	if (dibcr->stop)
		return -EIO;

	if (machine.native_iset_ver >= E2K_ISET_V6) {
		/*
		 * Prohibit user changing of monitor registers
		 */
		if (dimcr->u_m_en)
			return -EIO;
	}
	return 0;
}

static int check_permissions(const struct user_regs_struct *user_regs)
{
	e2k_ctpr_t ctpr1, ctpr2, ctpr3;
	e2k_dibcr_t dibcr;
	e2k_dimcr_t dimcr, dimcr1;
	e2k_ddmcr_t ddmcr, ddmcr1;
	e2k_aasr_t aasr;
	int i, ret;

	if (capable(CAP_SYS_ADMIN))
		return 0;

	AW(dibcr) = user_regs->dibcr;
	AW(dimcr) = user_regs->dimcr;
	AW(dimcr1) = user_regs->dimcr1;
	AW(ddmcr) = user_regs->ddmcr;
	AW(ddmcr1) = user_regs->ddmcr1;

	ret = check_debug_regs(&dibcr, &dimcr, &dimcr1, &ddmcr, &ddmcr1);
	if (ret)
		return ret;

	ctpr1 = ctpr_new(user_regs->ctpr1, user_regs->ctpr1_hi);
	ctpr2 = ctpr_new(user_regs->ctpr2, user_regs->ctpr2_hi);
	ctpr3 = ctpr_new(user_regs->ctpr3, user_regs->ctpr3_hi);

	/* Check, that all ctprs contain only user-space labels */
	if (is_priv_or_inv_ctpr(ctpr1, user_regs->oscud) ||
			is_priv_or_inv_ctpr(ctpr2, user_regs->oscud) ||
			is_priv_or_inv_ctpr(ctpr3, user_regs->oscud))
		return -EPERM;

	/*
	 * Check, that there are no privileged descriptors in global regs
	 * (descriptors, which point to kernel space)
	 */
	ret = check_user_gregs(E2K_MAXGR_d, user_regs->g, user_regs->gtag);
	if (ret)
		return ret;

	aasr.word = user_regs->aasr;
	aasr = aasr_parse(aasr);

	/* Check that aad registers don't contain privileged or segment descriptors */
	if (aau_has_state(aasr)) {
		for (i = 0; i < 32; i++) {
			if (is_priv_aad(user_regs->aad[i]) || AAD_IS_SD(user_regs->aad[i]))
				return -EPERM;
		}
	}

	return 0;
}

#define GET_DEBUG_REG(regs, dreg_mnemonic) TOS(e2k_##dreg_mnemonic##_t, (regs)->dreg_mnemonic)

#define CHECK_SIZE_AND_COPY_FIELD(dst, user_regs, field, size) \
do { \
	if ((size) >= offsetofend(struct user_regs_struct, field)) \
		(dst) = (user_regs)->field; \
} while (0)

static int user_regs_to_pt_regs(struct user_regs_struct *user_regs,
				struct task_struct *child, long size)
{
	struct thread_info *ti = task_thread_info(child);
	struct pt_regs *pt_regs = ti->pt_regs;
	struct trap_pt_regs *trap = (pt_regs) ? pt_regs->trap : NULL;
	struct sw_regs *sw_regs = &child->thread.sw_regs;
	e2k_aau_t *aau_regs;
	e2k_aasr_t aasr;
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	int ret;
	bool copy_ext;

	DebugTRACE("%s: current->pid=%d(%s) child->pid=%d BINCO(child) is %s\n",
		__func__, current->pid, current->comm, child->pid,
		TASK_IS_BINCO(child) ? "true" : "false");

	/* Sanity check */
	ret = check_permissions(user_regs);
	if (ret)
		return ret;

	ret = ptrace_write_hbp_registers(child,
			GET_DEBUG_REG(user_regs, dibcr), GET_DEBUG_REG(user_regs, ddbcr),
			GET_DEBUG_REG(user_regs, dibsr), GET_DEBUG_REG(user_regs, ddbsr),
			user_regs->dibar, user_regs->ddbar);
	if (ret)
		return ret;

	/*
	 * Parameter 'copy_ext' specifies whether set_gregs_to_thread() should
	 * set values from arrays gext_v5 and gext_tag_v5 or not.
	 *
	 * 1) For the case of PTRACE_SETREGS, an attempt to change only a part
	 *    of an array will be declined by the check in get_user_regs_struct_size(),
	 *    so 'size' values between offsetof(struct user_regs_struct, gext_v5[0]) and
	 *    offsetofend(struct user_regs_struct, gext_tag_v5[31]) are impossible.
	 *    If 'size' <= offsetof(struct user_regs_struct, gext_v5[0]), copy_ext
	 *    will be false and values from arrays gext_v5 and gext_tag_v5 will not be set
	 *    in set_gregs_to_thread() even on v5+ cpus.
	 *
	 * 2) For the case of PTRACE_SETREGSET, changing a part of arrays gext_v5
	 *    and gext_tag_v5 is OK: these arrays are unconditionally prefilled
	 *    in pt_regs_to_user_regs() with current values, so it is safe to set them
	 *    entirely if 'size' > offsetof(struct user_regs_struct, gext_v5[0]).
	 */
	copy_ext = size > offsetof(struct user_regs_struct, gext_v5[0]);
	set_gregs_to_thread(&sw_regs->u_gregs, &child->thread.u_gregs, user_regs, copy_ext);

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

	sw_regs->cs = user_regs->cs;
	sw_regs->ds = user_regs->ds;
	sw_regs->es = user_regs->es;
	sw_regs->fs = user_regs->fs;
	sw_regs->gs = user_regs->gs;
	sw_regs->ss = user_regs->ss;

	AW(sw_regs->dimcr) = user_regs->dimcr;
	AW(sw_regs->ddmcr) = user_regs->ddmcr;
	sw_regs->dimar[0] = user_regs->dimar[0];
	sw_regs->dimar[1] = user_regs->dimar[1];
	sw_regs->ddmar[0] = user_regs->ddmar[0];
	sw_regs->ddmar[1] = user_regs->ddmar[1];
	if (machine.native_iset_ver >= E2K_ISET_V7) {
		CHECK_SIZE_AND_COPY_FIELD(AW(sw_regs->ddmcr1), user_regs, ddmcr1, size);
		CHECK_SIZE_AND_COPY_FIELD(sw_regs->ddmar[2], user_regs, ddmar2, size);
		CHECK_SIZE_AND_COPY_FIELD(sw_regs->ddmar[3], user_regs, ddmar3, size);
		if (!cpu_has(CPU_HWBUG_DIMCR1)) {
			CHECK_SIZE_AND_COPY_FIELD(AW(sw_regs->dimcr1), user_regs, dimcr1, size);
			CHECK_SIZE_AND_COPY_FIELD(sw_regs->dimar[2], user_regs, dimar2, size);
			CHECK_SIZE_AND_COPY_FIELD(sw_regs->dimar[3], user_regs, dimar3, size);
		}
	}

	sw_regs->cutd = user_regs->cutd;
	/*  = user_regs->cuir; */

	/*  = user_regs->rpr; */
	sw_regs->rpr = user_regs->rpr;

	if (!pt_regs)
		return 0;

	/*  = user_regs->usbr; */
	pt_regs->stacks.usd = user_regs->usd;
	change_psl_field(&pt_regs->stacks.usd, 1);

	cr0 = user_regs->cr0;
	cr1 = user_regs->cr1;

	pt_regs->crs.cr0 = cr0;
	pt_regs->crs.cr1.cui = cr1.cui;
	if (machine.native_iset_ver < E2K_ISET_V6)
		pt_regs->crs.cr1.ic = cr1.ic;
	pt_regs->crs.cr1.ss = cr1.ss;
	if (cpu_has(CPU_FEAT_V7_CPU_REGS))
		pt_regs->crs.cr1.ussz_hi = cr1.ussz_hi;
	pt_regs->crs.cr1.ussz_lo = cr1.ussz_lo;
	pt_regs->crs.cr1.wdbl = cr1.wdbl;
	pt_regs->crs.cr1.br = cr1.br;

	AW(pt_regs->aasr) = user_regs->aasr;

	aasr.word = user_regs->aasr;
	aasr = aasr_parse(aasr);
	aau_regs = pt_regs->aau_context;

	/*
	 * Skip copying aaldi/aalda since they are recalculated anyway
	 */
	if (aau_has_state(aasr) && aau_regs) {
		BUILD_BUG_ON(AADS_REGS_NUM != 32 || AAINDS_REGS_NUM != 16 ||
			     AAINCRS_REGS_NUM != 8 || AASTIS_REGS_NUM != 16);

		memcpy(aau_regs->aads, user_regs->aad, sizeof(aau_regs->aads));
		memcpy(aau_regs->aainds, user_regs->aaind, sizeof(aau_regs->aainds));
		memcpy(aau_regs->aaincrs, user_regs->aaincr, sizeof(aau_regs->aaincrs));
		memcpy(aau_regs->aastis, user_regs->aasti, sizeof(aau_regs->aastis));

		AW(aau_regs->aaldv) = user_regs->aaldv;
		AW(aau_regs->aaldm) = user_regs->aaldm;

		aau_regs->aafstr = user_regs->aafstr;
	}

	AW(pt_regs->wd) = user_regs->wd;

	pt_regs->crs.cr1.br = user_regs->br;

	LO(pt_regs->ctpr1) = user_regs->ctpr1;
	LO(pt_regs->ctpr2) = user_regs->ctpr2;
	LO(pt_regs->ctpr3) = user_regs->ctpr3;
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		HI(pt_regs->ctpr1) = user_regs->ctpr1_hi;
		HI(pt_regs->ctpr2) = user_regs->ctpr2_hi;
		HI(pt_regs->ctpr3) = user_regs->ctpr3_hi;
	}

	CHECK_SIZE_AND_COPY_FIELD(AW(pt_regs->rndpr), user_regs, rndpr, size);

	pt_regs->lsr = user_regs->lsr;
	pt_regs->ilcr = user_regs->ilcr;
	if (machine.native_iset_ver >= E2K_ISET_V5) {
		CHECK_SIZE_AND_COPY_FIELD(pt_regs->lsr1, user_regs, lsr1, size);
		CHECK_SIZE_AND_COPY_FIELD(pt_regs->ilcr1, user_regs, ilcr1, size);
	}

	/* NB> The stuff below can be set ONLY IN REGULAR MODE */
	if (!trap && !TASK_IS_PROTECTED(child)) {
		pt_regs->dargs[0]   = user_regs->arg1;
		pt_regs->dargs[1]   = user_regs->arg2;
		pt_regs->dargs[2]   = user_regs->arg3;
		pt_regs->dargs[3]   = user_regs->arg4;
		pt_regs->dargs[4]   = user_regs->arg5;
		pt_regs->dargs[5]   = user_regs->arg6;
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


u8 get_tag_and_color_from_user_page(const void *src)
{
	u64 color;
	u8 tag;
	load_value_and_tagd(src, &color, &tag);
	if (cpu_has(CPU_FEAT_ISET_V7) && !cpu_has(CPU_FEAT_E48C_MAKET)) {
		ldst_rec_op_t ld_op = (ldst_rec_op_t) {
			.prot = 1,
			.fmt_h = LDST_MCOLOR_FMT_H,
			.mas = MAS_BYPASS_L1_CACHE
		};
		NATIVE_RECOVERY_LOAD_TO((u64 *)src, AW(ld_op), color, 0);
		tag = (tag & 0xf) | ((color & 0x7) << 4);
	}
	return tag;
}
EXPORT_SYMBOL(get_tag_and_color_from_user_page);

static int arch_ptrace_peek(struct task_struct *child,
		 unsigned long addr, unsigned long data, bool tag, bool user)
{
	unsigned long tmp;
	unsigned long value;
	int copied;
	bool privileged_access = range_intersects(addr, sizeof(tmp),
			USER_ADDR_MAX, PAGE_OFFSET - USER_ADDR_MAX);
	unsigned long ts_flag = 0;
	int tag_addr_alligned_8;


	if (tag) {
		if (!IS_ALIGNED(addr, 4))
			return -EINVAL;
		ts_flag = TS_PTRACE_WANTS_TAG;
		tag_addr_alligned_8 = IS_ALIGNED(addr, 8);
		addr = round_down(addr, 8);
	}
	if (privileged_access) {
		/* Only allow access to CUT and hw stacks */
		if (!range_includes(USER_HW_STACKS_BASE, E2K_ALL_STACKS_MAX_SIZE,
				    addr, sizeof(tmp)) &&
		    !range_includes(USER_CUT_AREA_BASE, USER_CUT_AREA_SIZE, addr, sizeof(tmp))) {
			return -EPERM;
		}
		/* Chain stack access works only with aligned dwords.
		 * Also this allows for the security check below. */
		if (!IS_ALIGNED(addr, 8))
			return -EINVAL;

		ts_flag |= TS_KERNEL_SYSCALL;
		set_ts_flag(ts_flag);
		copied = ptrace_access_vm(child, addr, (unsigned long *) &tmp,
					  sizeof(tmp), FOLL_FORCE);
	} else {
		set_ts_flag(ts_flag);
		copied = ptrace_access_vm(child, addr, (unsigned long *) &tmp,
					  sizeof(tmp), FOLL_FORCE);
	}
	clear_ts_flag(ts_flag);
	if (copied != sizeof(tmp))
		return -EIO;

	if (tag) {
		/* TS_PTRACE_WANTS_TAG flag forced to read tag of 64 bits data
		   in [3:4] bits of tmp and color (for v7) in [7:4] bits
		*/
		u8 color = tmp  & 0xf0;
		if (!tag_addr_alligned_8) {
			tmp = tmp >> 2;
		}
		value =  (tmp & 3) | color;
	} else {
		value = tmp;
	}

	if (user) {
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
	e2k_pl_t pl;
	long resdata = -1L;
	int ret = -EIO;

	if (arch_ptrace_peek(child, addr, (unsigned long) &LO(pl), false, false))
		return ret;
	if (arch_ptrace_peek(child, addr + sizeof(u64), (unsigned long) &HI(pl), false, false))
		return ret;

	if ((cpu_has(CPU_FEAT_V7_CPU_REGS) ? pl.itag_v7 : pl.itag_v6) == E2K_PL_ITAG) {
		resdata = pl.target;
		ret = put_user(resdata, (unsigned long __user *)data);
#ifdef	DEBUG_PTRACE
		pr_info("%s: result 0x%016lx\n", __func__, resdata);
#endif /* DEBUG_PTRACE */
	} else {
		/* TD not supported */
#ifdef	DEBUG_PTRACE
		pr_info("%s: TD not supported\n", __func__);
#endif /* DEBUG_PTRACE */
	}
	return ret;
}
#endif /* CONFIG_PROTECTED_MODE */

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

	pcs_used_top = PCSP_PTR(regs->stacks.pcsp);
	ps_used_top = PSP_PTR(regs->stacks.psp);

	store_tagged_dword((u64 *) &value, data, tag);

	if (addr >= pcs_base && addr + sizeof(value) <= pcs_used_top) {
		write_current_chain_stack(addr, (unsigned long) &value,
				false, sizeof(value));
	} else if (addr >= ps_base && addr + sizeof(value) <= ps_used_top) {
		copy_current_proc_stack((unsigned long) &value, false,
				(void __priv *) addr,
				sizeof(value), true, ps_used_top);
	} else {
		/* Writing of signal stack and CUT is prohibited */
		return;
	}
}

static int arch_ptrace_poke(struct task_struct *child,
		 unsigned long addr, unsigned long data, u8 tag)
{
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


/**
 * peek_user - read the word in the USER area.
 */
static int peek_user(struct task_struct *child, unsigned long offset, unsigned long data)
{
	struct thread_info *ti = task_thread_info(child);
	struct pt_regs *regs = ti->pt_regs;
	unsigned long value;

	DebugTRACE("%s  current->pid=%d(%s) child->pid=%d\n",
		   __func__, current->pid, current->comm, child->pid);

	if (!regs)
		return -EIO;

	switch (offset) {
	case offsetof(struct user, regs.ip):
		value = get_cr0_ip(regs->crs.cr0);
		break;
	case offsetof(struct user, regs.upsr):
		value = AW(ti->upsr);
		break;

	case offsetof(struct user, regs.usbr):
		value = regs->stacks.top;
		break;
	case offsetof(struct user, regs.usd.lo):
		value = regs->stacks.usd.lo;
		break;
	case offsetof(struct user, regs.usd.hi):
		value = regs->stacks.usd.hi;
		break;
	case offsetof(struct user, regs.psp.lo):
		value = regs->stacks.psp.lo;
		break;
	case offsetof(struct user, regs.psp.hi):
		value = regs->stacks.psp.hi;
		break;
	case offsetof(struct user, regs.pshtp):
		value = AW(regs->stacks.pshtp);
		break;
	case offsetof(struct user, regs.pcsp.lo):
		value = regs->stacks.pcsp.lo;
		break;
	case offsetof(struct user, regs.pcsp.hi):
		value = regs->stacks.pcsp.hi;
		break;
	case offsetof(struct user, regs.pcshtp):
		value = AW(regs->stacks.pcshtp);
		break;
	case offsetof(struct user, regs.cr0.lo):
		value = regs->crs.cr0.lo;
		break;
	case offsetof(struct user, regs.cr0.hi):
		value = regs->crs.cr0.hi;
		break;
	case offsetof(struct user, regs.cr1.lo):
		value = regs->crs.cr1.lo;
		break;
	case offsetof(struct user, regs.cr1.hi):
		value = regs->crs.cr1.hi;
		break;

	case offsetof(struct user, regs.sys_rval):
		value = regs->sys_rval;
		break;
	case offsetof(struct user, regs.sys_num):
		value = regs->sys_num;
		break;

	case offsetof(struct user, regs.arg1):
	case offsetof(struct user, regs.arg2):
	case offsetof(struct user, regs.arg3):
	case offsetof(struct user, regs.arg4):
	case offsetof(struct user, regs.arg5):
	case offsetof(struct user, regs.arg6):
		value = regs->dargs[(offset - offsetof(struct user, regs.arg1)) / 8];
		break;
#ifdef CONFIG_PROTECTED_MODE
	case offsetof(struct user, regs.arg7):
	case offsetof(struct user, regs.arg8):
	case offsetof(struct user, regs.arg9):
	case offsetof(struct user, regs.arg10):
	case offsetof(struct user, regs.arg11):
	case offsetof(struct user, regs.arg12):
		value = regs->dargs[(offset - offsetof(struct user, regs.arg7)) / 8 + 6];
		break;
#endif /* CONFIG_PROTECTED_MODE */
	default:
		return -EIO;
	}

	return put_user(value, (unsigned long __user *) data);
}

/**
 * poke_user - write the word in the USER area
 */
static int poke_user(struct task_struct *child, unsigned long offset, unsigned long data)
{
	struct thread_info *ti = task_thread_info(child);
	struct pt_regs *regs = ti->pt_regs;

	DebugTRACE("%s  current->pid=%d(%s) child->pid=%d\n",
		   __func__, current->pid, current->comm, child->pid);

	if (!regs)
		return -EIO;

	switch (offset) {
	case offsetof(struct user, regs.upsr):
		AW(ti->upsr) = data;
		return 0;
	case offsetof(struct user, regs.sys_rval):
		if (TASK_IS_PROTECTED(child))
			return -EPERM;

		regs->sys_rval = data;
		return 0;
	case offsetof(struct user, regs.sys_num):
		if (TASK_IS_PROTECTED(child))
			return -EPERM;

		regs->sys_num = data;
		return 0;
	default:
		return -EIO;
	}
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

	case PTRACE_PEEKUSR:
		ret = peek_user(child, addr, data);
		break;

	case PTRACE_POKEUSR:
		ret = poke_user(child, addr, data);
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
					     (unsigned long)&tag, true, false))
				break;
#ifdef DEBUG_PTRACE
			pr_info("%s: tag=0x%x\n", __func__, tag);
#endif /* DEBUG_PTRACE */
			if (tag == E2K_AP_HI_ETAG) {
				/* AP  */
				e2k_ap_t ap;

				if (arch_ptrace_peek(child, addr, (unsigned long) &ap.lo,
						     false, false))
					break;
				if (arch_ptrace_peek(child, addr + 8, (unsigned long) &ap.hi,
						     false, false))
					break;

				itag = cpu_has(CPU_FEAT_V7_CPU_REGS) ? ap.itag_v7 : ap.itag_v6;

				if (itag == E2K_AP_ITAG) {
					/* AP */
					resdata = AP_PTR(ap);
				} else {
					resdata = -1;
#ifdef DEBUG_PTRACE
					pr_info("%s: unknown itag 0x%x\n", __func__, itag);
#endif /* DEBUG_PTRACE */
				}

				ret = put_user(resdata, (unsigned long __user *) data);
#ifdef DEBUG_PTRACE
				pr_info("%s: result 0x%016lx\n", __func__, resdata);
#endif /* DEBUG_PTRACE */
			} else if (tag == E2K_PLHI_ETAG) {
				ret = arch_ptrace_peek_pl(child, addr, data);
			} else {
				/* OD not supported. */
#ifdef	DEBUG_PTRACE
				pr_info("%s: OD not supported\n", __func__);
#endif /* DEBUG_PTRACE */
				break;
			}
		} else if (tag == E2K_PL_ETAG) {
			ret = arch_ptrace_peek_pl(child, addr, data);
		} else {
			/* Unknown tag */
#ifdef	DEBUG_PTRACE
			pr_info("%s: unknown tag 0x%x\n", __func__, tag);
#endif /* DEBUG_PTRACE */
			break;
		}
		break;

	case PTRACE_POKEPTR:{
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
		 * as rw - RW_ENABLE
		 *
		 * If usd_base < = data < usd_base + usd_size, we will create
		 * descriptor of SAP
		 *
		 * If cud_base < = data < cud_base + cud_size, we will create
		 * PL descriptor */
		struct pt_regs *pt_regs = task_thread_info(child)->pt_regs;
		struct sw_regs *sw_regs = &child->thread.sw_regs;
		e2k_cutd_t cutd = sw_regs->cutd;
		e2k_usd_t pusd;
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
		pusd = pt_regs->stacks.usd;
		pusd_base = USD_PPTR(pusd);
		pusd_size = USD_IND(pusd);

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
		cute_entry_addr = cutd.base + cui * sizeof(e2k_cute_t);

#ifdef DEBUG_PTRACE
		pr_info("%s: cutd.base = 0x%llx, cui = 0x%x, cute_entry_addr = 0x%lx\n",
			__func__, cutd.E2K_RWP_base, cui, cute_entry_addr);
		pr_info("%s: pusd.base = 0x%lx, pusd.size = 0x%lx\n",
			__func__, pusd_base, pusd_size);
#endif /* DEBUG_PTRACE */

		if (cute_entry_addr + sizeof(cute) > PAGE_OFFSET)
			break;
		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		copied = access_process_vm(child, cute_entry_addr, &cute,
					   sizeof(cute), 0);
		clear_ts_flag(ts_flag);
		if (copied != sizeof(cute))
			break;

		gd_base = GD_BASE(cute.gd);
		gd_size = GD_SIZE(cute.gd);
		cud_base = CUD_BASE(cute.cud);
		cud_size = CUD_SIZE(cute.cud);

#ifdef DEBUG_PTRACE
		pr_info("%s: gd.base = 0x%lx, gd.size = 0x%lx\n"
			"%s: cud.base = 0x%lx, cud.size = 0x%lx\n",
			__func__, gd_base, gd_size, __func__, cud_base, cud_size);
#endif /* DEBUG_PTRACE */

		if ((gd_base <= data && data < (gd_base + gd_size)) ||
		    ((pusd_base <= data && data < stack_bottom))) {
			/* AP descriptor needed */
			e2k_ptr_t ap = {.hi = 0 };

			/* Address should be aligned at 16 bytes */
			if ((addr & 15) != 0)
				break;

			ap = new_ap(data, gd_base + gd_size - data, 0, RW_ENABLE);

			if (arch_ptrace_poke(child, addr,
					     ap.lo, E2K_AP_LO_ETAG))
				break;
			if (arch_ptrace_poke(child, addr + 8,
					     ap.hi, E2K_AP_HI_ETAG))
				break;

			ret = 0;
#ifdef DEBUG_PTRACE
			pr_info("%s: AP written\n", __func__);
#endif /* DEBUG_PTRACE */
		} else if (cud_base <= data && data < (cud_base + cud_size)) {
			/* PL descriptor needed */
			e2k_pl_t pl = MAKE_PL(data, cui);
			int tag_lo, tag_hi;


			if (!cpu_has(CPU_FEAT_ISET_V5)) {
				/* It is v3 */
				tag_lo = E2K_PL_ETAG;
				tag_hi = 0;
			} else {
				tag_lo = E2K_PLLO_ETAG;
				tag_hi = E2K_PLHI_ETAG;
			}
			if (arch_ptrace_poke(child, addr, LO(pl), tag_lo))
				break;
			if (arch_ptrace_poke(child, addr + 8, HI(pl), tag_hi))
				break;
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
					 sizeof(zero)))
				break;
		}
		ret = pt_regs_to_user_regs(child, &local_user_regs, size);
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
		ret = get_user_regs_struct_size((struct user_regs_struct __user *) data, &size);
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
		fallthrough;
	}

	default:
#ifdef CONFIG_COMPAT
		ret = (compat) ? compat_ptrace_request(child, request, addr, data) :
				 ptrace_request(child, request, addr, data);
#else
		ret = ptrace_request(child, request, addr, data);
#endif /* CONFIG_COMPAT */
		break;
	}
#ifdef DEBUG_PTRACE
	if (ret < 0)
		pr_info("%s: FAIL: ret=%ld\n", __func__, ret);
#endif /* DEBUG_PTRACE */
	return ret;
}

long arch_ptrace(struct task_struct *child, long request,
		 unsigned long addr, unsigned long data)
{
	return common_ptrace(child, request, addr, data, false);
}

/*
 * user_regset definitions.
 */

/*
 * N.B. in PTRACE_{GET,SET}REGS the field sizeof_struct is used to obtain
 * the size of user_regs_struct. In PTRACE_{GET,SET}REGSET for NT_PRSTATUS
 * regset the size of this structure is obtained via field iov_len of
 * struct iovec. Moreover, the field sizeof_struct is mostly unaccessable
 * from PTRACE_{GET,SET}REGSET internals. That's why in PTRACE_{GET,SET}REGSET
 * this field is ignored (with one exception: PTRACE_GETREGSET sets this field
 * to be equal to iov_len, which is returned to user by arch-independent part
 * of PTRACE_GETREGSET).
 */
static int e2k_user_regs_get(struct task_struct *target, const struct user_regset *regset,
			     struct membuf to)
{
	unsigned long long size = 0;
	struct user_regs_struct user_regs;
	int ret = 0;

	if (target == current) {
		/* The case of core dump */
		core_pt_regs_to_user_regs(current_pt_regs(), &user_regs);
		membuf_write(&to, &user_regs, sizeof(struct user_regs_struct));
		return 0;
	}

	/*
	 * This is the case of ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, ...).
	 * For e2k, it is the same as ptrace(PTRACE_GETREGS, pid, ...).
	 */
	size = to.left;
	user_regs_struct_size_checks(size);

	ret = pt_regs_to_user_regs(target, &user_regs, size);
	if (ret)
		return -EIO;

	return membuf_write(&to, &user_regs, size);
}

static int e2k_user_regs_set(struct task_struct *target, const struct user_regset *regset,
			     unsigned int pos, unsigned int count, const void *kbuf,
			     const void __user *ubuf)
{
	unsigned long long size = pos + count;
	struct user_regs_struct user_regs;
	int err = 0;

	/* e2k kernel does not support setting registers for 'current' */
	if (target == current)
		return -EINVAL;

	user_regs_struct_size_checks(size);

	/* Fill the structure with actual values */
	if (pt_regs_to_user_regs(target, &user_regs, size))
		return -EIO;

	/* Update the structure with user values */
	err = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &user_regs, 0, -1);
	if (err)
		return err;

	/* Set updated registers */
	return user_regs_to_pt_regs(&user_regs, target, size);
}

static void get_debug_regs(const struct task_struct *target, struct e2k_debug_regs *debug_regs)
{
	const struct thread_struct *thread = &target->thread;
	const struct sw_regs *sw_regs = &target->thread.sw_regs;
	int i;

	debug_regs->dibcr = AW(thread->debug.regs.dibcr);
	debug_regs->ddbcr = AW(thread->debug.regs.ddbcr);
	debug_regs->dibsr = AW(sw_regs->dibsr);
	debug_regs->ddbsr = AW(sw_regs->ddbsr);
	debug_regs->dimcr = AW(sw_regs->dimcr);
	debug_regs->ddmcr = AW(sw_regs->ddmcr);
	for (i = 0; i < 4; i++) {
		debug_regs->dibar[i] = thread->debug.regs.dibar[i];
		debug_regs->ddbar[i] = thread->debug.regs.ddbar[i];
	}
	for (i = 0; i < 2; i++) {
		debug_regs->dimar[i] = sw_regs->dimar[i];
		debug_regs->ddmar[i] = sw_regs->ddmar[i];
	}

	if (machine.native_iset_ver >= E2K_ISET_V6) {
		debug_regs->dimtp_lo = LO(sw_regs->dimtp);
		debug_regs->dimtp_hi = HI(sw_regs->dimtp);
	}

	if (machine.native_iset_ver >= E2K_ISET_V7) {
		debug_regs->ddmcr1 = AW(sw_regs->ddmcr1);
		debug_regs->ddmar2 = sw_regs->ddmar[2];
		debug_regs->ddmar3 = sw_regs->ddmar[3];

		if (!cpu_has(CPU_HWBUG_DIMCR1)) {
			debug_regs->dimcr1 = AW(sw_regs->dimcr1);
			debug_regs->dimar2 = sw_regs->dimar[2];
			debug_regs->dimar3 = sw_regs->dimar[3];
		}
	}
}

static int e2k_debug_regs_get(struct task_struct *target, const struct user_regset *regset,
			      struct membuf to)
{
	struct e2k_debug_regs debug_regs;
	unsigned long long size = to.left;

	/* There is no need to get NT_E2K_DEBUG_REGS regset for 'current' yet */
	if (target == current)
		return -EINVAL;

	debug_regs_struct_size_checks(size);

	memset(&debug_regs, 0, size);

	get_debug_regs(target, &debug_regs);

	return membuf_write(&to, &debug_regs, size);
}

static int check_permissions_for_debug_regs(const struct e2k_debug_regs *debug_regs)
{
	e2k_dibcr_t dibcr;
	e2k_dimcr_t dimcr, dimcr1;
	e2k_ddmcr_t ddmcr, ddmcr1;

	if (capable(CAP_SYS_ADMIN))
		return 0;

	AW(dibcr) = debug_regs->dibcr;
	AW(dimcr) = debug_regs->dimcr;
	AW(dimcr1) = debug_regs->dimcr1;
	AW(ddmcr) = debug_regs->ddmcr;
	AW(ddmcr1) = debug_regs->ddmcr1;

	return check_debug_regs(&dibcr, &dimcr, &dimcr1, &ddmcr, &ddmcr1);
}

static int set_debug_regs(struct task_struct *target, const struct e2k_debug_regs *debug_regs)
{
	struct sw_regs *sw_regs = &target->thread.sw_regs;
	int ret;

	ret = ptrace_write_hbp_registers(target,
			GET_DEBUG_REG(debug_regs, dibcr), GET_DEBUG_REG(debug_regs, ddbcr),
			GET_DEBUG_REG(debug_regs, dibsr), GET_DEBUG_REG(debug_regs, ddbsr),
			debug_regs->dibar, debug_regs->ddbar);
	if (ret)
		return ret;

	AW(sw_regs->dimcr) = debug_regs->dimcr;
	AW(sw_regs->ddmcr) = debug_regs->ddmcr;
	sw_regs->dimar[0] = debug_regs->dimar[0];
	sw_regs->dimar[1] = debug_regs->dimar[1];
	sw_regs->ddmar[0] = debug_regs->ddmar[0];
	sw_regs->ddmar[1] = debug_regs->ddmar[1];

	if (machine.native_iset_ver >= E2K_ISET_V7) {
		AW(sw_regs->ddmcr1) = debug_regs->ddmcr1;
		sw_regs->ddmar[2] = debug_regs->ddmar2;
		sw_regs->ddmar[3] = debug_regs->ddmar3;

		if (!cpu_has(CPU_HWBUG_DIMCR1)) {
			AW(sw_regs->dimcr1) = debug_regs->dimcr1;
			sw_regs->dimar[2] = debug_regs->dimar2;
			sw_regs->dimar[3] = debug_regs->dimar3;
		}
	}

	return 0;
}

static int e2k_debug_regs_set(struct task_struct *target, const struct user_regset *regset,
			      unsigned int pos, unsigned int count, const void *kbuf,
			      const void __user *ubuf)
{
	int err = 0;
	struct e2k_debug_regs debug_regs;
	unsigned long long size = regset->n * regset->size;

	/* e2k kernel does not support setting registers for 'current' */
	if (target == current)
		return -EINVAL;

	debug_regs_struct_size_checks(size);

	memset(&debug_regs, 0, size);

	/* Get a copy of target's debug registers */
	get_debug_regs(target, &debug_regs);

	/* Apply user changes to this copy */
	err = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &debug_regs, 0, -1);
	if (err)
		return err;

	/* Check the modified copy for correctness */
	err = check_permissions_for_debug_regs(&debug_regs);
	if (err)
		return err;

	/* Set the modified copy as actual debug registers */
	return set_debug_regs(target, &debug_regs);
}

static int e2k_debug_regs_active(struct task_struct *target,
				 const struct user_regset *regset)
{
	/*
	 * NT_E2K_DEBUG_REGS regset is a subset of NT_PRSTATUS regset in e2k.
	 * That's why it is useless to add this register set into core dumps.
	 * This function returns 0 to show that NT_E2K_DEBUG_REGS regset
	 * should not be used in core dumps.
	 */
	return 0;
}

static struct user_regset __ro_after_init e2k_regsets[] = {
	{
		/*
		 * Since elf_gregset_t was historically typedefed to struct
		 * user_regs_struct in e2k, for backward compatibility this
		 * structure should be used to describe NT_PRSTATUS regset.
		 * So, ptrace(PTRACE_{GET,SET}REGSET, pid, NT_PRSTATUS, ...)
		 * will be equivalent to ptrace(PTRACE_{GET,SET}REGS, pid, ...).
		 */
		.core_note_type = NT_PRSTATUS,
		.n = sizeof(struct user_regs_struct) / sizeof(u64),
		.size = sizeof(u64),
		.align = sizeof(u64),
		.regset_get = e2k_user_regs_get,
		.set = e2k_user_regs_set,

	},
	{
		.core_note_type = NT_E2K_DEBUG_REGS,
		.n = 0, /* this field is set in initcall set_debug_regs_number() */
		.size = sizeof(u64),
		.align = sizeof(u64),
		.regset_get = e2k_debug_regs_get,
		.set = e2k_debug_regs_set,
		.active = e2k_debug_regs_active,
	},
};

static int set_debug_regs_number(void)
{
	unsigned int size, i;

	if (machine.native_iset_ver >= E2K_ISET_V7) {
		size = offsetofend(struct e2k_debug_regs, dimar3);
	} else if (machine.native_iset_ver >= E2K_ISET_V6) {
		size = offsetofend(struct e2k_debug_regs, dimtp_hi);
	} else {
		size = offsetofend(struct e2k_debug_regs, ddbsr);
	}

	/* Find the NT_E2K_DEBUG_REGS regset and set its size */
	for (i = 0; i < ARRAY_SIZE(e2k_regsets); i++) {
		if (e2k_regsets[i].core_note_type == NT_E2K_DEBUG_REGS) {
			e2k_regsets[i].n = size / sizeof(u64);
			break;
		}
	}

	return 0;
}
pure_initcall(set_debug_regs_number);

static struct user_regset_view user_e2k_view __ro_after_init = {
	.name = "e2k",
	.e_machine = EM_E2K,
	.regsets = e2k_regsets,
	.n = ARRAY_SIZE(e2k_regsets)
};

static int init_user_e2k_view(void)
{
	user_e2k_view.e_flags = ELF_CORE_EFLAGS;
	return 0;
}
pure_initcall(init_user_e2k_view);

const struct user_regset_view *task_user_regset_view(struct task_struct *task)
{
	return &user_e2k_view;
}

void user_enable_single_step(struct task_struct *child)
{
	struct thread_info *ti = task_thread_info(child);

	set_ti_status_flag(ti, TS_SINGLESTEP_USER);
	if (!ti->pt_regs->crs.cr1.pm)
		ti->pt_regs->crs.cr1.ss = 1;
}

void user_disable_single_step(struct task_struct *child)
{
	struct thread_info *ti = task_thread_info(child);

	clear_ti_status_flag(ti, TS_SINGLESTEP_USER);
	if (ti->pt_regs)
		ti->pt_regs->crs.cr1.ss = 0;
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
		ret = ptrace_report_syscall_entry(regs);
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

	audit_syscall_entry(regs->sys_num, regs->dargs[0],
			    regs->dargs[1], regs->dargs[2], regs->dargs[3]);

	return ret;
}

void syscall_trace_leave(struct pt_regs *regs)
{
	audit_syscall_exit(regs);

	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_exit(regs, regs->sys_rval);

	if (test_thread_flag(TIF_SYSCALL_TRACE))
		ptrace_report_syscall_exit(regs, 0);

	if (test_thread_flag(TIF_NOHZ))
		user_enter();

	rseq_syscall(regs);
}

