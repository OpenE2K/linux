
/*
 * linux/arch/e2k/kernel/ptrace.c
 * 
 */

#include <linux/context_tracking.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/user.h>
#include <linux/pagemap.h>
#include <linux/signal.h>
#include <linux/audit.h>

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/e2k_ptypes.h>
#include <asm/regs_state.h>
#include <asm/e2k_debug.h>
#include <asm/aau_context.h>
#include <linux/tracehook.h>
#include <trace/syscall.h>

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

//#define DEBUG_PTRACE	0

#undef	DEBUG_PT_MODE
#undef	DebugPT
#define	DEBUG_PT_MODE		0	/* Compilation unit debugging */
#define DebugPT(...)		DebugPrint(DEBUG_PT_MODE ,##__VA_ARGS__)

#undef	DEBUG_CUI_MODE
#undef	DebugCUI
#define	DEBUG_CUI_MODE		0	/* Compilation unit debugging */
#define DebugCUI(...)		DebugPrint(DEBUG_CUI_MODE ,##__VA_ARGS__)

#undef	DEBUG_TRACE
#undef	DebugTRACE
#define	DEBUG_TRACE		0
#define DebugTRACE(...)		DebugPrint(DEBUG_TRACE ,##__VA_ARGS__)


#ifdef DEBUG_PTRACE
char *pt_rq [] = {
"TRACEME",
"PEEKTEXT",
"PEEKDATA",
"PEEKUSR",
"POKETEXT",
"POKEDATA",
"POKEUSR",
"CONT",
"KILL",
"SINGLESTEP",
"SUNATTACH",
"SUNDETACH",
"GETREGS",
"SETREGS",
"GETFPREGS",
"SETFPREGS",
"ATTACH",
"DETACH",
"GETFPXREGS",
"SETFPXREGS",
"GETFPAREGS",
"SETOPTIONS",
""
};
#endif


// users "struct user_regs_struct" may be less than kernel one                                  
#define GET_CURRENT_USER_SIZE(p1,sz)                          \
({                                                            \
	struct user_regs_struct *pnt = (struct user_regs_struct *) p1; \
	unsigned long val; \
	int __ret = 0; \
	__ret = get_user(val, &pnt->sizeof_struct); \
	if (!__ret) { \
		sz = val; \
		if (sizeof(struct user_regs_struct) != sz) \
			ret = -EPERM; \
	} \
	__ret; \
})
         
void core_pt_regs_to_user_regs (struct pt_regs *pt_regs,
			   struct user_regs_struct *user_regs)
{
	struct trap_pt_regs *trap = pt_regs->trap;
        long size = sizeof(struct user_regs_struct);
        int i;
	struct thread_info *ti = current_thread_info();
#ifdef CONFIG_GREGS_CONTEXT
	struct {
		u64 gbase[E2K_MAXGR_d];
		u16 gext[E2K_MAXGR_d];
		u8  tag[E2K_MAXGR_d];
		e2k_bgr_t bgr;
	} gregs;
#endif /* CONFIG_GREGS_CONTEXT */
#ifdef CONFIG_USE_AAU
	e2k_aau_t aau_regs;
#endif /* CONFIG_USE_AAU */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	int mlt_num = pt_regs->mlt_state.num;
#endif

	DebugTRACE("core_pt_regs_to_user_regs current->pid=%d(%s)\n",
		current->pid, current->comm);

        memset(user_regs, 0, size);

#ifdef CONFIG_GREGS_CONTEXT
	DO_SAVE_GLOBAL_REGISTERS(&gregs, true, true);
	E2K_MOVE_TAGGED_QWORD(&ti->gbase[0], &gregs.gbase[16]);
	E2K_MOVE_TAGGED_QWORD(&ti->gbase[2], &gregs.gbase[18]);
	gregs.gext[16] = ti->gext[0];
	gregs.gext[17] = ti->gext[1];
	gregs.gext[18] = ti->gext[2];
	gregs.gext[19] = ti->gext[3];
	GET_GREGS_FROM_THREAD(user_regs->g, user_regs->gtag, user_regs->gext,
			gregs.gbase, gregs.gext, gregs.tag);
	user_regs->bgr = AW(gregs.bgr);
#endif /* CONFIG_GREGS_CONTEXT */

	user_regs->upsr = AW(ti->upsr);

	/* user_regs->oscud_lo = ; */
	/* user_regs->oscud_hi = ; */
	/* user_regs->osgd_lo = ; */
	/* user_regs->osgd_hi = ; */
	/* user_regs->osem = ; */
	/* user_regs->osr0 = ; */

	user_regs->pfpfr = E2K_GET_SREG_NV(pfpfr);
	user_regs->fpcr = E2K_GET_SREG_NV(fpcr);
	user_regs->fpsr = E2K_GET_SREG_NV(fpsr);

	/* user_regs->usbr = ; */
	user_regs->usd_lo = AW(pt_regs->stacks.usd_lo);
	user_regs->usd_hi = AW(pt_regs->stacks.usd_hi);

	user_regs->psp_lo = AW(pt_regs->stacks.psp_lo);
	user_regs->psp_hi = AW(pt_regs->stacks.psp_hi);
	user_regs->pshtp = AW(pt_regs->pshtp);

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

	user_regs->cud_lo = ti->cud_lo;
	user_regs->cud_hi = ti->cud_hi;
	user_regs->gd_lo = ti->gd_lo;
	user_regs->gd_hi = ti->gd_hi;

	user_regs->cs_lo = E2K_GET_DSREG(cs.lo);
	user_regs->cs_hi = E2K_GET_DSREG(cs.hi);
	user_regs->ds_lo = E2K_GET_DSREG(ds.lo);
	user_regs->ds_hi = E2K_GET_DSREG(ds.hi);
	user_regs->es_lo = E2K_GET_DSREG(es.lo);
	user_regs->es_hi = E2K_GET_DSREG(es.hi);
	user_regs->fs_lo = E2K_GET_DSREG(fs.lo);
	user_regs->fs_hi = E2K_GET_DSREG(fs.hi);
	user_regs->gs_lo = E2K_GET_DSREG(gs.lo);
	user_regs->gs_hi = E2K_GET_DSREG(gs.hi);
	user_regs->ss_lo = E2K_GET_DSREG(ss.lo);
	user_regs->ss_hi = E2K_GET_DSREG(ss.hi);

#ifdef CONFIG_USE_AAU
	AW(aau_regs.aasr) = E2K_GET_AAU_AASR();
	SAVE_AAFSTR(aau_regs.aafstr);
	E2K_GET_AAU_AALDM(aau_regs.aaldm.lo, aau_regs.aaldm.hi);
	E2K_GET_AAU_AALDV(aau_regs.aaldv.lo, aau_regs.aaldv.hi);
	get_array_descriptors(&aau_regs);
	get_synchronous_part(&aau_regs);
	SAVE_AADS(&aau_regs);
	SAVE_AALDI(aau_regs.aaldi);
	SAVE_AALDA(aau_regs.aalda);

	for (i = 0; i < 32; i++) {
		user_regs->aad[2*i] = AW(aau_regs.aads[i]).lo;
		user_regs->aad[2*i+1] = AW(aau_regs.aads[i]).hi;
	}

	for (i = 0; i < 16; i++)
		user_regs->aaind[i] = aau_regs.aainds[i];

	for (i = 0; i < 8; i++)
		user_regs->aaincr[i] = aau_regs.aaincrs[i];

	for (i = 0; i < 64; i++)
		user_regs->aaldi[i] = (unsigned long long) aau_regs.aaldi[i];

	user_regs->aaldv = AW(aau_regs.aaldv);

	for (i = 0; i < 64; i++)
		user_regs->aalda[i] = AW(aau_regs.aalda[i]);

	user_regs->aaldm = AW(aau_regs.aaldm);

	user_regs->aasr = AW(aau_regs.aasr);
	user_regs->aafstr = (unsigned long long) aau_regs.aafstr;

	for (i = 0; i < 16; i++)
		user_regs->aasti[i] = aau_regs.aastis[i];
#endif /* CONFIG_USE_AAU */

	user_regs->clkr = 0;

	user_regs->dibcr = E2K_GET_DSREG(dibcr);
	user_regs->ddbcr = E2K_GET_MMUREG(ddbcr);
	user_regs->dibsr =  E2K_GET_DSREG(dibsr);
	user_regs->dibar[0] = E2K_GET_DSREG(dibar0);
	user_regs->dibar[1] = E2K_GET_DSREG(dibar1);
	user_regs->dibar[2] = E2K_GET_DSREG(dibar2);
	user_regs->dibar[3] = E2K_GET_DSREG(dibar3);
	user_regs->ddbar[0] = E2K_GET_MMUREG(ddbar0);
	user_regs->ddbar[1] = E2K_GET_MMUREG(ddbar1);
	user_regs->ddbar[2] = E2K_GET_MMUREG(ddbar2);
	user_regs->ddbar[3] = E2K_GET_MMUREG(ddbar3);
	user_regs->dimcr = E2K_GET_DSREG(dimcr);
	user_regs->ddmcr = E2K_GET_MMUREG(ddmcr);
	user_regs->dimar[0] = E2K_GET_DSREG(dimar0);
	user_regs->dimar[1] = E2K_GET_DSREG(dimar1);
	user_regs->ddmar[0] = E2K_GET_MMUREG(ddmar0);
	user_regs->ddmar[1] = E2K_GET_MMUREG(ddmar1);
	user_regs->ddbsr = E2K_GET_DSREG(dibsr);
	/* user_regs->dtcr = ; */
	/* user_regs->dtarf = ; */
	/* user_regs->dtart = ; */

	user_regs->wd = AW(pt_regs->wd);

	user_regs->br = AS(pt_regs->crs.cr1_hi).br;

	user_regs->ctpr1 = AW(pt_regs->ctpr1);
	user_regs->ctpr2 = AW(pt_regs->ctpr2);
	user_regs->ctpr3 = AW(pt_regs->ctpr3);

        /* user_regs->eir = ; */

	user_regs->cutd = E2K_GET_DSREG_NV(cutd);
	if (ti->flags & E2K_FLAG_32BIT)
		user_regs->cuir = USER_CODES_32_INDEX;
	else
		user_regs->cuir = USER_CODES_START_INDEX;
#ifdef CONFIG_PROTECTED_MODE
	if (ti->flags & E2K_FLAG_PROTECTED_MODE) {
		int cui = USER_CODES_PROT_INDEX;
		unsigned long ip = current_thread_info()->execve.entry;
		struct mm_struct *mm;
		struct vm_area_struct *vma;

		DebugCUI("computing CUIR for IP 0x%lx\n", ip);
		mm = current->mm;
		if (mm == NULL)
			panic("core_pt_regs_to_user_regs() current process has not mm structure\n");

		down_read(&mm->mmap_sem);
		vma = find_vma(mm, ip);
		if (vma == NULL) {
			DebugCUI("invalid IP 0x%lx of child process CUI set to initial state %d\n",
					ip, cui);
		} else {
			cui = _PAGE_INDEX_FROM_CUNIT(
					pgprot_val(vma->vm_page_prot));
			DebugCUI("CUI is %d\n", cui);
		}
		up_read(&mm->mmap_sem);
		user_regs->cuir = cui;
	}
#endif /* CONFIG_PROTECTED_MODE */

	user_regs->lsr = pt_regs->lsr;
	user_regs->ilcr = pt_regs->ilcr;

        /* user_regs->tir_lo = ; */
        /* user_regs->tir_hi = ; */

        /* user_regs->rpr = ; */
	user_regs->rpr_lo = E2K_GET_DSREG(rpr.lo);
	user_regs->rpr_hi = E2K_GET_DSREG(rpr.hi);

	/* MLT */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (mlt_num)
		memcpy(user_regs->mlt, pt_regs->mlt_state.mlt,
			sizeof(e2k_mlt_entry_t) * mlt_num);
#endif

	if (trap) {
		/* TC */
		for (i = 0; i < MAX_TC_SIZE; i++) {
			user_regs->trap_cell_addr[i] = trap->tcellar[i].address;
			user_regs->trap_cell_val[i] = trap->tcellar[i].data;
			user_regs->trap_cell_info[i] =
					AW(trap->tcellar[i].condition);
			user_regs->trap_cell_tag[i] =
					E2K_LOAD_TAGD(&trap->tcellar[i].data);
		}

		/* TIR */
		for (i = 0; i < TIR_NUM; i++) {
			user_regs->tir_hi[i] = AW(trap->TIRs[i].hi);
			user_regs->tir_lo[i] = AW(trap->TIRs[i].lo);
		}
	}

	/*   DAM  */
	memcpy(user_regs->dam, ti->dam, sizeof(ti->dam));

	user_regs->sizeof_struct = sizeof(struct user_regs_struct);
}

int pt_regs_to_user_regs(struct task_struct *child,
			 struct user_regs_struct *user_regs, long size)
{
	struct thread_info *ti = task_thread_info(child);
	struct pt_regs *pt_regs = ti->pt_regs;
	struct trap_pt_regs *trap;
	struct sw_regs *sw_regs = &child->thread.sw_regs;
#ifdef CONFIG_USE_AAU
	e2k_aau_t *aau_regs;
#endif /* CONFIG_USE_AAU*/
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	int mlt_num;
#endif
        int i;

        memset(user_regs, 0, size);
        DebugTRACE("pt_regs_to_user_regs  current->pid=%d(%s) child->pid=%d\n",
                  current->pid, current->comm, child->pid);

	if (!pt_regs)
		return -1;

#ifdef CONFIG_USE_AAU
	aau_regs = pt_regs->aau_context;
#endif /* CONFIG_USE_AAU*/

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	mlt_num = pt_regs->mlt_state.num;
#endif

	trap = pt_regs->trap;

#ifdef CONFIG_GREGS_CONTEXT
	E2K_MOVE_TAGGED_QWORD(&ti->gbase[0], &sw_regs->gbase[16]);
	E2K_MOVE_TAGGED_QWORD(&ti->gbase[2], &sw_regs->gbase[18]);
	sw_regs->gext[16] = ti->gext[0];
	sw_regs->gext[17] = ti->gext[1];
	sw_regs->gext[18] = ti->gext[2];
	sw_regs->gext[19] = ti->gext[3];
	GET_GREGS_FROM_THREAD(user_regs->g,
				user_regs->gtag,
				user_regs->gext,
				(void *)(sw_regs->gbase),
				(void *)(sw_regs->gext),
				(void *)(sw_regs->tag));
        user_regs->bgr = AW(sw_regs->bgr);
#endif /* CONFIG_GREGS_CONTEXT */

	user_regs->upsr = AW(ti->upsr);

	/* user_regs->oscud_lo = ; */
	/* user_regs->oscud_hi = ; */
	/* user_regs->osgd_lo = ; */
	/* user_regs->osgd_hi = ; */
	/* user_regs->osem = ; */
	/* user_regs->osr0 = ; */

        user_regs->pfpfr = AW(sw_regs->pfpfr);
        user_regs->fpcr = AW(sw_regs->fpcr);
        user_regs->fpsr = AW(sw_regs->fpsr);

	/* user_regs->usbr = ; */
	user_regs->usd_lo = AW(pt_regs->stacks.usd_lo);
	user_regs->usd_hi = AW(pt_regs->stacks.usd_hi);

	user_regs->psp_lo = AW(pt_regs->stacks.psp_lo);
	user_regs->psp_hi = AW(pt_regs->stacks.psp_hi);
	user_regs->pshtp = AW(pt_regs->pshtp);

	user_regs->cr0_lo = AW(pt_regs->crs.cr0_lo);
	user_regs->cr0_hi = AW(pt_regs->crs.cr0_hi);
	user_regs->cr1_lo = AW(pt_regs->crs.cr1_lo);
	user_regs->cr1_hi = AW(pt_regs->crs.cr1_hi);

	user_regs->pcsp_lo = AW(pt_regs->stacks.pcsp_lo);
	user_regs->pcsp_hi = AW(pt_regs->stacks.pcsp_hi);

	user_regs->cud_lo = ti->cud_lo;
	user_regs->cud_hi = ti->cud_hi;
	user_regs->gd_lo = ti->gd_lo;
	user_regs->gd_hi = ti->gd_hi;

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
	if (aau_regs) {
		for (i = 0; i < 32; i++) {
			user_regs->aad[2*i] = AW(aau_regs->aads[i]).lo;
			user_regs->aad[2*i+1] = AW(aau_regs->aads[i]).hi;
		}

		for (i = 0; i < 16; i++)
			user_regs->aaind[i] = aau_regs->aainds[i];

		for (i = 0; i < 8; i++)
			user_regs->aaincr[i] = aau_regs->aaincrs[i];

		for (i = 0; i < 64; i++)
			user_regs->aaldi[i] =
					(unsigned long long) aau_regs->aaldi[i];

		user_regs->aaldv = AW(aau_regs->aaldv);

		for (i = 0; i < 64; i++)
			user_regs->aalda[i] = AW(aau_regs->aalda[i]);

		user_regs->aaldm = AW(aau_regs->aaldm);

		user_regs->aasr = AW(aau_regs->aasr);
		user_regs->aafstr = (unsigned long long) aau_regs->aafstr;

		for (i = 0; i < 16; i++)
			user_regs->aasti[i] = aau_regs->aastis[i];
	}
#endif /* CONFIG_USE_AAU */

	user_regs->clkr = 0;

	user_regs->dibcr = AW(sw_regs->dibcr);
	user_regs->ddbcr = AW(sw_regs->ddbcr);
	user_regs->dibsr = AW(sw_regs->dibsr);
	user_regs->dibar[0] = sw_regs->dibar0;
	user_regs->dibar[1] = sw_regs->dibar1;
	user_regs->dibar[2] = sw_regs->dibar2;
	user_regs->dibar[3] = sw_regs->dibar3;
	user_regs->ddbar[0] = sw_regs->ddbar0;
	user_regs->ddbar[1] = sw_regs->ddbar1;
	user_regs->ddbar[2] = sw_regs->ddbar2;
	user_regs->ddbar[3] = sw_regs->ddbar3;
	user_regs->dimcr = AW(sw_regs->dimcr);
	user_regs->ddmcr = AW(sw_regs->ddmcr);
	user_regs->dimar[0] = sw_regs->dimar0;
	user_regs->dimar[1] = sw_regs->dimar1;
	user_regs->ddmar[0] = sw_regs->ddmar0;
	user_regs->ddmar[1] = sw_regs->ddmar1;
	user_regs->ddbsr = AW(sw_regs->ddbsr);
	/* user_regs->dtcr = ; */
	/* user_regs->dtarf = ; */
	/* user_regs->dtart = ; */

	user_regs->wd = AW(pt_regs->wd);

	user_regs->br = AS(pt_regs->crs.cr1_hi).br;

	user_regs->ctpr1 = AW(pt_regs->ctpr1);
	user_regs->ctpr2 = AW(pt_regs->ctpr2);
	user_regs->ctpr3 = AW(pt_regs->ctpr3);

        /* user_regs->eir = ; */

        user_regs->cutd = AW(sw_regs->cutd);
	if (child->thread.flags & E2K_FLAG_32BIT)
		user_regs->cuir = USER_CODES_32_INDEX;
	else
		user_regs->cuir = USER_CODES_START_INDEX;
#ifdef CONFIG_PROTECTED_MODE
	if (child->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		int cui = USER_CODES_PROT_INDEX;
		unsigned long ip = current_thread_info()->execve.entry;
		struct mm_struct *mm;
		struct vm_area_struct *vma;

		DebugCUI("computing CUIR for IP 0x%lx\n", ip);
		mm = get_task_mm(child);
		if (mm == NULL)
			panic("pt_regs_to_user_regs() child process has not mm structure\n");

		down_read(&mm->mmap_sem);
		vma = find_vma(mm, ip);
		if (vma == NULL) {
			DebugCUI("invalid IP 0x%lx of child process CUI set to initial state %d\n",
					ip, cui);
		} else {
			cui = _PAGE_INDEX_FROM_CUNIT(
					pgprot_val(vma->vm_page_prot));
			DebugCUI("CUI is %d\n", cui);
		}
		up_read(&mm->mmap_sem);
		mmput(mm);
		user_regs->cuir = cui;
	}
#endif /* CONFIG_PROTECTED_MODE */

	user_regs->lsr = pt_regs->lsr;
	user_regs->ilcr = pt_regs->ilcr;

        /* user_regs->tir_lo = ; */
        /* user_regs->tir_hi = ; */

        /* user_regs->rpr = ; */
 	user_regs->rpr_lo = sw_regs->rpr_lo;
	user_regs->rpr_hi = sw_regs->rpr_hi;

	/* additional sanity check :have user && OC  the same structures? */
	if (size != sizeof(struct user_regs_struct)) {
		return -1;
	}

        /* MLT */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (mlt_num)
		memcpy(user_regs->mlt, pt_regs->mlt_state.mlt,
			sizeof(e2k_mlt_entry_t) * mlt_num);
#endif

	if (trap) {
		/* TC */
		for (i = 0; i < MAX_TC_SIZE; i++) {
			user_regs->trap_cell_addr[i] = trap->tcellar[i].address;
			user_regs->trap_cell_val[i] = trap->tcellar[i].data;
			user_regs->trap_cell_info[i] =
					trap->tcellar[i].condition.word;
			user_regs->trap_cell_tag[i] =
					E2K_LOAD_TAGD(&trap->tcellar[i].data);
		}

		/* TIR */
		for (i = 0; i < TIR_NUM; i++) {
			user_regs->tir_hi[i] = AW(trap->TIRs[i].hi);
			user_regs->tir_lo[i] = AW(trap->TIRs[i].lo);
		}

		user_regs->sys_num  = -1UL;
	} else {
		user_regs->arg1     = pt_regs->arg1;
		user_regs->arg2     = pt_regs->arg2;
		user_regs->arg3     = pt_regs->arg3;
		user_regs->arg4     = pt_regs->arg4;
		user_regs->arg5     = pt_regs->arg5;
		user_regs->arg6     = pt_regs->arg6;
		user_regs->sys_rval = pt_regs->sys_rval;
		user_regs->sys_num  = pt_regs->sys_num;
	}

	/*   DAM  */
	memcpy(user_regs->dam, ti->dam, sizeof(ti->dam));

	user_regs->sizeof_struct = sizeof(struct user_regs_struct);

	return 0;
}

int user_regs_to_pt_regs (struct user_regs_struct *user_regs,
			   struct task_struct *child, long size)
{
	struct thread_info *ti = task_thread_info(child);
	struct pt_regs *pt_regs = ti->pt_regs;
	struct trap_pt_regs *trap = pt_regs->trap;
	struct sw_regs *sw_regs = &child->thread.sw_regs;
#ifdef CONFIG_USE_AAU
	e2k_aau_t *aau_regs = pt_regs->aau_context;
#endif /* CONFIG_USE_AAU */
	e2k_dibcr_t dibcr;
	e2k_ddbcr_t ddbcr;
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
	int i;

	DebugTRACE("user_regs_to_pt_regs current->pid=%d(%s) child->pid=%d BINCO(child) =%lx\n",
		current->pid, current->comm, child->pid, TASK_IS_BINCO(child));

	/* Sanity check */
	AW(dibcr) = user_regs->dibcr;
	AW(ddbcr) = user_regs->ddbcr;
	if (AS(dibcr).v0 && user_regs->dibar[0] >= TASK_SIZE
			|| AS(dibcr).v1 && user_regs->dibar[1] >= TASK_SIZE
			|| AS(dibcr).v2 && user_regs->dibar[2] >= TASK_SIZE
			|| AS(dibcr).v3 && user_regs->dibar[3] >= TASK_SIZE
			|| AS(ddbcr).v0 && user_regs->ddbar[0] >= TASK_SIZE
			|| AS(ddbcr).v1 && user_regs->ddbar[1] >= TASK_SIZE
			|| AS(ddbcr).v2 && user_regs->ddbar[2] >= TASK_SIZE
			|| AS(ddbcr).v3 && user_regs->ddbar[3] >= TASK_SIZE)
		return -EIO;

#ifdef	CONFIG_GREGS_CONTEXT
	SET_GREGS_TO_THREAD((void *)(sw_regs->gbase),
				(void *)(sw_regs->gext),
				(void *)(sw_regs->tag),
				user_regs->g,
				user_regs->gtag,
				user_regs->gext);
	E2K_MOVE_TAGGED_QWORD(&sw_regs->gbase[16], &ti->gbase[0]);
	E2K_MOVE_TAGGED_QWORD(&sw_regs->gbase[18], &ti->gbase[2]);
	sw_regs->tag[16] = ti->tag[0];
	sw_regs->tag[17] = ti->tag[1];
	sw_regs->tag[18] = ti->tag[2];
	sw_regs->tag[19] = ti->tag[3];

        AW(sw_regs->bgr) = user_regs->bgr;
#endif /* CONFIG_GREGS_CONTEXT */

	AW(ti->upsr) = user_regs->upsr;

	/*  = user_regs->oscud_lo; */
	/*  = user_regs->oscud_hi; */
	/*  = user_regs->osgd_lo; */
	/*  = user_regs->osgd_hi; */
	/*  = user_regs->osem; */
	/*  = user_regs->osr0; */

        AW(sw_regs->pfpfr) = user_regs->pfpfr;
        AW(sw_regs->fpcr) = user_regs->fpcr;
        AW(sw_regs->fpsr) = user_regs->fpsr;

	/*  = user_regs->usbr; */
	AW(pt_regs->stacks.usd_lo) = user_regs->usd_lo;
	AW(pt_regs->stacks.usd_hi) = user_regs->usd_hi;

	AW(cr0_hi) = user_regs->cr0_hi;
	AW(cr1_lo) = user_regs->cr1_lo;
	AW(cr1_hi) = user_regs->cr1_hi;

	AW(pt_regs->crs.cr0_lo) = user_regs->cr0_lo;
	AS(pt_regs->crs.cr0_hi).ip = AS(cr0_hi).ip;
	AS(pt_regs->crs.cr1_lo).wbs = AS(cr1_lo).wbs;
	AS(pt_regs->crs.cr1_lo).wpsz = AS(cr1_lo).wpsz;
	AS(pt_regs->crs.cr1_lo).wfx = AS(cr1_lo).wfx;
	AS(pt_regs->crs.cr1_lo).ss = AS(cr1_lo).ss;
	AS(pt_regs->crs.cr1_hi).ussz = AS(cr1_hi).ussz;
	AS(pt_regs->crs.cr1_hi).wdbl = AS(cr1_hi).wdbl;
	AS(pt_regs->crs.cr1_hi).br = AS(cr1_hi).br;

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

#ifdef CONFIG_USE_AAU
	if (aau_regs) {
		for (i = 0; i < 32; i++) {
			AW(aau_regs->aads[i]).lo = user_regs->aad[2*i];
			AW(aau_regs->aads[i]).hi = user_regs->aad[2*i+1];
		}

		for (i = 0; i < 16; i++)
			aau_regs->aainds[i] = user_regs->aaind[i];

		for (i = 0; i < 8; i++)
			aau_regs->aaincrs[i] = user_regs->aaincr[i];

		for (i = 0; i < 64; i++)
			aau_regs->aaldi[i] = (u32) user_regs->aaldi[i];

		AW(aau_regs->aaldv) = user_regs->aaldv;

		for (i = 0; i < 64; i++)
			AW(aau_regs->aalda[i]) = (u8) user_regs->aalda[i];

		AW(aau_regs->aaldm) = user_regs->aaldm;

		AW(aau_regs->aasr) = user_regs->aasr;
		aau_regs->aafstr = user_regs->aafstr;

		for (i = 0; i < 16; i++)
			aau_regs->aastis[i] = user_regs->aasti[i];
	}
#endif /* CONFIG_USE_AAU */

	AW(sw_regs->dibcr) = user_regs->dibcr;
	AW(sw_regs->ddbcr) = user_regs->ddbcr;
	AW(sw_regs->dibsr) = user_regs->dibsr;
	AW(sw_regs->ddbsr) = user_regs->ddbsr;
	sw_regs->dibar0 = user_regs->dibar[0];
	sw_regs->dibar1 = user_regs->dibar[1];
	sw_regs->dibar2 = user_regs->dibar[2];
	sw_regs->dibar3 = user_regs->dibar[3];
	sw_regs->ddbar0 = user_regs->ddbar[0];
	sw_regs->ddbar1 = user_regs->ddbar[1];
	sw_regs->ddbar2 = user_regs->ddbar[2];
	sw_regs->ddbar3 = user_regs->ddbar[3];
	AW(sw_regs->dimcr) = user_regs->dimcr;
	AW(sw_regs->ddmcr) = user_regs->ddmcr;
	sw_regs->dimar0 = user_regs->dimar[0];
	sw_regs->dimar1 = user_regs->dimar[1];
	sw_regs->ddmar0 = user_regs->ddmar[0];
	sw_regs->ddmar1 = user_regs->ddmar[1];
	/*  = user_regs->dtcr; */
	/*  = user_regs->dtarf; */
	/*  = user_regs->dtart; */

        AW(pt_regs->wd) = user_regs->wd;

	AS(pt_regs->crs.cr1_hi).br = user_regs->br;

	AW(pt_regs->ctpr1) = user_regs->ctpr1;
	AW(pt_regs->ctpr2) = user_regs->ctpr2;
	AW(pt_regs->ctpr3) = user_regs->ctpr3;

        /*  = user_regs->eir; */

        AW(sw_regs->cutd) = user_regs->cutd;
        /*  = user_regs->cuir; */

	pt_regs->lsr = user_regs->lsr;
	pt_regs->ilcr = user_regs->ilcr;

        /*  = user_regs->tir_lo; */
        /*  = user_regs->tir_hi; */

        /*  = user_regs->rpr; */
	sw_regs->rpr_lo = user_regs->rpr_lo;
	sw_regs->rpr_hi = user_regs->rpr_hi;

	if (!trap) {
		pt_regs->arg1       = user_regs->arg1;
		pt_regs->arg2       = user_regs->arg2;
		pt_regs->arg3       = user_regs->arg3;
		pt_regs->arg4       = user_regs->arg4;
		pt_regs->arg5       = user_regs->arg5;
		pt_regs->arg6       = user_regs->arg6;
		pt_regs->sys_rval   = user_regs->sys_rval;
		pt_regs->sys_num    = user_regs->sys_num;
	}

        /* copy MLT */
	/* Unsupported */

	user_regs->sizeof_struct = sizeof(struct user_regs_struct);

	return 0;
}

/*
 * Called by kernel/ptrace.c when detaching..
 *
 * Make sure the single step bit is not set.
 */
void ptrace_disable(struct task_struct *child)
{
/* It's ok but useless */
#if 0 
	struct pt_regs *pt_regs = child->thread.pt_regs;
	struct pt_regs *pt_regs = child->thread_info->pt_regs;
	e2k_DDMCR_reg_t mcr;

	mcr.entire = pt_regs->dimcr;
	mcr.fields[0].user = 0;
	mcr.fields[0].system = 0;
	mcr.fields[0].trap   = 0;

	
	pt_regs->dimcr = mcr.entire;
#endif
}

/* Read/write tag of a N-byte value at address `addr` of process `task`
 * If 'is_dword' is 0 than N=4 else N=8
 * Result writes in 'tag_p'
 * Return -1 on a error, 0 if ok */
static int
access_process_vm_tag (struct task_struct *task, long addr, int *tag_p,
                       int is_dword, int is_write)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct page *page;
	void *maddr;
        long offset, tagged_dword, targ_maddr;
	int ret, dtag;

        /* Check for aligned address */
        if ((addr & (is_dword ? 0x7 : 0x3)) != 0)
                return -1;

	mm = get_task_mm(task);
	if (!mm)
                return -1;

	down_read(&mm->mmap_sem);

	ret = get_user_pages(task, mm, addr, 1, 0, 1, &page, &vma);
	if (ret <= 0) {
		DebugPT("could not get user pages for task %s "
			"address 0x%lx\n", task->comm, addr);
		ret = -1;
		goto Error_End;
	}

	offset = addr & (PAGE_SIZE-1);

	flush_cache_page(vma, addr, 0);

	maddr = kmap(page);
        targ_maddr = (long) (maddr + offset);

        if (is_write) {
                if (is_dword) {
			E2K_LOAD_VAL_AND_TAGD(targ_maddr, tagged_dword, dtag);
                        E2K_STORE_VALUE_WITH_TAG(targ_maddr,
                                                       tagged_dword, *tag_p);
                } else {
			DebugPT("write tagged word not "
				"implemented\n");
			ret = -1;
			goto Error_End;
                }
        } else {
                if (is_dword) {
                        E2K_LOAD_VAL_AND_TAGD(targ_maddr, tagged_dword, dtag);
                        *tag_p = dtag;
                } else {
                        /* Because of descriptor tags we should use
                         * double-word operations */
                        E2K_LOAD_VAL_AND_TAGD(targ_maddr & ~0x7UL,
                                              tagged_dword, dtag);
                        if ((targ_maddr & 0x4) == 0)
                                *tag_p = dtag & 0x3;
                        else
                                *tag_p = (dtag >> 2) & 0x3;
                }
        }

	kunmap(page);
	page_cache_release(page);
	ret = 0;

Error_End:
	up_read(&mm->mmap_sem);
	mmput(mm);
        return ret;
}


long arch_ptrace(struct task_struct *child, long request,
		 unsigned long addr, unsigned long data)
{
	struct user_regs_struct local_user_regs;
	int i, tag;
	long ret;
#ifdef CONFIG_PROTECTED_MODE
        long resdata = -1L;
	int itag;
#endif /* CONFIG_PROTECTED_MODE */

	switch (request) {
	/* read the word at location addr in the USER area. */
	case PTRACE_PEEKUSR:

		/* not implemented yet. */
		ret = -EIO;

		break;

	case PTRACE_POKEUSR: /* write the word at location addr in the */
			     /* USER area */

		/* not implemented yet. */
		ret = -EIO;

		break;

        case PTRACE_PEEKTAG: {
		ret = -EIO;

                if (access_process_vm_tag (child, addr, &tag, 0, 0))
                        break;

		ret = put_user(tag,(unsigned long *) data);
#ifdef DEBUG_PTRACE
	        printk("do_ptrace: result 0x%x\n", tag);
#endif /* DEBUG_PTRACE */
		break;
	}

	case PTRACE_POKETAG:
		/* not implemented yet. */
		ret = -EIO;
#ifdef DEBUG_PTRACE
	        printk("do_ptrace: PTRACE_POKETAG not implemented yet\n");
#endif /* DEBUG_PTRACE */
		break;

#ifdef CONFIG_PROTECTED_MODE
        case PTRACE_PEEKPTR:
		ret = -EIO;

                /* Address should be aligned at least 8 bytes */
                if ((addr & 0x7) != 0)
                        break;

                if (access_process_vm_tag (child, addr, &tag, 1, 0))
                        break;
#ifdef DEBUG_PTRACE
    	        printk("do_ptrace: tag=0x%x\n", tag);
#endif /* DEBUG_PTRACE */
                if (tag == E2K_AP_LO_ETAG) {
                        /* C. 4.6.1. tag.lo = 1111 - AP or OD
                         * Address should be aligned at 16 bytes */
                        if ((addr & 15) != 0)
                                break;

                        if (access_process_vm_tag (child, addr + 8, &tag, 1, 0))
                                break;
#ifdef DEBUG_PTRACE
        	        printk("do_ptrace: tag=0x%x\n", tag);
#endif /* DEBUG_PTRACE */
                        if (tag == E2K_AP_HI_ETAG) {
                                /* AP & SAP */
                                e2k_rwap_lo_struct_t ap_lo;
                                e2k_rwap_hi_struct_t ap_hi;
                                e2k_rwsap_lo_struct_t sap_lo;
                                e2k_rwsap_hi_struct_t sap_hi;

                		if (access_process_vm(child, addr, &ap_lo, sizeof(ap_lo), 0) != sizeof(ap_lo))
                                        break;

                		if (access_process_vm(child, addr + 8, &ap_hi, sizeof(ap_hi), 0) != sizeof(ap_hi))
                                        break;

                                itag = ap_lo.E2K_RWAP_lo_itag;

                                if (itag == E2K_AP_ITAG) {
                                        /* AP */
                                        resdata = ap_lo.E2K_RWAP_lo_base + ap_hi.E2K_RWAP_hi_curptr;
                                } else if (itag == E2K_SAP_ITAG) {
                                        /* SAP */
                                        sap_lo.word = ap_lo.word;
                                        sap_hi.word = ap_hi.word;
                                        resdata = sap_lo.E2K_RWSAP_lo_base + sap_hi.E2K_RWSAP_hi_curptr;
                                } else
                                {
                                        resdata = -1;
#ifdef DEBUG_PTRACE
                        	        printk("do_ptrace: unknown itag 0x%x\n", itag);
#endif /* DEBUG_PTRACE */
                                }

                		ret = put_user(resdata,(unsigned long __user *) data);
#ifdef DEBUG_PTRACE
                	        printk("do_ptrace: result 0x%016lx\n", resdata);
#endif /* DEBUG_PTRACE */
                        } else
                        {
                                /* OD not supported. */
#ifdef DEBUG_PTRACE
                	        printk("do_ptrace: OD not supported\n");
#endif /* DEBUG_PTRACE */
                                break;
                        }
                } else if (tag == E2K_PL_ETAG)
                {
                        /* PL & TD */
                        e2k_pl_t pl;

            		if (access_process_vm(child, addr, &pl, sizeof(pl), 0) != sizeof(pl))
                                break;

			itag = pl.PL_ITAG;

                        if (itag == E2K_PL_ITAG) {
				resdata = pl.PL_TARGET;
                		ret = put_user(resdata,(unsigned long __user *) data);
#ifdef DEBUG_PTRACE
                	        printk("do_ptrace: result 0x%016lx\n", resdata);
#endif /* DEBUG_PTRACE */
                        } else
                        {
                                /* TD not supported */
#ifdef DEBUG_PTRACE
                	        printk("do_ptrace: TD not supported\n");
#endif /* DEBUG_PTRACE */
                                break;
                        }
                } else
                {
                        /* Unknown tag */
#ifdef DEBUG_PTRACE
            	        printk("do_ptrace: unknown tag 0x%x\n", tag);
#endif /* DEBUG_PTRACE */
                        break;
                }
                break;

        case PTRACE_POKEPTR: {

                /* О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫
                 *   data - О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫
                 *   addr - О©╫О©╫О©╫ О©╫ О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫
                 *
                 * О©╫О©╫ gd_base <= data < gd_base + gd_size, О©╫ О©╫О©╫О©╫О©╫О©╫
                 * О©╫О©╫О©╫О©╫О©╫ AP О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ ADDR,
                 * О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫
                 *
                 * FIXME
                 * О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ size О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫
                 * О©╫О©╫О©╫ gd_base + gd_addr (О©╫О©╫О©╫ О©╫О©╫О©╫ О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫
                 * О©╫О©╫О©╫О©╫О©╫О©╫, О©╫О©╫О©╫О©╫О©╫ curptr О©╫О©╫О©╫О©╫О©╫0.
                 * О©╫О©╫О©╫О©╫О©╫ rw - E2_RWAR_RW_ENABLE
                 *
                 * О©╫О©╫ usd_base <= data < usd_base + usd_size, О©╫ О©╫О©╫О©╫О©╫О©╫
                 * О©╫О©╫О©╫О©╫О©╫ SAP
                 *
                 * О©╫О©╫ cud_base <= data < cud_base + cud_size, О©╫ О©╫О©╫О©╫О©╫О©╫
                 * О©╫О©╫О©╫О©╫О©╫ PL */

        	struct pt_regs *pt_regs = task_thread_info(child)->pt_regs;
                struct sw_regs *sw_regs = &child->thread.sw_regs;
                e2k_cutd_t cutd = sw_regs->cutd;
                e2k_pusd_lo_t pusd_lo;
                e2k_pusd_hi_t pusd_hi;
                e2k_cute_t cute, *cute_p = &cute;
                int cuir = USER_CODES_PROT_INDEX; /* FIXME О©╫О©╫О©╫ О©╫О©╫ О©╫ О©╫О©╫О©╫О©╫О©╫О©╫*/
                long cute_entry_addr, stack_bottom;
                long pusd_base, pusd_size, gd_base, gd_size, cud_base, cud_size;

		ret = -EIO;

                /* Address should be aligned at least 8 bytes */
                if ((addr & 7) != 0)
                        break;

                /* О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫%pusd */
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

                /* О©╫%cutd О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫%cuir - О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫
                 * О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫entry */
                cute_entry_addr = cutd.E2K_RWP_base + cuir * sizeof (e2k_cute_t);

#ifdef DEBUG_PTRACE
    	        printk("do_ptrace: cutd.base = 0x%lx, cuir = 0x%x, cute_entry_addr = 0x%lx\n",
                       cutd.E2K_RWP_base, cuir, cute_entry_addr);
    	        printk("do_ptrace: pusd.base = 0x%lx, pusd.size = 0x%lx\n", pusd_base, pusd_size);
#endif /* DEBUG_PTRACE */

    		if (access_process_vm(child, cute_entry_addr, &cute, sizeof(cute), 0) != sizeof(cute))
                        break;

                gd_base = CUTE_GD_BASE(cute_p);
                gd_size = CUTE_GD_SIZE(cute_p);
                cud_base = CUTE_CUD_BASE(cute_p);
                cud_size = CUTE_CUD_SIZE(cute_p);

#ifdef DEBUG_PTRACE
    	        printk("do_ptrace: gd.base = 0x%lx, gd.size = 0x%lx\n", gd_base, gd_size);
    	        printk("do_ptrace: cud.base = 0x%lx, cud.size = 0x%lx\n", cud_base, cud_size);
#endif /* DEBUG_PTRACE */

                if (gd_base <= data && data < (gd_base + gd_size)) {

                        /* AP descriptor need */
                        e2k_rwap_struct_t ap = {{{ 0 }}};
                        int tag;

                        /* Address should be aligned at 16 bytes */
                        if ((addr & 15) != 0)
                                break;

                        ap.E2K_RWAP_base = data;
                        ap.E2K_RWAP_rw = E2_RWAR_RW_ENABLE;
                        ap.E2K_RWAP_itag = E2K_AP_ITAG;
                        ap.E2K_RWAP_curptr = 0;
                        ap.E2K_RWAP_size = gd_base + gd_size - data;

        		if (access_process_vm(child, addr, &ap, sizeof(ap), 1) != sizeof(ap))
	        		break;

                        tag = E2K_AP_LO_ETAG;
                        if (access_process_vm_tag (child, addr, &tag, 1, 1))
                                break;

                        tag = E2K_AP_HI_ETAG;
                        if (access_process_vm_tag (child, addr + 8, &tag, 1, 1))
                                break;

        		ret = 0;
#ifdef DEBUG_PTRACE
        	        printk("do_ptrace: AP writed\n");
#endif /* DEBUG_PTRACE */
                } else if (pusd_base <= data && data < stack_bottom) {

                        /* SAP descriptor need */
                        e2k_rwsap_struct_t sap = {{{ 0 }}};
                        int tag;

                        /* Address should be aligned at 16 bytes */
                        if ((addr & 15) != 0)
                                break;

                        sap.E2K_RWSAP_base = data;
                        sap.E2K_RWSAP_psl = pusd_lo.E2K_RPUSD_lo_psl - 1 /* FIXME О©╫О©╫-1 О©╫ О©╫О©╫О©╫О©╫, О©╫-1 - О©╫О©╫О©╫О©╫О©╫*/;
                        sap.E2K_RWSAP_rw = E2_RWAR_RW_ENABLE;
                        sap.E2K_RWSAP_itag = E2K_SAP_ITAG;
                        sap.E2K_RWSAP_curptr = 0;
                        sap.E2K_RWSAP_size = stack_bottom - data;
                        
        		if (access_process_vm(child, addr, &sap, sizeof(sap), 1) != sizeof(sap))
	        		break;

                        tag = E2K_SAP_LO_ETAG;
                        if (access_process_vm_tag (child, addr, &tag, 1, 1))
                                break;

                        tag = E2K_SAP_HI_ETAG;
                        if (access_process_vm_tag (child, addr + 8, &tag, 1, 1))
                                break;

        		ret = 0;
#ifdef DEBUG_PTRACE
        	        printk("do_ptrace: SAP writed\n");
#endif /* DEBUG_PTRACE */
                } else if (cud_base <= data && data < (cud_base + cud_size)) {

                        /* PL descriptor need */
                        e2k_pl_t pl;
                        int tag;
			pl = MAKE_PL(data);

        		if (access_process_vm(child, addr, &pl, sizeof(pl), 1) != sizeof(pl))
	        		break;

                        tag = E2K_PL_ETAG;
                        if (access_process_vm_tag (child, addr, &tag, 1, 1))
                                break;

        		ret = 0;
#ifdef DEBUG_PTRACE
        	        printk("do_ptrace: PL writed\n");
#endif /* DEBUG_PTRACE */
                } else
                {
#ifdef DEBUG_PTRACE
        	        printk("do_ptrace: incorrect ptr\n");
#endif /* DEBUG_PTRACE */
                }
                break;
        }
#endif /* CONFIG_PROTECTED_MODE */

	case PTRACE_EXPAND_STACK: {
                /* It needs to expand user stack */
		ret = expand_user_data_stack(task_thread_info(child)->pt_regs,
				       child, true);
		break;
	}

	case PTRACE_GETREGS: {
		long *ptr_local, *ptr_user;
		int i;
		long uninitialized_var(size);

		ptr_local = (long *) &local_user_regs;
		ptr_user = (long __user *) data;
		ret = GET_CURRENT_USER_SIZE(ptr_user, size);
		if (ret)
			break;
		ret = pt_regs_to_user_regs (child, &local_user_regs, size);
		if (ret) {
			/*
			 * Now pt_regs can be NULL (for example: under
			 * PTRACE_O_TRACEEXEC flag the user process
			 * doesn't work now). But result must be 0.
			 */
			ret = 0;
			memset(ptr_local, 0, size);
			for (i = 0; i < (size / sizeof(long)); i++) {
				ret = put_user(*ptr_local, ptr_user);
				if (ret)
					break;
				ptr_local++;
				ptr_user++;
			}
			break;
		}

		for (i = 0; i < (size / sizeof(long)); i++) {
			ret = put_user(*ptr_local, ptr_user);
			if (ret)
				break;
			ptr_local++;
			ptr_user++;
		}
		break;
	}

	case PTRACE_SETREGS: { /* Set all gp regs in the child. */
		long *ptr_local, *ptr_user;
		long uninitialized_var(size);

		ptr_local = (long*) &local_user_regs;
		ptr_user = (long*) data;
		ret = GET_CURRENT_USER_SIZE(ptr_user, size);
		if (ret)
			break;

		for (i = 0; i < (size / sizeof(long)); i++) {
			ret = get_user(*ptr_local, ptr_user);
			if (ret)
				break;
			ptr_local++;
			ptr_user++;
		}
		ret = user_regs_to_pt_regs (&local_user_regs, child, size);
		break;
	}

	case PTRACE_GETFPREGS: { /* Get the child FPU state. */

		/* not implemented yet. */
		ret = -EIO;

		break;
	}

	case PTRACE_SETFPREGS: { /* Set the child FPU state. */

		/* not implemented yet. */
		ret = -EIO;

		break;
	}

	case PTRACE_GETFPXREGS: { /* Get the child extended FPU state. */

		/* not implemented yet. */
		ret = -EIO;

		break;
	}

	case PTRACE_SETFPXREGS: { /* Set the child extended FPU state. */

		/* not implemented yet. */
		ret = -EIO;

		break;
	}

	default:
		ret = ptrace_request(child, request, addr, data);
		break;
	}
#ifdef DEBUG_PTRACE
	if (ret < 0)
		printk("do_ptrace: FAIL: ret=%d\n", ret);
#endif /* DEBUG_PTRACE */
	return ret;
}


int syscall_trace_entry(struct pt_regs *regs)
{
	int ret = 0;
	/* do the secure computing check first */
	secure_computing(regs->sys_num);

	if (test_thread_flag(TIF_NOHZ))
		user_exit();

	if (test_thread_flag(TIF_SYSCALL_TRACE)) {
		ret = tracehook_report_syscall_entry(regs);
	}
	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_enter(regs, regs->sys_num);

	audit_syscall_entry(AUDIT_ARCH_E2K, regs->sys_num, regs->arg1,
			    regs->arg2, regs->arg3, regs->arg4);

	return ret;
}

void syscall_trace_leave(struct pt_regs *regs)
{
	audit_syscall_exit(regs);

	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_exit(regs, regs->sys_num);

	if (test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall_exit(regs, 0);

	if (test_thread_flag(TIF_NOHZ))
		user_enter();
}

