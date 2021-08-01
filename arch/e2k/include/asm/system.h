/*
 * asm-e2k/system.h
 */
#ifndef _E2K_SYSTEM_H_
#define _E2K_SYSTEM_H_

#ifndef __ASSEMBLY__
#include <linux/kernel.h>
#endif	/* !(__ASSEMBLY__) */
#include <linux/irqflags.h>
#include <asm/atomic.h>
#include <asm/mas.h>
#include <asm/cpu_regs.h>
#include <asm/e2k_api.h>
#include <asm/ptrace.h>
#include <asm/trap_def.h>
#include <asm/unistd.h>

#define set_mb(var, value)  do { var = value;  smp_mb(); } while (0)
#define set_wmb(var, value) do { var = value; smp_wmb(); } while (0)

#define NATIVE_PSR_SET_LAST_WISH() \
do { \
	unsigned long __psr = NATIVE_NV_READ_PSR_REG_VALUE(); \
	__psr |= PSR_LW; \
	NATIVE_WRITE_PSR_REG_VALUE(__psr); \
} while (0)

#define PSR_SET_LAST_WISH() \
do { \
	unsigned long __psr = READ_PSR_REG_VALUE(); \
	__psr |= PSR_LW; \
	WRITE_PSR_REG_VALUE(__psr); \
} while (0)

#define	boot_native_set_sge()					\
({								\
	NATIVE_WRITE_PSR_REG_VALUE(				\
		NATIVE_NV_READ_PSR_REG_VALUE() | PSR_SGE);	\
})

static inline bool native_sge_is_set(void)
{
	e2k_psr_t psr = NATIVE_NV_READ_PSR_REG();

	return psr.PSR_sge;
}

#ifdef CONFIG_E2K_PROFILING

#define boot_smp_processor_id_() \
		(((e2k_addr_t)current_thread_info() >= TASK_SIZE) ? \
			smp_processor_id() \
			: \
			((long)READ_CURRENT_REG_VALUE()))
 
typedef struct {
                                                // FIRST ELEMENT
        long max_disable_interrupt;             // max #ticks of disable_interrupt
        long sum_disable_interrupt;             // all #ticks of disable_interrupt
        long number_interrupt;                  // number of interrupts
        long number_irqs;                       // number of closed irq
        long number_system_call;                // number of system_call
        
        long max_disable_interrupt_after_dump;  // max #ticks of disable_interrupt
                                                // after last read or write profile file
        long interrupts[exc_max_num];           // interrupt table 
        long interrupts_time[exc_max_num];      // interrupt time (in ticks)
        long max_interrupts_time[exc_max_num];  // max interrupt time (in ticks)
        long syscall[NR_syscalls];              // syscall   table
        long syscall_time[NR_syscalls];         // syscall   time (in ticks)
        long max_syscall_time[NR_syscalls];     // max syscall  time
        long clk;                               // time of interrupt's begining 
        // NR_VECTORS 256
        long max_do_irq_time[256];              // max DO_IRQ's  time
        long do_irq[256];                       // number of DO_IRQ
        long do_irq_time[256];                  // time of DO_IRQ
        long clk_of_do_irq;                     // time of DO_IRQ's begining 
        long last_element;
} disable_interrupt_t ;

extern unsigned long get_cmos_time(void);
extern disable_interrupt_t disable_interrupt[NR_CPUS];

#define read_ticks(n)	(n = NATIVE_READ_CLKR_REG_VALUE())
                     
#define add_info_interrupt(n, ticks)					\
({	long t; int cpu;						\
	t = NATIVE_READ_CLKR_REG_VALUE() - ticks;			\
	cpu = boot_smp_processor_id_();					\
	disable_interrupt[cpu].interrupts[n]++;				\
	disable_interrupt[cpu].interrupts_time[n] += t;			\
	if (t > disable_interrupt[cpu].max_interrupts_time[n]) {	\
		disable_interrupt[cpu].max_interrupts_time[n] = t;	\
	}								\
})      

#define add_info_syscall(n, ticks)					\
({	long t; int cpu;						\
	cpu = boot_smp_processor_id();					\
	t = NATIVE_READ_CLKR_REG_VALUE() - ticks;			\
	disable_interrupt[cpu].syscall[n]++;				\
	disable_interrupt[cpu].syscall_time[n] += t;			\
	if (t > disable_interrupt[cpu].max_syscall_time[n]) {		\
		disable_interrupt[cpu].max_syscall_time[n] = t;		\
	}								\
})

typedef struct {
        long max_time;
        long full_time;
        long begin_time;
        long number;
        long beg_ip;
        long beg_parent_ip;
        long end_ip;
        long end_parent_ip;
        long max_beg_ip;
        long max_beg_parent_ip;
        long max_end_ip;
        long max_begin_time; 
        long max_end_parent_ip;
} time_info_t;

/* 
 *  For adding new element you need do following things:
 *  -  add new "time_info_t" element after last one
 *  -  add name of your elemen in system_info_name (file e2k_sysworks.c)
 *  -  create two new define similar below:
 *     #define  info_save_mmu_reg(tick)                                \
 *              store_max_time_in_system_info(tick,max_mmu_reg)
 *     #define  info_save_mmu_reg(tick) - null for not CONFIG_E2K_PROFILING
 *  -  used your new define for merging what you want 
 */ 
typedef struct {
        time_info_t max_disabled_interrupt;           // max time of disabled inerrupts
        time_info_t max_stack_reg;                    // max time of saving of stack_registers
        time_info_t max_tir_reg;                      // max time for storing TIR
        time_info_t max_mmu_reg;                      // max time for storing mmu registers
        time_info_t max_restore_stack_reg;            // max time for restoring of stack_registers
        time_info_t max_restoring_reg;                // max time for restoring all registers
        time_info_t max_restore_mmu_reg;              // max time for restoring mmu registers
        time_info_t max_cpu_idle;                     // max time for cpu_idle
} system_info_t ;

extern char* system_info_name[];
extern system_info_t system_info[NR_CPUS];
extern int enable_collect_interrupt_ticks;
#define collect_disable_interrupt_ticks()                       \
({  int  cpu;                                                   \
    cpu = boot_smp_processor_id_();                             \
    if (system_info[cpu].max_disabled_interrupt.begin_time >0){ \
       store_max_time_in_system_info(                           \
         system_info[cpu].max_disabled_interrupt.begin_time,    \
         max_disabled_interrupt);                               \
       system_info[cpu].max_disabled_interrupt.begin_time = 0;  \
    }                                                           \
})

#define mark_disable_interrupt_ticks()                          \
      store_begin_ip_in_system_info(max_disabled_interrupt)

#define store_do_irq_ticks()						\
({	int  cpu = boot_smp_processor_id_();				\
	disable_interrupt[cpu].clk_of_do_irq = NATIVE_READ_CLKR_REG_VALUE(); \
})

#define	define_time_of_do_irq(N)					\
({	long t; int  cpu;						\
	cpu = boot_smp_processor_id_();					\
	t = NATIVE_READ_CLKR_REG_VALUE() -				\
			disable_interrupt[cpu].clk_of_do_irq;		\
	disable_interrupt[cpu].do_irq_time[N] += t;			\
	disable_interrupt[cpu].do_irq[N]++;				\
	if (disable_interrupt[cpu].max_do_irq_time[N] < t) {		\
		disable_interrupt[cpu].max_do_irq_time[N] = t;		\
	}								\
})
#define  info_save_stack_reg(tick)                              \
         store_max_time_in_system_info(tick,max_stack_reg)
#define  info_restore_stack_reg(tick)                           \
         store_max_time_in_system_info(tick,max_restore_stack_reg)

#define  info_save_mmu_reg(tick)                                \
         store_max_time_in_system_info(tick,max_mmu_reg)
    
#define  info_restore_mmu_reg(tick)                             \
         store_max_time_in_system_info(tick,max_restore_mmu_reg)
    
#define  info_save_tir_reg(tick)                                \
         store_max_time_in_system_info(tick,max_tir_reg)

#define  info_restore_all_reg(tick)                             \
         store_max_time_in_system_info(tick,max_restoring_reg); \

#define cpu_idle_time()                                         \
        store_begin_time_in_system_info(max_cpu_idle)
#define calculate_cpu_idle_time()                               \
        calculate_max_time_in_system_info(max_cpu_idle)

#define	store_begin_time_in_system_info(FIELD)				\
({	long t; int  cpu;						\
	register e2k_cr0_hi_t cr0_hi;					\
	if (enable_collect_interrupt_ticks) {				\
		cpu = boot_smp_processor_id_();				\
		t = NATIVE_READ_CLKR_REG_VALUE();			\
		AS_WORD(cr0_hi) = NATIVE_NV_READ_CR0_HI_REG_VALUE();	\
		system_info[cpu].FIELD.begin_time = tick;		\
		system_info[cpu].FIELD.beg_ip = NATIVE_READ_IP_REG_VALUE(); \
		system_info[cpu].FIELD.beg_parent_ip =			\
				(AS_STRUCT(cr0_hi)).ip<<3;		\
	}								\
})
#define  store_begin_ip_in_system_info(FIELD)				\
({									\
	int cpu;							\
	register e2k_cr0_hi_t cr0_hi;					\
	cpu = boot_smp_processor_id_();					\
	disable_interrupt[cpu].clk = NATIVE_READ_CLKR_REG_VALUE();	\
	cr0_hi = NATIVE_NV_READ_CR0_HI_REG_VALUE();			\
	system_info[cpu].FIELD.beg_ip = NATIVE_READ_IP_REG_VALUE();	\
	system_info[cpu].FIELD.beg_parent_ip =				\
				(AS_STRUCT(cr0_hi)).ip<<3;		\
})

#define  store_begin_time_ip_in_system_info(cpu, tick, FIELD)		\
({									\
	register e2k_cr0_hi_t cr0_hi;					\
	if (enable_collect_interrupt_ticks) {				\
		system_info[cpu].FIELD.begin_time = tick;		\
		cr0_hi = NATIVE_NV_READ_CR0_HI_REG_VALUE();		\
		system_info[cpu].FIELD.beg_ip = NATIVE_READ_IP_REG_VALUE(); \
		system_info[cpu].FIELD.beg_parent_ip =			\
				(AS_STRUCT(cr0_hi)).ip<<3;		\
	}								\
})

#define  store_end_ip_in_system_info(mutex, FIELD)			\
({									\
	int cpu;							\
	register e2k_cr0_hi_t cr0_hi;					\
	cpu = boot_smp_processor_id_();					\
	cr0_hi = NATIVE_NV_READ_CR0_HI_REG_VALUE();			\
	system_info[cpu].FIELD.beg_ip = mutex->ip;			\
	system_info[cpu].FIELD.beg_parent_ip = mutex->caller;		\
	system_info[cpu].FIELD.end_ip = NATIVE_READ_IP_REG_VALUE();	\
	system_info[cpu].FIELD.end_parent_ip =				\
				(AS_STRUCT(cr0_hi)).ip<<3;		\
})

#define  calculate_max_time_in_system_info(FIELD)			\
({									\
	long t; int cpu;						\
	register e2k_cr0_hi_t cr0_hi;					\
	cpu = boot_smp_processor_id_();					\
	if (enable_collect_interrupt_ticks) {				\
		t = NATIVE_READ_CLKR_REG_VALUE()-system_info[cpu].	\
							FIELD.begin_time; \
		system_info[cpu].FIELD.number++;			\
		system_info[cpu].FIELD.full_time += t;			\
		if (system_info[cpu].FIELD.max_time < t) {		\
			system_info[cpu].FIELD.max_time = t;		\
			system_info[cpu].FIELD.max_beg_ip =		\
				system_info[cpu].FIELD.beg_ip;		\
			system_info[cpu].FIELD.max_beg_parent_ip =	\
				system_info[cpu].FIELD.beg_parent_ip;	\
			system_info[cpu].FIELD.max_end_ip =		\
				NATIVE_READ_IP_REG_VALUE();		\
			cr0_hi = NATIVE_NV_READ_CR0_HI_REG_VALUE();	\
			system_info[cpu].FIELD.max_end_parent_ip =	\
				(AS_STRUCT(cr0_hi)).ip<<3;		\
			system_info[cpu].FIELD.max_begin_time =		\
				system_info[cpu].FIELD.begin_time;	\
		}							\
		system_info[cpu].FIELD.begin_time = 0;			\
	}								\
})

extern long TIME;
#define  store_max_time_in_system_info(tick, FIELD)			\
({									\
	long t; int cpu;						\
	register e2k_cr0_hi_t cr0_hi;					\
	cpu = boot_smp_processor_id_();					\
	t = NATIVE_READ_CLKR_REG_VALUE()-tick;				\
	if (enable_collect_interrupt_ticks) {				\
		system_info[cpu].FIELD.number++;			\
		system_info[cpu].FIELD.full_time += t;			\
		if (system_info[cpu].FIELD.max_time < t) {		\
			system_info[cpu].FIELD.max_time = t;		\
			system_info[cpu].FIELD.max_beg_ip =		\
				system_info[cpu].FIELD.beg_ip;		\
			system_info[cpu].FIELD.max_beg_parent_ip =	\
				system_info[cpu].FIELD.beg_parent_ip;	\
			system_info[cpu].FIELD.max_end_ip =		\
				NATIVE_READ_IP_REG_VALUE();		\
			cr0_hi = NATIVE_NV_READ_CR0_HI_REG_VALUE();	\
			system_info[cpu].FIELD.max_end_parent_ip =	\
				(AS_STRUCT(cr0_hi)).ip<<3;		\
			system_info[cpu].FIELD.max_begin_time =		\
				system_info[cpu].FIELD.begin_time;	\
		}							\
		system_info[cpu].FIELD.begin_time = 0;			\
	}								\
})

#define	UPSR_RESTORE(__src_upsr)					\
({									\
	unsigned long upsr1 = READ_UPSR_REG_VALUE();			\
	int _cond_ = (upsr1 & UPSR_IE) != ((__src_upsr) & UPSR_IE);	\
	if (enable_collect_interrupt_ticks && _cond_) {			\
		if (__src_upsr & UPSR_IE) {				\
			collect_disable_interrupt_ticks();		\
		} else {						\
			mark_disable_interrupt_ticks();			\
		}							\
	}								\
	WRITE_UPSR_IRQ_BARRIER(__src_upsr);				\
})

#define condition_mark_disable_interrupt_ticks(_cond_)          \
({                                                              \
     if (enable_collect_interrupt_ticks) {              	\
         mark_disable_interrupt_ticks();                        \
     }                                                          \
})

#define condition_collect_disable_interrupt_ticks(_cond_)       \
({                                                              \
     if (enable_collect_interrupt_ticks && _cond_) {            \
         collect_disable_interrupt_ticks();                     \
     }                                                          \
})
 
# else /* !CONFIG_E2K_PROFILING    */

#define  store_max_time_in_system_info(tick,FIELD) 
#define  calculate_max_time_in_system_info(FIELD) 
#define  store_begin_time_in_system_info(FIELD) 
#define  store_begin_ip_in_system_info(FIELD) 
#define  info_save_tir_reg(tick)
#define  info_restore_all_reg(tick)
#define  info_save_stack_reg(tick)
#define  info_restore_stack_reg(tick)
#define  info_save_mmu_reg(tick)
#define  info_restore_mmu_reg(tick)
#define  cpu_idle_time()
#define  calculate_cpu_idle_time()
#define  store_do_irq_ticks()
#define  define_time_of_do_irq(N)
#define condition_collect_disable_interrupt_ticks(_cond_)
#define condition_mark_disable_interrupt_ticks(_cond_)
#define collect_disable_interrupt_ticks()
#define mark_disable_interrupt_ticks()
#define add_info_syscall(n, ticks)
#define add_info_interrupt(n, ticks)
#define read_ticks(n) 
#define	UPSR_RESTORE(__src_upsr)	(WRITE_UPSR_IRQ_BARRIER(__src_upsr))
#endif /* CONFIG_E2K_PROFILING    */

#define E2K_KERNEL_PSR_ENABLED ((e2k_psr_t) { {	\
	pm	: 1,				\
	ie	: 1,				\
	sge	: 1,				\
	lw	: 0,				\
	uie	: 1,				\
	nmie	: 1,				\
	unmie	: 1,				\
} })

#define E2K_KERNEL_PSR_DISABLED ((e2k_psr_t) { { \
	pm	: 1,				\
	ie	: 0,				\
	sge	: 1,				\
	lw	: 0,				\
	uie	: 0,				\
	nmie	: 0,				\
	unmie	: 0,				\
} })

#define E2K_KERNEL_PSR_DIS_LWISH_EN ((e2k_psr_t) { { \
	pm	: 1,				\
	ie	: 0,				\
	sge	: 1,				\
	lw	: 1,				\
	uie	: 0,				\
	nmie	: 0,				\
	unmie	: 0,				\
} })

#define E2K_KERNEL_PSR_LWISH_DIS ((e2k_psr_t) { { \
	pm	: 1,				\
	ie	: 0,				\
	sge	: 1,				\
	lw	: 0,				\
	uie	: 0,				\
	nmie	: 0,				\
	unmie	: 0,				\
} })

#ifndef	CONFIG_ACCESS_CONTROL
#define E2K_KERNEL_UPSR_ENABLED_ASM		0xa1
#define E2K_KERNEL_UPSR_DISABLED_ALL_ASM	0x01
#define E2K_KERNEL_UPSR_DISABLED ((e2k_upsr_t) { {	\
		fe	: 1, 				\
		se	: 0,				\
		ac	: 0,				\
		a20	: 0,				\
		ie	: 0,				\
		nmie	: 1				\
} })
#define E2K_KERNEL_UPSR_ENABLED ((e2k_upsr_t) { {	\
		fe	: 1, 				\
		se	: 0,				\
		ac	: 0,				\
		a20	: 0,				\
		ie	: 1,				\
		nmie	: 1				\
} })
#define E2K_KERNEL_UPSR_DISABLED_ALL ((e2k_upsr_t) { {	\
		fe	: 1,				\
		se	: 0,				\
		ac	: 0,				\
		a20	: 0,				\
		ie	: 0,				\
		nmie	: 0				\
} })
#else
#define E2K_KERNEL_UPSR_ENABLED_ASM		0xa5
#define E2K_KERNEL_UPSR_DISABLED_ALL_ASM	0x05
#define E2K_KERNEL_UPSR_DISABLED ((e2k_upsr_t) { {	\
		fe	: 1, 				\
		se	: 0,				\
		ac	: 1,				\
		a20	: 0,				\
		ie	: 0,				\
		nmie	: 1				\
} })
#define E2K_KERNEL_UPSR_ENABLED ((e2k_upsr_t) { {	\
		fe	: 1, 				\
		se	: 0,				\
		ac	: 1,				\
		a20	: 0,				\
		ie	: 1,				\
		nmie	: 1				\
} })
#define E2K_KERNEL_UPSR_DISABLED_ALL ((e2k_upsr_t) { {	\
		fe	: 1,				\
		se	: 0,				\
		ac	: 1,				\
		a20	: 0,				\
		ie	: 0,				\
		nmie	: 0				\
} })
#endif	/* ! (CONFIG_ACCESS_CONTROL) */

#define E2K_KERNEL_INITIAL_UPSR		E2K_KERNEL_UPSR_DISABLED
#define	E2K_KERNEL_INITIAL_UPSR_WITH_DISABLED_NMI	\
		E2K_KERNEL_UPSR_DISABLED_ALL

#define	E2K_USER_INITIAL_UPSR	((e2k_upsr_t) { {	\
		fe	: 1,				\
		se	: 0,				\
		ac	: 0,				\
		di	: 0,				\
		wp	: 0,				\
		ie	: 0,				\
		a20	: 0,				\
		nmie	: 0				\
} })

#define	E2K_USER_INITIAL_PSR	((e2k_psr_t) { {	\
		pm	: 0,				\
		ie	: 1,				\
		sge	: 1,				\
		lw	: 0,				\
		uie	: 0,				\
		nmie	: 1,				\
		unmie	: 0				\
} })

#define	PREFIX_INIT_KERNEL_UPSR_REG(PV_TYPE, irq_en, nmirq_dis) \
do { \
	e2k_upsr_t upsr = E2K_KERNEL_UPSR_DISABLED; \
	if (irq_en) \
		AS(upsr).ie = 1; \
	if (nmirq_dis) \
		AS(upsr).nmie = 0; \
	PV_TYPE##_WRITE_UPSR_REG(upsr); \
} while (0)
#define	BOOT_PREFIX_INIT_KERNEL_UPSR_REG(PV_TYPE, irq_en, nmirq_dis) \
do { \
	e2k_upsr_t upsr = E2K_KERNEL_UPSR_DISABLED; \
	if (irq_en) \
		AS(upsr).ie = 1; \
	if (nmirq_dis) \
		AS(upsr).nmie = 0; \
	BOOT_##PV_TYPE##_WRITE_UPSR_REG(upsr); \
} while (0)

#define	NATIVE_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis) \
		PREFIX_INIT_KERNEL_UPSR_REG(NATIVE, irq_en, nmirq_dis)

#define	BOOT_NATIVE_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis) \
		BOOT_PREFIX_INIT_KERNEL_UPSR_REG(NATIVE, irq_en, nmirq_dis)

#define	NATIVE_INIT_USER_UPSR_REG()	\
		NATIVE_WRITE_UPSR_REG(E2K_USER_INITIAL_UPSR)
#define	INIT_USER_UPSR_REG()	WRITE_UPSR_REG(E2K_USER_INITIAL_UPSR)

#define	PREFIX_SET_KERNEL_UPSR(PV_TYPE)	\
({							\
	PV_TYPE##_INIT_KERNEL_UPSR_REG(false, false);	\
	PV_TYPE##_SWITCH_IRQ_TO_UPSR();			\
})

#define PREFIX_SET_KERNEL_UPSR_WITH_DISABLED_NMI(PV_TYPE) \
({							\
	PV_TYPE##_INIT_KERNEL_UPSR_REG(false, true);	\
	PV_TYPE##_SWITCH_IRQ_TO_UPSR();			\
})

#define	BOOT_PREFIX_SET_KERNEL_UPSR(PV_TYPE)			\
({								\
	BOOT_##PV_TYPE##_INIT_KERNEL_UPSR_REG(false, false);	\
	BOOT_##PV_TYPE##_SWITCH_IRQ_TO_UPSR();			\
})

#define	NATIVE_SET_KERNEL_UPSR_WITH_DISABLED_NMI() \
		PREFIX_SET_KERNEL_UPSR_WITH_DISABLED_NMI(NATIVE)
#define	BOOT_NATIVE_SET_KERNEL_UPSR()		\
		BOOT_PREFIX_SET_KERNEL_UPSR(NATIVE)

/*
 * UPSR should be saved and set to kernel initial state (where interrupts
 * are disabled) independently of trap or interrupt occurred on user
 * or kernel process.
 * In user process case it is as above.
 * In kernel process case:
 * 	Kernel process can be interrupted (so UPSR enable interrupts)
 * 	Hardware trap or system call operation disables interrupts mask
 * in PSR and PSR becomes main register to control interrupts.
 *	Trap handler should switch interrupts control from PSR to UPSR
 * previously it should set UPSR to initial state for kernel with disabled
 * interrupts (so UPSR disable interrupts)
 * If trap handler returns to trap point without UPSR restore, then
 * interrupted kernel process will have UPSR with disabled interrupts.
 * So UPSR should be saved and restored in any case
 *
 * Trap can occur on light hypercall, where switch of user data stack
 * to kernel stack is not executed, so these traps handle as user traps
 * (SBR < TASK_SIZE) Light hypercall already switch control from PSR to UPSR
 * so it need save current UPSR state (enable/disable interrupts)
 * to restore this state before return to trapped light hypercall.
 * Interrupt control by UPSR will be restored from PSR saved into CR1_LO
 */

#define	PREFIX_DO_SWITCH_TO_KERNEL_UPSR(PV_TYPE, pv_type,		\
					irq_en, nmirq_dis)		\
({									\
	PV_TYPE##_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis);		\
	PV_TYPE##_SWITCH_IRQ_TO_UPSR();					\
	if (!irq_en)							\
		trace_hardirqs_off();					\
})
#define	PREFIX_SWITCH_TO_KERNEL_UPSR(PV_TYPE, pv_type,			\
					upsr_reg, irq_en, nmirq_dis)	\
({									\
	PV_TYPE##_DO_SAVE_UPSR_REG((upsr_reg));				\
	PREFIX_DO_SWITCH_TO_KERNEL_UPSR(PV_TYPE, pv_type,		\
					irq_en, nmirq_dis);		\
})
#define	BOOT_PREFIX_SWITCH_TO_KERNEL_UPSR(PV_TYPE, pv_type)		\
({									\
	unsigned long cur_upsr;						\
	BOOT_##PV_TYPE##_DO_SAVE_UPSR_REG((cur_upsr));			\
	BOOT_##PV_TYPE##_INIT_KERNEL_UPSR_REG(false, false);		\
	BOOT_##PV_TYPE##_SWITCH_IRQ_TO_UPSR(false);			\
})
/* Native version of macroses (all read/write from/to real registers) */
#define	NATIVE_DO_SWITCH_TO_KERNEL_UPSR(irq_en, nmirq_dis)		\
		PREFIX_DO_SWITCH_TO_KERNEL_UPSR(NATIVE, native,		\
						irq_en, nmirq_dis)
#define	NATIVE_SWITCH_TO_KERNEL_UPSR(upsr_reg, irq_en, nmirq_dis)	\
		PREFIX_SWITCH_TO_KERNEL_UPSR(NATIVE, native,		\
			upsr_reg, irq_en, nmirq_dis)

#define	NATIVE_RETURN_TO_KERNEL_UPSR(upsr_reg) \
do { \
	NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED)); \
	NATIVE_DO_RESTORE_UPSR_REG(upsr_reg); \
} while (false)

#define	PREFIX_RETURN_TO_USER_UPSR(PV_TYPE, pv_type, upsr_reg, under_upsr) \
do {									\
	PV_TYPE##_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED));	\
	PV_TYPE##_DO_RESTORE_UPSR_REG(upsr_reg);			\
} while (false)
#define	NATIVE_RETURN_TO_USER_UPSR(upsr_reg) \
		PREFIX_RETURN_TO_USER_UPSR(NATIVE, native, upsr_reg, true)
#define	NATIVE_RETURN_PSR_IRQ_TO_USER_UPSR(upsr_reg, lwish_en) \
do { \
	if (lwish_en) { \
		NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DIS_LWISH_EN)); \
	} else { \
		NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_LWISH_DIS)); \
	} \
	NATIVE_DO_RESTORE_UPSR_REG(upsr_reg); \
} while (false)

#ifdef	CONFIG_ACCESS_CONTROL
#define	ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save)	\
({ \
	e2k_upsr_t upsr; \
	upsr_to_save = read_UPSR_reg(); \
	upsr = upsr_to_save; \
	AS_STRUCT(upsr).ac = 0; \
	write_UPSR_reg(upsr); \
})

#define	ACCESS_CONTROL_RESTORE(upsr_to_restore)	\
({ \
	write_UPSR_reg(upsr_to_restore); \
})
#else /* !CONFIG_ACCESS_CONTROL */
#define	ACCESS_CONTROL_DISABLE_AND_SAVE(upsr_to_save)	do { } while (0)
#define	ACCESS_CONTROL_RESTORE(upsr_to_restore)		do { } while (0)
#endif /* CONFIG_ACCESS_CONTROL */

extern void * __e2k_read_kernel_return_address(int n);
/* If n == 0 we can read return address directly from cr0.hi */
#define __e2k_kernel_return_address(n)					\
		({ (n == 0) ?						\
			((void *) (NATIVE_NV_READ_CR0_HI_REG_VALUE() & ~7UL)) \
			:						\
			__e2k_read_kernel_return_address(n); })

#ifndef CONFIG_CPU_HW_CLEAR_RF
typedef void (*clear_rf_t)(void);
extern const clear_rf_t clear_rf_fn[];

static __always_inline void clear_rf_kernel_except_current(u64 num_q)
{
	clear_rf_fn[num_q]();
}
#endif

#define	SWITCH_TO_KERNEL_UPSR(upsr_reg, irq_en, nmirq_dis) \
		NATIVE_SWITCH_TO_KERNEL_UPSR(upsr_reg, irq_en, nmirq_dis)
#define	RETURN_TO_USER_UPSR(upsr_reg) \
		NATIVE_RETURN_TO_USER_UPSR(upsr_reg)

#if	defined(CONFIG_PARAVIRT_GUEST)
#include <asm/paravirt/system.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
#include <asm/kvm/guest/system.h>
#else	/* native kernel */
#define	INIT_KERNEL_UPSR_REG	NATIVE_INIT_KERNEL_UPSR_REG
#define	BOOT_SET_KERNEL_UPSR()	BOOT_NATIVE_SET_KERNEL_UPSR()
#define	RETURN_TO_KERNEL_UPSR(upsr_reg) \
		NATIVE_RETURN_TO_KERNEL_UPSR(upsr_reg)
#define	SET_KERNEL_UPSR_WITH_DISABLED_NMI() \
		NATIVE_SET_KERNEL_UPSR_WITH_DISABLED_NMI()

static inline void *nested_kernel_return_address(int n)
{
	return __e2k_read_kernel_return_address(n);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* _E2K_SYSTEM_H_ */
