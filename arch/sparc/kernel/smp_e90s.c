#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/seq_file.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <asm/cpudata.h>
#include <linux/memblock.h>
#include <asm/dma.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/io.h>
#include <asm/head.h>
#include <asm/e90s.h>
#include <asm/mpspec.h>
#include <asm/epic.h>
#include <asm/l_pmc.h>
#include <asm-l/pic.h>

#define DEBUG_SMP_BOOT_MODE	0	/* SMP Booting process */
#if DEBUG_SMP_BOOT_MODE
# define DebugSMPB(...)	printk(__VA_ARGS__)
#else
# define DebugSMPB(...)
#endif

int sparc64_multi_core __read_mostly;

cpumask_t cpu_core_map[NR_CPUS] __read_mostly = {
	[0 ... NR_CPUS - 1] = CPU_MASK_NONE
};
EXPORT_SYMBOL(cpu_core_map);

long long do_sync_cpu_clocks = 1; /* 0 - watch only; 1 - do_sync(modify); */

static void smp_store_cpu_info(int cpu)
{
	cpu_data(cpu).clock_tick = loops_per_jiffy * HZ;
	cpu_data(cpu).dcache_size = E90S_DCACHE_SIZE;
	cpu_data(cpu).dcache_line_size = E90S_DCACHE_LINE_SIZE;
	cpu_data(cpu).icache_size = E90S_ICACHE_SIZE;
	cpu_data(cpu).icache_line_size = E90S_ICACHE_LINE_SIZE;
	cpu_data(cpu).ecache_size = E90S_ECACHE_SIZE;
	cpu_data(cpu).ecache_line_size = E90S_ECACHE_LINE_SIZE;
	cpu_data(cpu).core_id = cpu;
	cpu_data(cpu).proc_id = cpu_to_node(cpu);

	printk("CPU[%d]: Caches "
		   "D[sz(%d):line_sz(%d)] "
		   "I[sz(%d):line_sz(%d)] "
		   "E[sz(%d):line_sz(%d)]\n",
		   cpu,
		   cpu_data(cpu).dcache_size, cpu_data(cpu).dcache_line_size,
		   cpu_data(cpu).icache_size, cpu_data(cpu).icache_line_size,
		   cpu_data(cpu).ecache_size, cpu_data(cpu).ecache_line_size);

}

void __init smp_fill_in_sib_core_maps(void)
{
	unsigned int i;

	for_each_present_cpu(i) {
		unsigned int j;
		ncpus_probed++;
		cpumask_clear(&cpu_core_map[i]);

		for_each_present_cpu(j) {
			if (cpu_data(i).proc_id == cpu_data(j).proc_id)
				cpumask_set_cpu(j, &cpu_core_map[i]);
		}
	}
}

void __init smp_prepare_cpus(unsigned int max_cpus)
{
	DebugSMPB("smp_prepare_cpus entered, max_cpus = %d\n", max_cpus);
}

void __init smp_prepare_boot_cpu(void)
{
	sparc64_multi_core = 1;
	smp_store_cpu_info(smp_processor_id());
}

void smp_info(struct seq_file *m)
{
	int i;

	seq_printf(m, "State:\n");
	for_each_online_cpu(i)
		seq_printf(m, "CPU%d:\t\tonline\n", i);
}

void smp_bogo(struct seq_file *m)
{
	int i;
	unsigned long ctick;
	for_each_online_cpu(i) {
		switch (e90s_get_cpu_type()) {
		case E90S_CPU_R2000:
			ctick = s2_get_freq_mult(i) *
					cpu_data(i).clock_tick;
			break;
		default:
			ctick = cpu_data(i).clock_tick;
		}
		seq_printf(m,
			   "Cpu%dClkTck\t: %016lx\n"
			   "Cpu%d MHz\t: %lu.%02lu\n",
			   i, ctick,
			   i, ctick / 1000000,
			   ctick % 1000000);
	}
}

struct thread_info *cpu_new_thread = NULL;
static volatile unsigned long callin_flag = 0;

static int smp_boot_one_cpu(unsigned int cpu, struct task_struct *idle)
{
	int timeout, ret, node;
	int reg;
	callin_flag = 0;
	cpu_new_thread = task_thread_info(idle);

	cpu = cpu_physical_id(cpu);
	node = cpu / e90s_max_nr_node_cpus();
	cpu %= e90s_max_nr_node_cpus();

	reg = cpu < E90S_R1000_MAX_NR_NODE_CPUS ?
				NBSR_NODE_CFG : NBSR_NODE_CFG2;
	cpu %= E90S_R1000_MAX_NR_NODE_CPUS;

	nbsr_writel(nbsr_readl(reg, node) | (1 << cpu), reg, node);

	for (timeout = 0; timeout < 50000; timeout++) {
		if (callin_flag)
			break;
		udelay(100);
	}
	if (callin_flag) {
		ret = 0;
	} else {
		panic("Processor %d is stuck.\n", cpu);
		ret = -ENODEV;
	}
	cpu_new_thread = NULL;
	DebugSMPB("smp_boot_one_cpu finished for cpu%d\n", cpu);

	return ret;
}

int __cpu_up(unsigned int cpu, struct task_struct *tidle)
{
	int ret = smp_boot_one_cpu(cpu, tidle);

	if (!ret) {
		while (!cpu_online(cpu))
			mb();
		if (!cpu_online(cpu)) {
			ret = -ENODEV;
		}
	}
	return ret;
}

void smp_callin(void)
{
	int cpuid = smp_processor_id();

	if (!cpu_has_epic()) {
		/* use APIC_LVT0 to store cpuid for __GET_CPUID() */
		u32 v = apic_read(APIC_LVT0);
		v &= ~APIC_VECTOR_MASK;
		v |= cpuid;
		apic_write(APIC_LVT0, v);
	}
	DebugSMPB("smp calling entered on CPU %d\n", cpuid);

	init_cur_cpu_trap(current_thread_info());

	__local_per_cpu_offset = __per_cpu_offset(cpuid);

	__flush_tlb_all();

	calibrate_delay();
	smp_store_cpu_info(cpuid);

	/* Let the user get at STICK too. */
	__asm__ __volatile__("	rd	%%stick, %%g2\n"
			 "	andn	%%g2, %0, %%g2\n"
			"	wr	%%g2, 0, %%stick"
		:	/* no outputs */
		: "r" (TICK_PRIV_BIT)
		: "g1", "g2");
	/* Let the user get at TICK too.
	 * If you will set TICK_PRIV_BIT add
	 * 'return ret & ~TICK_PRIV_BIT' in get_cycles() */
	__asm__ __volatile__("	rd	%%tick, %%g2\n"
			"	andn	%%g2, %0, %%g2\n"
			"	wrpr	%%g2, 0, %%tick"
		:	/* no outputs */
		: "r" (TICK_PRIV_BIT)
		: "g1", "g2");

	if (cpu_has_epic()) {
		setup_cepic();
	} else {
		if (apic->smp_callin_clear_local_apic)
			apic->smp_callin_clear_local_apic();
		setup_local_APIC();
		end_local_APIC_setup();
	}

	setup_secondary_pic_clock();
	flush_locked_tte();

	callin_flag = 1;
	__asm__ __volatile__("membar #Sync\n\t" "flush  %%g6" : : : "memory");

	/* Clear this or we will die instantly when we
	 * schedule back to this idler...
	 */
	current_thread_info()->new_child = 0;

	/* Attach to the address space of init_task. */
	atomic_inc(&init_mm.mm_count);
	current->active_mm = &init_mm;

	/* inform the notifiers about the new cpu */
	notify_cpu_starting(cpuid);

	__setup_vector_irq(cpuid);
	set_cpu_online(cpuid, true);

	/* idle thread is expected to have preempt disabled */
	preempt_disable();

	local_irq_enable();

	cpu_startup_entry(CPUHP_AP_ONLINE_IDLE);
}

void cpu_panic(void)
{
	printk("CPU[%d]: Returns from cpu_idle!\n", smp_processor_id());
	panic("SMP bolixed\n");
}

extern unsigned long xcall_flush_tlb_page;
extern unsigned long xcall_flush_tlb_mm;
extern unsigned long xcall_flush_tlb_kernel_range;
extern unsigned long xcall_fetch_glob_regs;
extern unsigned long xcall_receive_signal;
extern unsigned long xcall_new_mmu_context_version;
#ifdef CONFIG_KGDB
extern unsigned long xcall_kgdb_capture;
#endif

static DEFINE_RAW_SPINLOCK(tlb_call_lock);

struct tlb_call_data_struct {
	unsigned long *func;
	u64 data0;
	u64 data1;
	u64 data2;
} tlb_call_data;
atomic_t tlb_call_finished;

static int smp_tlb_call_function(struct tlb_call_data_struct *info,
				 const cpumask_t *cpu_mask)
{
	int cpus = 0, this_cpu, i, print_once = 1;
	cpumask_t mask = *cpu_mask;
	int vec = cpu_has_epic() ?
		EPIC_INVALIDATE_TLB_VECTOR : INVALIDATE_TLB_VECTOR;

	/* We don't use raw_spin_lock_irqsave here on 2.6.14 too */
	raw_spin_lock(&tlb_call_lock);
	memcpy(&tlb_call_data, info, sizeof(tlb_call_data));
	atomic_set(&tlb_call_finished, 0);
	this_cpu = smp_processor_id();
	cpumask_clear_cpu(this_cpu, &mask);
	cpus = cpumask_weight(&mask);

	if (!cpus) {
		raw_spin_unlock(&tlb_call_lock);
		return 0;
	}

	/* Send a message to all other CPUs and wait for them to respond */
	apic->send_IPI_mask((const struct cpumask *)&mask, vec);

	while (1) {
		for (i = 0; i < loops_per_jiffy * HZ; i++) {
			if (atomic_read(&tlb_call_finished) == cpus) {
				goto out;
			}
			cpu_relax();
		}
		if (print_once) {
			pr_err("smp_tlb_call_function lock up on CPU#%d\n",
				   this_cpu);
			dump_stack();
			print_once = 0;
		}
	}
out:
	raw_spin_unlock(&tlb_call_lock);
	return 0;
}

/* This tick register synchronization scheme is taken entirely from
 * the ia64 port, see arch/ia64/kernel/smpboot.c for details and credit.
 *
 * The only change I've made is to rework it so that the master
 * initiates the synchonization instead of the slave. -DaveM
 */

#define MASTER	0
#define SLAVE	(SMP_CACHE_BYTES/sizeof(unsigned long))

#define NUM_ROUNDS	64	/* magic value */
#define NUM_ITERS	5	/* likewise */

static DEFINE_RAW_SPINLOCK(itc_sync_lock);
unsigned long go_cycl_sync[SLAVE + 1];
long long delta_ticks[NR_CPUS];

#define DEBUG_TICK_SYNC	0

static unsigned long tick_add_tick(unsigned long adj)
{
	unsigned long new_tick;

	__asm__ __volatile__("rd	%%stick, %0\n\t"
				 "add	%0, %1, %0\n\t"
				 "wr	%0, 0, %%stick\n\t"
				 : "=&r"(new_tick)
				 : "r"(adj));
	return new_tick;
}

static inline long get_delta(long *rt, long *master)
{
	unsigned long best_t0 = 0, best_t1 = ~0UL, best_tm = 0;
	unsigned long tcenter, t0, t1, tm;
	int i;

	for (i = 0; i < NUM_ITERS; i++) {
		t0 = get_cycles();
		go_cycl_sync[MASTER] = 1;
		membar_safe("#StoreLoad");
		while (!(tm = go_cycl_sync[SLAVE]))
			rmb();
		go_cycl_sync[SLAVE] = 0;
		wmb();
		t1 = get_cycles();

		if (t1 - t0 < best_t1 - best_t0)
			best_t0 = t0, best_t1 = t1, best_tm = tm;
	}

	*rt = best_t1 - best_t0;
	*master = best_tm - best_t0;

	/* average best_t0 and best_t1 without overflow: */
	tcenter = (best_t0 / 2 + best_t1 / 2);
	if (best_t0 % 2 + best_t1 % 2 == 2)
		tcenter++;
	return tcenter - best_tm;
}

void smp_synchronize_tick_client(void)
{
	long i, delta, adj, adjust_latency = 0, done = 0;
	unsigned long flags, rt, master_time_stamp;
	int	do_sync = do_sync_cpu_clocks;
#if DEBUG_TICK_SYNC
	struct {
		long rt;	/* roundtrip time */
		long master;	/* master's timestamp */
		long diff;	/* difference between midpoint and master's timestamp */
		long lat;	/* estimate of itc adjustment latency */
	} t[NUM_ROUNDS];
#endif

	go_cycl_sync[MASTER] = 1;
	wmb();	/* */

	while (go_cycl_sync[MASTER])
		rmb();

	local_irq_save(flags);
	{
		for (i = 0; i < NUM_ROUNDS; i++) {
			delta = get_delta(&rt, &master_time_stamp);
			if (delta == 0) {
				done = 1;	/* let's lock on to this... */
			}

			if (!done) {
				if (i > 0) {
					adjust_latency += -delta;
					adj = -delta + adjust_latency / 4;
				} else
					adj = -delta;
				if (do_sync)
					tick_add_tick(adj);
			}
#if DEBUG_TICK_SYNC
			t[i].rt = rt;
			t[i].master = master_time_stamp;
			t[i].diff = delta;
			t[i].lat = adjust_latency / 4;
#endif
		}
		if (do_sync) {
			/* This %tick register synchronization step avoids
			 * memory reading which may have jitter.
			 * Run master which will send IPI CYCLES_SYNC
			 * when master have 0 in his %tick low order bits. */
			go_cycl_sync[MASTER] = 1;
			/* wait for IPI CYCLES_SYNC which will
			 * set slave %tick register low order bits to 0
			 * (with round up) */
			while (go_cycl_sync[MASTER])
				rmb();	/* */
		}
	}
	local_irq_restore(flags);

#if DEBUG_TICK_SYNC
	for (i = 0; i < NUM_ROUNDS; i++)
		printk("rt=%5ld master=%5ld diff=%5ld adjlat=%5ld\n",
			   t[i].rt, t[i].master, t[i].diff, t[i].lat);
#endif

	if (!do_sync) {
		delta_ticks[smp_processor_id()] = delta;
		return;
	}
	printk(KERN_INFO "CPU %d: synchronized TICK with master CPU "
		   "(last diff %ld cycles, maxerr %lu cycles)\n",
		   smp_processor_id(), delta, rt);
}

void smp_synchronize_one_tick(int cpu)
{
	unsigned long flags;
	int i;
	int vec = cpu_has_epic() ? EPIC_CYCLES_SYNC_VECTOR
					: CYCLES_SYNC_VECTOR;

	go_cycl_sync[MASTER] = 0;

	smp_call_function_many(get_cpu_mask(cpu),
		(smp_call_func_t)smp_synchronize_tick_client, NULL, 0);

	/* wait for client to be ready */
	while (!go_cycl_sync[MASTER])
		rmb();

	/* now let the client proceed into his loop */
	go_cycl_sync[MASTER] = 0;
	membar_safe("#StoreLoad");

	raw_spin_lock_irqsave(&itc_sync_lock, flags);
	{
		for (i = 0; i < NUM_ROUNDS * NUM_ITERS; i++) {
			while (!go_cycl_sync[MASTER])
				rmb();
			go_cycl_sync[MASTER] = 0;
			wmb();
			go_cycl_sync[SLAVE] = get_cycles();
			membar_safe("#StoreLoad");
		}
	}
	if (do_sync_cpu_clocks) {
		while (!go_cycl_sync[MASTER])
			rmb();	/* */
		go_cycl_sync[MASTER] = 0;
		wmb();	/* */
		/* prepare to catch 0 in low order CYCL_SYNC_GAP bits */
		while (!(get_cycles() & (CYCL_SYNC_GAP >> 1))) {
			;
		}
		/* catch 0 in low order bits or just after it was */
		while (get_cycles() & (CYCL_SYNC_GAP >> 1)) {
			;
		}
		apic->send_IPI_mask(get_cpu_mask(cpu), vec);
		while (!go_cycl_sync[MASTER])
			rmb();	/* */
		if ((go_cycl_sync[MASTER] & ~(CYCL_SYNC_GAP - 1)) !=
				(get_cycles() & ~(CYCL_SYNC_GAP - 1))) {
			pr_err("CYCLES_SYNC ERR cpu%d: slv=0x%lx mst=0x%lx\n",
				cpu, go_cycl_sync[MASTER],
				get_cycles());
		}
	}
	raw_spin_unlock_irqrestore(&itc_sync_lock, flags);
}

void __init smp_cpus_done(unsigned int max_cpus)
{
	int i;
	int this_cpu = smp_processor_id();

	for_each_online_cpu(i) {
		if (i != this_cpu)
			smp_synchronize_one_tick(i);
	}
	setup_ioapic_dest();
	smp_fill_in_sib_core_maps();
}

void smp_fetch_global_regs(void)
{
	struct tlb_call_data_struct t = { &xcall_fetch_glob_regs };
	smp_tlb_call_function(&t, cpu_online_mask);
}

extern unsigned long xcall_dump_stack_chain;
void smp_show_backtrace_all_cpus(void)
{
	struct tlb_call_data_struct t = { &xcall_dump_stack_chain };
	preempt_disable();
	smp_tlb_call_function(&t, cpu_online_mask);
	preempt_enable();
}

void smp_flush_tlb_mm(struct mm_struct *mm)
{
	u32 ctx = CTX_HWBITS(mm->context);
	int cpu = get_cpu();
	struct tlb_call_data_struct t =	{
		&xcall_flush_tlb_mm, ctx
	};

	if (atomic_read(&mm->mm_users) == 1) {
		cpumask_copy(mm_cpumask(mm), cpumask_of(cpu));
		goto local_flush_and_out;
	}

	smp_tlb_call_function(&t, mm_cpumask(mm));

local_flush_and_out:
	__flush_tlb_mm(ctx, SECONDARY_CONTEXT);

	put_cpu();
}

struct tlb_pending_info {
	unsigned long ctx;
	unsigned long nr;
	unsigned long *vaddrs;
};

static void tlb_pending_func(void *info)
{
	struct tlb_pending_info *t = info;

	__flush_tlb_pending(t->ctx, t->nr, t->vaddrs);
}

void smp_flush_tlb_pending(struct mm_struct *mm, unsigned long nr, unsigned long *vaddrs)
{
	u32 ctx = CTX_HWBITS(mm->context);
	struct tlb_pending_info info;
	int cpu = get_cpu();

	info.ctx = ctx;
	info.nr = nr;
	info.vaddrs = vaddrs;

	if (mm == current->mm && atomic_read(&mm->mm_users) == 1)
		cpumask_copy(mm_cpumask(mm), cpumask_of(cpu));
	else
		smp_call_function_many(mm_cpumask(mm), tlb_pending_func,
				       &info, 1);

	__flush_tlb_pending(ctx, nr, vaddrs);

	put_cpu();
}

void smp_flush_tlb_page(struct mm_struct *mm, unsigned long vaddr)
{
	unsigned long context = CTX_HWBITS(mm->context);
	int cpu = get_cpu();
	struct tlb_call_data_struct r =	{
		&xcall_flush_tlb_page, context, vaddr, 0,
	};

	if (mm == current->mm && atomic_read(&mm->mm_users) == 1)
		cpumask_copy(mm_cpumask(mm), cpumask_of(cpu));
	else
		smp_tlb_call_function(&r, mm_cpumask(mm));
	__flush_tlb_page(context, vaddr);

	put_cpu();
}

void smp_flush_tlb_kernel_range(unsigned long _start, unsigned long _end)
{
	unsigned long start = _start & PAGE_MASK;
	unsigned long end = PAGE_ALIGN(_end);
	struct tlb_call_data_struct r =	{
		&xcall_flush_tlb_kernel_range, 0, start, end
	};
	if (start != end) {
		smp_tlb_call_function(&r, cpu_online_mask);
		__flush_tlb_kernel_range(start, end);
	}
}

#ifdef CONFIG_KGDB
void kgdb_roundup_cpus(unsigned long flags)
{
	struct tlb_call_data_struct r = { &xcall_kgdb_capture };
	smp_tlb_call_function(&r, cpu_online_mask);
}
#endif

void smp_flush_dcache_page_impl(struct page *page, int cpu)
{
}

void flush_dcache_page_all(struct mm_struct *mm, struct page *page)
{
}

static void tsb_sync(void *info)
{
	struct trap_per_cpu *tp = &trap_block[raw_smp_processor_id()];
	struct mm_struct *mm = info;

	/* It is not valid to test "currrent->active_mm == mm" here.
	 *
	 * The value of "current" is not changed atomically with
	 * switch_mm().  But that's OK, we just need to check the
	 * current cpu's trap block PGD physical address.
	 */
	if (tp->pgd_paddr == __pa(mm->pgd))
		tsb_context_switch(mm);
}

void smp_tsb_sync(struct mm_struct *mm)
{
#ifdef CONFIG_MCST_RT
	preempt_disable();
	smp_call_function_many(mm_cpumask(mm), tsb_sync, mm, 1);
	preempt_enable();
#else
	smp_call_function_many(mm_cpumask(mm), tsb_sync, mm, 1);
#endif
}

static void stop_this_cpu(void *dummy)
{
	/* Remove this CPU */
	set_cpu_online(smp_processor_id(), false);

	local_irq_disable();
	while (1)
		;
}

void smp_send_stop(void)
{
	smp_call_function(stop_this_cpu, NULL, 0);
}

/**
 * pcpu_alloc_bootmem - NUMA friendly alloc_bootmem wrapper for percpu
 * @cpu: cpu to allocate for
 * @size: size allocation in bytes
 * @align: alignment
 *
 * Allocate @size bytes aligned at @align for cpu @cpu.  This wrapper
 * does the right thing for NUMA regardless of the current
 * configuration.
 *
 * RETURNS:
 * Pointer to the allocated area on success, NULL on failure.
 */

static void * __init pcpu_alloc_bootmem(unsigned int cpu, size_t size,
					size_t align)
{
	const unsigned long goal = __pa(MAX_DMA_ADDRESS);
#ifdef CONFIG_NEED_MULTIPLE_NODES
	int node = cpu_to_node(cpu);
	void *ptr;

	if (!node_online(node) || !NODE_DATA(node)) {
		ptr = memblock_alloc_from(size, align, goal);
		pr_info("cpu %d has no node %d or node-local memory\n",
			cpu, node);
		pr_debug("per cpu data for cpu%d %lu bytes at %016lx\n",
			 cpu, size, __pa(ptr));
	} else {
		ptr = memblock_alloc_try_nid(size, align, goal,
					     MEMBLOCK_ALLOC_ACCESSIBLE, node);
		pr_debug("per cpu data for cpu%d %lu bytes on node%d at "
			 "%016lx\n", cpu, size, node, __pa(ptr));
	}
	return ptr;
#else
	return memblock_alloc_from(size, align, goal);
#endif
}


static void __init pcpu_free_bootmem(void *ptr, size_t size)
{
	memblock_free(__pa(ptr), size);
}

static int __init pcpu_cpu_distance(unsigned int from, unsigned int to)
{
	if (cpu_to_node(from) == cpu_to_node(to))
		return LOCAL_DISTANCE;
	else
		return REMOTE_DISTANCE;
}

static void __init pcpu_populate_pte(unsigned long addr)
{
	pgd_t *pgd = pgd_offset_k(addr);
	pud_t *pud;
	pmd_t *pmd;

	if (pgd_none(*pgd)) {
		pud_t *new;

		new = memblock_alloc_from(PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
		if (!new)
			goto err_alloc;
		pgd_populate(&init_mm, pgd, new);
	}

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud)) {
		pmd_t *new;

		new = memblock_alloc_from(PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
		if (!new)
			goto err_alloc;
		pud_populate(&init_mm, pud, new);
	}

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd)) {
		pte_t *new;

		new = memblock_alloc_from(PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
		if (!new)
			goto err_alloc;
		pmd_populate_kernel(&init_mm, pmd, new);
	}

	return;

err_alloc:
	panic("%s: Failed to allocate %lu bytes align=%lx from=%lx\n",
	      __func__, PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
}

void __init setup_per_cpu_areas(void)
{
	unsigned long delta;
	unsigned int cpu;
	int rc = -EINVAL;

	if (pcpu_chosen_fc != PCPU_FC_PAGE) {
		rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
					    PERCPU_DYNAMIC_RESERVE, 4 << 20,
					    pcpu_cpu_distance,
					    pcpu_alloc_bootmem,
					    pcpu_free_bootmem);
		if (rc)
			pr_warning("PERCPU: %s allocator failed (%d), "
				   "falling back to page size\n",
				   pcpu_fc_names[pcpu_chosen_fc], rc);
	}
	if (rc < 0)
		rc = pcpu_page_first_chunk(PERCPU_MODULE_RESERVE,
					   pcpu_alloc_bootmem,
					   pcpu_free_bootmem,
					   pcpu_populate_pte);
	if (rc < 0)
		panic("cannot initialize percpu area (err=%d)", rc);

	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
	for_each_possible_cpu(cpu)
		__per_cpu_offset(cpu) = delta + pcpu_unit_offsets[cpu];

	/* Setup %g5 for the boot cpu.  */
	__local_per_cpu_offset = __per_cpu_offset(smp_processor_id());

#ifdef CONFIG_L_LOCAL_APIC
	for_each_possible_cpu(cpu) {
		per_cpu(x86_cpu_to_apicid, cpu) =
			early_per_cpu_map(x86_cpu_to_apicid, cpu);
		per_cpu(x86_bios_cpu_apicid, cpu) =
			early_per_cpu_map(x86_bios_cpu_apicid, cpu);
	}
#endif
		/* alrighty, percpu areas up and running */
}
#ifdef CONFIG_HOTPLUG_CPU
void cpu_play_dead(void)
{
	int cpu = smp_processor_id();
	unsigned long node;
	int reg;

#if 0
	idle_task_exit();
#endif
	cpu = cpu_physical_id(cpu);
	node = cpu / e90s_max_nr_node_cpus();
	cpu %= e90s_max_nr_node_cpus();
	reg = cpu < E90S_R1000_MAX_NR_NODE_CPUS ?
				NBSR_NODE_CFG : NBSR_NODE_CFG2;
	cpu %= E90S_R1000_MAX_NR_NODE_CPUS;
#if 0
	cpumask_clear_cpu(cpu, &smp_commenced_mask);
#endif
	membar_safe("#StoreLoad");
	local_irq_disable();
	e90s_flush_l2_cache();

	nbsr_writel(nbsr_readl(reg, node) | ~(1 << cpu), reg, node);
	while (1)
		barrier();
}

int __cpu_disable(void)
{
	lock_vector_lock();
	set_cpu_online(raw_smp_processor_id(), false);
	unlock_vector_lock();
#if 0
	fixup_irqs();
#endif

	return 0;
}

void __cpu_die(unsigned int cpu)
{
	/* They ack this in play_dead() by setting CPU_DEAD */
	if (cpu_wait_death(cpu, 5)) {
		if (system_state == SYSTEM_RUNNING)
			pr_info("CPU %u is now offline\n", cpu);
	} else {
		pr_err("CPU %u didn't die...\n", cpu);
	}
}
#endif
