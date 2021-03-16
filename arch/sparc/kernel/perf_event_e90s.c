/* Performance event support for sparc64.
 *
 */
/*#define DEBUG*/
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/perf_event.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/ftrace.h>
#include <linux/kdebug.h>

#include <asm/stacktrace.h>
#include <asm/cpudata.h>
#include <asm/pcr.h>
#include <asm/cacheflush.h>

#include "kernel.h"
#include "kstack.h"

#define E90S_MAX_HWEVENTS	E90S_PIC_NR
#define E90S_MAX_HWEVENTS_MASK	((1 << E90S_MAX_HWEVENTS) - 1)

/* An event map describes the characteristics of a performance
 * counter event.  In particular it gives the encoding as well as
 * a mask telling which counters the event can be measured on.
 *
 */
struct perf_event_map {
	u16	encoding;
	u8	pic_mask;

#define PIC_E90S_0	0x01
#define PIC_E90S_1	0x02
#define PIC_E90S_2	0x04
#define PIC_E90S_3	0x08
};

/* Encode a perf_event_map entry into a long.  */
static inline unsigned long perf_event_encode(const struct perf_event_map *pmap)
{
	return ((unsigned long) pmap->encoding << 16) | pmap->pic_mask;
}

static inline u8 perf_event_get_msk(unsigned long val)
{
	return val & 0xff;
}

static inline u64 perf_event_get_enc(unsigned long val)
{
	return val >> 16;
}

static inline u64 nop_for_index(int idx)
{
	return E90S_NOP_EVENT |  (idx << E90S_PCR_SC_SHIFT);
}

#define C(x) PERF_COUNT_HW_CACHE_##x

#define CACHE_OP_UNSUPPORTED	0xfffe
#define CACHE_OP_NONSENSE	0xffff

typedef struct perf_event_map cache_map_t
				[PERF_COUNT_HW_CACHE_MAX]
				[PERF_COUNT_HW_CACHE_OP_MAX]
				[PERF_COUNT_HW_CACHE_RESULT_MAX];

static const struct perf_event_map e90s_perfmon_event_map[] = {
	[PERF_COUNT_HW_CPU_CYCLES] = { 0x0, PIC_E90S_0 | PIC_E90S_1
		 			| PIC_E90S_2 | PIC_E90S_3 },
};

static const struct perf_event_map *e90s_event_map(int event_id)
{
	return &e90s_perfmon_event_map[event_id];
}

static const cache_map_t e90s_cache_map = {
[C(L1D)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x2d, PIC_E90S_0 },
		[C(RESULT_MISS)] = { 0x2d, PIC_E90S_1  },
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = { 0x2d, PIC_E90S_2 },
		[C(RESULT_MISS)] = { 0x2d, PIC_E90S_3 },
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(L1I)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x2c, PIC_E90S_1 },
		[C(RESULT_MISS)] = { 0x2c, PIC_E90S_2  },
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(LL)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x28, PIC_E90S_2 },
		[C(RESULT_MISS)] = { 0x2d, PIC_E90S_3  },
	},
	[C(OP_WRITE)] = {
		[C(RESULT_ACCESS)] = { 0x2a, PIC_E90S_0 },
		[C(RESULT_MISS)] = { 0x2a, PIC_E90S_1 },
	},
	[C(OP_PREFETCH)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(DTLB)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x25, PIC_E90S_3 },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS)   ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS)   ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(ITLB)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)] = { 0x25, PIC_E90S_2 },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS)   ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS)   ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(BPU)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { 0x20, PIC_E90S_2 },
		[C(RESULT_MISS)] = { 0x20, PIC_E90S_3 },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS)   ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS)   ] = { CACHE_OP_UNSUPPORTED },
	},
},
[C(NODE)] = {
	[C(OP_READ)] = {
		[C(RESULT_ACCESS)] = { CACHE_OP_UNSUPPORTED },
		[C(RESULT_MISS)  ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_WRITE) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS)   ] = { CACHE_OP_UNSUPPORTED },
	},
	[ C(OP_PREFETCH) ] = {
		[ C(RESULT_ACCESS) ] = { CACHE_OP_UNSUPPORTED },
		[ C(RESULT_MISS)   ] = { CACHE_OP_UNSUPPORTED },
	},
},
};

/* For tracking PMCs and the hw events they monitor on each CPU. */
struct cpu_hw_events {

	/* Events currently scheduled. */
	struct perf_event	*event[E90S_MAX_HWEVENTS];
	u64		pcr[E90S_MAX_HWEVENTS];
	unsigned long		config_base;
	unsigned long		used_mask;
};
DEFINE_PER_CPU(struct cpu_hw_events, cpu_hw_events);

static inline u64 __pcr_read(void)
{
	u64 val;
	rd_pcr(val);
	return val;
}

static inline void __pcr_write(u64 val)
{
	wr_pcr(val);
}

static inline u64 __pic_read(unsigned long reg_num)
{
	unsigned long pcr, old_pcr, pic;
	rd_pcr(old_pcr);
	pcr = old_pcr;
	pcr &= ~(E90S_PCR_USR | E90S_PCR_SYS |
			(E90S_PCR_SC_MASK << E90S_PCR_SC_SHIFT));

	pcr |= E90S_PCR_ULRO | E90S_PCR_OVRO;

	wr_pcr(pcr | (reg_num << E90S_PCR_SC_SHIFT));
	rd_pic(pic);
	wr_pcr(old_pcr);
	return pic;
}

static inline void __pic_write(unsigned long reg_num, u64 val)
{
	unsigned long pcr, old_pcr;
	rd_pcr(old_pcr);
	pcr = old_pcr;
	pcr &= ~(E90S_PCR_USR | E90S_PCR_SYS |
			(E90S_PCR_SC_MASK << E90S_PCR_SC_SHIFT));

	pcr |= E90S_PCR_ULRO | E90S_PCR_OVRO;

	wr_pcr(pcr | (reg_num << E90S_PCR_SC_SHIFT));
	wr_pic(val);
	wr_pcr(old_pcr);
}

#define pcr_read()						\
({								\
	u64 __val = __pcr_read();				\
	pr_debug("pcrR:%llx\t%s:%d\n",  __val,			\
				__func__, __LINE__);		\
	__val;							\
})

#define pcr_write(__val)	do {				\
	pr_debug("pcrW:%llx\t%s:%d\n", __val,			\
				__func__, __LINE__);		\
	__pcr_write(__val);					\
} while (0)


#define pic_read(__reg_num)					\
({								\
	u64 __val = __pic_read(__reg_num);			\
	pr_debug("picR:%x:%llx\t%s:%d\n", __reg_num, __val,	\
				__func__, __LINE__);		\
	__val;							\
})

#define pic_write(__reg_num, __val)	do {			\
	pr_debug("picW:%x:%llx\t%s:%d\n", __reg_num, __val,	\
				__func__, __LINE__);		\
	__pic_write(__reg_num, __val);				\
} while (0)


static u64 event_encoding(u64 event_id, int idx)
{
	return (idx << E90S_PCR_SC_SHIFT) |
		(perf_event_get_enc(event_id) << E90S_PCR_PICU_SHIFT);

}

static u64 sparc_perf_event_update(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	int idx = event->hw.idx;
	u64 pcr = pcr_read();
	u64 prev_raw_count, new_raw_count;
	s64 delta;
	int user_overflow;
	user_overflow = (pcr & (1UL << (idx + E90S_PCR_OVF_SHIFT))) &&
			((pcr & (E90S_PCR_USR | E90S_PCR_SYS)) == E90S_PCR_USR);

again:
	prev_raw_count = local64_read(&hwc->prev_count);
	new_raw_count = user_overflow ? 0 : pic_read(idx);

	if (local64_cmpxchg(&hwc->prev_count, prev_raw_count,
			     new_raw_count) != prev_raw_count)
		goto again;

	delta = new_raw_count - prev_raw_count;

	local64_add(delta, &event->count);
	local64_sub(delta, &hwc->period_left);

	return new_raw_count;
}

static int sparc_perf_event_set_period(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	int idx = event->hw.idx;
	s64 left = local64_read(&hwc->period_left);
	s64 period = hwc->sample_period;
	int ret = 0;

	/*
	 * If we are way outside a reasonable range then just skip forward:
	 */
	if (unlikely(left <= -period)) {
		left = period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		ret = 1;
	}

	if (unlikely(left <= 0)) {
		left += period;
		local64_set(&hwc->period_left, left);
		hwc->last_period = period;
		ret = 1;
	}

	/*
	 * The hw event starts counting from this event offset,
	 * mark it to be able to extra future deltas:
	 */
	local64_set(&hwc->prev_count, (u64)-left);

	pic_write(idx, (u64)(-left));

	perf_event_update_userpage(event);

	return ret;
}

static void sparc_pmu_enable(struct pmu *pmu)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	u64 pcr = pcr_read();
	pcr |= cpuc->config_base;
	pcr_write(pcr);
}

static void sparc_pmu_disable(struct pmu *pmu)
{
	u64 pcr = pcr_read();
	pcr &= ~(E90S_PCR_USR | E90S_PCR_SYS);
	pcr |= E90S_PCR_ULRO | E90S_PCR_OVRO;
	pcr_write(pcr);
}

static inline void sparc_pmu_enable_event(struct cpu_hw_events *cpuc,
					   struct perf_event *event, int idx)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 val = hwc->config_base;

	val |= event_encoding(hwc->event_base, idx);
	cpuc->pcr[idx] = val;
	cpuc->event[idx] = event;
	/* prevent interrupt */
	mb();
	pcr_write(val);
}

static inline void sparc_pmu_disable_event(struct cpu_hw_events *cpuc,
					    struct hw_perf_event *hwc, int idx)
{
	cpuc->pcr[idx] = nop_for_index(idx);
	pcr_write(cpuc->pcr[idx]);
	/* prevent interrupt */
	mb();
	cpuc->event[idx] = NULL;
}

static void sparc_pmu_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);

	if (flags & PERF_EF_RELOAD) {
		WARN_ON_ONCE(!(event->hw.state & PERF_HES_UPTODATE));
		sparc_perf_event_set_period(event);
	}
	hwc->state = 0;
	sparc_pmu_enable_event(cpuc, event, hwc->idx);
}

static void sparc_pmu_stop(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	int idx = event->hw.idx;

	if (!(event->hw.state & PERF_HES_STOPPED)) {
		sparc_pmu_disable_event(cpuc, &event->hw, idx);
		event->hw.state |= PERF_HES_STOPPED;
	}

	if (!(event->hw.state & PERF_HES_UPTODATE) && (flags & PERF_EF_UPDATE)) {
		sparc_perf_event_update(event);
		event->hw.state |= PERF_HES_UPTODATE;
	}
}

static void sparc_pmu_del(struct perf_event *event, int _flags)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	sparc_pmu_stop(event, PERF_EF_UPDATE);
	__clear_bit(event->hw.idx, &cpuc->used_mask);
	cpuc->event[event->hw.idx] = NULL;
	perf_event_update_userpage(event);
}

static void sparc_pmu_read(struct perf_event *event)
{
	sparc_perf_event_update(event);
}

static const struct perf_event_map *sparc_map_cache_event(u64 config)
{
	unsigned int cache_type, cache_op, cache_result;
	const struct perf_event_map *pmap;

	cache_type = (config >>  0) & 0xff;
	cache_op = (config >>  8) & 0xff;
	cache_result = (config >> 16) & 0xff;

	pr_debug("event[%d][%d][%d]\n",
	       cache_type, cache_op, cache_result);

	if (cache_type >= PERF_COUNT_HW_CACHE_MAX)
		return ERR_PTR(-EINVAL);

	if (cache_op >= PERF_COUNT_HW_CACHE_OP_MAX)
		return ERR_PTR(-EINVAL);

	if (cache_result >= PERF_COUNT_HW_CACHE_RESULT_MAX)
		return ERR_PTR(-EINVAL);


	pmap = &e90s_cache_map[cache_type][cache_op][cache_result];

	if (pmap->encoding == CACHE_OP_UNSUPPORTED)
		return ERR_PTR(-ENOENT);

	if (pmap->encoding == CACHE_OP_NONSENSE)
		return ERR_PTR(-EINVAL);

	return pmap;
}

static int e90s_get_event_idx(struct cpu_hw_events *cpuc,
			       struct hw_perf_event *hwc)
{
	int idx;
	unsigned long msk = perf_event_get_msk(hwc->event_base);
	unsigned long free_msk = (~cpuc->used_mask) & E90S_MAX_HWEVENTS_MASK;
	free_msk &= msk;
	idx = find_first_bit(&free_msk, E90S_MAX_HWEVENTS);

	if (idx >= E90S_MAX_HWEVENTS)
		return -EAGAIN;

	set_bit(idx, &cpuc->used_mask);
	return idx;
}

static int sparc_pmu_add(struct perf_event *event, int flags)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	struct hw_perf_event *hwc = &event->hw;
	int idx;
	int err = 0;

	perf_pmu_disable(event->pmu);

	/* If we don't have a space for the counter then finish early. */
	idx = e90s_get_event_idx(cpuc, hwc);
	if (idx < 0) {
		err = idx;
		goto out;
	}

	/*
	 * If there is an event in the counter we are going to use then make
	 * sure it is disabled.
	 */
	event->hw.idx = idx;
	cpuc->event[idx] = event;

	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;
	if (flags & PERF_EF_START)
		sparc_pmu_start(event, PERF_EF_RELOAD);

	/* Propagate our changes to the userspace mapping. */
	perf_event_update_userpage(event);

out:
	perf_pmu_enable(event->pmu);
	return err;
}

static int validate_event(struct cpu_hw_events *hw_events,
	       struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct pmu *leader_pmu = event->group_leader->pmu;

	if (is_software_event(event))
		return 1;

	if (event->pmu != leader_pmu || event->state < PERF_EVENT_STATE_OFF)
		return 1;

	if (event->state == PERF_EVENT_STATE_OFF && !event->attr.enable_on_exec)
		return 1;

	return hw_events->config_base == hwc->config_base &&
			e90s_get_event_idx(hw_events, hwc) >= 0;
}

static int validate_group(struct perf_event *event)
{
	struct perf_event *sibling, *leader = event->group_leader;
	struct cpu_hw_events fake_pmu;

	/*
	 * Initialise the fake PMU. We only need to populate the
	 * used_mask and config for the purposes of validation.
	 */
	fake_pmu.used_mask = 0;
	fake_pmu.config_base = leader->hw.config_base;

	if (!validate_event(&fake_pmu, leader))
		return -EINVAL;

	for_each_sibling_event(sibling, leader) {
		if (!validate_event(&fake_pmu, sibling))
			return -EINVAL;
	}

	if (!validate_event(&fake_pmu, event))
		return -EINVAL;

	return 0;
}

static int sparc_pmu_event_init(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	struct hw_perf_event *hwc = &event->hw;
	const struct perf_event_map *pmap;

	/* does not support taken branch sampling */
	if (has_branch_stack(event))
		return -EOPNOTSUPP;

	switch (attr->type) {
	case PERF_TYPE_HARDWARE:
		if (attr->config >= ARRAY_SIZE(e90s_perfmon_event_map))
			return -EINVAL;
		pmap = e90s_event_map(attr->config);
		break;

	case PERF_TYPE_HW_CACHE:
		pmap = sparc_map_cache_event(attr->config);
		if (IS_ERR(pmap))
			return PTR_ERR(pmap);
		break;

	case PERF_TYPE_RAW:
		pmap = NULL;
		break;

	default:
		return -ENOENT;

	}

	if (pmap) {
		hwc->event_base = perf_event_encode(pmap);
	} else {
		/*
		 * User gives us "(encoding << 16) | pic_mask" for
		 * PERF_TYPE_RAW events.
		 */
		hwc->event_base = attr->config;
	}

	if (!attr->exclude_user)
		hwc->config_base |= E90S_PCR_USR;
	if (!attr->exclude_kernel)
		hwc->config_base |= E90S_PCR_SYS;

	if (event->group_leader != event) {
		if (validate_group(event))
			return -EINVAL;
	}

	if (!hwc->sample_period) {
		hwc->last_period = hwc->sample_period;
		local64_set(&hwc->period_left, hwc->sample_period);
	}

	return 0;
}

static struct pmu pmu = {
	.pmu_enable	= sparc_pmu_enable,
	.pmu_disable	= sparc_pmu_disable,
	.event_init	= sparc_pmu_event_init,
	.add		= sparc_pmu_add,
	.del		= sparc_pmu_del,
	.start		= sparc_pmu_start,
	.stop		= sparc_pmu_stop,
	.read		= sparc_pmu_read,
};

int perf_event_nmi_handler(struct pt_regs *regs)
{
	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
	int i;
	u64 pcr = pcr_read();

	for (i = 0; i < E90S_MAX_HWEVENTS; i++) {
		struct perf_sample_data data;
		struct hw_perf_event *hwc;
		struct perf_event *event = cpuc->event[i];
		if (!(pcr & (1ULL << (i + E90S_PCR_OVF_SHIFT))))
			continue;
		if (!event) {
			pr_err("perf_event_nmi_handler:"
				" event[%d] == NULL\n", i);
			continue;
		}
		hwc = &event->hw;
		sparc_perf_event_update(event);
		perf_sample_data_init(&data, 0, hwc->last_period);
		if (!sparc_perf_event_set_period(event))
			continue;

		if (perf_event_overflow(event, &data, regs))
			sparc_pmu_stop(event, 0);
	}
	pcr = pcr_read();
	pcr_write(pcr & ~(pcr & E90S_PCR_OVF));

	return NOTIFY_STOP;
}

static int __init init_hw_perf_events(void)
{
	perf_pmu_register(&pmu, "cpu", PERF_TYPE_RAW);
	return 0;
}

pure_initcall(init_hw_perf_events);

void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
			   struct pt_regs *regs)
{
	unsigned long ksp, fp;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	int graph = 0;
#endif

	stack_trace_flush();

	perf_callchain_store(entry, regs->tpc);

	ksp = regs->u_regs[UREG_I6];
	fp = ksp + STACK_BIAS;
	do {
		struct sparc_stackf *sf;
		struct pt_regs *regs;
		unsigned long pc;

		if (!kstack_valid(current_thread_info(), fp))
			break;

		sf = (struct sparc_stackf *) fp;
		regs = (struct pt_regs *) (sf + 1);

		if (kstack_is_trap_frame(current_thread_info(), regs)) {
			if (user_mode(regs))
				break;
			pc = regs->tpc;
			fp = regs->u_regs[UREG_I6] + STACK_BIAS;
		} else {
			pc = sf->callers_pc;
			fp = (unsigned long)sf->fp + STACK_BIAS;
		}
		perf_callchain_store(entry, pc);
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		if ((pc + 8UL) == (unsigned long) &return_to_handler) {
			int index = current->curr_ret_stack;
			if (current->ret_stack && index >= graph) {
				pc = current->ret_stack[index - graph].ret;
				perf_callchain_store(entry, pc);
				graph++;
			}
		}
#endif
	} while (entry->nr < entry->max_stack);
}

static inline int
valid_user_frame(const void __user *fp, unsigned long size)
{
	/* addresses should be at least 4-byte aligned */
	if (((unsigned long) fp) & 3)
		return 0;

	return (__range_not_ok(fp, size, TASK_SIZE) == 0);
}

static void perf_callchain_user_64(struct perf_callchain_entry_ctx *entry,
				   struct pt_regs *regs)
{
	unsigned long ufp;

	ufp = regs->u_regs[UREG_FP] + STACK_BIAS;
	do {
		struct sparc_stackf __user *usf;
		struct sparc_stackf sf;
		unsigned long pc;

		usf = (struct sparc_stackf __user *)ufp;
		if (!valid_user_frame(usf, sizeof(sf)))
			break;

		if (__copy_from_user_inatomic(&sf, usf, sizeof(sf)))
			break;

		pc = sf.callers_pc;
		ufp = (unsigned long)sf.fp + STACK_BIAS;
		perf_callchain_store(entry, pc);
	} while (entry->nr < entry->max_stack);
}

static void perf_callchain_user_32(struct perf_callchain_entry_ctx *entry,
				   struct pt_regs *regs)
{
	unsigned long ufp;

	ufp = regs->u_regs[UREG_FP] & 0xffffffffUL;
	do {
		unsigned long pc;

		if (thread32_stack_is_64bit(ufp)) {
			struct sparc_stackf __user *usf;
			struct sparc_stackf sf;

			ufp += STACK_BIAS;
			usf = (struct sparc_stackf __user *)ufp;
			if (__copy_from_user_inatomic(&sf, usf, sizeof(sf)))
				break;
			pc = sf.callers_pc & 0xffffffff;
			ufp = ((unsigned long) sf.fp) & 0xffffffff;
		} else {
			struct sparc_stackf32 __user *usf;
			struct sparc_stackf32 sf;
			usf = (struct sparc_stackf32 __user *)ufp;
			if (__copy_from_user_inatomic(&sf, usf, sizeof(sf)))
				break;
			pc = sf.callers_pc;
			ufp = (unsigned long)sf.fp;
		}
		perf_callchain_store(entry, pc);
	} while (entry->nr < entry->max_stack);
}

void
perf_callchain_user(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
{
	u64 saved_fault_address = current_thread_info()->fault_address;
	u8 saved_fault_code = get_thread_fault_code();
	mm_segment_t old_fs;

	perf_callchain_store(entry, regs->tpc);

	if (!current->mm)
		return;

	old_fs = get_fs();
	set_fs(USER_DS);

	flushw_user();

	pagefault_disable();

	if (test_thread_flag(TIF_32BIT))
		perf_callchain_user_32(entry, regs);
	else
		perf_callchain_user_64(entry, regs);

	pagefault_enable();

	set_fs(old_fs);
	set_thread_fault_code(saved_fault_code);
	current_thread_info()->fault_address = saved_fault_address;
}
