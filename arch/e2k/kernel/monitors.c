/*
 * arch/e2k/kernel/monitors.c
 *
 * This file contains implementation of interface functions for working with 
 * monitors and implementation of mechanism for adjusting monitors.
 *
 * Copyright (C) 2009-2015 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/module.h>

#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/uaccess.h>
#include <asm/monitors.h>

#include "../../../fs/proc/internal.h" /* for get_proc_task() */


#define MONITORS_FILENAME			"monitors"
static struct proc_dir_entry *monitors_dir_entry;

/*
 * Monitors
 */

#define MONITORS_SETTINGS_FILENAME		"monitors_settings"
#define MONITORS_EVENTS_FILENAME		"monitors_events"
#define MONITORS_DEAD_PROC_EVENTS_FILENAME	"monitors_dead_proc_events"
#define MONITORS_HELP_FILENAME 			"monitors_help"

#define MONITORS_MODE_NAME_LEN		1
#define MONITORS_SETTINGS_STR_MAX_SIZE	256

#define MONITORS_MODES_COUNT		3
#define SYSTEM_MODE			1
#define USER_MODE			2
#define COMMON_MODE			(SYSTEM_MODE | USER_MODE)

struct monitors_mode_info {
	char		*name;
	unsigned char	mode;
};

static struct monitors_mode_info monitors_mode_info[] = {
	{"S",	SYSTEM_MODE},
	{"U",	USER_MODE  },
	{"C",	COMMON_MODE}
};

struct monitors_info {
	int		mode;
	unsigned short	event;
	unsigned char	is_used;
};

static struct monitors_info	monitors[MONITORS_COUNT];

int monitors_used __read_mostly = 0;

enum {
	DIM0,
	DIM1,
	DDM0,
	DDM1
};

static char *monitors_id_names[] = {
	"I0",
	"I1",
	"D0",
	"D1"
};

struct monitors_events_range {
	unsigned short start;
	unsigned short end;
};

#define DDM0_EVENTS_RANGE_COUNT_V1	7
#define DDM1_EVENTS_RANGE_COUNT_V1	5
#define DIM_EVENTS_RANGE_COUNT_V1	8

static struct monitors_events_range ddm0_monitors_events_list_v1[] = {
	{0x00, 0x03}, {0x10, 0x14}, {0x20, 0x21}, {0x30, 0x31}, {0x33, 0x36},
	{0x40, 0x46}, {0x48, 0x48}
};

static struct monitors_events_range ddm1_monitors_events_list_v1[] = {
	{0x00, 0x02}, {0x10, 0x15}, {0x20, 0x21}, {0x30, 0x37}, {0x40, 0x48}
};

static struct monitors_events_range dim_monitors_events_list_v1[] = {
	{0X00, 0x0a}, {0x10, 0x1e}, {0x20, 0x26}, {0x30, 0x3c}, {0x40, 0x4a},
	{0x50, 0x5a}, {0x60, 0x67}, {0x70, 0x71}
};

#define DDM0_EVENTS_RANGE_COUNT_V2	7
#define DDM1_EVENTS_RANGE_COUNT_V2	7
#define DIM_EVENTS_RANGE_COUNT_V2	9

static struct monitors_events_range ddm0_monitors_events_list_v2[] = {
	{0x00, 0x03}, {0x10, 0x16}, {0x20, 0x21}, {0x30, 0x3a}, {0x40, 0x46},
	{0x48, 0x4f}, {0x70, 0x72}
};

static struct monitors_events_range ddm1_monitors_events_list_v2[] = {
	{0x00, 0x02}, {0x10, 0x17}, {0x20, 0x21}, {0x30, 0x3a}, {0x40, 0x48},
	{0x4a, 0x4f}, {0x70, 0x72}
};

static struct monitors_events_range dim_monitors_events_list_v2[] = {
	{0x00, 0x0a}, {0x10, 0x1f}, {0x20, 0x26}, {0x30, 0x3c}, {0x40, 0x4a},
	{0x50, 0x5a}, {0x60, 0x69}, {0x70, 0x74}, {0x7c, 0x7e}
};

#define DDM0_EVENTS_RANGE_COUNT_V3	7
#define DDM1_EVENTS_RANGE_COUNT_V3	6
#define DIM_EVENTS_RANGE_COUNT_V3	10

static struct monitors_events_range ddm0_monitors_events_list_v3[] = {
	{0x00, 0x03}, {0x10, 0x19}, {0x20, 0x24}, {0x30, 0x3a}, {0x40, 0x46},
	{0x48, 0x48}, {0x4a, 0x4b}
};

static struct monitors_events_range ddm1_monitors_events_list_v3[] = {
	{0x00, 0x02}, {0x10, 0x19}, {0x20, 0x24}, {0x30, 0x3a}, {0x40, 0x48},
	{0x4a, 0x4b}
};

static struct monitors_events_range dim_monitors_events_list_v3[] = {
	{0x00, 0x03}, {0x07, 0x0a}, {0x0f, 0x1f}, {0x20, 0x26}, {0x30, 0x3d},
	{0x40, 0x4a}, {0x50, 0x5a}, {0x60, 0x69}, {0x70, 0x74}, {0x7c, 0x7e}
};

#define DDM0_EVENTS_RANGE_COUNT_V4	DDM0_EVENTS_RANGE_COUNT_V3
#define DDM1_EVENTS_RANGE_COUNT_V4	DDM1_EVENTS_RANGE_COUNT_V3
#define DIM_EVENTS_RANGE_COUNT_V4	DIM_EVENTS_RANGE_COUNT_V3

#define ddm0_monitors_events_list_v4	ddm0_monitors_events_list_v3
#define ddm1_monitors_events_list_v4	ddm1_monitors_events_list_v3
#define dim_monitors_events_list_v4	dim_monitors_events_list_v3

#define DDM0_EVENTS_RANGE_COUNT_V5	6
#define DDM1_EVENTS_RANGE_COUNT_V5	7
#define DIM_EVENTS_RANGE_COUNT_V5	11

static struct monitors_events_range ddm0_monitors_events_list_v5[] = {
	{0x00, 0x04}, {0x10, 0x19}, {0x20, 0x24}, {0x30, 0x3a}, {0x40, 0x48},
	{0x4a, 0x4b}
};

static struct monitors_events_range ddm1_monitors_events_list_v5[] = {
	{0x00, 0x02}, {0x04, 0x04}, {0x10, 0x19}, {0x20, 0x24}, {0x30, 0x3a},
	{0x40, 0x48}, {0x4a, 0x4b}
};

static struct monitors_events_range dim_monitors_events_list_v5[] = {
	{0x00, 0x03}, {0x07, 0x0a}, {0x0f, 0x1f}, {0x20, 0x26}, {0x2d, 0x2f},
	{0x30, 0x3d}, {0x40, 0x4a}, {0x50, 0x5a}, {0x60, 0x69}, {0x70, 0x74},
	{0x7c, 0x7e}
};

static struct monitors_events_range *ddm0_monitors_events_list;
static struct monitors_events_range *ddm1_monitors_events_list;
static struct monitors_events_range *dim_monitors_events_list;

unsigned char ddm0_monitors_events_range_count;
unsigned char ddm1_monitors_events_range_count;
unsigned char dim_monitors_events_range_count;

static atomic64_t common_events_count[NR_CPUS][MONITORS_COUNT];

typedef struct {
	unsigned long		monitors_count[NR_CPUS][MONITORS_COUNT];
	struct monitors_info	monitors[MONITORS_COUNT];
	pid_t			pid;
	cpumask_t		cpus_mask;
} dead_proc_events_t;

#define DEAD_PROC_EVENTS_COUNT	20

static dead_proc_events_t dead_proc_events_buf[DEAD_PROC_EVENTS_COUNT];
static dead_proc_events_t dead_proc_events_buf_tmp[DEAD_PROC_EVENTS_COUNT];
static char		  dead_proc_events_buf_id = -1;
static char		  dead_proc_events_buf_id_tmp;
static unsigned char	  dead_proc_events_buf_full = 0;
static unsigned char	  dead_proc_events_buf_full_tmp;

static DEFINE_RAW_SPINLOCK(monitors_lock);
static DEFINE_RAW_SPINLOCK(dead_proc_lock);
static DEFINE_RAW_SPINLOCK(dead_proc_lock_tmp);

/*
 * SIC monitors
 */

#define SICMONITORS_SETTINGS_FILENAME		"sicmonitors_settings"
#define SICMONITORS_EVENTS_FILENAME		"sicmonitors_events"
#define SICMONITORS_HELP_FILENAME		"sicmonitors_help"

#define SICMONITORS_SETTINGS_STR_MAX_SIZE	256

#define HAS_MACHINE_SICMONITORS					\
	(HAS_MACHINE_L_SIC && !IS_MACHINE_E3S && !IS_MACHINE_ES2)

struct sicmonitors_info {
	unsigned short	event;
	unsigned char	is_used;
};

static struct sicmonitors_info	sicmonitors[SICMONITORS_COUNT];

enum {
	MCM0,
	MCM1,
};

static char *sicmonitors_id_names[] = {
	"M0",
	"M1",
};

struct sicmonitors_event_info {
	char		*name;
	unsigned short	event;
};

#define MCM0_EVENTS_COUNT	9

enum {
	SIC_MC_READ,
	SIC_MC_WRITE_LOCAL,
	SIC_MC_READ_LOCAL_CORES,
	SIC_DIR_CACHE_HIT,
	SIC_DIR_CACHE_READ_HIT,
	SIC_RETRY,
	SIC_RETRY2_RDBUF_FULL,
	SIC_RETRY2_WRBUF,
	SIC_RETRY2_DM
};

static struct sicmonitors_event_info MCM0_event_info[] = {
	{"SIC_MC_READ",			0x00},
	{"SIC_MC_WRITE_LOCAL",		0x01},
	{"SIC_MC_READ_LOCAL_CORES",	0x02},
	{"SIC_DIR_CACHE_HIT",		0x03},
	{"SIC_DIR_CACHE_READ_HIT",	0x04},
	{"SIC_RETRY",			0x05},
	{"SIC_RETRY2_RDBUF_FULL",	0x06},
	{"SIC_RETRY2_WRBUF",		0x07},
	{"SIC_RETRY2_DM",		0x08},
};

#define MCM1_EVENTS_COUNT	7

enum {
	SIC_MC_WRITE,
	SIC_MC_READ_LOCAL,
	SIC_MC_WRITE_LOCAL_CORES,
	SIC_DIR_CACHE_MISS,
	SIC_DIR_CACHE_READ_MISS,
	SIC_RETRY1,
	SIC_RETRY2
};

static struct sicmonitors_event_info MCM1_event_info[] = {
	{"SIC_MC_WRITE",		0x00},
	{"SIC_MC_READ_LOCAL",		0x01},
	{"SIC_MC_WRITE_LOCAL_CORES",	0x02},
	{"SIC_DIR_CACHE_MISS",		0x03},
	{"SIC_DIR_CACHE_READ_MISS",	0x04},
	{"SIC_RETRY1",			0x05},
	{"SIC_RETRY2",			0x06},
};

static DEFINE_RAW_SPINLOCK(sicmonitors_lock);

/*
 * IPCC monitors
 */

#define IPCCMONITORS_SETTINGS_FILENAME		"ipccmonitors_settings"
#define IPCCMONITORS_EVENTS_FILENAME		"ipccmonitors_events"
#define IPCCMONITORS_HELP_FILENAME		"ipccmonitors_help"

#define IPCCMONITORS_SETTINGS_STR_MAX_SIZE	16

#define HAS_MACHINE_IPCCMONITORS		\
	(IS_MACHINE_E2S || IS_MACHINE_E8C)

struct ipccmonitors_info {
	unsigned short	event;
	unsigned char	is_used;
};

static struct ipccmonitors_info	ipccmonitors;

struct ipccmonitors_event_info {
	char		*name;
	unsigned short	event;
};

#define IPCC_EVENTS_COUNT	2

enum {
	IPCC_LERR,
	IPCC_RTRY,
};

static struct ipccmonitors_event_info IPCC_event_info[] = {
	{"IPCC_LERR",	0x01},
	{"IPCC_RTRY",	0x02},
};

static DEFINE_RAW_SPINLOCK(ipccmonitors_lock);

/*
 * IOCC monitors
 */

#define IOCCMONITORS_SETTINGS_FILENAME		"ioccmonitors_settings"
#define IOCCMONITORS_EVENTS_FILENAME		"ioccmonitors_events"
#define IOCCMONITORS_HELP_FILENAME		"ioccmonitors_help"

#define E2K_IO_STR_EVENT_SHIFT			29
#define E2K_IO_STR_EVENT_MASK			0xE0000000

#define IOCCMONITORS_SETTINGS_STR_MAX_SIZE	16

#define HAS_MACHINE_IOCCMONITORS				\
	(IS_MACHINE_E3S || IS_MACHINE_ES2 || IS_MACHINE_E2S ||	\
		IS_MACHINE_E1CP)

struct ioccmonitors_info {
	unsigned short	event;
	unsigned char	is_used;
};

static struct ioccmonitors_info	ioccmonitors;

struct ioccmonitors_event_info {
	char		*name;
	unsigned short	event;
};

#define IOCC_EVENTS_COUNT	4

enum {
	IOCC_BSY_RC,
	IOCC_ERR_RC,
	IOCC_TO_RC,
	IOCC_CMN_RC,
};

static struct ioccmonitors_event_info IOCC_event_info[] = {
	{"IOCC_BSY_RC",	0x01},
	{"IOCC_ERR_RC",	0x02},
	{"IOCC_TO_RC",	0x04},
	{"IOCC_CMN_RC",	0x07},
};

static DEFINE_RAW_SPINLOCK(ioccmonitors_lock);


/*
 * Monitors
 */

static inline int dim_check_start_monitoring(int monitor)
{
	e2k_dimcr_t	dimcr_reg;
	unsigned char	user, new_user;
	unsigned char	system, new_system;
	unsigned short	event, new_event;
	unsigned char	new_mode;

	if (monitors[monitor].is_used) {
		AW(dimcr_reg) = E2K_GET_DSREG(dimcr);

		user   = dimcr_reg.fields[monitor].user;
		system = dimcr_reg.fields[monitor].system;
		event  = dimcr_reg.fields[monitor].event;

		new_mode   = monitors_mode_info[monitors[monitor].mode].mode;
		new_user   = (new_mode & USER_MODE) ? 1 : 0;
		new_system = (new_mode & SYSTEM_MODE) ? 1 : 0;
		new_event  = monitors[monitor].event;

		if (user != new_user || system != new_system ||
				event != new_event)
			return 1;
	}

	return 0;
}

static inline unsigned char ddm_check_start_monitoring(int monitor)
{
	e2k_ddmcr_t	ddmcr_reg;
	unsigned char	user, new_user;
	unsigned char	system, new_system;
	unsigned short	event, new_event = 0;
	unsigned char	new_mode;
	unsigned char	num;

	if (monitors[monitor].is_used) {
		AW(ddmcr_reg) = E2K_GET_MMUREG(ddmcr);

		num = monitor - 2;

		user   = ddmcr_reg.fields[num].user;
		system = ddmcr_reg.fields[num].system;
		event  = ddmcr_reg.fields[num].event;

		new_mode   = monitors_mode_info[monitors[monitor].mode].mode;
		new_user   = (new_mode & USER_MODE) ? 1 : 0;
		new_system = (new_mode & SYSTEM_MODE) ? 1 : 0;
		new_event  = monitors[monitor].event;

		if (user != new_user || system != new_system ||
			event != new_event)
			return 1;
	}

	return 0;
}

static inline unsigned char check_start_monitoring(int monitor)
{
	if (monitor == DIM0 || monitor == DIM1)
		return dim_check_start_monitoring(monitor);
	else if (monitor == DDM0 || monitor == DDM1)
		return ddm_check_start_monitoring(monitor);

	return 0;
}

static inline unsigned char dim_check_process_start_monitoring(
					int monitor, struct task_struct *task)
{
	e2k_dimcr_t	dimcr_reg;
	unsigned char	user, proc_user;
	unsigned char	system, proc_system;
	unsigned short	event, proc_event;
	unsigned char	proc_mode;

	if (monitors[monitor].is_used) {
		dimcr_reg = task->thread.sw_regs.dimcr;

		user   = dimcr_reg.fields[monitor].user;
		system = dimcr_reg.fields[monitor].system;
		event  = dimcr_reg.fields[monitor].event;

		proc_mode   = monitors_mode_info[monitors[monitor].mode].mode;
		proc_user   = (proc_mode & USER_MODE) ? 1 : 0;
		proc_system = (proc_mode & SYSTEM_MODE) ? 1 : 0;
		proc_event  = monitors[monitor].event;

		if (user != proc_user || system != proc_system ||
			event != proc_event)
			return 1;
	}

	return 0;
}

static inline unsigned char ddm_check_process_start_monitoring(
					int monitor, struct task_struct *task)
{
	e2k_ddmcr_t	ddmcr_reg;
	unsigned char	user, proc_user;
	unsigned char	system, proc_system;
	unsigned short	event, proc_event = 0;
	unsigned char	proc_mode;
	unsigned char	num;

	if (monitors[monitor].is_used) {
		ddmcr_reg = task->thread.sw_regs.ddmcr;

		num = monitor - 2;

		user   = ddmcr_reg.fields[num].user;
		system = ddmcr_reg.fields[num].system;
		event  = ddmcr_reg.fields[num].event;

		proc_mode   = monitors_mode_info[monitors[monitor].mode].mode;
		proc_user   = (proc_mode & USER_MODE) ? 1 : 0;
		proc_system = (proc_mode & SYSTEM_MODE) ? 1 : 0;
		proc_event  = monitors[monitor].event;

		if (user != proc_user || system != proc_system ||
			event != proc_event)
			return 1;
	}

	return 0;
}

static inline unsigned char check_process_start_monitoring(
					int monitor, struct task_struct *task)
{
	if (monitor == DIM0 || monitor == DIM1)
		return dim_check_process_start_monitoring(monitor, task);
	else if (monitor == DDM0 || monitor == DDM1)
		return ddm_check_process_start_monitoring(monitor, task);

	return 0;
}

static inline void dim_start_monitoring(int monitor)
{
	e2k_dimcr_t	dimcr_reg;
	unsigned char	user;
	unsigned char	system;
	unsigned short	event;
	unsigned char	mode;

	AW(dimcr_reg) = E2K_GET_DSREG(dimcr);

	mode   = monitors_mode_info[monitors[monitor].mode].mode;
	user   = (mode & USER_MODE) ? 1 : 0;
	system = (mode & SYSTEM_MODE) ? 1 : 0;
	event  = monitors[monitor].event;

	dimcr_reg.fields[monitor].user   = user;
	dimcr_reg.fields[monitor].system = system;
	dimcr_reg.fields[monitor].event  = event;

	E2K_SET_DSREG(dimcr, AW(dimcr_reg));

	/*
	 * We should reset dimar0 and dimar1 at the end or we can receive some
	 * events of previous type.
	 */
	if (monitor == DIM0)
		E2K_SET_DSREG(dimar0, 0);
	else if (monitor == DIM1)
		E2K_SET_DSREG(dimar1, 0);
}

static inline void ddm_start_monitoring(int monitor)
{
	e2k_ddmcr_t	ddmcr_reg;
	unsigned char	user;
	unsigned char	system;
	unsigned short	event;
	unsigned char	mode;
	unsigned char	num;

	AW(ddmcr_reg) = E2K_GET_MMUREG(ddmcr);

	mode   = monitors_mode_info[monitors[monitor].mode].mode;
	user   = (mode & USER_MODE) ? 1 : 0;
	system = (mode & SYSTEM_MODE) ? 1 : 0;
	event  = monitors[monitor].event;

	num = monitor - 2;

	ddmcr_reg.fields[num].user   = user;
	ddmcr_reg.fields[num].system = system;
	ddmcr_reg.fields[num].event  = event;

	E2K_SET_MMUREG(ddmcr, AW(ddmcr_reg));

	/*
	 * We should reset ddmar0 and ddmar1 at the end or we can receive some
	 * events of previous type.
	 */
	if (monitor == DDM0)
		E2K_SET_MMUREG(ddmar0, 0);
	else if (monitor == DDM1)
		E2K_SET_MMUREG(ddmar1, 0);
}

static inline void start_monitoring(int monitor)
{
	if (monitor == DIM0 || monitor == DIM1)
		dim_start_monitoring(monitor);
	else if (monitor == DDM0 || monitor == DDM1)
		ddm_start_monitoring(monitor);
}

static inline void start_process_monitoring(int monitor,
			struct task_struct *task)
{
	struct thread_info	*thread_info = task_thread_info(task);
	unsigned char		i;

	for (i = 0; i < NR_CPUS; i++)
		atomic64_set(&thread_info->monitors_count[i][monitor], 0);

	/*
	 * When monitoring is activated for the process, monitoring might
	 * already been activated. So, we need right values of
	 * thread_info->monitors_delta.dim0, thread_info->monitors_delta.dim1,
	 * thread_info->monitors_delta.ddm0 and
	 * thread_info->monitors_delta.ddm1 to count right value of
	 * delta_event_count, when the processor will be switched on the
	 * process next time.
	 */
	switch (monitor) {
	case DIM0:
		thread_info->monitors_delta.dim0 = 0;
		break;
	case DIM1:
		thread_info->monitors_delta.dim1 = 0;
		break;
	case DDM0:
		thread_info->monitors_delta.ddm0 = 0;
		break;
	case DDM1:
		thread_info->monitors_delta.ddm1 = 0;
		break;
	}
}

void process_monitors(struct task_struct *task)
{
	struct thread_info	*thread_info = task_thread_info(task);
	unsigned long		delta_event_count;
	unsigned char		cpu_num;
	unsigned long		flags;
	unsigned char		i;

	if (!thread_info)
		return;

	raw_spin_lock_irqsave(&monitors_lock, flags);

	for (i = 0; i < MONITORS_COUNT; i++) {
		if (check_process_start_monitoring(i, task))
			start_process_monitoring(i, task);

		if (check_start_monitoring(i))
			start_monitoring(i);

		if (monitors[i].is_used) {
			switch (i) {
			case DIM0:
				delta_event_count =
					thread_info->monitors_delta.dim0;
				task->thread.sw_regs.dimar0 =
					E2K_GET_DSREG(dimar0);
				break;
			case DIM1:
				delta_event_count =
					thread_info->monitors_delta.dim1;
				task->thread.sw_regs.dimar1 =
					E2K_GET_DSREG(dimar1);
					break;
			case DDM0:
				delta_event_count =
					thread_info->monitors_delta.ddm0;
				task->thread.sw_regs.ddmar0 = 
					E2K_GET_MMUREG(ddmar0);
				break;
			case DDM1:
				delta_event_count =
					thread_info->monitors_delta.ddm1;
				task->thread.sw_regs.ddmar1 = 
					E2K_GET_MMUREG(ddmar1);
				break;
			default:
				delta_event_count = 0;
			}

			/*
			 * We do it here, because we are not already
			 * interested in common_events_count for monitor, when
			 * it is stopping, and because there is no events for
			 * monitor, when it is started.
			 */
			cpu_num = thread_info->monitors_delta.cpu_num;
			atomic64_add(delta_event_count,
				&common_events_count[cpu_num][i]);
			atomic64_add(delta_event_count,
				&thread_info->monitors_count[cpu_num][i]);
		}
	}

	raw_spin_unlock_irqrestore(&monitors_lock, flags);
}

void init_monitors(struct task_struct *task)
{
	AW(task->thread.sw_regs.dimcr) = 0;
	AW(task->thread.sw_regs.ddmcr) = 0;
}

void store_monitors_delta(struct task_struct *task)
{
	struct thread_info	*thread_info = task_thread_info(task);
	unsigned long		initial_count;
	unsigned long		current_count;
	unsigned long		flags;

	if (!thread_info)
		return;

	raw_spin_lock_irqsave(&monitors_lock, flags);

	thread_info->monitors_delta.cpu_num = thread_info->cpu;

	if (monitors[DIM0].is_used) {
		initial_count = task->thread.sw_regs.dimar0;
		current_count = E2K_GET_DSREG(dimar0);
		thread_info->monitors_delta.dim0 =
			current_count - initial_count;
	} else
		thread_info->monitors_delta.dim0 = 0;

	if (monitors[DIM1].is_used) {
		initial_count = task->thread.sw_regs.dimar1;
		current_count = E2K_GET_DSREG(dimar1);
		thread_info->monitors_delta.dim1 =
			current_count - initial_count;
	} else
		thread_info->monitors_delta.dim1 = 0;

	if (monitors[DDM0].is_used) {
		initial_count = task->thread.sw_regs.ddmar0;
		current_count = E2K_GET_MMUREG(ddmar0);
		thread_info->monitors_delta.ddm0 =
			current_count - initial_count;
	} else
		thread_info->monitors_delta.ddm0 = 0;

	if (monitors[DDM1].is_used) {
		initial_count = task->thread.sw_regs.ddmar1;
		current_count = E2K_GET_MMUREG(ddmar1);
		thread_info->monitors_delta.ddm1 =
			current_count - initial_count;
	} else
		thread_info->monitors_delta.ddm1 = 0;

	raw_spin_unlock_irqrestore(&monitors_lock, flags);
}

void add_dead_proc_events(struct task_struct *task)
{
	/*
	 * We can have a situation, when a monitoring event or mode have been
	 * changed or monitoring has been started or stopped after the last
	 * call of process_monitors function and before the call of this
	 * function. In this case we will have wrong data in
	 * dead_proc_events_buf. But as this situation is almost impossible,
	 * we do nothing to avoid it.
	 */

	struct thread_info *thread_info = task_thread_info(task);
	unsigned char id;
	unsigned long flags;

	if (!thread_info)
		return;

	raw_spin_lock_irqsave(&dead_proc_lock, flags);

	if (++dead_proc_events_buf_id == DEAD_PROC_EVENTS_COUNT) {
		dead_proc_events_buf_full = 1;
		dead_proc_events_buf_id = 0;
	}

	id = dead_proc_events_buf_id;

	raw_spin_lock(&monitors_lock);
	memcpy(dead_proc_events_buf[id].monitors, monitors,
		sizeof(struct monitors_info) * MONITORS_COUNT);
	raw_spin_unlock(&monitors_lock);

	memcpy(dead_proc_events_buf[id].monitors_count,
		thread_info->monitors_count,
		sizeof(atomic64_t) * NR_CPUS * MONITORS_COUNT);

	dead_proc_events_buf[id].pid = task->pid;
	dead_proc_events_buf[id].cpus_mask = *cpu_online_mask;

	raw_spin_unlock_irqrestore(&dead_proc_lock, flags);
}

unsigned char get_monitors_mask(char *title)
{
	unsigned char	mask = 0;
	unsigned char	title_start = 0;
	unsigned short	len = 0;
	unsigned short	event_id;
	char		event_name[8];
	unsigned long	flags;
	unsigned char	i;

	raw_spin_lock_irqsave(&monitors_lock, flags);

	for (i = 0; i < MONITORS_COUNT; i++) {
		if (!monitors[i].is_used)
			continue;

		event_id = monitors[i].event;

		memset(event_name, 0, 8);
		sprintf(event_name, "0x%X", event_id);

		mask |= 1 << i;

		if (title_start) {
			sprintf(title + len, "%s", event_name);
			len += strlen(event_name);
			title_start = 0;
		} else {
			sprintf(title + len, " %s", event_name);
			len += strlen(event_name) + 1;
		}
	}

	raw_spin_unlock_irqrestore(&monitors_lock, flags);

	title[len] = 0;

	return mask;
}

static int pid_monitors_events_show(struct seq_file *file, void *data)
{
	struct inode			*inode;
	struct task_struct		*task;
	struct thread_info		*thread_info;
	e2k_ddmcr_t			mcr_reg;
	unsigned char			user;
	unsigned char			system;
	unsigned char			mode;
	unsigned long			count;
	unsigned char			num;
	unsigned long			flags;
	unsigned char			i, j;

	inode = file->private;
	if (!inode)
		return 0;

	task = get_proc_task(inode);
	if (!task)
		return 0;

	thread_info = task_thread_info(task);
	if (!thread_info)
		return 0;

	raw_spin_lock_irqsave(&monitors_lock, flags);

	for (i = 0; i < NR_CPUS; i++) {
		if (!cpu_online(i))
			continue;

		for (j = 0; j < MONITORS_COUNT; j++) {
			if (!monitors[j].is_used)
				continue;

			mode   = monitors_mode_info[monitors[j].mode].mode;
			user   = (mode & USER_MODE) ? 1 : 0;
			system = (mode & SYSTEM_MODE) ? 1 : 0;

			switch (j) {
			case DIM0:
				AW(mcr_reg) = AW(task->thread.sw_regs.dimcr);
				break;
			case DIM1:
				AW(mcr_reg) = AW(task->thread.sw_regs.dimcr);
				break;
			case DDM0:
				mcr_reg = task->thread.sw_regs.ddmcr;
				break;
			case DDM1:
				mcr_reg = task->thread.sw_regs.ddmcr;
				break;
			default:
				continue;
			}

			num = j % 2;

			count = atomic64_read(
				&thread_info->monitors_count[i][j]);

			/*
			 * We should do it, because we can have a situation,
			 * when a monitoring event or mode have been changed
			 * or monitoring has been started, but the process,
			 * for which we want to see a count of monitoring
			 * events, has not yet started processing, so a count
			 * of monitoring events, taken from the process
			 * context, is invalid.
			 */
			if (mcr_reg.fields[num].event != monitors[j].event
				|| mcr_reg.fields[num].user != user
				|| mcr_reg.fields[num].system != system)
				count = 0;

			seq_printf(file, "CPU%d:%s:%s:0x%x=%lu\n",
				i,
				monitors_id_names[j],
				monitors_mode_info[monitors[j].mode].name,
				monitors[j].event,
				count);
		}
	}

	raw_spin_unlock_irqrestore(&monitors_lock, flags);

	put_task_struct(task);

	return 0;
}

static int pid_monitors_events_open(struct inode *inode, struct file *file)
{
	single_open(file, pid_monitors_events_show, inode);
	return 0;
}

const struct file_operations proc_pid_monitors_events_operations =
{
	.owner	 = THIS_MODULE,
	.open    = pid_monitors_events_open,
	.read    = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static inline unsigned short monitors_settings_string_get_next_word_len(
					char *str, unsigned char *is_last)
{
	unsigned short len;

	*is_last = 0;
	len = strcspn(str, " \n");

	if (str[len] == '\n' || len == strlen(str))
		*is_last = 1;

	return len;
}

static inline char lookup_monitors_id(char *str, unsigned short len)
{
	unsigned char i;
	char *name;

	for (i = 0; i < MONITORS_COUNT; i++) {
		name = monitors_id_names[i];

		if (len == strlen(name) && strncmp(str, name, len) == 0)
			return i;
	}

	return -1;
}

static inline char lookup_monitors_mode_id(char *str, unsigned short len)
{
	unsigned char	i;
	char		*name;

	if (len > MONITORS_MODE_NAME_LEN)
		return -1;

	for (i = 0; i < MONITORS_MODES_COUNT; i++) {
		name = monitors_mode_info[i].name;

		if (len == strlen(name) && strncmp(str, name, len) == 0)
			return i;
	}

	return -1;
}

static inline int lookup_monitors_event(char *str,
				unsigned short len, int monitor)
{
	int				event = -1;
	struct monitors_events_range	*monitors_events_list;
	unsigned char			monitors_events_range_count;
	unsigned char			i;

	switch (monitor) {
	case DIM0:
	case DIM1:
		monitors_events_range_count = dim_monitors_events_range_count;
		monitors_events_list = dim_monitors_events_list;
		break;
	case DDM0:
		monitors_events_range_count = ddm0_monitors_events_range_count;
		monitors_events_list = ddm0_monitors_events_list;
		break;
	case DDM1:
		monitors_events_range_count = ddm1_monitors_events_range_count;
		monitors_events_list = ddm1_monitors_events_list;
		break;
	default:
		return -1;
	}

	sscanf(str, "0x%X", &event);

	for (i = 0; i < monitors_events_range_count; i++) {
		if (monitors_events_list[i].start <= event &&
				monitors_events_list[i].end >= event)
			return event;
	}

	return -1;
}

static inline void parse_monitors_settings_string(char *str)
{
	unsigned short		i = 0;
	unsigned char		j;
	unsigned short		len1 = 0, len2 = 0, len3 = 0;
	unsigned char		is_last = 0;
	struct monitors_info	new_monitors[MONITORS_COUNT];
	int			new_monitors_used = 0;
	char			monitor_id;
	char			mode_id;
	int			event;
	unsigned long		flags;

	memset(new_monitors, 0, sizeof(struct monitors_info) *
		MONITORS_COUNT);

	while (!is_last) {
		if (i % 3 == 0) {
			len1 = monitors_settings_string_get_next_word_len(
				str, &is_last);

			/*
			 * We check, if input string is an empty string, or if
			 * it is an invalid string (without monitor name or
			 * number), or if it is a valid string.
			 */
			if (is_last && (i || len1 > 1 || (len1 &&
				strncmp(str, "\n", 1)))) {
				pr_err("Failed to adjust monitors (invalid "
					"settings string).\n");
				return;
			}
		} else if (i % 3 == 1) {
			len2 = monitors_settings_string_get_next_word_len(
				str + len1 + 1, &is_last);

			if (is_last) {
				pr_err("Failed to adjust monitors (invalid "
					"settings string).\n");
				return;
			}
		} else {
			len3 = monitors_settings_string_get_next_word_len(
				str + len1 + len2 + 2, &is_last);

			monitor_id = lookup_monitors_id(str, len1);
			if (monitor_id == -1) {
				pr_err("Failed to adjust monitors (invalid "
					"monitor name).\n");
				return;
			}

			mode_id = lookup_monitors_mode_id(
						str + len1 + 1, len2);
			if (mode_id == -1) {
				pr_err("Failed to adjust monitors (invalid "
					"mode name).\n");
				return;
			}

			event = lookup_monitors_event(str + len1 + len2 + 2,
					len3, monitor_id);
			if (event == -1) {
				pr_err("Failed to adjust monitors (invalid "
					"event number).\n");
				return;
			}

			new_monitors[(unsigned char)
				monitor_id].is_used = 1;
			new_monitors[(unsigned char)
				monitor_id].event = event;
			new_monitors[(unsigned char)
				monitor_id].mode = mode_id;

			str += len1 + len2 + len3 + 3;
		}

		i++;
	}

	raw_spin_lock_irqsave(&monitors_lock, flags);

	for (i = 0; i < MONITORS_COUNT; i++) {
		if ((new_monitors[i].is_used && !monitors[i].is_used) ||
			(new_monitors[i].is_used && monitors[i].is_used &&
				(new_monitors[i].event != monitors[i].event ||
					new_monitors[i].mode !=
						monitors[i].mode))) {
			for (j = 0; j < NR_CPUS; j++)
				atomic64_set(&common_events_count[j][i], 0);
		}

		if (new_monitors[i].is_used)
			new_monitors_used |= 1 << i;
	}

	memcpy(monitors, new_monitors,
		sizeof(struct monitors_info) * MONITORS_COUNT);

	monitors_used = new_monitors_used;

	raw_spin_unlock_irqrestore(&monitors_lock, flags);
}

static ssize_t monitors_settings_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *data)
{
	char monitors_settings_buffer[MONITORS_SETTINGS_STR_MAX_SIZE];
	int  ret;

	memset(monitors_settings_buffer, 0, sizeof(char) *
		MONITORS_SETTINGS_STR_MAX_SIZE);

	if (count + 1 > MONITORS_SETTINGS_STR_MAX_SIZE) {
		pr_err("Failed to adjust monitors (too long settings "
			"string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(monitors_settings_buffer, buffer, count)) {
		pr_err("Failed to adjust monitors (kernel error).\n");
		ret = -EFAULT;
	} else {
		parse_monitors_settings_string(monitors_settings_buffer);
		ret = count;
	}

	return ret;
}

static int monitors_settings_proc_show(struct seq_file *m, void *data)
{	
	unsigned short	event;
	unsigned char	str_start = 1;
	char		*mode_name;
	unsigned long	flags;
	unsigned char	i;

	raw_spin_lock_irqsave(&monitors_lock, flags);

	for (i = 0; i < MONITORS_COUNT; i++) {
		if (monitors[i].is_used) {
			event = monitors[i].event;
			mode_name = monitors_mode_info[monitors[i].mode].name;

			if (str_start) {
				seq_printf(m, "%s %s 0x%x",
					monitors_id_names[i], 
					mode_name, 
					event);
				str_start = 0;
			} else
				seq_printf(m, " %s %s 0x%x",
					monitors_id_names[i], 
					mode_name, 
					event);
		}
	}

	raw_spin_unlock_irqrestore(&monitors_lock, flags);

	if (!str_start)
		seq_printf(m, "%s", "\n");

	return 0;
}

static int monitors_events_proc_show(struct seq_file *m, void *data)
{	
	unsigned long	flags;
	unsigned char	i, j;

	raw_spin_lock_irqsave(&monitors_lock, flags);

	for (i = 0; i < NR_CPUS; i++) {
		if (!cpu_online(i))
			continue;

		for (j = 0; j < MONITORS_COUNT; j++) {
			if (!monitors[j].is_used)
				continue;

			seq_printf(m, "CPU%d:%s:%s:0x%x=%lu\n",
				i, 
				monitors_id_names[j], 
				monitors_mode_info[monitors[j].mode].name, 
				monitors[j].event,
				atomic64_read(&common_events_count[i][j]));
		}
	}

	raw_spin_unlock_irqrestore(&monitors_lock, flags);

	return 0;
}

static int monitors_dead_proc_events_seq_show(struct seq_file *s, void *v)
{
	unsigned char			dead_proc_id;
	dead_proc_events_t		dead_proc_event;
	pid_t				pid;
	cpumask_t			cpus_mask;
	struct monitors_info		monitor;
	unsigned long			events_count;
	unsigned char			i, j;

	dead_proc_id = *((loff_t *)v);

	if (dead_proc_events_buf_full_tmp)
		dead_proc_id =
			(dead_proc_events_buf_id_tmp + dead_proc_id + 1) %
				DEAD_PROC_EVENTS_COUNT;

	dead_proc_event = dead_proc_events_buf_tmp[dead_proc_id];
	pid = dead_proc_event.pid;
	cpus_mask = dead_proc_event.cpus_mask;

	seq_printf(s, "pid=%d:\n", pid);

	for (i = 0; i < NR_CPUS; i++) {
		if (!cpu_isset(i, cpus_mask))
			continue;

		for (j = 0; j < MONITORS_COUNT; j++) {
			monitor = dead_proc_event.monitors[j];

			if (!monitor.is_used)
				continue;

			events_count =
				dead_proc_event.monitors_count[i][j];

			seq_printf(s, "CPU%d:%s:%s:0x%x=%lu\n",
				i,
				monitors_id_names[j],
				monitors_mode_info[monitor.mode].name,
				monitor.event,
				events_count);
		}
	}

	return 0;
}

static void *monitors_dead_proc_events_seq_start(
				struct seq_file *s, loff_t *pos)
{
	unsigned char dead_proc_count;
	unsigned long flags;

	raw_spin_lock(&dead_proc_lock_tmp);

	if (*pos == 0) {
		raw_spin_lock_irqsave(&dead_proc_lock, flags);

		memcpy(dead_proc_events_buf_tmp, dead_proc_events_buf,
			sizeof(dead_proc_events_t) * DEAD_PROC_EVENTS_COUNT);
		dead_proc_events_buf_id_tmp = dead_proc_events_buf_id;
		dead_proc_events_buf_full_tmp = dead_proc_events_buf_full;

		dead_proc_events_buf_id = -1;
		dead_proc_events_buf_full = 0;

		raw_spin_unlock_irqrestore(&dead_proc_lock, flags);
	}

	if (dead_proc_events_buf_full_tmp)
		dead_proc_count = DEAD_PROC_EVENTS_COUNT;
	else
		dead_proc_count = dead_proc_events_buf_id_tmp + 1;

	if (*pos >= dead_proc_count)
		return 0;

	return (void *)pos;
}

static void *monitors_dead_proc_events_seq_next(struct seq_file *s, void *v,
				loff_t *pos)
{
	unsigned char dead_proc_count;

	(*pos)++;

	if (dead_proc_events_buf_full_tmp)
		dead_proc_count = DEAD_PROC_EVENTS_COUNT;
	else
		dead_proc_count = dead_proc_events_buf_id_tmp + 1;

	if (*pos >= dead_proc_count)
		return 0;

	return (void *)pos;
}

static void monitors_dead_proc_events_seq_stop(struct seq_file *s, void *v)
{
	/*
	 * We unlock dead_proc_lock_tmp here, because we could not lock it
	 * for a long time and perform user code with it is locked. But one
	 * could 'cat /proc/monitors/dead_proc_events' simultaneously with us.
	 * In this case we recieve wrong data for some dead processes. Now we
	 * do nothing with it.
	 */
	raw_spin_unlock(&dead_proc_lock_tmp);
}

static const struct seq_operations monitors_dead_proc_events_seq_ops = {
	.start = monitors_dead_proc_events_seq_start,
	.next  = monitors_dead_proc_events_seq_next,
	.stop  = monitors_dead_proc_events_seq_stop,
	.show  = monitors_dead_proc_events_seq_show
};

static int monitors_dead_proc_events_proc_open(struct inode *inode,
			struct file *file)
{
	return seq_open(file, &monitors_dead_proc_events_seq_ops);
}

static const struct file_operations monitors_dead_proc_events_proc_ops = {
	.owner   = THIS_MODULE,
	.open    = monitors_dead_proc_events_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

static int monitors_help_seq_show(struct seq_file *s, void *v)
{
	unsigned char id = *((loff_t *)v);
	unsigned char i;

	if (id == DIM0) {
		seq_printf(s, "I0, I1 events:\n");
		for (i = 0; i < dim_monitors_events_range_count; i++) {
			if (i)
				seq_printf(s, ", ");
			if (dim_monitors_events_list[i].start !=
					dim_monitors_events_list[i].end)
				seq_printf(s, "0x%x, ..., 0x%x",
					dim_monitors_events_list[i].start,
					dim_monitors_events_list[i].end);
			else
				seq_printf(s, "0x%x",
					dim_monitors_events_list[i].end);
		}
	} else if (id == DDM0) {
		seq_printf(s, "\nD0 events:\n");
		for (i = 0; i < ddm0_monitors_events_range_count; i++) {
			if (i)
				seq_printf(s, ", ");
			if (ddm0_monitors_events_list[i].start !=
					ddm0_monitors_events_list[i].end)
				seq_printf(s, "0x%x, ..., 0x%x",
					ddm0_monitors_events_list[i].start,
					ddm0_monitors_events_list[i].end);
			else
				seq_printf(s, "0x%x",
					ddm0_monitors_events_list[i].end);
		}
	} else if (id == DDM1) {
		seq_printf(s, "\nD1 events:\n");
		for (i = 0; i < ddm1_monitors_events_range_count; i++) {
			if (i)
				seq_printf(s, ", ");
			if (ddm1_monitors_events_list[i].start !=
					ddm1_monitors_events_list[i].end)
				seq_printf(s, "0x%x, ..., 0x%x",
					ddm1_monitors_events_list[i].start,
					ddm1_monitors_events_list[i].end);
			else
				seq_printf(s, "0x%x",
					ddm1_monitors_events_list[i].end);
		}
	} else if (id == MONITORS_COUNT) {
		seq_printf(s, "\nSetting example:\n"
			"echo \"D0 S 0x1 D1 C 0x2\" > "
			"/proc/monitors/monitors_settings\n");
	}

	return 0;
}

static void *monitors_help_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= MONITORS_COUNT + 1)
		return 0;
	return (void *)pos;
}

static void *monitors_help_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos >= MONITORS_COUNT + 1)
		return 0;
	return (void *)pos;
}

static void monitors_help_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations monitors_help_seq_ops = {
	.start = monitors_help_seq_start,
	.next  = monitors_help_seq_next,
	.stop  = monitors_help_seq_stop,
	.show  = monitors_help_seq_show
};

static int monitors_help_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &monitors_help_seq_ops);
}

static const struct file_operations monitors_help_proc_ops = {
	.owner		= THIS_MODULE,
	.open		= monitors_help_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release
};


/*
 * SIC monitors
 */

static int sicmonitors_events_proc_show(struct seq_file *m, void *data)
{
	e2k_sic_mar_lo_struct_t		mar_lo_reg;
	e2k_sic_mar_hi_struct_t		mar_hi_reg;
	int				monitor_id;
	struct sicmonitors_event_info	event;
	unsigned short			event_id;
	int				node;
	unsigned long			flags;
	unsigned char			i;

	raw_spin_lock_irqsave(&sicmonitors_lock, flags);

	for (i = 0; i < SICMONITORS_COUNT; i++) {
		if (sicmonitors[i].is_used) {
			node = i / SICMONITORS_COUNT_PER_NODE;
			monitor_id = i % SICMONITORS_COUNT_PER_NODE;
			event_id = sicmonitors[i].event;

			switch (monitor_id) {
			case MCM0:
				event = MCM0_event_info[event_id];
				mar_lo_reg.E2K_SIC_MAR_LO_reg =
					sic_read_node_nbsr_reg(
						node, SIC_sic_mar0_lo);
				mar_hi_reg.E2K_SIC_MAR_HI_reg =
					sic_read_node_nbsr_reg(
						node, SIC_sic_mar0_hi);
				break;
			case MCM1:
				event = MCM1_event_info[event_id];
				mar_lo_reg.E2K_SIC_MAR_LO_reg =
					sic_read_node_nbsr_reg(
						node, SIC_sic_mar1_lo);
				mar_hi_reg.E2K_SIC_MAR_HI_reg =
					sic_read_node_nbsr_reg(
						node, SIC_sic_mar1_hi);
				break;
			default:
				continue;
			}

			seq_printf(m, "NODE%d:%s:%s(0x%x)=0x%x%x\n",
					node,
					sicmonitors_id_names[monitor_id],
					event.name,
					event.event,
					mar_hi_reg.E2K_SIC_MAR_HI_val,
					mar_lo_reg.E2K_SIC_MAR_LO_val);
		}
	}

	raw_spin_unlock_irqrestore(&sicmonitors_lock, flags);

	return 0;
}

static inline char lookup_sicmonitors_id(char *str, unsigned short len)
{
	unsigned char i;
	char *name;

	for (i = 0; i < SICMONITORS_COUNT; i++) {
		name = sicmonitors_id_names[i];

		if (len == strlen(name) && strncmp(str, name, len) == 0)
			return i;
	}

	return -1;
}

static inline short lookup_sicmonitors_event_id(char *str, unsigned short len,
				int monitor)
{
	unsigned char			i;
	char				*name;
	unsigned short			event;
	int				input_event;
	unsigned char			is_event_as_num = 0;
	unsigned short			events_count;
	struct sicmonitors_event_info	*event_info;

	is_event_as_num = sscanf(str, "0x%X", &input_event);

	switch (monitor) {
	case MCM0:
		events_count = MCM0_EVENTS_COUNT;
		event_info   = MCM0_event_info;
		break;
	case MCM1:
		events_count = MCM1_EVENTS_COUNT;
		event_info   = MCM1_event_info;
		break;
	default:
		return -1;
	}

	for (i = 0; i < events_count; i++) {
		name  = event_info[i].name;
		event = event_info[i].event;

		/*
		 * We can set event, using event name or using event number.
		 */
		if ((len == strlen(name) && strncmp(str, name, len) == 0) ||
			(is_event_as_num && event == input_event))
			return i;
	}

	return -1;
}

static void sicmonitors_adjust(int node, int monitor,
					struct sicmonitors_info *new_monitors)
{
	e2k_sic_mcr_struct_t	mcr_reg;
	e2k_sic_mar_lo_struct_t	mar_lo_reg;
	e2k_sic_mar_hi_struct_t	mar_hi_reg;
	unsigned short		event_id;
	int			idx;

	idx = node * SICMONITORS_COUNT_PER_NODE + monitor;
	event_id = new_monitors[idx].event;

	mcr_reg.E2K_SIC_MCR_reg = sic_read_node_nbsr_reg(node, SIC_sic_mcr);
	mar_lo_reg.E2K_SIC_MAR_LO_reg = 0;
	mar_hi_reg.E2K_SIC_MAR_HI_reg = 0;

	if (monitor == MCM0) {
		mcr_reg.E2K_SIC_MCR_v0 = new_monitors[idx].is_used;
		mcr_reg.E2K_SIC_MCR_es0 = MCM0_event_info[event_id].event;

		sic_write_node_nbsr_reg(
			node, SIC_sic_mcr, mcr_reg.E2K_SIC_MCR_reg);
		sic_write_node_nbsr_reg(
			node, SIC_sic_mar0_lo, mar_lo_reg.E2K_SIC_MAR_LO_reg);
		sic_write_node_nbsr_reg(
			node, SIC_sic_mar0_hi, mar_hi_reg.E2K_SIC_MAR_HI_reg);
	} else if (monitor == MCM1) {
		mcr_reg.E2K_SIC_MCR_v1 = new_monitors[idx].is_used;
		mcr_reg.E2K_SIC_MCR_es1 = MCM1_event_info[event_id].event;

		sic_write_node_nbsr_reg(
			node, SIC_sic_mcr, mcr_reg.E2K_SIC_MCR_reg);
		sic_write_node_nbsr_reg(
			node, SIC_sic_mar1_lo, mar_lo_reg.E2K_SIC_MAR_LO_reg);
		sic_write_node_nbsr_reg(
			node, SIC_sic_mar1_hi, mar_hi_reg.E2K_SIC_MAR_HI_reg);
	}
}

static inline void parse_sicmonitors_settings_string(char *str)
{
	unsigned short		i = 0;
	unsigned short		len1 = 0, len2 = 0, len3 = 0;
	unsigned char		is_last = 0;
	struct sicmonitors_info	new_monitors[SICMONITORS_COUNT];
	int			node;
	char			monitor_id;
	short			event_id;
	unsigned long		flags;

	memset(new_monitors, 0, sizeof(struct sicmonitors_info) *
		SICMONITORS_COUNT);

	while (!is_last) {
		if (i % 3 == 0) {
			len1 = monitors_settings_string_get_next_word_len(
				str, &is_last);

			/*
			 * We check, if input string is an empty string, or if
			 * it is an invalid string (without sicmonitor name or
			 * number), or if it is a valid string.
			 */
			if (is_last && (i || len1 > 1 || (len1 &&
				strncmp(str, "\n", 1)))) {
				pr_err("Failed to adjust sicmonitors (invalid "
					"settings string).\n");
				return;
			}
		} else if (i % 3 == 1) {
			len2 = monitors_settings_string_get_next_word_len(
				str + len1 + 1, &is_last);

			if (is_last) {
				pr_err("Failed to adjust sicmonitors (invalid "
					"settings string).\n");
				return;
			}
		} else {
			len3 = monitors_settings_string_get_next_word_len(
				str + len1 + len2 + 2, &is_last);

			node = NUMA_NO_NODE;
			sscanf(str, "%d", &node);
			if (!node_online(node)) {
				pr_err("Failed to adjust sicmonitors (invalid "
					"node number).\n");
				return;
			}

			monitor_id = lookup_sicmonitors_id(
					str + len1 + 1, len2);
			if (monitor_id == -1) {
				pr_err("Failed to adjust sicmonitors (invalid "
					"monitor name).\n");
				return;
			}

			event_id = lookup_sicmonitors_event_id(
					str + len1 + len2 + 2,
					len3, monitor_id);
			if (event_id == -1) {
				pr_err("Failed to adjust sicmonitors (invalid "
					"event name or number).\n");
				return;
			}

			monitor_id += node * SICMONITORS_COUNT_PER_NODE;

			new_monitors[(unsigned char)
				monitor_id].is_used = 1;
			new_monitors[(unsigned char)
				monitor_id].event = event_id;

			str += len1 + len2 + len3 + 3;
		}

		i++;
	}

	raw_spin_lock_irqsave(&sicmonitors_lock, flags);

	for (i = 0; i < SICMONITORS_COUNT; i++) {
		if (new_monitors[i].is_used != sicmonitors[i].is_used ||
				new_monitors[i].event !=
					sicmonitors[i].event) {
			sicmonitors_adjust(i / SICMONITORS_COUNT_PER_NODE,
				i % SICMONITORS_COUNT_PER_NODE, new_monitors);
		}
	}

	memcpy(sicmonitors, new_monitors,
		sizeof(struct sicmonitors_info) * SICMONITORS_COUNT);

	raw_spin_unlock_irqrestore(&sicmonitors_lock, flags);
}

static ssize_t sicmonitors_settings_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *data)
{
	char monitors_settings_buffer[SICMONITORS_SETTINGS_STR_MAX_SIZE];
	int  ret;

	memset(monitors_settings_buffer, 0, sizeof(char) *
		SICMONITORS_SETTINGS_STR_MAX_SIZE);

	if (count + 1 > SICMONITORS_SETTINGS_STR_MAX_SIZE) {
		pr_err("Failed to adjust sicmonitors (too long settings "
			"string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(monitors_settings_buffer, buffer, count)) {
		pr_err("Failed to adjust sicmonitors (kernel error).\n");
		ret = -EFAULT;
	} else {
		parse_sicmonitors_settings_string(monitors_settings_buffer);
		ret = count;
	}

	return ret;
}

static int sicmonitors_settings_proc_show(struct seq_file *m, void *data)
{
	int				monitor_id;
	struct sicmonitors_event_info	event;
	unsigned short			event_id;
	int				node;
	unsigned char			str_start = 1;
	unsigned long			flags;
	unsigned char			i;

	raw_spin_lock_irqsave(&sicmonitors_lock, flags);

	for (i = 0; i < SICMONITORS_COUNT; i++) {
		if (sicmonitors[i].is_used) {
			node = i / SICMONITORS_COUNT_PER_NODE;
			monitor_id = i % SICMONITORS_COUNT_PER_NODE;
			event_id = sicmonitors[i].event;

			switch (monitor_id) {
			case MCM0:
				event = MCM0_event_info[event_id];
				break;
			case MCM1:
				event = MCM1_event_info[event_id];
				break;
			default:
				continue;
			}

			if (str_start) {
				seq_printf(m, "NODE%d %s %s(0x%x)",
					node,
					sicmonitors_id_names[monitor_id],
					event.name,
					event.event);
				str_start = 0;
			} else
				seq_printf(m, " NODE%d %s %s(0x%x)",
					node,
					sicmonitors_id_names[monitor_id],
					event.name,
					event.event);
		}
	}

	raw_spin_unlock_irqrestore(&sicmonitors_lock, flags);

	if (!str_start)
		seq_printf(m, "%s", "\n");

	return 0;
}

static int sicmonitors_help_seq_show(struct seq_file *s, void *v)
{
	unsigned char id = *((loff_t *)v);
	unsigned char i;

	if (id == MCM0) {
		seq_printf(s, "M0 events:\n");

		for (i = 0; i < MCM0_EVENTS_COUNT; i++)
			seq_printf(s, "%s=0x%x\n",
				   MCM0_event_info[i].name,
				   MCM0_event_info[i].event);
	} else if (id == MCM1) {
		seq_printf(s, "\nM1 events:\n");

		for (i = 0; i < MCM1_EVENTS_COUNT; i++)
			seq_printf(s, "%s=0x%x\n",
				   MCM1_event_info[i].name,
				   MCM1_event_info[i].event);
	} else if (id == SICMONITORS_COUNT_PER_NODE) {
		seq_printf(s, "\nSetting example:\n"
			"echo \"0 M0 0x2 0 M1 SIC_MC_READ_LOCAL\" > "
			"/proc/monitors/sicmonitors_settings\n");
	}

	return 0;
}

static void *sicmonitors_help_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= SICMONITORS_COUNT_PER_NODE + 1)
		return 0;
	return (void *)pos;
}

static void *sicmonitors_help_seq_next(struct seq_file *s, void *v,
						loff_t *pos)
{
	(*pos)++;
	if (*pos >= SICMONITORS_COUNT_PER_NODE + 1)
		return 0;
	return (void *)pos;
}

static void sicmonitors_help_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations sicmonitors_help_seq_ops = {
	.start = sicmonitors_help_seq_start,
	.next  = sicmonitors_help_seq_next,
	.stop  = sicmonitors_help_seq_stop,
	.show  = sicmonitors_help_seq_show
};

static int sicmonitors_help_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sicmonitors_help_seq_ops);
}

static const struct file_operations sicmonitors_help_proc_ops = {
	.owner		= THIS_MODULE,
	.open		= sicmonitors_help_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release
};


/*
 * IPCC monitors
 */

static int ipccmonitors_events_proc_show(struct seq_file *m, void *data)
{
	e2k_ipcc_str_struct_t		ipcc_str_reg;
	struct ipccmonitors_event_info	event;
	unsigned short			event_id;
	int				node;
	unsigned long			flags;
	unsigned char			i;

	raw_spin_lock_irqsave(&ipccmonitors_lock, flags);

	if (ipccmonitors.is_used) {
		event_id = ipccmonitors.event;
		event = IPCC_event_info[event_id];

		for_each_online_node(node) {
			for (i = 1; i < SIC_IPCC_LINKS_COUNT + 1; i++) {
				ipcc_str_reg.E2K_IPCC_STR_reg =
					sic_get_ipcc_str(node, i);

				seq_printf(m, "NODE%d:IPCC%d:%s(0x%x)=0x%x\n",
					node, i,
					event.name,
					event.event,
					ipcc_str_reg.E2K_IPCC_STR_ecnt);
			}
		}
	}

	raw_spin_unlock_irqrestore(&ipccmonitors_lock, flags);

	return 0;
}

static inline short lookup_ipccmonitors_event_id(char *str, unsigned short len)
{
	unsigned char			i;
	char				*name;
	unsigned short			event;
	int				input_event;
	unsigned char			is_event_as_num = 0;

	is_event_as_num = sscanf(str, "0x%X", &input_event);

	for (i = 0; i < IPCC_EVENTS_COUNT; i++) {
		name  = IPCC_event_info[i].name;
		event = IPCC_event_info[i].event;

		/*
		 * We can set event, using event name or using event number.
		 */
		if ((len == strlen(name) && strncmp(str, name, len) == 0) ||
			(is_event_as_num && event == input_event))
			return i;
	}

	return -1;
}

static void ipccmonitors_adjust(struct ipccmonitors_info new_monitors)
{
	e2k_ipcc_str_struct_t	ipcc_str_reg;
	unsigned short		event_id = new_monitors.event;
	int			node;
	int			i;

	for_each_online_node(node) {
		for (i = 1; i < SIC_IPCC_LINKS_COUNT + 1; i++) {
			ipcc_str_reg.E2K_IPCC_STR_reg =
				sic_get_ipcc_str(node, i);

			ipcc_str_reg.E2K_IPCC_STR_ecf =
				(new_monitors.is_used ?
					IPCC_event_info[event_id].event : 0);
			ipcc_str_reg.E2K_IPCC_STR_eco = 1;

			sic_set_ipcc_str(
				node, i, ipcc_str_reg.E2K_IPCC_STR_reg);
		}
	}
}

static inline void parse_ipccmonitors_settings_string(char *str)
{
	unsigned short			len = 0;
	unsigned char			is_last = 0;
	struct ipccmonitors_info	new_monitors;
	short				event_id;
	unsigned long			flags;

	memset(&new_monitors, 0, sizeof(struct ipccmonitors_info));

	len = monitors_settings_string_get_next_word_len(str, &is_last);

	if (!is_last) {
		pr_err("Failed to adjust ipccmonitors (invalid settings "
			"string).\n");
		return;
	}

	if (len && strncmp(str, "\n", 1)) {
		event_id = lookup_ipccmonitors_event_id(str, len);
		if (event_id == -1) {
			pr_err("Failed to adjust ipccmonitors (invalid event "
				"name or number).\n");
			return;
		}

		new_monitors.is_used = 1;
		new_monitors.event = event_id;
	}

	raw_spin_lock_irqsave(&ipccmonitors_lock, flags);

	if (new_monitors.is_used != ipccmonitors.is_used ||
			new_monitors.event !=
				ipccmonitors.event) {
		ipccmonitors_adjust(new_monitors);
	}

	memcpy(&ipccmonitors, &new_monitors, sizeof(struct ipccmonitors_info));

	raw_spin_unlock_irqrestore(&ipccmonitors_lock, flags);
}

static ssize_t ipccmonitors_settings_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *data)
{
	char monitors_settings_buffer[IPCCMONITORS_SETTINGS_STR_MAX_SIZE];
	int  ret;

	memset(monitors_settings_buffer, 0, sizeof(char) *
		IPCCMONITORS_SETTINGS_STR_MAX_SIZE);

	if (count + 1 > IPCCMONITORS_SETTINGS_STR_MAX_SIZE) {
		pr_err("Failed to adjust ipccmonitors (too long settings "
			"string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(monitors_settings_buffer, buffer, count)) {
		pr_err("Failed to adjust ipccmonitors (kernel error).\n");
		ret = -EFAULT;
	} else {
		parse_ipccmonitors_settings_string(monitors_settings_buffer);
		ret = count;
	}

	return ret;
}

static int ipccmonitors_settings_proc_show(struct seq_file *m, void *data)
{
	struct ipccmonitors_event_info	event;
	unsigned short			event_id;
	unsigned char			is_used;
	unsigned long			flags;

	raw_spin_lock_irqsave(&ipccmonitors_lock, flags);
	is_used = ipccmonitors.is_used;
	event_id = ipccmonitors.event;
	raw_spin_unlock_irqrestore(&ipccmonitors_lock, flags);

	if (is_used) {
		event = IPCC_event_info[event_id];
		seq_printf(m, "%s(0x%x)\n", event.name, event.event);
	}

	return 0;
}

static int ipccmonitors_help_seq_show(struct seq_file *s, void *v)
{
	unsigned char i;

	seq_printf(s, "Events:\n");

	for (i = 0; i < IPCC_EVENTS_COUNT; i++)
		seq_printf(s, "%s=0x%x\n",
			IPCC_event_info[i].name,
			IPCC_event_info[i].event);

	seq_printf(s, "\nSetting example:\n"
		"echo \"0x1\" > /proc/monitors/ipccmonitors_settings\n"
		"echo \"IPCC_LERR\" > /proc/monitors/ipccmonitors_settings\n");

	return 0;
}

static void *ipccmonitors_help_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= IPCCMONITORS_COUNT)
		return 0;
	return (void *)pos;
}

static void *ipccmonitors_help_seq_next(struct seq_file *s, void *v,
						loff_t *pos)
{
	(*pos)++;
	if (*pos >= IPCCMONITORS_COUNT)
		return 0;
	return (void *)pos;
}

static void ipccmonitors_help_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations ipccmonitors_help_seq_ops = {
	.start = ipccmonitors_help_seq_start,
	.next  = ipccmonitors_help_seq_next,
	.stop  = ipccmonitors_help_seq_stop,
	.show  = ipccmonitors_help_seq_show
};

static int ipccmonitors_help_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ipccmonitors_help_seq_ops);
}

static const struct file_operations ipccmonitors_help_proc_ops = {
	.owner		= THIS_MODULE,
	.open		= ipccmonitors_help_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release
};


/*
 * IOCC monitors
 */

static int ioccmonitors_events_proc_show(struct seq_file *m, void *data)
{
	e2k_io_str_struct_t		io_str_reg;
	struct ioccmonitors_event_info	event;
	unsigned short			event_id;
	int				node;
	char				*s;
	unsigned long			flags;
	unsigned char			i;

	raw_spin_lock_irqsave(&ioccmonitors_lock, flags);

	if (ioccmonitors.is_used) {
		event_id = ioccmonitors.event;
		event = IOCC_event_info[event_id];

		for_each_online_node(node) {
			for (i = 0; i < SIC_IO_LINKS_COUNT; i++) {
				io_str_reg.E2K_IO_STR_reg =
					sic_get_io_str(node, i);

				if (!i)
					s = "IOCC";
				else if (IS_MACHINE_E2S)
					s = "IOCC_HI";
				else
					s = "IOCC1";

				seq_printf(m, "NODE%d:%s:%s(0x%x)=0x%x\n",
					node, s,
					event.name,
					event.event,
					io_str_reg.E2K_IO_STR_rc);
			}
		}
	}

	raw_spin_unlock_irqrestore(&ioccmonitors_lock, flags);

	return 0;
}

static inline short lookup_ioccmonitors_event_id(char *str, unsigned short len)
{
	unsigned char			i;
	char				*name;
	unsigned short			event;
	int				input_event;
	unsigned char			is_event_as_num = 0;

	is_event_as_num = sscanf(str, "0x%X", &input_event);

	for (i = 0; i < IOCC_EVENTS_COUNT; i++) {
		name  = IOCC_event_info[i].name;
		event = IOCC_event_info[i].event;

		/*
		 * We can set event, using event name or using event number.
		 */
		if ((len == strlen(name) && strncmp(str, name, len) == 0) ||
			(is_event_as_num && event == input_event))
			return i;
	}

	return -1;
}

static void ioccmonitors_adjust(struct ioccmonitors_info new_monitors)
{
	e2k_io_str_struct_t	io_str_reg;
	unsigned short		event_id = new_monitors.event;
	int			node;
	int			i;

	for_each_online_node(node) {
		for (i = 0; i < SIC_IO_LINKS_COUNT; i++) {
			io_str_reg.E2K_IO_STR_reg = sic_get_io_str(node, i);

			io_str_reg.E2K_IO_STR_reg &= ~E2K_IO_STR_EVENT_MASK;
			if (new_monitors.is_used)
				io_str_reg.E2K_IO_STR_reg |=
					IOCC_event_info[event_id].event <<
							E2K_IO_STR_EVENT_SHIFT;
			io_str_reg.E2K_IO_STR_rcol = 1;

			sic_set_io_str(node, i, io_str_reg.E2K_IO_STR_reg);
		}
	}
}

static inline void parse_ioccmonitors_settings_string(char *str)
{
	unsigned short			len = 0;
	unsigned char			is_last = 0;
	struct ioccmonitors_info	new_monitors;
	short				event_id;
	unsigned long			flags;

	memset(&new_monitors, 0, sizeof(struct ioccmonitors_info));

	len = monitors_settings_string_get_next_word_len(str, &is_last);

	if (!is_last) {
		pr_err("Failed to adjust ioccmonitors (invalid settings "
			"string).\n");
		return;
	}

	if (len && strncmp(str, "\n", 1)) {
		event_id = lookup_ioccmonitors_event_id(str, len);
		if (event_id == -1) {
			pr_err("Failed to adjust ioccmonitors (invalid event "
				"name or number).\n");
			return;
		}

		new_monitors.is_used = 1;
		new_monitors.event = event_id;
	}

	raw_spin_lock_irqsave(&ioccmonitors_lock, flags);

	if (new_monitors.is_used != ioccmonitors.is_used ||
			new_monitors.event !=
				ioccmonitors.event) {
		ioccmonitors_adjust(new_monitors);
	}

	memcpy(&ioccmonitors, &new_monitors, sizeof(struct ioccmonitors_info));

	raw_spin_unlock_irqrestore(&ioccmonitors_lock, flags);
}

static ssize_t ioccmonitors_settings_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *data)
{
	char monitors_settings_buffer[IOCCMONITORS_SETTINGS_STR_MAX_SIZE];
	int  ret;

	memset(monitors_settings_buffer, 0, sizeof(char) *
		IOCCMONITORS_SETTINGS_STR_MAX_SIZE);

	if (count + 1 > IOCCMONITORS_SETTINGS_STR_MAX_SIZE) {
		pr_err("Failed to adjust ioccmonitors (too long settings "
			"string).\n");
		ret = -EINVAL;
	} else if (copy_from_user(monitors_settings_buffer, buffer, count)) {
		pr_err("Failed to adjust ioccmonitors (kernel error).\n");
		ret = -EFAULT;
	} else {
		parse_ioccmonitors_settings_string(monitors_settings_buffer);
		ret = count;
	}

	return ret;
}

static int ioccmonitors_settings_proc_show(struct seq_file *m, void *data)
{
	struct ioccmonitors_event_info	event;
	unsigned short			event_id;
	unsigned char			is_used;
	unsigned long			flags;

	raw_spin_lock_irqsave(&ioccmonitors_lock, flags);
	is_used = ioccmonitors.is_used;
	event_id = ioccmonitors.event;
	raw_spin_unlock_irqrestore(&ioccmonitors_lock, flags);

	if (is_used) {
		event = IOCC_event_info[event_id];
		seq_printf(m, "%s(0x%x)\n", event.name, event.event);
	}

	return 0;
}

static int ioccmonitors_help_seq_show(struct seq_file *s, void *v)
{
	unsigned char i;

	seq_printf(s, "Events:\n");

	for (i = 0; i < IOCC_EVENTS_COUNT; i++)
		seq_printf(s, "%s=0x%x\n",
			IOCC_event_info[i].name,
			IOCC_event_info[i].event);

	seq_printf(s, "\nSetting example:\n"
		"echo \"0x1\" > /proc/monitors/ioccmonitors_settings\n"
		"echo \"IOCC_BSY_RC\" > /proc/monitors/ioccmonitors_settings\n");

	return 0;
}

static void *ioccmonitors_help_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= IOCCMONITORS_COUNT)
		return 0;
	return (void *)pos;
}

static void *ioccmonitors_help_seq_next(struct seq_file *s, void *v,
						loff_t *pos)
{
	(*pos)++;
	if (*pos >= IOCCMONITORS_COUNT)
		return 0;
	return (void *)pos;
}

static void ioccmonitors_help_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations ioccmonitors_help_seq_ops = {
	.start = ioccmonitors_help_seq_start,
	.next  = ioccmonitors_help_seq_next,
	.stop  = ioccmonitors_help_seq_stop,
	.show  = ioccmonitors_help_seq_show
};

static int ioccmonitors_help_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ioccmonitors_help_seq_ops);
}

static const struct file_operations ioccmonitors_help_proc_ops = {
	.owner		= THIS_MODULE,
	.open		= ioccmonitors_help_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release
};

static int monitors_settings_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, monitors_settings_proc_show, NULL);
}

static const struct file_operations monitors_settings_proc_fops = {
	.open	 = monitors_settings_proc_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
	.write	 = monitors_settings_write,
};

static int monitors_events_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, monitors_events_proc_show, NULL);
}

static const struct file_operations monitors_events_proc_fops = {
	.open	 = monitors_events_proc_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static int sicmonitors_settings_proc_open(struct inode *inode,
					  struct file *file)
{
	return single_open(file, sicmonitors_settings_proc_show, NULL);
}

static const struct file_operations sicmonitors_settings_proc_fops = {
	.open	 = sicmonitors_settings_proc_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
	.write	 = sicmonitors_settings_write,
};

static int sicmonitors_events_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, sicmonitors_events_proc_show, NULL);
}

static const struct file_operations sicmonitors_events_proc_fops = {
	.open	 = sicmonitors_events_proc_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static int ipccmonitors_settings_proc_open(struct inode *inode,
					   struct file *file)
{
	return single_open(file, ipccmonitors_settings_proc_show, NULL);
}

static const struct file_operations ipccmonitors_settings_proc_fops = {
	.open	 = ipccmonitors_settings_proc_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
	.write	 = ipccmonitors_settings_write,
};

static int ipccmonitors_events_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, ipccmonitors_events_proc_show, NULL);
}

static const struct file_operations ipccmonitors_events_proc_fops = {
	.open	 = ipccmonitors_events_proc_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static int ioccmonitors_settings_proc_open(struct inode *inode,
					   struct file *file)
{
	return single_open(file, ioccmonitors_settings_proc_show, NULL);
}

static const struct file_operations ioccmonitors_settings_proc_fops = {
	.open	 = ioccmonitors_settings_proc_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
	.write	 = ioccmonitors_settings_write,
};

static int ioccmonitors_events_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, ioccmonitors_events_proc_show, NULL);
}

static const struct file_operations ioccmonitors_events_proc_fops = {
	.open	 = ioccmonitors_events_proc_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};


/*
 * Init
 */

static void monitors_init(void)
{
	switch (machine.iset_ver) {
	case E2K_ISET_V1:
		ddm0_monitors_events_list = ddm0_monitors_events_list_v1;
		ddm1_monitors_events_list = ddm1_monitors_events_list_v1;
		dim_monitors_events_list = dim_monitors_events_list_v1;
		ddm0_monitors_events_range_count = DDM0_EVENTS_RANGE_COUNT_V1;
		ddm1_monitors_events_range_count = DDM1_EVENTS_RANGE_COUNT_V1;
		dim_monitors_events_range_count = DIM_EVENTS_RANGE_COUNT_V1;
		break;
	case E2K_ISET_V2:
		ddm0_monitors_events_list = ddm0_monitors_events_list_v2;
		ddm1_monitors_events_list = ddm1_monitors_events_list_v2;
		dim_monitors_events_list = dim_monitors_events_list_v2;
		ddm0_monitors_events_range_count = DDM0_EVENTS_RANGE_COUNT_V2;
		ddm1_monitors_events_range_count = DDM1_EVENTS_RANGE_COUNT_V2;
		dim_monitors_events_range_count = DIM_EVENTS_RANGE_COUNT_V2;
		break;
	case E2K_ISET_V3:
		ddm0_monitors_events_list = ddm0_monitors_events_list_v3;
		ddm1_monitors_events_list = ddm1_monitors_events_list_v3;
		dim_monitors_events_list = dim_monitors_events_list_v3;
		ddm0_monitors_events_range_count = DDM0_EVENTS_RANGE_COUNT_V3;
		ddm1_monitors_events_range_count = DDM1_EVENTS_RANGE_COUNT_V3;
		dim_monitors_events_range_count = DIM_EVENTS_RANGE_COUNT_V3;
		break;
	case E2K_ISET_V4:
		ddm0_monitors_events_list = ddm0_monitors_events_list_v4;
		ddm1_monitors_events_list = ddm1_monitors_events_list_v4;
		dim_monitors_events_list = dim_monitors_events_list_v4;
		ddm0_monitors_events_range_count = DDM0_EVENTS_RANGE_COUNT_V4;
		ddm1_monitors_events_range_count = DDM1_EVENTS_RANGE_COUNT_V4;
		dim_monitors_events_range_count = DIM_EVENTS_RANGE_COUNT_V4;
		break;
	case E2K_ISET_V5:
		ddm0_monitors_events_list = ddm0_monitors_events_list_v5;
		ddm1_monitors_events_list = ddm1_monitors_events_list_v5;
		dim_monitors_events_list = dim_monitors_events_list_v5;
		ddm0_monitors_events_range_count = DDM0_EVENTS_RANGE_COUNT_V5;
		ddm1_monitors_events_range_count = DDM1_EVENTS_RANGE_COUNT_V5;
		dim_monitors_events_range_count = DIM_EVENTS_RANGE_COUNT_V5;
		break;
	default:
		BUG();
	}

	proc_create(MONITORS_SETTINGS_FILENAME, S_IRUGO | S_IWUSR,
		monitors_dir_entry, &monitors_settings_proc_fops);
	proc_create(MONITORS_EVENTS_FILENAME, S_IRUGO,
		monitors_dir_entry, &monitors_events_proc_fops);
	proc_create(MONITORS_DEAD_PROC_EVENTS_FILENAME, S_IRUGO,
		monitors_dir_entry, &monitors_dead_proc_events_proc_ops);
	proc_create(MONITORS_HELP_FILENAME, S_IRUGO,
		monitors_dir_entry, &monitors_help_proc_ops);
}

static void sicmonitors_init(void)
{
	if (!HAS_MACHINE_SICMONITORS)
		return;

	proc_create(SICMONITORS_SETTINGS_FILENAME, S_IRUGO | S_IWUSR,
		monitors_dir_entry, &sicmonitors_settings_proc_fops);
	proc_create(SICMONITORS_EVENTS_FILENAME, S_IRUGO,
		monitors_dir_entry, &sicmonitors_events_proc_fops);
	proc_create(SICMONITORS_HELP_FILENAME, S_IRUGO,
		monitors_dir_entry, &sicmonitors_help_proc_ops);
}

static void ipccmonitors_init(void)
{
	if (!HAS_MACHINE_IPCCMONITORS)
		return;

	proc_create(IPCCMONITORS_SETTINGS_FILENAME, S_IRUGO | S_IWUSR,
		monitors_dir_entry, &ipccmonitors_settings_proc_fops);
	proc_create(IPCCMONITORS_EVENTS_FILENAME, S_IRUGO,
		monitors_dir_entry, &ipccmonitors_events_proc_fops);
	proc_create(IPCCMONITORS_HELP_FILENAME, S_IRUGO,
		monitors_dir_entry, &ipccmonitors_help_proc_ops);
}

static void ioccmonitors_init(void)
{
	if (!HAS_MACHINE_IOCCMONITORS)
		return;

	proc_create(IOCCMONITORS_SETTINGS_FILENAME, S_IRUGO,
		monitors_dir_entry, &ioccmonitors_settings_proc_fops);
	proc_create(IOCCMONITORS_EVENTS_FILENAME, S_IRUGO,
		monitors_dir_entry, &ioccmonitors_events_proc_fops);
	proc_create(IOCCMONITORS_HELP_FILENAME, S_IRUGO,
		monitors_dir_entry, &ioccmonitors_help_proc_ops);
}

static int __init monitors_module_init(void)
{
	monitors_dir_entry = proc_mkdir(MONITORS_FILENAME, NULL);
	if (!monitors_dir_entry)
		return 0;

	monitors_init();
	sicmonitors_init();
	ipccmonitors_init();
	ioccmonitors_init();

	return 0;
}

module_init(monitors_module_init);

