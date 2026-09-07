/*
 * SPDX_license-Identifier: GPL-2.0  OR BSD-3-Clause
 * Copyright (c) 2015, Verisilicon Inc. - All Rights Reserved
 *
 ********************************************************************************
 *
 * GPL-2.0
 *
 ********************************************************************************
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 ********************************************************************************
 *
 * Alternatively, This software may be distributed under the terms of
 * BSD-3-Clause, in which case the following provisions apply instead of the ones
 * mentioned above :
 *
 ********************************************************************************
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "hantrodec_defs.h"
#include <linux/kernel.h>
#include <linux/module.h>
/* needed for __init,__exit directives */
#include <linux/init.h>
/* needed for remap_page_range
 * SetPageReserved
 * ClearPageReserved
 */
#include <linux/mm.h>
/* obviously, for kmalloc */
#include <linux/slab.h>
/* for struct file_operations, register_chrdev() */
#include <linux/fs.h>
/* standard error codes */
#include <linux/errno.h>

#include <linux/moduleparam.h>
/* request_irq(), free_irq() */
#include <linux/interrupt.h>
#include <linux/sched.h>

#include <linux/semaphore.h>
#include <linux/spinlock.h>
/* needed for virt_to_phys() */
#include <asm/io.h>
#ifdef PCIE_EN
#include <linux/pci.h>
#endif
#include <linux/uaccess.h>
#include <linux/ioport.h>

#include <asm/irq.h>

#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/of_device.h>
#include <linux/kthread.h>
#include <linux/platform_device.h>

/* our own stuff */
#include "subsys.h"
#include "hantrovcmd.h"
#include "hantrovcmd_priv.h"
#ifdef SUPPORT_AXIFE
#include "hantroaxife.h"
#endif
#include "hantrovcmddbgfs.h"
#include "hantroabnormalirq.h"
#include "subsys_cfg.h"
#ifdef AXI2TO1_SUPPORT
#include "hantroaxi2to1.h"
#endif

/****************************************************************
 * Macro definitions
 ***************************************************************/
#define TIMEOUT_IRQ_TIMER

/*---------------------------------------------------------------
 * Macros related to sub-system config
 *---------------------------------------------------------------
 */
/* VCMD master_out_clk mode */
#define APB_CLK_ON	(1)
#define APB_CLK_OFF	(0)
#define APB_CLK_MODE	APB_CLK_ON

/*---------------------------------------------------------------
 * Macros related to debug
 *---------------------------------------------------------------
 */

//#define VCMD_DEBUG_INTERNAL
//#define IRQ_SIMULATION

/*---------------------------------------------------------------
 * Macros related to dev/process workload management
 *---------------------------------------------------------------
 */
#define VCMD_WORKLOAD_UNIT   (8192L * 4096L)
#define VCMD_INTR_INTERVAL   (VCMD_WORKLOAD_UNIT * 8)
#define PROCESS_MAX_WORKLOAD (VCMD_WORKLOAD_UNIT * 64)


/****************************************************************
 * external/global variables declarations
 ***************************************************************/
/* PCI base register address (memalloc) */
extern unsigned long gBaseDDRHw;
extern unsigned int mmu_enable;
struct vcmd_config vcmd_core_array[MAX_SUBSYS_NUM];
extern unsigned long vcmd_isr_polling;
extern u32 arbiter_weight;
extern u32 arbiter_urgent;
extern u32 arbiter_timewindow;
extern u32 arbiter_bw_overflow;
extern unsigned long sw_timeout_time;
extern unsigned long ddr_offset;

/****************************************************************
 * local functions declarations
 ***************************************************************/
static struct cmd_jmp_t *_get_jmp_cmd(struct cmdbuf_obj *obj);
static struct cmd_end_t *_get_end_cmd(struct cmdbuf_obj *obj);

#if (KERNEL_VERSION(2, 6, 18) > LINUX_VERSION_CODE)
static irqreturn_t hantrovcmd_isr(int irq, void *dev_id, struct pt_regs *regs);
#else
static irqreturn_t hantrovcmd_isr(int irq, void *dev_id);
#endif
static void vcmd_start(struct hantrovcmd_dev *dev);

extern void abort_vcd(volatile u8 *reg_base);
/****************************************************************
 * watchdog, irq_simulation, kernel thread and debug functions
 ***************************************************************/

#ifdef IRQ_SIMULATION
struct timer_manager {
	void *vcmd_mgr;
	void *obj;
};

static struct timer_list irq_simul_timer[SLOT_NUM_CMDBUF];
struct timer_manager irq_simul_ctx[SLOT_NUM_CMDBUF];

void get_random_bytes(void *buf, int nbytes);
/**
 * @brief trigger isr processing for irq simulation.
 */
void _irq_simul_trigger_isr(struct timer_list *timer)
{
	struct cmdbuf_obj *obj;
	u32 timer_id = 0;

	timer_id = timer - irq_simul_timer;
	if (irq_simul_ctx[timer_id].obj) {
		obj = (struct cmdbuf_obj *)irq_simul_ctx[timer_id].obj;
	} else {
		vcmd_klog(LOGLVL_ERROR, "tigger isr failed, the cmdbuf obj is NULL\n");
		return;
	}

	vcmd_klog(LOGLVL_FLOW, "trigger core 0 irq\n");
	hantrovcmd_isr(obj->core_id, irq_simul_ctx[timer_id].vcmd_mgr);
	del_timer(timer);
	irq_simul_ctx[timer_id].obj = NULL;
}

/**
 * @brief add timer for irq simulation.
 */
void _irq_simul_add_timer(struct cmdbuf_obj *obj)
{
	u64 random_num;
	struct timer_list *temp_timer = NULL;

	//get_random_bytes(&random_num, sizeof(u32));
	random_num = (u32)((u64)100 * obj->workload / VCMD_WORKLOAD_UNIT + 50);
	vcmd_klog(LOGLVL_FLOW, "random_num=%lld\n", random_num);

	temp_timer = &irq_simul_timer[obj->cmdbuf_id];
	irq_simul_ctx[obj->cmdbuf_id].obj = (void *)obj;

	//if (obj->core_id==0)
	{
		//init_timer(&timer0);
		//timer0.function =
		//hantrovcmd_trigger_irq_0;
		timer_setup(temp_timer, _irq_simul_trigger_isr, 0);
		//the expires time is 1s
		temp_timer->expires = jiffies + random_num * HZ / 10;
		add_timer(temp_timer);
	}
}

/**
 * @brief init timers for irq simulation.
 */
void _irq_simul_init(void *vcmd_mgr)
{
	u32 i;

	for (i = 0; i < SLOT_NUM_CMDBUF; i++) {
		irq_simul_ctx[i].obj = NULL;
		irq_simul_ctx[i].vcmd_mgr = vcmd_mgr;
	}
}
#endif //IRQ_SIMULATION

#ifdef SUPPORT_WATCHDOG
/**
 * @brief hook function for system-driver to do further process
 *  for tiggered watchdog.
 */
static void hook_vcmd_watchdog(struct hantrovcmd_dev *dev, int succeed)
{
	if (succeed) {
		/*watchdog process successful*/
		vcmd_klog(LOGLVL_ERROR, "flush succeed!!");
	} else {
		/*watchdog process failed*/
		vcmd_klog(LOGLVL_ERROR, "flush failed, need to re-power sub-system");
	}
}

/**
 * @brief reset vcmd arbiter when VCARB hang
 */
static void watchdog_reset_vcmd_arbiter(struct hantrovcmd_dev *dev)
{
	u32 arb = 0;
	int loop_cnt = 0;
	unsigned long flags;

	spin_lock_irqsave(dev->spinlock, flags);
	arb = vcmd_read_reg((const void *)dev->hwregs,
						VCMD_REGISTER_ARB_OFFSET);
	arb &= 0xfffffff8;
	vcmd_write_reg((const void *)dev->hwregs, VCMD_REGISTER_ARB_OFFSET, arb);
	spin_unlock_irqrestore(dev->spinlock, flags);

	do {
		if (dev->arb_reset_irq == 1) {
			dev->arb_reset_irq = 0;
			vcmd_klog(LOGLVL_BRIEF, "VCARB is hang, reset it!\n");
			return;
		}
		mdelay(10); // wait 10ms
	} while (++loop_cnt < 100);

	vcmd_klog(LOGLVL_ERROR, "Reseted VCARB, but failed!\n");
}

/**
 * @brief watchdog wait vcmd abort done
 */
static int watchdog_wait_vcmd_aborted(struct hantrovcmd_dev *dev)
{
	int loop_cnt = 0;
	u32 state;

	do {
		state = vcmd_get_register_value((const void *)dev->hwregs,
									dev->reg_mirror, HWIF_VCMD_WORK_STATE);
		if (state == HW_WORK_STATE_IDLE) {
			//aborted
			return 0;
		}
		mdelay(10); // wait 10ms
	} while (++loop_cnt < 100);

	vcmd_klog(LOGLVL_ERROR, "%s, can't go to IDLE, need to re-power sub-system!\n",
			  __func__);

	return -1;
}

/**
 * @brief stop vcmd when watchdog triggered
 */
static int watchdog_stop_vcmd(struct hantrovcmd_dev *dev)
{
	u32 state;

	vcmd_klog(LOGLVL_WARNING, "enter %s\n", __func__);

	state = vcmd_get_register_value((const void *)dev->hwregs,
				dev->reg_mirror, HWIF_VCMD_WORK_STATE);

	if (state == HW_WORK_STATE_IDLE || state == HW_WORK_STATE_PEND) {
		dev->state = VCMD_STATE_POWER_ON;
		return 0;
	}

	//if state is not in IDLE/PEND, abort VCMD by sw.
	if (dev->hw_feature.vcarb_ver == VCARB_VERSION_2_0) {
		vcmd_set_reg_mirror(dev->reg_mirror, HWIF_VCMD_ABORT_MODE, 0x0);
	} else {
		dev->abort_mode = 0x1;
		vcmd_set_reg_mirror(dev->reg_mirror, HWIF_VCMD_ABORT_MODE, 0x1);
	}
	vcmd_write_register_value((const void *)dev->hwregs,
					dev->reg_mirror,
					HWIF_VCMD_START_TRIGGER, 0);
	dev->state = VCMD_STATE_POWER_ON;
	if (dev->hw_feature.vcarb_ver == VCARB_VERSION_2_0)
		return 0;

	//wait vcmd core aborted and vcmd enters IDLE mode.
	if (watchdog_wait_vcmd_aborted(dev) == 0)
		return 0;

	return -1;
}

extern void watchdog_stop_vcd(volatile u8 *reg_base);
/**
 * @brief process when watchdog triggered.
 */
static void _vcmd_watchdog_process(struct hantrovcmd_dev *dev)
{
	struct vcmd_subsys_info *subsys = dev->subsys_info;
	int succeed = 1, ret;
	unsigned long flags;

	spin_lock_irqsave(dev->spinlock, flags);
	if (dev->hw_feature.vcarb_ver <= VCARB_VERSION_2_0) {
		ret = watchdog_stop_vcmd(dev);
		watchdog_stop_vcd(subsys->hwregs[SUB_MOD_MAIN]);
	}
	if (dev->hw_feature.vcarb_ver == VCARB_VERSION_2_0) {
		spin_unlock_irqrestore(dev->spinlock, flags);
		mdelay(10); // wait 10ms
		/* if not own arbier, it will receive arberr interrupt */
		if (dev->arb_err_irq) {
			dev->arb_err_irq = 0;
			return;
		}
		spin_lock_irqsave(dev->spinlock, flags);
		ret = watchdog_wait_vcmd_aborted(dev);
		spin_unlock_irqrestore(dev->spinlock, flags);
		if (ret == 0)
			watchdog_reset_vcmd_arbiter(dev);
		spin_lock_irqsave(dev->spinlock, flags);
	} else if (dev->hw_feature.vcarb_ver == VCARB_VERSION_3_0) {
		vcmd_start(dev);
		spin_unlock_irqrestore(dev->spinlock, flags);
		return;
	}
	if (ret < 0)
		succeed = 0;

#ifdef SUPPORT_AXIFE
	if (succeed && AXIFEFlush(subsys->hwregs[SUB_MOD_AXIFE]) == -1)
		succeed = 0;
#else
	succeed = 0;
#endif
	hook_vcmd_watchdog(dev, succeed);
	spin_unlock_irqrestore(dev->spinlock, flags);
	if (succeed) {
		mdelay(10); // wait 10ms
		if (dev->state == VCMD_STATE_IDLE) {
			spin_lock_irqsave(dev->spinlock, flags);
			if (dev->abort_mode == 1)
				dev->abort_mode = 0;
			vcmd_start(dev);
			spin_unlock_irqrestore(dev->spinlock, flags);
		}
	}
}
#endif //SUPPORT_WATCHDOG

/**
 * @brief sw process flow for v1.6.x bus err.
 */
static void _vcmd_bus_err_process(struct hantrovcmd_dev *dev)
{
	struct vcmd_subsys_info *subsys = dev->subsys_info;
	unsigned long flags;

	spin_lock_irqsave(dev->spinlock, flags);
	if (dev->hw_feature.vcarb_ver == VCARB_VERSION_3_0) {
		// PF do vcd/vce abort and AXIFE flush
		vcmd_start(dev);
		spin_unlock_irqrestore(dev->spinlock, flags);
		return;
	}
	abort_vcd(subsys->hwregs[SUB_MOD_MAIN]);
#ifdef SUPPORT_AXIFE
	if (AXIFEFlush(subsys->hwregs[SUB_MOD_AXIFE]) == -1)
		vcmd_klog(LOGLVL_ERROR, "%s: AXIFE flush failed!", __func__);
#endif
	if (dev->state == VCMD_STATE_IDLE)
		vcmd_start(dev);
	spin_unlock_irqrestore(dev->spinlock, flags);
}

#ifdef AXI2TO1_SUPPORT
/**
 * @brief process subsystem exceptions
 */
static int process_subsystem_exceptions(struct hantrovcmd_dev *dev)
{
	int ret;
	u32 val;
	unsigned long flags;

	volatile u8 *axi2to1_hwregs = dev->subsys_info->hwregs[SUB_MOD_AXI2TO1];

	if (!axi2to1_hwregs) {
		vcmd_klog(LOGLVL_ERROR, "AXI2TO1 is not exsit!\n");
		return -1;
	}

	spin_lock_irqsave(dev->spinlock, flags);
	ret = AXI2TO1_flush(axi2to1_hwregs);
	if (ret < 0) {
		spin_unlock_irqrestore(dev->spinlock, flags);
		return ret;
	}

	if (dev->hw_version_id < HW_ID_1_6_0) {
		// VCMD reset
		val = vcmd_read_reg((const void *)dev->hwregs, 0x40);
		val |= (0x1 << 1);
		vcmd_write_reg((const void *)dev->hwregs, 0x40, val);

		// IP core and AXI2TO1 reset
		val = SUBSYSTEM_RESET(IP_RESET_CORE);
		val |= SUBSYSTEM_RESET(IP_RESET_AXI2TO1);
		val |= SUBSYSTEM_RESET(IP_RESET_DEC400);
		val |= SUBSYSTEM_RESET(IP_RESET_AXIF);
		val |= SUBSYSTEM_RESET(IP_RESET_MMU);
		vcmd_write_reg((const void *)dev->hwregs, 0x40, val);

		// release IP core and AXI2TO1 reset
		vcmd_write_reg((const void *)dev->hwregs, 0x40, 0);
	} else {
		// IP core and AXI2TO1 reset
		val = vcmd_read_reg((const void *)dev->hwregs, 0x40);
		val |= SUBSYSTEM_RESET(IP_RESET_CORE);
		val |= SUBSYSTEM_RESET(IP_RESET_AXI2TO1);
		val |= SUBSYSTEM_RESET(IP_RESET_DEC400);
		val |= SUBSYSTEM_RESET(IP_RESET_AXIF);
		val |= SUBSYSTEM_RESET(IP_RESET_MMU);
		vcmd_write_reg((const void *)dev->hwregs, 0x40, val);
		// VCMD reset
		val = (0x1 << 1);
		vcmd_write_reg((const void *)dev->hwregs, 0x40, val);

		// after vcmd reset, need not to release ip reset
	}

	/* recover vcmd registers and continue to encode/decode */
	dev->state = VCMD_STATE_POWER_ON;
	vcmd_start(dev);
	spin_unlock_irqrestore(dev->spinlock, flags);

	return 0;
}
#endif

/**
 * @brief process external vcmd timeout.
 */
static void hook_vcmd_external_timeout(void *_dev)
{
	unsigned long flags;
	struct hantrovcmd_dev *dev = (struct hantrovcmd_dev *)_dev;

	spin_lock_irqsave(dev->spinlock, flags);
	dev->state = VCMD_STATE_IDLE;
	spin_unlock_irqrestore(dev->spinlock, flags);

	vcmd_klog(LOGLVL_ERROR,
		"vcmd abort is not waited, the timeout is from external system!\n");

	//need to do sub-system reset
}

/**
 * @brief To check vcmd_mgr/dev's actions which need kthread to process
 * @return int: 0: no actions; 1: have actions
 */
static int _vcmd_kthread_actions(vcmd_mgr_t *vcmd_mgr,
			struct hantrovcmd_dev **dev)
{
	int ret = 0, i;

	if (vcmd_mgr->stop_kthread == 1)
		return 1;

	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		*dev = &vcmd_mgr->dev_ctx[i];
		if ((*dev)->kthread_actions) {
			ret = 1;
			break;
		}
	}

	return ret;
}

/**
 * @brief vcmd kernel thread main function
 */
static int _vcmd_kthread_fn(void *data)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)data;
	struct hantrovcmd_dev *dev = NULL;

	while (!kthread_should_stop()) {
		if (wait_event_interruptible(vcmd_mgr->kthread_waitq,
				_vcmd_kthread_actions(vcmd_mgr, &dev))) {
			vcmd_klog(LOGLVL_ERROR, "%s: signaled!!!\n", __func__);
			return -ERESTARTSYS;
		}

		if (dev == NULL)
			continue;

		if (dev->kthread_actions & KT_ACT_HW_TIMEOUT) {
			dev->kthread_actions = 0;
			/* if external timeout, will do system reset */
			hook_vcmd_external_timeout(dev);
			continue;
		}
		if (dev->kthread_actions & KT_ACT_HW_BUS_ERR) {
			dev->kthread_actions = 0;
			_vcmd_bus_err_process(dev);
			continue;
		}
#ifdef AXI2TO1_SUPPORT
		if (dev->kthread_actions &
				(KT_ACT_CMDBUF_TIMEOUT | KT_ACT_AXI2TO1_EXCEPTION)) {
			dev->kthread_actions = 0;
			/* if has exceptions, will reset subsystem */
			process_subsystem_exceptions(dev);
			continue;
		}
#endif
#ifdef SUPPORT_WATCHDOG
		if (dev->kthread_actions & KT_ACT_WATCHDOG) {
			dev->kthread_actions = 0;
			_vcmd_watchdog_process(dev);
			continue;
		}
#endif
	}

	return 0;
}

/**
 * @brief wake up vcmd kernel thread
 */
void _vcmd_kthread_wakeup(vcmd_mgr_t *vcmd_mgr)
{

	if (IS_ERR(vcmd_mgr->kthread))
		return;

	wake_up_interruptible_all(&vcmd_mgr->kthread_waitq);
}

/**
 * @brief create kernel thread for vcmd driver
 */
static void _vcmd_kthread_create(vcmd_mgr_t *vcmd_mgr)
{
	vcmd_mgr->stop_kthread = 0;
	init_waitqueue_head(&vcmd_mgr->kthread_waitq);
	vcmd_mgr->kthread =
		kthread_run(_vcmd_kthread_fn, (void *)vcmd_mgr, "vcmd_kthread");
	if (IS_ERR(vcmd_mgr->kthread)) {
		vcmd_klog(LOGLVL_ERROR, "create vcmd kthread failed\n");
		return;
	}
}

/**
 * @brief stop kernel thread vcmd driver
 */
static void _vcmd_kthread_stop(vcmd_mgr_t *vcmd_mgr)
{
	if (!IS_ERR(vcmd_mgr->kthread)) {
		vcmd_mgr->stop_kthread = 1;
		kthread_stop(vcmd_mgr->kthread);
		vcmd_mgr->kthread = NULL;
	}
}

#ifdef TIMEOUT_IRQ_TIMER
/**
 * @brief timer callback of vcmd timeout timer
 */
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
static void _vcmd_timeout_timer_cb(unsigned long arg)
#else
static void _vcmd_timeout_timer_cb(struct timer_list *timer)
#endif
{
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	struct timer_list *timer = (struct timer_list *)arg;
#endif
	vcmd_mgr_t *vcmd_mgr;
	struct hantrovcmd_dev *dev;

	dev = container_of(timer, struct hantrovcmd_dev, timeout_timer);
	vcmd_mgr = (vcmd_mgr_t *)dev->handler;

	dev->kthread_actions |= KT_ACT_HW_TIMEOUT;

	_vcmd_kthread_wakeup(vcmd_mgr);
}

/**
 * @brief init timer for vcmd timeout
 */
static void _vcmd_timeout_add_timer(struct hantrovcmd_dev *dev)
{
	struct timer_list *timer = &dev->timeout_timer;

	dev->timeout_timer_active = 1;
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	init_timer(timer);
	timer->expires =  jiffies + HZ * 350 / 1000; // 350ms
	timer->function = _vcmd_timeout_timer_cb;
	timer->data = (unsigned long)timer;
	add_timer(timer);
#else
	timer_setup(timer, _vcmd_timeout_timer_cb, 0);
	timer->expires =  jiffies + HZ * 350 / 1000;
	add_timer(timer);
#endif
}

/**
 * @brief delete vcmd timeout timer
 */
static void _vcmd_timeout_del_timer(struct hantrovcmd_dev *dev)
{
	if (dev->timeout_timer_active) {
		del_timer(&dev->timeout_timer);
		dev->timeout_timer_active = 0;
	}
}
#endif //TIMEOUT_IRQ_TIMER

#ifdef SUPPORT_WATCHDOG
/**
 * @brief wait jobs count that need to be finished from dev work_list
 */
static u32 dev_wait_job_num(struct hantrovcmd_dev *dev)
{
	struct cmdbuf_obj *obj;
	bi_list_node *node = dev->work_list.head;
	u32 num = 0;

	while (node) {
		obj = (struct cmdbuf_obj *)node->data;
		if (obj->cmdbuf_run_done == 0) {
			num++;
			if (obj->has_jmp_cmd == 0 || obj->jmp_ie)
				return num;
		}
		node = node->next;
	}

	return num;
}

/**
 * @brief timer callback function of watchdog
 */
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
static void _vcmd_watchdog_cb(unsigned long arg)
#else
static void _vcmd_watchdog_cb(struct timer_list *timer)
#endif
{
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	struct timer_list *timer = (struct timer_list *)arg;
#endif
	vcmd_mgr_t *vcmd_mgr;
	struct hantrovcmd_dev *dev;

	dev = container_of(timer, struct hantrovcmd_dev, watchdog_timer);
	vcmd_mgr = (vcmd_mgr_t *)dev->handler;

	dev->kthread_actions |= KT_ACT_WATCHDOG;
	_vcmd_kthread_wakeup(vcmd_mgr);
}

/**
 * @brief init vcmd watchdog
 */
static void _vcmd_watchdog_start(struct hantrovcmd_dev *dev)
{
	struct timer_list *timer = &dev->watchdog_timer;

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	init_timer(timer);
	timer->function = _vcmd_watchdog_cb;
	timer->data = (unsigned long)timer;
#else
	timer_setup(timer, _vcmd_watchdog_cb, 0);
#endif
	dev->watchdog_active = 1;
}

/**
 * stop vcmd watchdog
 */
void _vcmd_watchdog_stop(struct hantrovcmd_dev *dev)
{
	if (dev->watchdog_active) {
		del_timer(&dev->watchdog_timer);
		dev->watchdog_active = 0;
	}
}

/**
 * feed and start vcmd watchdog
 */
static void _vcmd_watchdog_feed(struct hantrovcmd_dev *dev)
{
	u32 num = 0;

	num = dev_wait_job_num(dev);
	if (num == 0) {
		if (dev->watchdog_active)
			_vcmd_watchdog_stop(dev);
	} else {
		if (dev->watchdog_active == 0)
			_vcmd_watchdog_start(dev);

		if (dev->hw_feature.vcarb_ver == VCARB_VERSION_2_0)
			mod_timer(&dev->watchdog_timer,
				(jiffies + (HZ * VCMD_ARBITER_RESET_TIME / 1000)));
		else if (dev->hw_feature.vcarb_ver == VCARB_VERSION_3_0)
			mod_timer(&dev->watchdog_timer,
				(jiffies + (HZ * sw_timeout_time / 1000)));
		else
			mod_timer(&dev->watchdog_timer,
				(jiffies + num * (HZ * ONE_JOB_WAIT_TIME / 1000)));
	}
}
#endif //SUPPORT_WATCHDOG



void _dbg_log_instr(u32 offset, u32 instr, u32 *size, char *str)
{
	u32 opcode = instr & OPCODE_MASK;

	if (opcode == OPCODE_WREG) {
		int length = ((instr >> 16) & 0x3FF);

		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s %s %d 0x%x]\n",
			offset, instr, "WREG", ((instr >> 26) & 0x1) ? "FIX" : "",
			   length, (instr & 0xFFFF));
		*size = ((length + 2) >> 1) << 1;
	} else if (opcode == OPCODE_END) {
		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s]\n", offset,
			instr, "END");
		*size = 2;
	} else if (opcode == OPCODE_NOP) {
		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s]\n", offset,
			instr, "NOP");
		*size = 2;
	} else if (opcode == OPCODE_RREG) {
		int length = ((instr >> 16) & 0x3FF);

		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s %s %d 0x%x]\n",
			offset, instr, "RREG", ((instr >> 26) & 0x1) ? "FIX" : "",
			   length, (instr & 0xFFFF));
		*size = 4;
	} else if (opcode == OPCODE_JMP) {
		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s %s %s]\n",
			offset, instr, "JMP", ((instr >> 26) & 0x1) ? "RDY" : "",
			   ((instr >> 25) & 0x1) ? "IE" : "");
		*size = 4;
	} else if (opcode == OPCODE_STALL) {
		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s %s 0x%x]\n",
			offset, instr, "STALL", ((instr >> 26) & 0x1) ? "IM" : "",
			   (instr & 0xFFFF));
		*size = 2;
	} else if (opcode == OPCODE_CLRINT) {
		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s %u 0x%x]\n",
			offset, instr, "CLRINT", (instr >> 25) & 0x3,
			   (instr & 0xFFFF));
		*size = 2;
	} else if (opcode == OPCODE_M2M) {
		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s]\n",
			offset, instr, "M2M");
		*size = 6;
	} else if (opcode == OPCODE_MSET) {
		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s]\n",
			offset, instr, "MSET");
		*size = 4;
	} else if (opcode == OPCODE_M2MP) {
		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s]\n",
			offset, instr, "M2MP");
		*size = 6;
	} else {
		sprintf(str, "current cmdbuf data %u = 0x%08x => [%s]\n",
			offset, instr, "UNKNOWN CMD");
		*size = 1;
	}
}

#ifdef VCMD_DEBUG_INTERNAL
static void _dbg_log_last_cmd(struct cmdbuf_obj *obj)
{
	u32 *p, len, offset, size;
	char log_buf[512];

	vcmd_klog(LOGLVL_FLOW, "last cmdbuf content:\n");
	if (obj->has_jmp_cmd) {
		p = (void *)_get_jmp_cmd(obj);
		len = sizeof(struct cmd_jmp_t) / sizeof(u32);
	} else {
		p = (void *)_get_end_cmd(obj);
		len = sizeof(struct cmd_end_t) / sizeof(u32);
	}

	offset = p - obj->cmd_va;
	_dbg_log_instr(offset, *p, &size, log_buf);
	vcmd_klog(LOGLVL_FLOW, "%s", log_buf);
	len--;
	offset++;

	while (len--) {
		vcmd_klog(LOGLVL_FLOW, "current cmdbuf data %d = 0x%x\n",
						offset, *(obj->cmd_va + offset));
		offset++;
	}
}

static void _dbg_log_cmdbuf(struct cmdbuf_obj *obj)
{
	u32 i, instr = 0, size = 0;
	char log_buf[512];

	vcmd_klog(LOGLVL_FLOW, "vcmd link, current cmdbuf content\n");
	for (i = 0; i < obj->cmdbuf_size / 4; i++) {
		if (i == instr) {
			//memset(log_buf, 0, sizeof(log_buf));
			_dbg_log_instr(i, *(obj->cmd_va + i), &size, log_buf);
			vcmd_klog(LOGLVL_FLOW, "%s", log_buf);
			instr += size;
		} else {
			vcmd_klog(LOGLVL_FLOW, "current cmdbuf data %d = 0x%x\n",
					i, *(obj->cmd_va + i));
		}
	}
}

static void _dbg_log_dev_regs(struct hantrovcmd_dev *dev, u32 dump)
{
	u32 i, reg_val;

	if (dump) {
		for (i = 0; i < ASIC_VCMD_SWREG_AMOUNT; i++) {
			reg_val = vcmd_read_reg((const void *)dev->hwregs, i * 4);
			vcmd_klog(LOGLVL_FLOW, "vcmd swreg%d: 0x%x\n", i, reg_val);
		}
	} else {
		for (i = 0; i < ASIC_VCMD_SWREG_AMOUNT; i++) {
			reg_val = *(dev->reg_mem_va + i);
			vcmd_klog(LOGLVL_FLOW, "ddr vcmd swreg%d: 0x%x\n", i, reg_val);
		}
	}
}
#endif

static void printk_vcmd_register_debug(const void *hwregs, char *info)
{
#ifdef VCMD_DEBUG_INTERNAL
	u32 i, fordebug;

	for (i = 0; i < ASIC_VCMD_SWREG_AMOUNT; i++) {
		fordebug = vcmd_read_reg((const void *)hwregs, i * 4);
		vcmd_klog(LOGLVL_FLOW, "%s vcmd register %d:0x%x\n", info, i,
			fordebug);
	}
#endif
}

static void _log_ioctl_cmd(unsigned int cmd)
{
	static unsigned int last_cmd;

	if ((cmd == HANTRO_VCMD_IOCH_POLLING_CMDBUF) && (last_cmd == cmd))
		return;

	last_cmd = cmd;
	vcmd_klog(LOGLVL_FLOW, "ioctl cmd 0x%08x\n", cmd);
}

/*======================= cmdbuf object management ================*/

/**
 * @brief initialize all of cmdbuf objs of vcmd driver handler.
 */
static void vcmd_init_objs(vcmd_mgr_t *vcmd_mgr)
{
	u32 i;
	struct cmdbuf_obj *obj;
	struct noncache_mem *m0, *m1;

	m0 = &vcmd_mgr->mem_vcmd;
	m1 = &vcmd_mgr->mem_status;
	for (i = 0; i < SLOT_NUM_CMDBUF; i++) {
		obj = &vcmd_mgr->objs[i];
		obj->cmdbuf_id = i;
		obj->cmdbuf_size = SLOT_SIZE_CMDBUF;
		obj->cmd_va = m0->va + CMDBUF_OFF_32(i);
		obj->cmd_pa = m0->pa + CMDBUF_OFF(i);
		obj->mmu_cmd_ba = m0->mmu_ba + CMDBUF_OFF(i);

		obj->status_size = SLOT_SIZE_STATUSBUF;
		obj->status_va = m1->va + STATUSBUF_OFF_32(i);
		obj->status_pa = m1->pa + STATUSBUF_OFF(i);
		obj->mmu_status_ba = m1->mmu_ba + STATUSBUF_OFF(i);
	}
}

/**
 * @brief initialize all of cmdbuf nodes of vcmd driver handler.
 */
static void vcmd_init_nodes(vcmd_mgr_t *vcmd_mgr)
{
	u32 i;

	for (i = 0; i < SLOT_NUM_CMDBUF; i++)
		vcmd_mgr->nodes[i].data = (void *)&vcmd_mgr->objs[i];

}

/**
 * @brief reset flag/status of cmdbuf obj specified by id.
 */
static void reset_cmdbuf_obj(vcmd_mgr_t *vcmd_mgr, u32 id)
{
	struct cmdbuf_obj *obj = &vcmd_mgr->objs[id];

	obj->executing_status = CMDBUF_EXE_STATUS_OK;
	obj->cmdbuf_run_done = 0;
	obj->slice_run_done = 0;
	obj->cmdbuf_linked = 0;
	obj->cmdbuf_need_remove = 0;
	obj->core_id = 0xFFFF;
	obj->cmdbuf_size = SLOT_SIZE_CMDBUF;

	obj->has_jmp_cmd = 1;
	obj->jmp_ie = 0;
}

/**
 * @brief reset pointer of cmdbuf node specified by id.
 */
static void reset_cmdbuf_node(vcmd_mgr_t *vcmd_mgr, u32 id)
{
	struct bi_list_node  *node;

	node = &vcmd_mgr->nodes[id];
	node->next = NULL;
	node->prev = NULL;

	node = &vcmd_mgr->po_jobs[id];
	node->next = NULL;
	node->prev = NULL;
	node->data = NULL;
}

/**
 * @brief put a node to tail of si-list.
 */
static void _si_list_put(struct si_linked_list *list,
							struct si_linked_node *node)
{
	if (list->head == NULL) {
		list->head = list->tail = node;
	} else {
		list->tail->next = node;
		list->tail = node;
	}
	node->next = NULL;
}

/**
 * @brief get & remove a node from head of si-list.
 * @return struct si_linked_node *: NULL: no node got; other: the node.
 */
static struct si_linked_node *_si_list_get(struct si_linked_list *list)
{
	struct si_linked_node *node = list->head;

	if (list->head) {
		list->head = node->next;
		if (list->head == NULL)
			list->tail = NULL;
	}

	return node;
}

/**
 * @brief init a si-list.
 */
static void vcmd_init_si_list(struct si_linked_list *list)
{

	spin_lock_init(&list->spinlock);
	list->head = NULL;
	list->tail = NULL;
}

/**
 * @brief init free obj (cmdbuf) list of vcmd driver handler.
 */
static void vcmd_init_free_obj_list(vcmd_mgr_t *vcmd_mgr)
{
	u32 i;
	struct si_linked_list *list = &vcmd_mgr->free_obj_list;

	vcmd_init_si_list(list);
	sema_init(&vcmd_mgr->free_obj_sema, SLOT_NUM_CMDBUF);

	for (i = 0; i < SLOT_NUM_CMDBUF; i++) {
		list->nodes[i].data = (void *)&vcmd_mgr->objs[i];
		_si_list_put(list, &list->nodes[i]);
	}
}

/**
 * @brief acquire a free cmdbuf.
 * @param u32 *id: to store acquired free cmdbuf id.
 * @return int: 0: succeed; otherwise: failed.
 */
static int acquire_cmdbuf(vcmd_mgr_t *vcmd_mgr, u32 *id)
{
	struct si_linked_list *list = &vcmd_mgr->free_obj_list;
	struct si_linked_node *node;
	struct cmdbuf_obj *obj;

	if (down_interruptible(&vcmd_mgr->free_obj_sema)) {
		vcmd_klog(LOGLVL_ERROR, "%s: sema-down is interrupted!", __func__);
		return -1;
	}

	spin_lock(&list->spinlock);
	node = _si_list_get(list);
	spin_unlock(&list->spinlock);

	if (node == NULL) {
		vcmd_klog(LOGLVL_ERROR, "%s: get NULL node!", __func__);
		return -1;
	}

	obj = (struct cmdbuf_obj *)node->data;
	*id = obj->cmdbuf_id;
	return 0;
}

/**
 * @brief return (release) a cmdbuf specified by id.
 */
static void return_cmdbuf(vcmd_mgr_t *vcmd_mgr, u32 id)
{
	struct si_linked_list *list = &vcmd_mgr->free_obj_list;
	struct si_linked_node *node = &list->nodes[id];
	struct cmdbuf_obj *obj = (struct cmdbuf_obj *)node->data;

	obj->po = NULL;

	spin_lock(&list->spinlock);
	_si_list_put(list, node);
	spin_unlock(&list->spinlock);
	up(&vcmd_mgr->free_obj_sema);
}

/**
 * @brief get cmdbuf node by cmd physical addr.
 * @param addr_t pa: the cmd physical addr.
 * @return bi_list_node *: NULL: no cmdbuf found; otherwise: cmdbuf node.
 */
static bi_list_node *get_cmdbuf_node_by_addr(vcmd_mgr_t *vcmd_mgr,
									struct hantrovcmd_dev *dev, addr_t pa)
{
	bi_list_node *node;
	struct cmdbuf_obj *obj;

	u32 id;
	addr_t pa_base = vcmd_mgr->mem_vcmd.pa - vcmd_mgr->pa_trans_offset;

	id = (pa - pa_base) / SLOT_SIZE_CMDBUF;
	if (id >= SLOT_NUM_CMDBUF) {
		vcmd_klog(LOGLVL_ERROR, "cmdbuf_id greater than the ceiling !!\n");
		return NULL;
	}

	obj = &vcmd_mgr->objs[id];
	node = &vcmd_mgr->nodes[id];

	if (obj->core_id != dev->core_id) {
		vcmd_klog(LOGLVL_ERROR, "cmdbuf is not in dev[%d] list !!\n", dev->core_id);
		return NULL;
	}

	return node;
}

/**
 * @brief get the va of vcmdbuf obj's JMP cmd.
 */
static struct cmd_jmp_t *_get_jmp_cmd(struct cmdbuf_obj *obj)
{
	u8 *p = (u8 *)obj->cmd_va;

	p += obj->cmdbuf_size - sizeof(struct cmd_jmp_t);
	return (struct cmd_jmp_t *)p;
}

/**
 * @brief get the va of vcmdbuf obj's END cmd.
 */
static struct cmd_end_t *_get_end_cmd(struct cmdbuf_obj *obj)
{
	u8 *p = (u8 *)obj->cmd_va;

	p += obj->cmdbuf_size - sizeof(struct cmd_end_t);
	return (struct cmd_end_t *)p;
}

/**
 * @brief set bus-address to 2 rreg cmd with dev reg mem ba,
 * the 2 rreg cmds are the 1st & the last but one cmd of specified cmdbuf.
 */
static void _set_rreg_addr(struct hantrovcmd_dev *dev, struct cmdbuf_obj *obj)
{
	addr_t reg_mem_ba;
	struct cmd_rreg_t *cmd_rreg;
	u8 *p;

	if (dev->hw_version_id <= HW_ID_1_0_C)
		return;

	reg_mem_ba = dev->reg_mem_ba;
	if (dev->mmu_enable)
		reg_mem_ba = (addr_t)dev->mmu_reg_mem_ba;

	//read vcmd executing ID register into ddr memory.
	cmd_rreg = (struct cmd_rreg_t *)obj->cmd_va;
	CMD_SET_ADDR(cmd_rreg, reg_mem_ba + REG_ID2_CMDBUF_EXE_ID * 4);

	//read vcmd all registers into ddr memory.
	if (obj->has_jmp_cmd)
		p = (u8 *)_get_jmp_cmd(obj);
	else
		p = (u8 *)_get_end_cmd(obj);
	cmd_rreg = (struct cmd_rreg_t *)(p - sizeof(struct cmd_rreg_t));
	CMD_SET_ADDR(cmd_rreg, reg_mem_ba);
}

/**
 * @brief update intr-enable bit of JMP cmd in specified cmdbuf.
 */
static void _update_jmp_ie(struct hantrovcmd_dev *dev, struct cmdbuf_obj *obj)
{
	struct cmd_jmp_t *cmd_jmp;

	if (obj->has_jmp_cmd) {
		//update dev->duration and adjust JMP_IE accordingly
		if (obj->jmp_ie) {
			dev->duration = 0;
		} else {
			dev->duration += obj->workload;
			if (dev->duration >= VCMD_INTR_INTERVAL) {
				cmd_jmp = _get_jmp_cmd(obj);
				obj->jmp_ie = 1;
				cmd_jmp->opcode |= JMP_IE(1);
			}
		}
	}
}

/**
 * @brief link 2 specified cmdbufs' data by JMP cmd of prev comdbuf.
 */
static void dev_link_cmdbuf(struct hantrovcmd_dev *dev,
								bi_list_node *prev_node,
								bi_list_node *next_node)
{
	struct cmdbuf_obj *next_obj, *prev_obj;
	struct cmd_jmp_t *cmd_jmp;
	addr_t next_ba;
	u32 op;

	if (!prev_node)
		return;

	prev_obj = (struct cmdbuf_obj *)prev_node->data;

	if (prev_obj->has_jmp_cmd) {
		cmd_jmp = _get_jmp_cmd(prev_obj);
		if (!next_node) {
			// If next cmdbuf is not available, set the RDY to 0.
			op = cmd_jmp->opcode;
			cmd_jmp->opcode = OPCODE_JMP |
								JMP_RDY(0) | JMP_IE(JMP_G_IE(op)) |
								JMP_NEXT_LEN(0);
		} else {
			next_obj = (struct cmdbuf_obj *)next_node->data;
			if (dev->hw_version_id > HW_ID_1_0_C) {
				//set next cmdbuf id
				cmd_jmp->id = next_obj->cmdbuf_id;
			}
			next_ba = next_obj->cmd_pa - dev->pa_trans_offset;
			if (dev->mmu_enable)
				next_ba = (addr_t)next_obj->mmu_cmd_ba;

			CMD_SET_ADDR(cmd_jmp, next_ba);
			op = cmd_jmp->opcode;
			cmd_jmp->opcode = OPCODE_JMP |
								JMP_RDY(1) | JMP_IE(JMP_G_IE(op)) |
								JMP_NEXT_LEN((next_obj->cmdbuf_size + 7) / 8);
		}
	}

#ifdef VCMD_DEBUG_INTERNAL
	_dbg_log_last_cmd(prev_obj);
#endif
}

/**
 * @brief create a process object
 */
static struct proc_obj *create_process_object(void)
{
	struct proc_obj *po;

	po = vmalloc(sizeof(struct proc_obj));
	if (!po) {
		vcmd_klog(LOGLVL_ERROR, "%s: vmalloc failed!\n", __func__);
		return NULL;
	}

	memset(po, 0, sizeof(struct proc_obj));
	spin_lock_init(&po->spinlock);
	init_waitqueue_head(&po->resource_waitq);
	init_waitqueue_head(&po->job_waitq);

	spin_lock_init(&po->job_lock);
	init_bi_list(&po->job_done_list);
	return po;
}

/**
 * @brief free a process object
 */
static void free_process_object(struct proc_obj *po)
{
	if (!po) {
		vcmd_klog(LOGLVL_ERROR, "%s: po is NULL!\n", __func__);
		return;
	}
	vfree(po);
}

/**
 * @brief add done obj to job_done_list of its po, wake-up job_waitq if needed.
 */
void proc_add_done_job(vcmd_mgr_t *vcmd_mgr, struct cmdbuf_obj *obj)
{
	u16 id = obj->cmdbuf_id;
	struct proc_obj *po;
	struct bi_list *list;
	unsigned long flags;
	u32 is_empty, is_wait;
	struct hantrovcmd_dev *dev;

	if (!obj->po) {
		vcmd_klog(LOGLVL_BRIEF, "%s: the po and cmdbufs of this po has been released!\n",
						__func__);
		return;
	}

	po = obj->po;
	list = &po->job_done_list;

	dev = &vcmd_mgr->dev_ctx[obj->core_id];
	wake_up_interruptible_all(&dev->buff_empty_waitq);

	spin_lock_irqsave(&po->job_lock, flags);

	if (vcmd_mgr->po_jobs[id].data) {
		//already in job-done list, do nothing
		spin_unlock_irqrestore(&po->job_lock, flags);
		return;
	}

	vcmd_mgr->po_jobs[id].data = (void *)&vcmd_mgr->objs[id];
	is_empty = (list->head == NULL);
	is_wait = po->in_wait;
	po->in_wait = 0;
	bi_list_insert_node_tail(list, &vcmd_mgr->po_jobs[id]);

	spin_unlock_irqrestore(&po->job_lock, flags);

	if (is_empty || is_wait)
		wake_up_interruptible_all(&po->job_waitq);
}

/**
 * @brief get & remove a done obj from po's job_done_list.
 * @param struct cmdbuf_obj **pobj: *pobj==NULL: get head node from list.
 *									otherwise, get specified node from list.
 * @return int: 0: no done obj; 1: obj is done.
 */
static int proc_get_done_job(vcmd_mgr_t *vcmd_mgr, struct proc_obj *po,
									struct cmdbuf_obj **pobj)
{

	struct bi_list *list = &po->job_done_list;
	bi_list_node *node;
	unsigned long flags;
	struct cmdbuf_obj *obj = NULL;
	int is_done = 0, i;

	spin_lock_irqsave(&po->job_lock, flags);
	node = list->head;

	if (node == NULL) {
		// job done list is empty
		po->in_wait = 1;
		for (i = 0; i < SLOT_NUM_CMDBUF; i++) {
			obj = &vcmd_mgr->objs[i];
			if (obj->po == po)
				break;
		}
		if (i == SLOT_NUM_CMDBUF) {
			spin_unlock_irqrestore(&po->job_lock, flags);
			return 1; /* used to drop_cmd_ids!=NULL when seek */
		}
		spin_unlock_irqrestore(&po->job_lock, flags);

		return 0;
	}

	if (*pobj == NULL) {
		//any po's cmdbuf ready, return head of job_done_list
		*pobj = (struct cmdbuf_obj *)node->data;
		is_done = 1;
	} else {
		//specified cmdbuf ready?
		obj = *pobj;
		if (obj->cmdbuf_run_done || obj->slice_run_done) {
			// check if the obj is in job done list
			while (node && node->data != (void *)obj)
				node = node->next;

			if (node == NULL) {
				vcmd_klog(LOGLVL_BRIEF, "%s: cmdbuf[%d] is done, but not in done-list!\n",
						__func__, obj->cmdbuf_id);
			} else {
				vcmd_klog(LOGLVL_BRIEF, "%s: cmdbuf[%d] is done!\n", __func__, obj->cmdbuf_id);
				is_done = 1;
			}
		}
	}

	if (is_done) {
		bi_list_remove_node(list, &vcmd_mgr->po_jobs[(*pobj)->cmdbuf_id]);
		vcmd_mgr->po_jobs[(*pobj)->cmdbuf_id].data = NULL;
	} else {
		po->in_wait = 1;
	}

	spin_unlock_irqrestore(&po->job_lock, flags);

	return is_done;
}

/**
 * @brief remove a job (cmdbuf node) from device work_list,
 * and de-link from cmdbuf jmp list
 * @return int: 1: succeed; 0: failed, the node's JMP cmd is still used by hw.
 */
static int dev_delink_job(struct hantrovcmd_dev *dev,
											bi_list_node *node)
{
	struct cmdbuf_obj *obj = (struct cmdbuf_obj *)node->data;

	if (obj->cmdbuf_linked == 0) {
		//already de-linked or not link into work list yet
		return 1;
	}

	if (dev->state != VCMD_STATE_WORKING ||
		obj->has_jmp_cmd == 0 || node->next) {
		//delink cmdbuf, and remove node from work list.
		dev_link_cmdbuf(dev, node->prev, node->next);
		bi_list_remove_node(&dev->work_list, node);
		obj->cmdbuf_linked = 0;
		return 1;
	}
	// Not remove the last node, its JMP cmd is needed to link new cmd.
	return 0;
}

/**
 * @brief add a job to tail of device work_list,
 *  and link to cmdbuf jmp list if needed.
 */
static int dev_add_job(struct hantrovcmd_dev *dev, bi_list_node *job_node)
{

	struct cmdbuf_obj *obj;

	obj = (struct cmdbuf_obj *)job_node->data;
	_set_rreg_addr(dev, obj);

	bi_list_insert_node_tail(&dev->work_list, job_node);
	_update_jmp_ie(dev, obj);

#ifdef SUPPORT_DBGFS
	_dbgfs_record_active_start_time(dev->dbgfs_info);
#endif

	dev_link_cmdbuf(dev, job_node->prev, job_node);
	obj->core_id = dev->core_id;
	obj->cmdbuf_linked = 1;

	return 0;
}

/**
 * @brief insert job_node prior to base_node of dev work_list,
 *  and insert to cmdbuf jmp list accordingly if needed.
 */
static int dev_insert_job(struct hantrovcmd_dev *dev,
							bi_list_node *base_node,
							bi_list_node *job_node)
{
	struct cmdbuf_obj *obj;

	obj = (struct cmdbuf_obj *)job_node->data;
	_set_rreg_addr(dev, obj);

	bi_list_insert_node_before(&dev->work_list, base_node, job_node);

#ifdef SUPPORT_DBGFS
	_dbgfs_record_active_start_time(dev->dbgfs_info);
#endif

	dev_link_cmdbuf(dev, job_node->prev, job_node);
	dev_link_cmdbuf(dev, job_node, job_node->next);
	obj->core_id = dev->core_id;
	obj->cmdbuf_linked = 1;

	return 0;
}

/**
 * @brief remove a job from dev work_list,
 *  de-link it from cmdbuf jmp list if needed, and return the cmdbuf.
 */
static int dev_remove_job(vcmd_mgr_t *vcmd_mgr,
							struct hantrovcmd_dev *dev, bi_list_node *node)
{
	struct cmdbuf_obj *obj;

	obj = (struct cmdbuf_obj *)node->data;

	vcmd_klog(LOGLVL_FLOW, "Delink and remove cmdbuf [%d] from dev [%d].\n",
			obj->cmdbuf_id, dev->core_id);
	if (node->prev) {
		vcmd_klog(LOGLVL_BRIEF, "prev cmdbuf [%d].\n",
			   ((struct cmdbuf_obj *)node->prev->data)->cmdbuf_id);
	} else {
		vcmd_klog(LOGLVL_BRIEF, "NO prev cmdbuf.\n");
	}
	if (node->next) {
		vcmd_klog(LOGLVL_BRIEF, "next cmdbuf [%d].\n",
			   ((struct cmdbuf_obj *)node->next->data)->cmdbuf_id);
	} else {
		vcmd_klog(LOGLVL_BRIEF, "NO next cmdbuf.\n");
	}

	if (dev_delink_job(dev, node))
		return_cmdbuf(vcmd_mgr, obj->cmdbuf_id);

	return 0;
}

/**
 * @brief get remain (un-do) jobs count from dev work_list,
 */
static u32 dev_get_job_num(struct hantrovcmd_dev *dev)
{
	struct cmdbuf_obj *obj;
	bi_list_node *node = dev->work_list.head;
	u32 num = 0;

	while (node) {
		obj = (struct cmdbuf_obj *)node->data;
		if (obj->cmdbuf_run_done == 0)
			num++;
		node = node->next;
	}
	return num;
}

/**
 * @brief calculate workload after specified node in dev work_list.
 */
static u64 calc_workload_after_node(bi_list_node *node)
{
	u64 sum = 0;
	struct cmdbuf_obj *obj;

	while (node) {
		obj = (struct cmdbuf_obj *)node->data;
		sum += obj->workload;
		node = node->next;
	}
	return sum;
}

/**
 * @brief check if specified device is in core_mask
 * @return int: 1: device is in core_mask; 0: not in core_mask.
 */
static int is_supported_core(u32 core_mask, u16 dev_id)
{
	if (core_mask && ((core_mask >> dev_id) & 0x1))
		return 1; //found one supported core

	return 0; //not found the supported core
}

struct sub_ip_init_cfg {
	u32 reg_id;
	u32 reg_val;
};

#ifdef SUPPORT_AXIFE
struct sub_ip_init_cfg axife_init_cfg[] = {
	{AXI_REG10_SW_FRONTEND_EN, 0x02},
	{AXI_REG11_SW_WORK_MODE, 0x00},
	{0xffff, }	//end guard
};
#endif

#ifdef SUPPORT_MMU
struct sub_ip_init_cfg mmu_init_cfg[] = {
	{MMU_REG_ADDRESS, 0x0000},		//not move, sw will update mmu addr LSB to index0
	{MMU_REG_ADDRESS_MSB, 0x0000},	//not move, sw will update mmu addr MSB to index1
#ifdef SUPPORT_48PA_MMU
	{MMU_REG_ARRAY_SIZE, 0x0001},
#endif
	{MMU_REG_PAGE_TABLE_ID, 0x10000},
	{MMU_REG_PAGE_TABLE_ID, 0x00000},
	{MMU_REG_CONTROL, 0x0001},
	{0xffff, }	//end guard
};
#endif

#ifdef AXI2TO1_SUPPORT
struct sub_ip_init_cfg axi2to1_init_cfg[] = {
	{AXI2TO1_REG6_SW_IRQ_EN, 0xffffffff}, // axi2to1 irq enable
	{AXI2TO1_REG7_SW_TIMEOUT_CYCLES, 0x40000000} // axife flush timeout cycles
};
#endif

#ifdef HANTROVCMD_ENABLE_IP_SUPPORT
/**
 * @brief set reg id/val of specified sub-ip to init-cmd regs.
 */
static void _set_module_init_cmds(struct hantrovcmd_dev *dev, u32 module_id,
									struct sub_ip_init_cfg *module_cfg)
{
	u16 reg_off = dev->subsys_info->reg_off[module_id];
	u32 opcode = OPCODE_WREG | WREG_MODE(WREG_ADDR_FIX) | WREG_LEN(1);

	if (reg_off == 0xffff)
		return;

	while (module_cfg->reg_id != 0xffff) {
		dev->reg_mirror[dev->init_cmd_idx++] = opcode |
												(reg_off + module_cfg->reg_id);
		dev->reg_mirror[dev->init_cmd_idx++] = module_cfg->reg_val;
		module_cfg++;
	}
}
#endif

/**
 * @brief set init-cmd regs to init sub-ips if necessary.
 */
static void vcmd_set_init_cmds(struct hantrovcmd_dev *dev)
{
#ifdef HANTROVCMD_ENABLE_IP_SUPPORT
	u32 i;

	dev->init_cmd_idx = VCMD_REG_ID_SW_INIT_CMD0;

#ifdef SUPPORT_AXIFE
	//enable AXIFE by VCMD
	_set_module_init_cmds(dev, SUB_MOD_AXIFE, axife_init_cfg);
#endif

#ifdef AXI2TO1_SUPPORT
	_set_module_init_cmds(dev, SUB_MOD_AXI2TO1, axi2to1_init_cfg);
#endif

#ifdef SUPPORT_MMU
	//enable MMU by VCMD
	if (dev->mmu_enable) {
		u64 mmu_addr = GetMMUAddress();

		vcmd_klog(LOGLVL_FLOW, "%s: mmu address = 0x%llx", __func__, mmu_addr);
		mmu_init_cfg[0].reg_val = (u32)mmu_addr;
		mmu_init_cfg[1].reg_val = (u32)(mmu_addr >> 32);
#ifdef SUPPORT_48PA_MMU
		mmu_init_cfg[2].reg_val = GetMMUPageTableArraySize();
#endif
		_set_module_init_cmds(dev, SUB_MOD_MMU, mmu_init_cfg);
		_set_module_init_cmds(dev, SUB_MOD_MMU_WR, mmu_init_cfg);
	}
#endif //SUPPORT_MMU

	//finished with END command
	dev->reg_mirror[dev->init_cmd_idx++] = OPCODE_END;
	dev->reg_mirror[dev->init_cmd_idx++] = 0x00;

	for (i = VCMD_REG_ID_SW_INIT_CMD0; i < dev->init_cmd_idx; i++)
		vcmd_write_reg((const void *)dev->hwregs, i*4, dev->reg_mirror[i]);
#endif //HANTROVCMD_ENABLE_IP_SUPPORT
}

/**
 * @brief reset all vcmd hw devices.
 */
static void vcmd_reset_asic(vcmd_mgr_t *vcmd_mgr)
{
	int n;
	u32 status;
	struct hantrovcmd_dev *dev = vcmd_mgr->dev_ctx;

	for (n = 0; n < vcmd_mgr->subsys_num; n++) {
		if (dev[n].hwregs) {
			//disable interrupt at first
			vcmd_write_reg((const void *)dev[n].hwregs,
					   VCMD_REGISTER_INT_CTL_OFFSET, 0x0000);
			//reset core
			vcmd_write_reg((const void *)dev[n].hwregs,
					   VCMD_REGISTER_CONTROL_OFFSET, 0x0004);
			//read status register
			status = vcmd_read_reg((const void *)dev[n].hwregs,
						   VCMD_REGISTER_INT_STATUS_OFFSET);
			//clean status register
			vcmd_write_reg((const void *)dev[n].hwregs,
					   VCMD_REGISTER_INT_STATUS_OFFSET, status);
			//when reset core need clear reg[3]
			vcmd_write_reg((const void *)dev[n].hwregs,
							VCMD_REGISTER_EXE_CMDBUF_COUNT_OFFSET, 0x0000);
		}
	}
}

#ifndef TIMEOUT_IRQ_TIMER
/**
 * @brief reset core to the specified vcmd hw device.
 */
static void vcmd_reset_current_asic(struct hantrovcmd_dev *dev)
{
	u32 status;

	volatile u8 *hwregs = dev->hwregs;

	if (hwregs) {
		//disable interrupt at first
		vcmd_write_reg((const void *)hwregs,
				   VCMD_REGISTER_INT_CTL_OFFSET, 0x0000);
		//reset core
		vcmd_write_reg((const void *)hwregs,
				   VCMD_REGISTER_CONTROL_OFFSET, 0x0004);
		//read status register
		status = vcmd_read_reg((const void *)hwregs,
					   VCMD_REGISTER_INT_STATUS_OFFSET);
		//clean status register
		vcmd_write_reg((const void *)hwregs,
				   VCMD_REGISTER_INT_STATUS_OFFSET, status);
		//when reset core need clear reg[3]
		vcmd_write_reg((const void *)hwregs,
						VCMD_REGISTER_EXE_CMDBUF_COUNT_OFFSET, 0x0000);
	}
}
#endif

#ifdef VCARB_REQUEST
/**
 * @brief vcmd get online for arbiter
 */
void vcmd_online_for_arbiter(const volatile u8 *hwregs)
{
	u32 arbiter_cfg;

	arbiter_cfg = ioread32((void __iomem *)(hwregs +
							VCMD_REGISTER_ARBITER_CONFIG_OFFSET));
	iowrite32((arbiter_cfg | VCMD_ARBITER_ENABLE),
			(void __iomem *)(hwregs +
			VCMD_REGISTER_ARBITER_CONFIG_OFFSET));
}

/**
 * @brief vcmd get offline for arbiter
 */
void vcmd_offline_for_arbiter(const volatile u8 *hwregs)
{
	// vcmd offline
	iowrite32(0, (void __iomem *)(hwregs +
			VCMD_REGISTER_ARBITER_CONFIG_OFFSET));
}

/**
 * @brief vcmd request arbiter manully
 */
void vcmd_request_arbiter(void *_vcmd_mgr, u32 subsys_id)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	struct hantrovcmd_dev *dev = &vcmd_mgr->dev_ctx[subsys_id];
	volatile u8 *hwregs = dev->hwregs;

	if (dev->hw_feature.vcarb_ver == 0)
		return;
	if (dev->hw_feature.vcarb_ver == VCARB_VERSION_2_0)
		vcmd_online_for_arbiter(hwregs);

	iowrite32(0x0, (void __iomem *)(hwregs +
			VCMD_REGISTER_ARB_OFFSET));
	iowrite32(0x1, (void __iomem *)(hwregs +
			VCMD_REGISTER_ARB_OFFSET));
	while ((ioread32((void __iomem *)(hwregs +
		VCMD_REGISTER_ARB_OFFSET)) & 0x4) == 0)
		schedule();
}

/**
 * @brief release arbiter from keep serving vcmd
 */
void vcmd_release_arbiter(void *_vcmd_mgr, u32 subsys_id)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	struct hantrovcmd_dev *dev = &vcmd_mgr->dev_ctx[subsys_id];
	volatile u8 *hwregs = dev->hwregs;

	if (dev->hw_feature.vcarb_ver == 0)
		return;
	if (dev->hw_feature.vcarb_ver == VCARB_VERSION_2_0)
		vcmd_offline_for_arbiter(hwregs);

	// write arb_fe to clear arb_req
	iowrite32(0x2, (void __iomem *)(hwregs +
			VCMD_REGISTER_ARB_OFFSET));
}
#endif // VCARB_REQUEST

/**
 * @brief start a vcmd hw device to run the 1st not-done job in its work list.
 */
static void vcmd_start(struct hantrovcmd_dev *dev)
{
	struct cmdbuf_obj *obj = NULL;
	const void *hwregs = (const void *)dev->hwregs;
	bi_list_node *node;
	u32 *reg_mirror = dev->reg_mirror;
	addr_t cmd_ba;
	u32 ba_msb = 0;

	if (dev->state == VCMD_STATE_WORKING) {
		vcmd_klog(LOGLVL_BRIEF, "%s: vcmd is already in working state!\n", __func__);
		return;
	}

	dev->sw_cmdbuf_rdy_num = dev_get_job_num(dev);
	node = dev->work_list.head;
	while (node && ((struct cmdbuf_obj *)node->data)->cmdbuf_run_done)
		node = node->next;

	if (dev->sw_cmdbuf_rdy_num == 0 || node == NULL) {
		vcmd_klog(LOGLVL_BRIEF, "%s: no cmdbuf to start yet!\n", __func__);
#ifdef SUPPORT_WATCHDOG
		_vcmd_watchdog_stop(dev);
#endif
		return;
	}

	obj = (struct cmdbuf_obj *)node->data;

	printk_vcmd_register_debug(hwregs, "vcmd start enters");
	vcmd_klog(LOGLVL_FLOW, "vcmd start for cmdbuf id %d, cmdbuf_run_done = %d\n",
							obj->cmdbuf_id, obj->cmdbuf_run_done);

	//init HWIF_VCMD_EXE_CMDBUF_COUNT
	vcmd_write_register_value(hwregs, reg_mirror, HWIF_VCMD_EXE_CMDBUF_COUNT, 0);

	vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_RDY_CMDBUF_COUNT,
							dev->sw_cmdbuf_rdy_num);

	if (dev->state == VCMD_STATE_POWER_ON) {
		//0x40
	#ifdef HANTROVCMD_ENABLE_IP_SUPPORT
		//when start vcmd, first vcmd is init mode
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_INIT_ENABLE, dev->init_mode);
	#endif
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_AXI_CLK_GATE_DISABLE, 0);
		vcmd_set_reg_mirror(reg_mirror,
						HWIF_VCMD_MASTER_OUT_CLK_GATE_DISABLE, APB_CLK_MODE);
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_CORE_CLK_GATE_DISABLE, 0);
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_ABORT_MODE, dev->abort_mode);
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_RESET_CORE, 0);
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_RESET_ALL, 0);
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_START_TRIGGER, 0);
		//0x48
		if (dev->hw_feature.vcarb_ver) {
			if (dev->hw_feature.vcarb_ver == VCARB_VERSION_2_0)
				vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_IRQ_ARBRST_EN, 1);
			vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_IRQ_ARBERR_EN, 0);
		}
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_IRQ_JMP_EN, 1);

		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_IRQ_ABORT_EN, 1);
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_IRQ_CMDERR_EN, 1);
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_IRQ_TIMEOUT_EN, 1);
		if (dev->hw_version_id >= HW_ID_1_6_0) {
			vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_IRQ_BUSERR_EN, 1);
		} else {
			/* not report bus err interrup before v1.6.0*/
			vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_IRQ_BUSERR_EN, 0);
		}
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_IRQ_ENDCMD_EN, 1);
		//0x4c
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_TIMEOUT_ENABLE, 1);
		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_TIMEOUT_CYCLES, 500000000);

		vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_MAX_BURST_LEN, 0x10);

		//0x64
		reg_mirror[VCMD_REGISTER_EXT_INT_GATE_OFFSET / 4] = dev->intr_gate_mask;

		if (dev->hw_feature.vcarb_ver == VCARB_VERSION_2_0) {
			//0x70
			reg_mirror[VCMD_REGISTER_ARBITER_CONFIG_OFFSET / 4] =
					VCMD_ARBITER_PARAMS(arbiter_weight, arbiter_urgent, arbiter_bw_overflow,
										arbiter_timewindow);

		} else if (dev->hw_feature.has_cmdbuf_timeout) {
			// 0x70
			/* set cmdbuf_timeout_enable */
			reg_mirror[VCMD_REGISTER_CMDBUF_TIMEOUT_OFFSET / 4] |= 0xC0000000;
			/* need set one frame time, the value is multiple 256 cycles:
			 *  default: 0x40000000
			 *  according one frame time to set: frequency * ms / 1000 / 256
			 */
			//reg_mirror[VCMD_REGISTER_CMDBUF_TIMEOUT_OFFSET / 4] |=
			//		PLATFORM_FREQUENCY * ONE_JOB_WAIT_TIME / 1000 / 256;
			// 0x48
			reg_mirror[VCMD_REGISTER_INT_CTL_OFFSET / 4] |= (0x1 << 9);
		}
	}

	cmd_ba = obj->cmd_pa - dev->pa_trans_offset;
	if (dev->mmu_enable)
		cmd_ba = (addr_t)obj->mmu_cmd_ba;
	if (sizeof(addr_t) == 8)
		ba_msb = (u32)(cmd_ba >> 32);


	vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_CMDBUF_EXE_ADDR, (u32)cmd_ba);
	vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_CMDBUF_EXE_ADDR_MSB, ba_msb);
	vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_CMDBUF_EXE_LENGTH,
							(obj->cmdbuf_size + 7) / 8);

	if (dev->hw_version_id > HW_ID_1_0_C)
		vcmd_write_register_value(hwregs, reg_mirror,
									HWIF_VCMD_CMDBUF_EXE_ID,
									(u32)obj->cmdbuf_id);

	if (dev->state == VCMD_STATE_POWER_ON) {
		//0x44
		vcmd_write_reg(hwregs, VCMD_REGISTER_INT_STATUS_OFFSET,
			vcmd_read_reg(hwregs, VCMD_REGISTER_INT_STATUS_OFFSET));
		//0x40
		vcmd_write_reg(hwregs, VCMD_REGISTER_CONTROL_OFFSET,
			reg_mirror[VCMD_REGISTER_CONTROL_OFFSET / 4]);
		//0x48
		vcmd_write_reg(hwregs, VCMD_REGISTER_INT_CTL_OFFSET,
			reg_mirror[VCMD_REGISTER_INT_CTL_OFFSET / 4]);
		//0x4c
		vcmd_write_reg(hwregs, VCMD_REGISTER_TIMEOUT_OFFSET,
			reg_mirror[VCMD_REGISTER_TIMEOUT_OFFSET / 4]);
		//0x5c
		vcmd_write_reg(hwregs, VCMD_REGISTER_SWAP_OFFSET,
			reg_mirror[VCMD_REGISTER_SWAP_OFFSET / 4]);
		//0x64
		vcmd_write_reg(hwregs, VCMD_REGISTER_EXT_INT_GATE_OFFSET,
			reg_mirror[VCMD_REGISTER_EXT_INT_GATE_OFFSET / 4]);
		//0x70
		if (dev->hw_feature.vcarb_ver == VCARB_VERSION_2_0)
			vcmd_write_reg(hwregs, VCMD_REGISTER_ARBITER_CONFIG_OFFSET,
				reg_mirror[VCMD_REGISTER_ARBITER_CONFIG_OFFSET / 4]);
		else if (dev->hw_feature.has_cmdbuf_timeout)
			vcmd_write_reg(hwregs, VCMD_REGISTER_CMDBUF_TIMEOUT_OFFSET,
				reg_mirror[VCMD_REGISTER_CMDBUF_TIMEOUT_OFFSET / 4]);
		if (dev->hw_version_id >= HW_ID_1_2_1)
			vcmd_set_init_cmds(dev);
	}

	//0x50
	vcmd_write_reg(hwregs, VCMD_REGISTER_CMDBUF_EXE_ADDR_LSB_OFFSET,
		reg_mirror[VCMD_REGISTER_CMDBUF_EXE_ADDR_LSB_OFFSET / 4]);
	//0x54
	vcmd_write_reg(hwregs, VCMD_REGISTER_CMDBUF_EXE_ADDR_MSB_OFFSET,
		reg_mirror[VCMD_REGISTER_CMDBUF_EXE_ADDR_MSB_OFFSET / 4]);
	//0x58
	vcmd_write_reg(hwregs, VCMD_REGISTER_CMDBUF_EXE_LEN_OFFSET,
		reg_mirror[VCMD_REGISTER_CMDBUF_EXE_LEN_OFFSET / 4]);
	//0x60
	vcmd_write_reg(hwregs, VCMD_REGISTER_RDY_CMDBUF_COUNT_OFFSET,
		reg_mirror[VCMD_REGISTER_RDY_CMDBUF_COUNT_OFFSET / 4]);
	dev->state = VCMD_STATE_WORKING;

	//start
	vcmd_set_reg_mirror(reg_mirror, HWIF_VCMD_START_TRIGGER, 1);
	vcmd_write_reg(hwregs, VCMD_REGISTER_CONTROL_OFFSET,
		reg_mirror[VCMD_REGISTER_CONTROL_OFFSET / 4]);

#ifdef SUPPORT_WATCHDOG
	_vcmd_watchdog_feed(dev);
#endif

	printk_vcmd_register_debug(hwregs, "vcmd start exits");
}

/**
 * @brief abort a specified vcmd hw device.
 * @param u32 *aborted_id: the id of aborted cmdbuf.
 * @param u32 vcmd_isr_polling: the mode to wait for device being aborted.
 */
static int vcmd_abort(vcmd_mgr_t *vcmd_mgr, struct hantrovcmd_dev *dev, u32 *aborted_id)
{
	unsigned long flags = 0;
	u32 cnt = 100000, irq;

	spin_lock_irqsave(dev->spinlock, flags);
	vcmd_write_register_value((const void *)dev->hwregs,
								dev->reg_mirror,
								HWIF_VCMD_START_TRIGGER, 0);
	spin_unlock_irqrestore(dev->spinlock, flags);
	if (vcmd_isr_polling == 0) {
		if (wait_event_interruptible(*dev->abort_waitq,
						(dev->state == VCMD_STATE_IDLE))) {
			vcmd_klog(LOGLVL_ERROR, "%s: abort_waitq is signaled!!!\n", __func__);
			vcmd_klog(LOGLVL_BRIEF, "%s: continue to wait vcmd aborted!!!\n", __func__);
			goto isr_polling;
		} else {
			goto out;
		}
	}

isr_polling:
	irq = (dev->subsys_info->irq == -1) ?
			dev->core_id : dev->subsys_info->irq;

	while (cnt--) {
		usleep_range(100, 120);
		hantrovcmd_isr(irq, vcmd_mgr);
		if (dev->state == VCMD_STATE_IDLE) {
			cnt += 1;
			break;
		}
	}
	if (cnt == 0) {
		vcmd_klog(LOGLVL_ERROR, "%s: can't wait aborted!!!\n", __func__);
		return -ERESTARTSYS;
	}

out:
	if (aborted_id)
		*aborted_id = dev->aborted_cmdbuf_id;

	vcmd_klog(LOGLVL_BRIEF, "%s: vcmd aborted cmdbuf[%u].\n", __func__, dev->aborted_cmdbuf_id);

	return 0;

}

/**
 * @brief select a suitable device, and add/insert a job node to its work_list.
 */
static int select_vcmd(vcmd_mgr_t *vcmd_mgr, bi_list_node *new_node)
{
	struct hantrovcmd_dev *dev, *smallest_dev;
	struct vcmd_module_mgr *module;
	struct cmdbuf_obj *obj, *tmp_obj;
	bi_list_node *curr_node;
	bi_list *list;
	u64 least_workload;
	u32 reg_id_exe;

	u32 cmdbuf_id, i;
	unsigned long flags = 0;
	addr_t curr_exe_addr;
	int ret;

	obj = (struct cmdbuf_obj *)new_node->data;
	module = &vcmd_mgr->module_mgr[obj->module_type];

	/* To check if there is free dev, or dev which tail node is run-done. */
	for (i = 0; i < module->num; i++) {
		dev = module->dev[i];
		ret = is_supported_core(obj->core_mask, dev->core_id);
		if (ret == 0)
			continue;

		list = &dev->work_list;
		spin_lock_irqsave(dev->spinlock, flags);
		if (!list->tail ||
			((struct cmdbuf_obj *)list->tail->data)->cmdbuf_run_done) {
			dev_add_job(dev, new_node);
			spin_unlock_irqrestore(dev->spinlock, flags);
			return 0;
		}
		spin_unlock_irqrestore(dev->spinlock, flags);
	}

	// There is no vcmd in free, calculate each workload, select the least one.
	// If low priority, insert to tail.
	// If high priority, abort the dev, and insert to "head".
	reg_id_exe = REG_ID_CMDBUF_EXE_ID;
	if (obj->priority == CMDBUF_PRIORITY_NORMAL)
		reg_id_exe = REG_ID2_CMDBUF_EXE_ID;

	least_workload = 0xffffffffffffffff;
	smallest_dev = NULL;
	//calculate remain workload of all dev, find the least one
	for (i = 0; i < module->num; i++) {
		dev = module->dev[i];
		ret = is_supported_core(obj->core_mask, dev->core_id);
		if (ret == 0)
			continue;

		list = &dev->work_list;

		//get the executing cmdbuf node.
		if (dev->hw_version_id <= HW_ID_1_0_C) {
			curr_exe_addr = VCMDGetAddrRegisterValue((const void *)dev->hwregs,
												dev->reg_mirror,
												HWIF_VCMD_CMDBUF_EXE_ADDR);

			curr_node = get_cmdbuf_node_by_addr(vcmd_mgr, dev, curr_exe_addr);

		} else {
			//cmdbuf_id = vcmd_get_register_value((const void *)dev->hwregs,
			//dev->reg_mirror,HWIF_VCMD_CMDBUF_EXE_ID);
			cmdbuf_id = *(dev->reg_mem_va + reg_id_exe);
			if (cmdbuf_id >= SLOT_NUM_CMDBUF) {
				vcmd_klog(LOGLVL_ERROR, "cmdbuf_id greater than the ceiling !!\n");
				return -1;
			}

			curr_node = &vcmd_mgr->nodes[cmdbuf_id];
		}

		spin_lock_irqsave(dev->spinlock, flags);
		if (!curr_node)
			curr_node = list->head;
		//calculate total workload of this device
		dev->total_workload = calc_workload_after_node(curr_node);
		spin_unlock_irqrestore(dev->spinlock, flags);

		if (dev->total_workload <= least_workload) {
			least_workload = dev->total_workload;
			smallest_dev = dev;
		}
	}

	if (smallest_dev == NULL) {
		vcmd_klog(LOGLVL_ERROR, "%s: no dev is available to cmdbuf [%d] with core_mask 0x%x\n",
					__func__, obj->cmdbuf_id, obj->core_mask);
		return -EINVAL;
	}

	list = &smallest_dev->work_list;
	if (obj->priority == CMDBUF_PRIORITY_NORMAL) {
		//insert to tail
		spin_lock_irqsave(smallest_dev->spinlock, flags);
		dev_add_job(smallest_dev, new_node);
		spin_unlock_irqrestore(smallest_dev->spinlock, flags);
		return 0;
	}

	//CMDBUF_PRIORITY_HIGH
	//abort the vcmd and wait
	if (vcmd_abort(vcmd_mgr, smallest_dev, &cmdbuf_id)) {
		//abort failed
		return -ERESTARTSYS;
	}
	// need to select inserting position again
	// because hw maybe have run to the next node.
	// CMDBUF_PRIORITY_HIGH
	spin_lock_irqsave(smallest_dev->spinlock, flags);
	curr_node = &vcmd_mgr->nodes[cmdbuf_id];
	if (smallest_dev->abort_mode == 0)
		curr_node = curr_node->next;
	while (curr_node) {
		tmp_obj = (struct cmdbuf_obj *)curr_node->data;
		//find the 1st node with normal priority, and insert node prior to it
		if (tmp_obj->priority == CMDBUF_PRIORITY_NORMAL)
			break;
		curr_node = curr_node->next;
	}

	//insert to "head" of normal priority nodes
	dev_insert_job(smallest_dev, curr_node, new_node);
	spin_unlock_irqrestore(smallest_dev->spinlock, flags);
	return 0;
}

/**
 * @brief acquire workload from process object.
 * @return int: 0: succeed; Others: failed.
 */
static int wait_process_resource_rdy(struct proc_obj *po)
{
	return po->total_workload <= PROCESS_MAX_WORKLOAD;
}

static int acquire_process_resource(struct proc_obj *po, u64 workload)
{
	spin_lock(&po->spinlock);
	po->total_workload += workload;
	spin_unlock(&po->spinlock);
	if (wait_event_interruptible(po->resource_waitq,
									wait_process_resource_rdy(po))) {
		vcmd_klog(LOGLVL_ERROR, "%s: wait event is interrupted!", __func__);
		return -1;
	}

	return 0;
}

/**
 * @brief return cmdbuf obj's workload to process object.
 */
static void return_process_resource(struct proc_obj *po,
									struct cmdbuf_obj *obj)
{
	if (po && obj->workload) {
		spin_lock(&po->spinlock);
		po->total_workload -= obj->workload;
		spin_unlock(&po->spinlock);
		obj->workload = 0;
		wake_up_interruptible_all(&po->resource_waitq);
	}
}

/**
 * @brief reserve a cmdbuf for specified process object.
 * @param struct exchange_parameter *param: the param of cmdbuf to reserve.
 * @return long: 0: succeed; oters: failed.
 */
static long reserve_cmdbuf(vcmd_mgr_t *vcmd_mgr, struct proc_obj *po,
			   struct exchange_parameter *param)
{
	struct cmdbuf_obj *obj;
	u32 cmdbuf_id = 0;

	if (param->cmdbuf_size > SLOT_SIZE_CMDBUF) {
		vcmd_klog(LOGLVL_ERROR, "%s size is larger than slot size !!\n", __func__);
		return -1;
	}

	if (!po) {
		vcmd_klog(LOGLVL_ERROR, "%s: not find process obj!\n", __func__);
		return -1;
	}
	vcmd_klog(LOGLVL_FLOW, "reserve cmdbuf by filp %p\n", (void *)po->filp);

	if (acquire_process_resource(po, param->executing_time))
		return -1;

	if (acquire_cmdbuf(vcmd_mgr, &cmdbuf_id))
		return -ERESTARTSYS;

	reset_cmdbuf_obj(vcmd_mgr, cmdbuf_id);
	reset_cmdbuf_node(vcmd_mgr, cmdbuf_id);

	obj = &vcmd_mgr->objs[cmdbuf_id];
	obj->module_type = param->module_type;
	obj->priority = EXCH_G_BIT(param->input_mask, EXCH_PRIO_BIT);
	obj->workload = param->executing_time;
	obj->filp = po->filp;
	obj->po = po;
	obj->owner = param->owner;
	obj->core_mask = param->core_mask;

	param->cmdbuf_size = SLOT_SIZE_CMDBUF;
	param->cmdbuf_id = cmdbuf_id;
	vcmd_klog(LOGLVL_FLOW, "%s, filp[%p] reserved cmdbuf[%d]: obj %p, node %p of owner %p\n",
			__func__, (void *)obj->filp, cmdbuf_id, (void *)obj,
			(void *)&vcmd_mgr->nodes[cmdbuf_id], obj->owner);
#ifdef SUPPORT_DBGFS
	_dbgfs_record_reserved_time(vcmd_mgr->dev_ctx[0].dbgfs_info,
								param->cmdbuf_id);
#endif

	return 0;
}

/**
 * @brief release a specified cmdbuf.
 * @return long: 0: succeed; oters: failed.
 */
static long release_cmdbuf(vcmd_mgr_t *vcmd_mgr,
							struct proc_obj *po, u16 cmdbuf_id)
{
	struct cmdbuf_obj *obj = NULL;
	bi_list_node *curr_node = NULL;
	unsigned long flags;
	struct hantrovcmd_dev *dev = NULL;

	if (cmdbuf_id >= SLOT_NUM_CMDBUF) {
		//should not happen
		vcmd_klog(LOGLVL_ERROR, "%s: ERROR cmdbuf_id %d!!\n", __func__, cmdbuf_id);
		return -1;
	}

	curr_node = &vcmd_mgr->nodes[cmdbuf_id];
	obj = (struct cmdbuf_obj *)curr_node->data;
	if (obj->po != po) {
		//should not happen
		vcmd_klog(LOGLVL_ERROR, "%s: cmdbuf[%d] po not match: owned by %p, released by %p!!\n",
						__func__, cmdbuf_id, obj->po, po);
		return -1;
	}

	obj->owner = NULL;
	if (obj->cmdbuf_linked == 0) {
		//not link_and_run yet
		obj = (struct cmdbuf_obj *)curr_node->data;
		return_process_resource(obj->po, obj);
		return_cmdbuf(vcmd_mgr, cmdbuf_id);
	} else {
		obj->cmdbuf_need_remove = 1;
		dev = &vcmd_mgr->dev_ctx[obj->core_id];

		return_process_resource(obj->po, obj);
		spin_lock_irqsave(dev->spinlock, flags);
		dev_remove_job(vcmd_mgr, dev, curr_node);
		spin_unlock_irqrestore(dev->spinlock, flags);
	}

	return 0;
}

/**
 * @brief add/insert a cmdbuf (job) to suitable device,
 *  and start the device hw if it is not working.
 * @param struct exchange_parameter *param: the param of cmdbuf to link & run.
 * @return long: 0: succeed; oters: failed.
 */
static long link_and_run_cmdbuf(vcmd_mgr_t *vcmd_mgr, struct proc_obj *po,
				struct exchange_parameter *param)
{
	struct cmdbuf_obj *obj;
	bi_list_node *curr_node;

	struct hantrovcmd_dev *dev = NULL;
	unsigned long flags;
	int ret;
	u16 cmdbuf_id = param->cmdbuf_id;

	struct cmd_jmp_t *cmd_jmp;

	if (cmdbuf_id >= SLOT_NUM_CMDBUF) {
		//should not happen
		vcmd_klog(LOGLVL_ERROR, "%s: ERROR cmdbuf_id %d!!\n", __func__, cmdbuf_id);
		return -1;
	}

	curr_node = &vcmd_mgr->nodes[cmdbuf_id];
	obj = (struct cmdbuf_obj *)curr_node->data;
	if (obj->po != po) {
		//should not happen
		vcmd_klog(LOGLVL_ERROR, "%s: cmdbuf[%d] po not match: owned by %p, released by %p!!\n",
						__func__, cmdbuf_id, obj->po, po);
		return -1;
	}

	obj->cmdbuf_size = param->cmdbuf_size;
#ifdef VCMD_DEBUG_INTERNAL
	_dbg_log_cmdbuf(obj);
#endif
	//0: has jmp opcode,1 has end code
	obj->has_jmp_cmd = (EXCH_G_BIT(param->input_mask, EXCH_END_CMD_BIT)) ? 0 : 1;

	if (obj->has_jmp_cmd) {
		//last command is JMP, get its IE value.
		cmd_jmp = _get_jmp_cmd(obj);
		vcmd_klog(LOGLVL_FLOW, "has jmp cmd and the last cmd is JMP!\n");

		if ((cmd_jmp->opcode & OPCODE_MASK) != OPCODE_JMP) {
			vcmd_klog(LOGLVL_ERROR,
				"%s: cmdbuf[%d] is not terminated by JMP, not match with its flag!",
				__func__, obj->cmdbuf_id);
			return -1;
		}
		obj->jmp_ie = 0;
		if (JMP_G_IE(cmd_jmp->opcode))
			obj->jmp_ie = 1;
	}

	if (down_interruptible(&vcmd_mgr->module_mgr[obj->module_type].sem))
		return -ERESTARTSYS;

	ret = select_vcmd(vcmd_mgr, curr_node);
	if (ret) {
		up(&vcmd_mgr->module_mgr[obj->module_type].sem);
		return ret;
	}

	dev = &vcmd_mgr->dev_ctx[obj->core_id];
	param->core_id = obj->core_id;
	vcmd_klog(LOGLVL_FLOW, "Assign cmdbuf[%d] to core[%d]\n",
			  cmdbuf_id, param->core_id);

	//start to run
	spin_lock_irqsave(dev->spinlock, flags);
	if (dev->state != VCMD_STATE_WORKING) {
		//start vcmd
		vcmd_start(dev);
	} else {
		dev->sw_cmdbuf_rdy_num++;
#ifdef SUPPORT_DBGFS
		_dbgfs_record_link_time(dev->dbgfs_info, cmdbuf_id,
								dev->sw_cmdbuf_rdy_num,
								obj->workload);
#endif
		//just update cmdbuf ready number
		vcmd_write_register_value((const void *)dev->hwregs,
									dev->reg_mirror,
									HWIF_VCMD_RDY_CMDBUF_COUNT,
									dev->sw_cmdbuf_rdy_num);
#ifdef SUPPORT_WATCHDOG
		_vcmd_watchdog_feed(dev);
#endif
	}

	//new cmdbuf linked, and free the removeable cmdbuf.
	if (curr_node->prev) {
		obj = (struct cmdbuf_obj *)curr_node->prev->data;
		if (obj->cmdbuf_need_remove) {
			//free the job
			dev_remove_job(vcmd_mgr, dev, curr_node->prev);
		}
	}

	spin_unlock_irqrestore(dev->spinlock, flags);

	up(&vcmd_mgr->module_mgr[obj->module_type].sem);

	return 0;
}

/**
 * @brief wait a cmdbuf runs done.
 * @param u16 cmdbuf_id: the id of cmdbuf to wait.
 * @param u16 *done_id: point to the id of done cmdbuf.
 * @return long: 0: succeed; oters: failed.
 */
static long wait_cmdbuf_ready(vcmd_mgr_t *vcmd_mgr, struct proc_obj *po,
								u16 cmdbuf_id, u16 *done_id)
{
	struct cmdbuf_obj *obj = NULL;

	if (!po) {
		vcmd_klog(LOGLVL_ERROR, "%s: not find process obj!\n", __func__);
		return -ERESTARTSYS;
	}

	if (cmdbuf_id != ANY_CMDBUF_ID) {
		vcmd_klog(LOGLVL_FLOW, "%s\n", __func__);
		obj = &vcmd_mgr->objs[cmdbuf_id];
		if (obj->po != po) {
			//should not happen
			vcmd_klog(LOGLVL_ERROR, "%s: ERROR cmdbuf filp not match!\n", __func__);
			return -1;
		}
#ifdef IRQ_SIMULATION
		_irq_simul_add_timer(obj);
#endif
	}

	if (wait_event_interruptible(po->job_waitq,
						proc_get_done_job(vcmd_mgr, po, &obj))) {
		vcmd_klog(LOGLVL_ERROR, "vcmd_wait_queue_0 interrupted\n");
		return -ERESTARTSYS;
	}

	if (obj == NULL)
		*done_id = ANY_CMDBUF_ID;
	else
		*done_id = obj->cmdbuf_id;

	return 0;
}

#if !defined(PCI_DDR_BAR)

#ifdef PCIE_EN
#define TOP_DEVICE_WORKED_BY_DMA (vcmd_mgr->platformdev->dev.parent)
#else
#define TOP_DEVICE_WORKED_BY_DMA (&vcmd_mgr->platformdev->dev)
#endif

/**
 * @brief allocate a memory pool, for non-PCIe platform.
 */
static int _vcmd_alloc_mem(vcmd_mgr_t *vcmd_mgr, struct noncache_mem *mem)
{
	dma_addr_t dma_handle = 0;

	/* command buffer */
	mem->va = (u32 *)dma_alloc_coherent(TOP_DEVICE_WORKED_BY_DMA,
							mem->size, &dma_handle,
							GFP_KERNEL | __GFP_DMA32);
	if (!mem->va)
		return -EFAULT;

	mem->pa = (unsigned long long)dma_handle;

	vcmd_klog(LOGLVL_FLOW, "Init[%s]: mem size=%d pa=0x%llx, va=0x%llx.\n", __func__,
			mem->size, (unsigned long long)mem->pa, (unsigned long long)mem->va);
#ifdef SUPPORT_MMU
	if (vcmd_mgr->mmu_enable) {
		struct kernel_addr_desc mmu_addr;

		mmu_addr.bus_address = mem->pa;
		mmu_addr.size = mem->size;
		if (MMUKernelMemNodeMap(&mmu_addr, NULL) != MMU_STATUS_OK) {
			vcmd_klog(LOGLVL_ERROR, "Init[%s] mmu map mem failed\n", __func__);
			return -1;
		}
		mem->mmu_ba = mmu_addr.mmu_bus_address;
		vcmd_klog(LOGLVL_FLOW, "Init[%s]: mem->mmu_ba=0x%llx.\n", __func__,
				(unsigned long long)mem->mmu_ba);
	}
#endif
	return 0;
}

/**
 * @brief free the specified memory pool, for non-PCIe platform.
 */
static void _vcmd_free_mem(vcmd_mgr_t *vcmd_mgr, struct noncache_mem *mem)
{
	if (mem->va) {
#ifdef SUPPORT_MMU
		struct kernel_addr_desc mmu_addr;

		if (vcmd_mgr->mmu_enable && mem->mmu_ba) {
			mmu_addr.bus_address = mem->pa;
			mmu_addr.size = mem->size;
			MMUKernelMemNodeUnmap(&mmu_addr);
			mem->mmu_ba = 0;
		}
#endif
		dma_free_coherent(TOP_DEVICE_WORKED_BY_DMA,
							mem->size, mem->va, (dma_addr_t)mem->pa);
		mem->va = NULL;
	}
}
#endif

#if defined(PCI_DDR_BAR)
/**
 * @brief clean-up reserved PCIe resources.
 */
static void _vcmd_pcie_cleanup(vcmd_mgr_t *vcmd_mgr)
{
#ifdef SUPPORT_MMU
	struct kernel_addr_desc mmu_addr;

	if (vcmd_mgr->mmu_enable && vcmd_mgr->pcie_pool.mmu_ba) {
		mmu_addr.bus_address = vcmd_mgr->pcie_pool.pa - vcmd_mgr->pa_trans_offset;
		mmu_addr.size = vcmd_mgr->pcie_pool.size;
		MMUKernelMemNodeUnmap(&mmu_addr);
		vcmd_mgr->pcie_pool.mmu_ba = 0;
	}
#endif
	if (vcmd_mgr->pcie_pool.va) {
		iounmap((void __iomem *)vcmd_mgr->pcie_pool.va);
		release_mem_region(vcmd_mgr->pcie_pool.pa, vcmd_mgr->pcie_pool.size);
		vcmd_mgr->pcie_pool.va = NULL;
	}
}
#endif

/**
 * @brief allocate memory pools.
 * @return int: 0: succeed; other: failed.
 */
static int vcmd_init(vcmd_mgr_t *vcmd_mgr)
{
#if defined(PCIE_EN) && defined(PCI_DDR_BAR)
	u8 *va;
	struct noncache_mem *mem_pcie = &vcmd_mgr->pcie_pool;
	u32 offset;
	unsigned long pci_ddr_base = gBaseDDRHw;
#endif
#ifdef SUPPORT_MMU
	struct kernel_addr_desc mmu_addr;

	vcmd_mgr->mmu_enable = mmu_enable;
#endif
	vcmd_klog(LOGLVL_CONFIG, "MMU %s.\n", vcmd_mgr->mmu_enable ? "ENABLE" : "DISABLE");

#if defined(PCIE_EN) && defined(PCI_DDR_BAR)
	mem_pcie->size = vcmd_mgr->mem_vcmd.size +
						vcmd_mgr->mem_status.size +
						vcmd_mgr->mem_regs.size;

	vcmd_mgr->pa_trans_offset = pci_ddr_base;

	/* allocate a single pool for all noncache_mems*/
	mem_pcie->pa = pci_ddr_base + ddr_offset + VCMD_BUF_POOL_OFFSET;
	if (!request_mem_region(mem_pcie->pa,
							mem_pcie->size,
							"vcx_vcmd_driver")) {
		vcmd_klog(LOGLVL_ERROR, "%s: failed to request vcmd pool memory region .\n", __func__);
		return -1;
	}
	vcmd_klog(LOGLVL_CONFIG, "Init: pcie pool pa=0x%llx.\n", (unsigned long long)mem_pcie->pa);
#if (KERNEL_VERSION(4, 17, 0) > LINUX_VERSION_CODE)
	mem_pcie->va = (void __force *)ioremap_nocache(mem_pcie->pa, mem_pcie->size);
#else
	mem_pcie->va = (void __force *)ioremap(mem_pcie->pa, mem_pcie->size);
#endif

	if (!mem_pcie->va) {
		vcmd_klog(LOGLVL_ERROR, "Init: failed to ioremap.\n");
		return -1;
	}
	vcmd_klog(LOGLVL_CONFIG, "%s: pcie pool va=0x%p.\n", __func__, mem_pcie->va);
#ifdef SUPPORT_MMU
	if (vcmd_mgr->mmu_enable) {
		mmu_addr.bus_address = mem_pcie->pa - pci_ddr_base;
		mmu_addr.size = mem_pcie->size;
		if (MMUKernelMemNodeMap(&mmu_addr, NULL) != MMU_STATUS_OK)
			return -1;
		mem_pcie->mmu_ba = mmu_addr.mmu_bus_address;
		vcmd_klog(LOGLVL_CONFIG, "%s: pool mmu_ba=0x%llx.\n", __func__,
			(unsigned long long)mem_pcie->mmu_ba);
	}
#endif

	/* layout this pool to noncache_mems*/
	offset = 0;
	va = (u8 *)mem_pcie->va;

	vcmd_mgr->mem_vcmd.pa = mem_pcie->pa + offset;
	vcmd_mgr->mem_vcmd.va = (u32 *)(va + offset);
	vcmd_mgr->mem_vcmd.mmu_ba = mem_pcie->mmu_ba + offset;
	offset += vcmd_mgr->mem_vcmd.size;

	vcmd_mgr->mem_status.pa = mem_pcie->pa + offset;
	vcmd_mgr->mem_status.va = (u32 *)(va + offset);
	vcmd_mgr->mem_status.mmu_ba = mem_pcie->mmu_ba + offset;
	offset += vcmd_mgr->mem_status.size;

	vcmd_mgr->mem_regs.pa = mem_pcie->pa + offset;
	vcmd_mgr->mem_regs.va = (u32 *)(va + offset);
	vcmd_mgr->mem_regs.mmu_ba = mem_pcie->mmu_ba + offset;


#else //PCIE_EN && PCI_DDR_BAR
	/* use dma_alloc_coherent for non-pcie env or pci without memory BAR */
#if 0
	pci_ddr_base = alloc_base;
	g_vcmd_base_len = alloc_size * 1024 * 1024;
#else

	if (_vcmd_alloc_mem(vcmd_mgr, &vcmd_mgr->mem_vcmd))
		return -1;
	if (_vcmd_alloc_mem(vcmd_mgr, &vcmd_mgr->mem_status))
		return -1;
	if (_vcmd_alloc_mem(vcmd_mgr, &vcmd_mgr->mem_regs))
		return -1;
#endif
#endif //PCIE_EN && PCI_DDR_BAR

	return 0;
}

/**
 * @brief initialize context of all vcmd dev
 */
static void dev_ctx_init(vcmd_mgr_t *vcmd_mgr)
{
	u32 i;
	struct hantrovcmd_dev *dev;
	u32 m_type;
	struct vcmd_module_mgr *module;

	memset(vcmd_mgr->dev_ctx,
			0, sizeof(struct hantrovcmd_dev) * vcmd_mgr->subsys_num);
	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		dev = &vcmd_mgr->dev_ctx[i];

		dev->handler = (void *)vcmd_mgr;
		dev->subsys_info = &vcmd_mgr->core_array[i];
		m_type = dev->subsys_info->sub_module_type;

		dev->core_id = i;
		dev->state = VCMD_STATE_POWER_ON;
		dev->sw_cmdbuf_rdy_num = 0;
		/* the abnormal interrupts source from VCD */
		dev->abn_irq_mask = DEC_ABN_IRQ_MASK;
		dev->vcd_abn_irq_mask = DEC_ABN_IRQ_MASK;
#ifdef AXI2TO1_SUPPORT
		/* the abnormal interrupts source from AXI2TO1.
		 * currently, the axi2to1 interrupt has been connect to abnormal by HW,
		 * SW does't need to set the interrupt type as abnormal
		 */
		dev->abn_irq_mask |= AXI2TO1_ABN_IRQ_MASK;
#endif
		dev->intr_gate_mask = 0xFFFFFFFF & (~dev->abn_irq_mask);

		dev->timeout_timer_active = 0;
		dev->watchdog_active = 0;
		dev->arb_reset_irq = 0;
		dev->arb_err_irq = 0;
		dev->mmu_enable = vcmd_mgr->mmu_enable;
		dev->abort_mode = 0;
		dev->init_mode = VCMD_INIT_NORMAL;

		dev->spinlock = &dev->owner_lock_vcmd;
		spin_lock_init(dev->spinlock);
		spin_lock_init(&dev->abn_irq_lock);
		dev->abort_waitq = &dev->abort_queue_vcmd;
		init_waitqueue_head(dev->abort_waitq);
		init_waitqueue_head(&dev->buff_empty_waitq);

		init_bi_list(&dev->work_list);

		dev->reg_mem_ba = vcmd_mgr->mem_regs.pa +
							i * SLOT_SIZE_REGBUF - vcmd_mgr->pa_trans_offset;
		dev->mmu_reg_mem_ba = vcmd_mgr->mem_regs.mmu_ba +
								i * SLOT_SIZE_REGBUF;
		dev->reg_mem_va = vcmd_mgr->mem_regs.va + i * SLOT_SIZE_REGBUF / 4;
		dev->reg_mem_sz = SLOT_SIZE_REGBUF;
		memset(dev->reg_mem_va, 0, dev->reg_mem_sz);
		dev->pa_trans_offset = vcmd_mgr->pa_trans_offset;

		module = &vcmd_mgr->module_mgr[m_type];
		if (module->num == 0)
			sema_init(&module->sem, 1);
		module->dev[module->num++] = dev;

		vcmd_klog(LOGLVL_CONFIG, "module init - vcmdcore[%d] addr =0x%llx\n",
			i, (unsigned long long)dev->subsys_info->reg_base);
	}
}

/**
 * @brief fill cmdbuf to read main module's all regs.
 */
#define VCMD_READ_CMD(cmd, n, off, addr) \
	do { \
		(cmd)->opcode = OPCODE_RREG | RREG_MODE(RREG_ADDR_INC) | \
						RREG_LEN(n) | \
						RREG_START_ADDR(off); \
		CMD_SET_ADDR(cmd, (addr)+(off)); \
		(cmd)->padding = 0; \
		cmd++; \
	} while (0)

static void create_read_all_registers_cmdbuf(vcmd_mgr_t *vcmd_mgr,
											struct exchange_parameter *param)
{
	struct hantrovcmd_dev *dev;
	struct vcmd_subsys_info *subsys;
	struct cmd_rreg_t *cmd_rreg;
	struct cmd_end_t *cmd_end;
	u8 *p_cmdbuf;
	addr_t reg_ba;

	dev = &vcmd_mgr->dev_ctx[param->core_id];
	subsys = dev->subsys_info;

	reg_ba = dev->reg_mem_ba;
	if (dev->mmu_enable)
		reg_ba = (addr_t)dev->mmu_reg_mem_ba;

	p_cmdbuf = (u8 *)vcmd_mgr->mem_vcmd.va + CMDBUF_OFF(param->cmdbuf_id);

	cmd_rreg = (struct cmd_rreg_t *)(p_cmdbuf + 0);
	if (dev->hw_version_id > HW_ID_1_0_C) {
		//read vcmd executing cmdbuf id registers to ddr for balancing core load.
		VCMD_READ_CMD(cmd_rreg, 1, REG_ID_CMDBUF_EXE_ID * 4, 0);
	}
	//read main IP all registers
	VCMD_READ_CMD(cmd_rreg,
				subsys->io_size[SUB_MOD_MAIN] / 4,
				subsys->reg_off[SUB_MOD_MAIN] + 0,
				reg_ba);

#ifdef SUPPORT_AXIFE
	if (subsys->io_size[SUB_MOD_AXIFE])
		VCMD_READ_CMD(cmd_rreg, 1,
					subsys->reg_off[SUB_MOD_AXIFE] + 0,
					reg_ba);
#endif

	if (dev->hw_version_id > HW_ID_1_0_C) {
		//read vcmd registers to ddr, to compliant with user cmdbuf
		VCMD_READ_CMD(cmd_rreg, 27, 0, 0);
	}
	//end cmd
	cmd_end = (struct cmd_end_t *)cmd_rreg;
	cmd_end->opcode = OPCODE_END;
	cmd_end->padding = 0;
	cmd_end++;

	param->cmdbuf_size = (u8 *)cmd_end - p_cmdbuf;
}

/**
 * @brief release submodule IO resource for vcmd driver
 */
static void vcmd_release_submodule_IO(struct vcmd_subsys_info *subsys, u32 sub_mod_id)
{
	if (subsys->hwregs[sub_mod_id]) {
		iounmap((volatile u8 __iomem *)subsys->hwregs[sub_mod_id]);
		release_mem_region(subsys->reg_base + subsys->reg_off[sub_mod_id],
			subsys->io_size[sub_mod_id]);
		subsys->hwregs[sub_mod_id] = NULL;
	}
}

/**
 * @brief reserve submodule IO resource for vcmd driver
 */
static u32 vcmd_reserve_submodule_IO(struct vcmd_subsys_info *subsys, u32 sub_mod_id)
{
	addr_t pa = subsys->reg_base + subsys->reg_off[sub_mod_id];
	size_t sz = subsys->io_size[sub_mod_id];

	if (!request_mem_region(pa, sz, "vcx_vcmd_driver"))
		return -EBUSY;

#if (KERNEL_VERSION(4, 17, 0) > LINUX_VERSION_CODE)
	subsys->hwregs[sub_mod_id] = (volatile u8 __force *)ioremap_nocache(pa, sz);
#else
	subsys->hwregs[sub_mod_id] = (volatile u8 __force *)ioremap(pa, sz);
#endif

	return 0;
}

/**
 * @brief reserve IO resources for vcmd driver.
 */
static int vcmd_reserve_IO(vcmd_mgr_t *vcmd_mgr)
{
	u32 hwid;
	int i;
	u32 found_hw = 0;
	struct hantrovcmd_dev *dev;
	struct vcmd_subsys_info *subsys;
	u32 reg_val;
	int ret, has_arbiter;

	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		dev = &vcmd_mgr->dev_ctx[i];
		subsys = dev->subsys_info;
		dev->hwregs = NULL;

		ret = vcmd_reserve_submodule_IO(subsys, SUB_MOD_VCMD);
		if (ret < 0) {
			vcmd_klog(LOGLVL_ERROR, "failed to reserve HW regs for vcmd[%d]\n",
						i);
			vcmd_klog(LOGLVL_ERROR,
						"vcmd_base_addr = %llx, iosize = %d\n",
						subsys->reg_base, subsys->io_size[SUB_MOD_VCMD]);
			continue;
		}
		if (!subsys->hwregs[SUB_MOD_VCMD]) {
			vcmd_klog(LOGLVL_ERROR, "failed to ioremap HW regs\n");
			release_mem_region(
				subsys->reg_base, subsys->io_size[SUB_MOD_VCMD]);
			continue;
		}
		dev->hwregs = subsys->hwregs[SUB_MOD_VCMD];
		vcmd_core_array[i].submodule_vcmd_virtual_address = dev->hwregs;

		/*read hwid and check validness and store it*/
		hwid = (u32)ioread32((void __iomem *)dev->hwregs);
		vcmd_klog(LOGLVL_CONFIG, DRIVER_NAME "_vcmd: vcmd[%d] hwid=0x%08x\n", i, hwid);
		dev->hw_version_id = hwid;

		/* check for vcmd HW ID */
		if (((hwid >> 16) & 0xFFFF) != VCMD_HW_ID) {
			vcmd_klog(LOGLVL_WARNING, "HW not found at 0x%llx\n",
				(unsigned long long)subsys->reg_base);
			iounmap((void __iomem *)dev->hwregs);
			release_mem_region(subsys->reg_base,
								subsys->io_size[SUB_MOD_VCMD]);
			dev->hwregs = NULL;
			continue;
		}

		reg_val = (u32)ioread32((void __iomem *)dev->hwregs +
				   VCMD_REGISTER_HW_APB_ARBITER_MODE_OFFSET);
		has_arbiter = (u8)((reg_val >> HW_APB_ARBITER_MODE_BIT) & 0x01);
		dev->hw_feature.vcarb_ver = 0;
		if (has_arbiter)
			dev->hw_feature.vcarb_ver = hwid < HW_ID_1_5_9 ? VCARB_VERSION_2_0 :
										VCARB_VERSION_3_0;

		reg_val = (u32)ioread32((void __iomem *)dev->hwregs +
				   VCMD_REGISTER_HW_INIT_MODE_OFFSET);
		dev->hw_feature.has_init_mode = (u8)((reg_val >> HW_INIT_MODE_BIT) &
										0x01);
		dev->hw_feature.has_cmdbuf_timeout = 0;
		if (hwid >= HW_ID_1_5_10) {
			dev->hw_feature.has_cmdbuf_timeout = 1;
			dev->abn_irq_mask &= ~DEC_ABN_IRQ_MASK;
			dev->abn_irq_mask |= CORE_IP_ABN_IRQ_MASK;
			dev->vcd_abn_irq_mask = CORE_IP_ABN_IRQ_MASK;
			dev->intr_gate_mask = 0xFFFFFFFF & (~dev->abn_irq_mask);
		}
#ifdef HANTROVCMD_ENABLE_IP_SUPPORT
		if (dev->hw_feature.has_init_mode)
			dev->init_mode = DEFAULT_VCMD_INIT_MODE;
#endif

		found_hw = 1;
		vcmd_klog(LOGLVL_CONFIG, "HW at base <0x%llx> with ID <0x%08x>\n",
					(unsigned long long)subsys->reg_base, hwid);
	}

	if (found_hw == 0) {
		vcmd_klog(LOGLVL_ERROR, "NO ANY HW found!!\n");
		return -1;
	}

	return 0;
}

/**
 * @brief release IO resources of vcmd driver.
 */
static void vcmd_release_IO(vcmd_mgr_t *vcmd_mgr)
{
	u32 i;
	struct vcmd_subsys_info *subsys;

	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		subsys = &vcmd_mgr->core_array[i];
		vcmd_release_submodule_IO(subsys, SUB_MOD_VCMD);
		vcmd_mgr->dev_ctx[i].hwregs = NULL;
	}
}

/**
 * @brief reserve irq for vcmd driver.
 */
static int vcmd_reserve_irq(vcmd_mgr_t *vcmd_mgr)
{
	u32 i;
	int result;
	struct hantrovcmd_dev *dev;
	struct vcmd_subsys_info *subsys;


	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		dev = &vcmd_mgr->dev_ctx[i];
		subsys = dev->subsys_info;

		if (!dev->hwregs)
			continue;

		if (subsys->irq == -1) {
			vcmd_klog(LOGLVL_CONFIG, "vcmd[%d]: IRQ not in use!\n", i);
			continue;
		}

		result = request_irq(subsys->irq,
							hantrovcmd_isr,
#if (KERNEL_VERSION(2, 6, 18) > LINUX_VERSION_CODE)
							SA_INTERRUPT | SA_SHIRQ,
#else
							IRQF_SHARED,
#endif
							DRIVER_NAME "_vcmd_driver",
							(void *)vcmd_mgr);

		if (result == -EINVAL) {
			vcmd_klog(LOGLVL_ERROR, "vcmd[%d]: Bad vcmd_irq number or handler.\n", i);
			return -1;
		} else if (result == -EBUSY) {
			vcmd_klog(LOGLVL_ERROR, "vcmd[%d]: IRQ <%d> is occupied!!!\n", i, subsys->irq);
			return -1;
		} else {
			vcmd_klog(LOGLVL_ERROR, "vcmd[%d]: request IRQ <%d> succeed\n", i, subsys->irq);
			vcmd_mgr->vcmd_irq_enabled = 1;
		}
	}
	return 0;
}

/**
 * @brief get a device submodule regs virtual address
 */
u32 *get_submodule_regs_va(void *_vcmd_mgr, u32 subsys_id, u32 sub_mod_id)
{
	u32 *regs_va;
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	struct hantrovcmd_dev *dev = &vcmd_mgr->dev_ctx[subsys_id];

	regs_va = dev->reg_mem_va +
				dev->subsys_info->reg_off[sub_mod_id] / 4 + 0;

	return regs_va;
}

/**
 * @brief read main module's all regs for all vcmd hw devices.
 */
static void read_main_module_all_registers(vcmd_mgr_t *vcmd_mgr)
{
	int ret;
	struct exchange_parameter param[MAX_SUBSYS_NUM];
	u16 done_id = 0;
	struct proc_obj *po;
	u32 i, irq;
	struct hantrovcmd_dev *dev;
	struct vcmd_module_mgr *module;
	u32 *main_regs_va;

	po = vcmd_mgr->init_po;

	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		dev = &vcmd_mgr->dev_ctx[i];
		param[i].executing_time = 0;
		param[i].input_mask = 0;
		param[i].cmdbuf_size = 0;
		param[i].module_type = dev->subsys_info->sub_module_type;
		param[i].core_mask = 1 << dev->core_id;
		param[i].core_id = dev->core_id;
		/* normal priority and last cmd is end */
		EXCH_S_BIT(param[i].input_mask, EXCH_END_CMD_BIT);
		module = &vcmd_mgr->module_mgr[param[i].module_type];

		ret = reserve_cmdbuf(vcmd_mgr, po, &param[i]);
		create_read_all_registers_cmdbuf(vcmd_mgr, &param[i]);
		link_and_run_cmdbuf(vcmd_mgr, po, &param[i]);
	}

	/* make sure vcmd can complete job, and clear irq
	 */
	if (vcmd_mgr->vcmd_irq_enabled == 0)
		msleep(100);
	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		dev = &vcmd_mgr->dev_ctx[i];

		if (vcmd_mgr->vcmd_irq_enabled == 0) {
			irq = dev->core_id;
			hantrovcmd_isr(irq, vcmd_mgr);
		}

		wait_cmdbuf_ready(vcmd_mgr, po, param[i].cmdbuf_id, &done_id);
		main_regs_va = dev->reg_mem_va +
				dev->subsys_info->reg_off[SUB_MOD_MAIN] / 4 + 0;
		vcmd_klog(LOGLVL_CONFIG, "main module register 0:0x%x\n",
			*main_regs_va);
		vcmd_klog(LOGLVL_CONFIG, "main module register 50:0x%08x\n",
			*(main_regs_va + 50));
		vcmd_klog(LOGLVL_CONFIG, "main module register 54:0x%08x\n",
			*(main_regs_va + 54));
		vcmd_klog(LOGLVL_CONFIG, "main module register 56:0x%08x\n",
			*(main_regs_va + 56));
		vcmd_klog(LOGLVL_CONFIG, "main module register 309:0x%x\n",
			*(main_regs_va + 309));

		release_cmdbuf(vcmd_mgr, po, param[i].cmdbuf_id);

	}
}

/**
 * @brief convert subsys info to core array info of vcmd driver context.
 */
static void SubsysToVcmdCoreCfg(struct subsys_config *subsys,
								int subsys_num, vcmd_mgr_t *vcmd_mgr)
{
	int i, j = 0;
	struct vcmd_subsys_info *core_array;

	/* To plug into hantro_vcmd.c */
	for (i = 0; i < subsys_num; i++) {
		if (subsys[i].submodule_iosize[HW_VCMD]) {
			core_array = &vcmd_mgr->core_array[j];
			core_array->irq = subsys[i].irq;
			core_array->reg_base = subsys[i].base_addr;
			core_array->sub_module_type = subsys[i].subsys_type;

			core_array->reg_off[SUB_MOD_VCMD] = 0;
			core_array->reg_off[SUB_MOD_MAIN] = subsys[i].submodule_offset[HW_VCD];
			core_array->reg_off[SUB_MOD_DEC400] = subsys[i].submodule_offset[HW_DEC400];
			core_array->reg_off[SUB_MOD_MMU] = subsys[i].submodule_offset[HW_MMU];
			core_array->reg_off[SUB_MOD_MMU_WR] = subsys[i].submodule_offset[HW_MMU_WR];
			core_array->reg_off[SUB_MOD_AXIFE] = subsys[i].submodule_offset[HW_AXIFE];
			core_array->reg_off[SUB_MOD_UFBC] = subsys[i].submodule_offset[HW_AFBC];
			core_array->reg_off[SUB_MOD_AXI2TO1] = subsys[i].submodule_offset[HW_AXI2TO1];

			core_array->io_size[SUB_MOD_VCMD] = subsys[i].submodule_iosize[HW_VCMD];
			core_array->io_size[SUB_MOD_MAIN] = subsys[i].submodule_iosize[HW_VCD];
			core_array->io_size[SUB_MOD_DEC400] = subsys[i].submodule_iosize[HW_DEC400];
			core_array->io_size[SUB_MOD_MMU] = subsys[i].submodule_iosize[HW_MMU];
			core_array->io_size[SUB_MOD_MMU_WR] = subsys[i].submodule_iosize[HW_MMU_WR];
			core_array->io_size[SUB_MOD_AXIFE] = subsys[i].submodule_iosize[HW_AXIFE];
			core_array->io_size[SUB_MOD_UFBC] = subsys[i].submodule_iosize[HW_AFBC];
			core_array->io_size[SUB_MOD_AXI2TO1] = subsys[i].submodule_iosize[HW_AXI2TO1];

			core_array->hwregs[SUB_MOD_MAIN] = vcmd_core_array[i].submodule_vcd_virtual_address;
			core_array->hwregs[SUB_MOD_DEC400] = vcmd_core_array[i].submodule_dec400_virtual_address;
			core_array->hwregs[SUB_MOD_MMU] = vcmd_core_array[i].submodule_MMU_virtual_address;
			core_array->hwregs[SUB_MOD_MMU_WR] = vcmd_core_array[i].submodule_MMUWrite_virtual_address;
			core_array->hwregs[SUB_MOD_AXIFE] = vcmd_core_array[i].submodule_axife_virtual_address;
			core_array->hwregs[SUB_MOD_AXI2TO1] = vcmd_core_array[i].submodule_axi2to1_virtual_address;

			j++;
		}
	}
	vcmd_mgr->subsys_num = j;
	vcmd_klog(LOGLVL_CONFIG, "%d VCMD cores found\n", j);
}

/**
 * @brief vcmd driver initialization
 * @param struct subsys_config *subsys: info of sub-systems.
 * @param int subsys_num: number of sub-systems.
 * @param void *platformdev: platform device handler
 * @return void *: NULL: failed; other: vcmd driver handler.
 */
void *hantrovcmd_init(struct subsys_config *subsys,
						int subsys_num, void *platformdev)
{
	int result;
	struct hantrovcmd_dev *dev_ctx;
	vcmd_mgr_t *vcmd_mgr;

	vcmd_mgr = vmalloc(sizeof(vcmd_mgr_t));
	if (!vcmd_mgr)
		return NULL;

	memset(vcmd_mgr, 0, sizeof(vcmd_mgr_t));
	SubsysToVcmdCoreCfg(subsys, subsys_num, vcmd_mgr);

	if (!vcmd_mgr->subsys_num)
		goto err;

	subsys_num = vcmd_mgr->subsys_num;
	vcmd_mgr->platformdev = (struct platform_device *)platformdev;

	vcmd_mgr->mem_vcmd.size = ALIGN_4K(SLOT_NUM_CMDBUF * SLOT_SIZE_CMDBUF);
	vcmd_mgr->mem_status.size = ALIGN_4K(SLOT_NUM_CMDBUF * SLOT_SIZE_STATUSBUF);
	vcmd_mgr->mem_regs.size = ALIGN_4K(subsys_num * SLOT_SIZE_REGBUF);
	result = vcmd_init(vcmd_mgr);
	if (result)
		goto err;

	dev_ctx = vmalloc(sizeof(struct hantrovcmd_dev) * subsys_num);
	if (!dev_ctx)
		goto err;

	vcmd_mgr->dev_ctx = dev_ctx;
	dev_ctx_init(vcmd_mgr);

	sema_init(&vcmd_mgr->isr_polling_sema, 1);

	vcmd_mgr->init_po = create_process_object();
	if (!vcmd_mgr->init_po)
		goto err;

#if 0
	result = register_chrdev(hantrovcmd_major,
				 DRIVER_NAME, &hantrovcmd_fops);
	if (result < 0) {
		vcmd_klog(LOGLVL_ERROR, "unable to get major <%d>\n",
			hantrovcmd_major);
		goto err1;
	} else if (result != 0) /* this is for dynamic major */
		hantrovcmd_major = result;
#endif
	result = vcmd_reserve_IO(vcmd_mgr);
	if (result < 0)
		goto err0;
	vcmd_reset_asic(vcmd_mgr);

#ifdef SUPPORT_DBGFS
	/* for debugfs */
	if (_dbgfs_init((void *)vcmd_mgr))
		goto err0;
	_dbgfs_init_ctx((void *)vcmd_mgr, 0);
#endif
	/* get the IRQ line */
	result = vcmd_reserve_irq(vcmd_mgr);
	if (result < 0)
		goto err0;

#ifdef IRQ_SIMULATION
	_irq_simul_init((void *)vcmd_mgr);
#endif

	vcmd_init_objs(vcmd_mgr);
	vcmd_init_nodes(vcmd_mgr);
	vcmd_init_free_obj_list(vcmd_mgr);

	/* create vcmd kthread, which need to be woken up */
	_vcmd_kthread_create(vcmd_mgr);

	/* read all registers of main-module for each dev
	 * for analyzing configuration in cwl
	 */
	read_main_module_all_registers(vcmd_mgr);

	return vcmd_mgr;

err0:
	vcmd_release_IO(vcmd_mgr);

err:
#if defined(PCI_DDR_BAR)
	_vcmd_pcie_cleanup(vcmd_mgr);
#else
	_vcmd_free_mem(vcmd_mgr, &vcmd_mgr->mem_vcmd);
	_vcmd_free_mem(vcmd_mgr, &vcmd_mgr->mem_status);
	_vcmd_free_mem(vcmd_mgr, &vcmd_mgr->mem_regs);
#endif

	free_process_object(vcmd_mgr->init_po);

	if (vcmd_mgr->dev_ctx)
		vfree(vcmd_mgr->dev_ctx);
	if (vcmd_mgr)
		vfree(vcmd_mgr);
	vcmd_klog(LOGLVL_ERROR, "module not inserted!\n");
	return NULL;
}

/**
 * @brief de-init vcmd driver.
 */
void hantrovcmd_cleanup(void *_vcmd_mgr)
{
	int i = 0;
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	struct hantrovcmd_dev *dev_ctx = vcmd_mgr->dev_ctx;

	_vcmd_kthread_stop(vcmd_mgr);

	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		if (!dev_ctx[i].hwregs)
			continue;

		/* free the vcmd IRQ */
		if (dev_ctx[i].subsys_info->irq != -1)
			free_irq(dev_ctx[i].subsys_info->irq, (void *)vcmd_mgr);
	}

#ifdef SUPPORT_DBGFS
	_dbgfs_cleanup((void *)vcmd_mgr);
#endif
	vcmd_release_IO(vcmd_mgr);
	vfree(dev_ctx);

	//release_vcmd_non_cachable_memory();
#if defined(PCI_DDR_BAR)
	_vcmd_pcie_cleanup(vcmd_mgr);
#else
	_vcmd_free_mem(vcmd_mgr, &vcmd_mgr->mem_vcmd);
	_vcmd_free_mem(vcmd_mgr, &vcmd_mgr->mem_status);
	_vcmd_free_mem(vcmd_mgr, &vcmd_mgr->mem_regs);
#endif

	free_process_object(vcmd_mgr->init_po);
	vfree(vcmd_mgr);
	vcmd_klog(LOGLVL_FLOW, "module removed\n");
}

/**
 * @brief flush slice regs in vcmd driver
 */
static long flush_slice_regs(vcmd_mgr_t *vcmd_mgr,
			struct subsys_regs_desc *slice_regs)
{
	u32 cmdbuf_id = slice_regs->id;
	struct hantrovcmd_dev *dev = NULL;
	struct cmdbuf_obj *obj = NULL;
	bi_list_node *node = NULL;
	volatile u8 *hwregs;
	unsigned long flags;
	u32 reg_id;
	int i;

	node = &vcmd_mgr->nodes[cmdbuf_id];
	obj = (struct cmdbuf_obj *)node->data;

	dev = &vcmd_mgr->dev_ctx[obj->core_id];
	hwregs = dev->subsys_info->hwregs[SUB_MOD_MAIN];

	for (i = 0; i < slice_regs->reg_num - 1; i++) {
		reg_id = slice_regs->regs[i].reg_id;
		iowrite32(slice_regs->regs[i].reg_data, (void __iomem *)(hwregs + 4 * reg_id));
	}

	spin_lock_irqsave(&dev->abn_irq_lock, flags);
	iowrite32(slice_regs->regs[i].reg_data, (void __iomem *)(hwregs + 0x4));
	obj->slice_run_done = 0;
	spin_unlock_irqrestore(&dev->abn_irq_lock, flags);

#ifdef SUPPORT_WATCHDOG
	spin_lock_irqsave(dev->spinlock, flags);
	_vcmd_watchdog_feed(dev);
	spin_unlock_irqrestore(dev->spinlock, flags);
#endif

	vcmd_write_reg((const void *)dev->hwregs,
		VCMD_REGISTER_EXT_INT_GATE_OFFSET,
		dev->intr_gate_mask);

	return 0;
}

/**
 * @brief abort the decoder of the cmdbuf_id which is waiting more slice.
 */
static long abort_cmdbuf(vcmd_mgr_t *vcmd_mgr, u16 cmdbuf_id)
{
	struct hantrovcmd_dev *dev = NULL;
	struct cmdbuf_obj *obj = NULL;
	bi_list_node *node = NULL;
	volatile u8 *hwregs;
	u16 reg_id_exe;
	unsigned long flags;

	node = &vcmd_mgr->nodes[cmdbuf_id];
	obj = (struct cmdbuf_obj *)node->data;

	dev = &vcmd_mgr->dev_ctx[obj->core_id];
	hwregs = dev->subsys_info->hwregs[SUB_MOD_MAIN];
	reg_id_exe = (u16)(*(dev->reg_mem_va + REG_ID2_CMDBUF_EXE_ID));
	if (cmdbuf_id == reg_id_exe) {
		spin_lock_irqsave(dev->spinlock, flags);
		abort_vcd(hwregs);
		spin_unlock_irqrestore(dev->spinlock, flags);
	} else {
		//should not happen
		vcmd_klog(LOGLVL_ERROR, "%s: ERROR cmdbuf id not match with current dev!\n", __func__);
		return -1;
	}

	return 0;
}

/**
 * @brief get current executing cmdbuf by vcmd register
 * @param bi_list_node *node: the current executing cmdbuf node
 */
static void vcmd_get_executing_cmdbuf(vcmd_mgr_t *vcmd_mgr, struct hantrovcmd_dev *dev,
									bi_list_node **node)
{
	u32 curr_id;

	curr_id = vcmd_get_register_value((const void *)dev->hwregs,
									dev->reg_mirror,
									HWIF_VCMD_CMDBUF_EXE_ID);
	*node = &vcmd_mgr->nodes[curr_id];
}

/**
 * @brief set vcmd abort by immediate mode for some special scenes
 */
static u32 vcmd_abort_mode_set(vcmd_mgr_t *vcmd_mgr, struct hantrovcmd_dev *dev,
							struct cmdbuf_obj *obj)
{
	unsigned long flags;

	/* abort for slice decoding */
	if (!obj->cmdbuf_run_done && !obj->slice_run_done)
		wait_event_interruptible_timeout(dev->buff_empty_waitq,
									obj->cmdbuf_run_done || obj->slice_run_done,
									msecs_to_jiffies(ONE_SLICE_WAIT_TIME));
	spin_lock_irqsave(dev->spinlock, flags);
	if (!obj->cmdbuf_run_done && obj->slice_run_done) {
		/* abort vcmd by immediate mode */
		dev->abort_mode = 0x1;
		vcmd_set_reg_mirror(dev->reg_mirror, HWIF_VCMD_ABORT_MODE, dev->abort_mode);
	}
	spin_unlock_irqrestore(dev->spinlock, flags);

	return dev->abort_mode;
}


/**
 * @brief drop cmdbufs_id or releae cmd from this po
 */
static long drop_release_cmdbufs(vcmd_mgr_t *vcmd_mgr,
								struct proc_obj *po, void *owner)
{
	struct hantrovcmd_dev *dev;
	bi_list *list;
	bi_list_node *node;
	struct cmdbuf_obj *obj;

	u32 i, handled, to_drop;
	u32 has_work_node, vcmd_aborted;
	unsigned long flags;
	int aborted_cmdbuf_id;
	long dropped_cmdbuf_num = 0;

	handled = 0;
	//remove nodes in dev->work_list
	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		dev = &vcmd_mgr->dev_ctx[i];
		if (dev == NULL || dev->hwregs == NULL)
			continue;

		list = &dev->work_list;

		has_work_node = 0;
		vcmd_aborted = 0;

		spin_lock_irqsave(dev->spinlock, flags);
		node = list->head;
		while (node) {
			obj = (struct cmdbuf_obj *)node->data;
			if (obj->po == po) {
				if ((owner == NULL) || (owner == obj->owner)) {
					has_work_node = 1;
					break;
				}
			}
			node = node->next;
		}

		if (has_work_node) {
			if (dev->state == VCMD_STATE_WORKING) {
				vcmd_klog(LOGLVL_FLOW, "Abort dev[%d].\n", dev->core_id);
				vcmd_get_executing_cmdbuf(vcmd_mgr, dev, &node);
				obj = (struct cmdbuf_obj *)node->data;
				spin_unlock_irqrestore(dev->spinlock, flags);

				vcmd_abort_mode_set(vcmd_mgr, dev, obj);
				vcmd_abort(vcmd_mgr, dev, &aborted_cmdbuf_id);

				spin_lock_irqsave(dev->spinlock, flags);
				if (dev->abort_mode == 1)
					dev->abort_mode = 0;
				if (dev->state != VCMD_STATE_IDLE) {
					vcmd_klog(LOGLVL_ERROR, "dev [%d] is not aborted as expected.", dev->core_id);
					spin_unlock_irqrestore(dev->spinlock, flags);
					continue;
				}
				vcmd_aborted = 1;

				if (!obj->cmdbuf_run_done && obj->slice_run_done)
					abort_vcd(dev->subsys_info->hwregs[SUB_MOD_MAIN]);
			}

			node = list->head;
			while (node) {
				obj = (struct cmdbuf_obj *)node->data;
				if (obj->po == po || obj->cmdbuf_need_remove) {
					to_drop = 0;
					if (owner && owner == obj->owner && !obj->cmdbuf_run_done) {
						to_drop = 1;
						handled++;
					}
					if (owner == NULL || to_drop == 1) {
						vcmd_klog(LOGLVL_FLOW, "cmdbuf %d of process %p is released or dropped\n",
												obj->cmdbuf_id, obj->filp);
						dev_remove_job(vcmd_mgr, dev, node);
					}
				}

				node = node->next;
			}

			vcmd_klog(LOGLVL_FLOW, "Restart dev[%d].\n", dev->core_id);
			if (vcmd_aborted == 1)
				vcmd_start(dev);
		}
		spin_unlock_irqrestore(dev->spinlock, flags);
	}

	// remove cmdbuf reserved but not in work_list or has been dropped
	for (i = 0; i < SLOT_NUM_CMDBUF; i++) {
		obj = &vcmd_mgr->objs[i];
		if (obj->po == po) {
			if (owner == NULL ||
				 (owner == obj->owner && !obj->cmdbuf_run_done)) {
				if (obj->core_id == 0xFFFF) {
					return_cmdbuf(vcmd_mgr, i);
				} else {
					dev = &vcmd_mgr->dev_ctx[obj->core_id];
					spin_lock_irqsave(dev->spinlock, flags);
					return_cmdbuf(vcmd_mgr, i);
					spin_unlock_irqrestore(dev->spinlock, flags);
				}
			}
		}
	}

	if (owner && handled) {
		dropped_cmdbuf_num = handled;
		wake_up_interruptible_all(&po->job_waitq);
	}

	return dropped_cmdbuf_num;
}

/**
 * @brief drop owner from current po
 */
static long drop_owner(vcmd_mgr_t *vcmd_mgr, struct proc_obj *po,
												void *owner)
{
	u32 module_type;
	long dropped_cmdbuf_num = 0;

	module_type = po->module_type;
	if (down_interruptible(&vcmd_mgr->module_mgr[module_type].sem))
		return -ERESTARTSYS;

	dropped_cmdbuf_num = drop_release_cmdbufs(vcmd_mgr, po, owner);

	up(&vcmd_mgr->module_mgr[module_type].sem);
	return dropped_cmdbuf_num;
}

/**
 * @brief wait the cmdbuf with special owner done
 */
static long wait_owner_done(vcmd_mgr_t *vcmd_mgr, struct proc_obj *po, void *owner)
{
	struct cmdbuf_obj *obj = NULL;
	u32 module_type;
	u32 i, ret;

	ret = 0;
	module_type = po->module_type;
	if (down_interruptible(&vcmd_mgr->module_mgr[module_type].sem))
		return -ERESTARTSYS;

	for (i = 0; i < SLOT_NUM_CMDBUF; i++) {
		obj = &vcmd_mgr->objs[i];
		if (obj->po == po && obj->owner == owner) {
			ret = 1;
			break;
		}
	}

	up(&vcmd_mgr->module_mgr[module_type].sem);
	return ret;
}

/**
 * @brief ioctl function of vcmd driver.
 */
long hantrovcmd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	long tmp;
	struct vcmd_priv_ctx *ctx = (struct vcmd_priv_ctx *)filp->private_data;
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)ctx->vcmd_mgr;

	_log_ioctl_cmd(cmd);
	/*
	 * extract the type and number bitfields, and don't encode
	 * wrong cmds: return ENOTTY (inappropriate ioctl)
	 * before access_ok()
	 */
	if (_IOC_TYPE(cmd) != HANTRO_VCMD_IOC_MAGIC)
		return -ENOTTY;
	if ((_IOC_TYPE(cmd) == HANTRO_VCMD_IOC_MAGIC &&
		 _IOC_NR(cmd) > HANTRO_VCMD_IOC_MAXNR))
		return -ENOTTY;

		/*
		 * the direction is a bitmask, and VERIFY_WRITE catches R/W
		 * transfers. `Type' is user-oriented, while
		 * access_ok is kernel-oriented, so the concept of "read" and
		 * "write" is reversed
		 */
#if (KERNEL_VERSION(5, 0, 0) > LINUX_VERSION_CODE)
	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user *)arg,
				 _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		err = !access_ok(VERIFY_READ, (void __user *)arg,
				 _IOC_SIZE(cmd));
#else
	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok((void *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		err = !access_ok((void *)arg, _IOC_SIZE(cmd));
#endif
	if (err)
		return -EFAULT;

	switch (cmd) {
	case HANTRO_VCMD_IOCH_GET_CMDBUF_PARAMETER: {
		struct cmdbuf_mem_parameter mem;

		vcmd_klog(LOGLVL_CONFIG, "VCMD get cmdbuf parameter\n");
		mem.cmdbuf_unit_size = SLOT_SIZE_CMDBUF;
		mem.status_cmdbuf_unit_size = SLOT_SIZE_STATUSBUF;
		mem.vcmd_regbuf_unit_size = SLOT_SIZE_REGBUF;
		mem.cmdbuf_total_size = vcmd_mgr->mem_vcmd.size;
		mem.phy_cmdbuf_addr = vcmd_mgr->mem_vcmd.pa;
		mem.status_cmdbuf_total_size = vcmd_mgr->mem_status.size;
		mem.phy_status_cmdbuf_addr = vcmd_mgr->mem_status.pa;
		mem.vcmd_regbuf_total_size = vcmd_mgr->mem_regs.size;
		mem.phy_vcmd_regbuf_addr = vcmd_mgr->mem_regs.pa;
		mem.mmu_phy_status_cmdbuf_addr = vcmd_mgr->mem_status.mmu_ba;
		mem.mmu_phy_cmdbuf_addr = vcmd_mgr->mem_vcmd.mmu_ba;
		mem.mmu_phy_vcmd_regbuf_addr = vcmd_mgr->mem_regs.mmu_ba;
		mem.base_ddr_addr = vcmd_mgr->pa_trans_offset;
		tmp = copy_to_user((struct cmdbuf_mem_parameter __user *)arg,
				 &mem, sizeof(struct cmdbuf_mem_parameter));
		if (tmp) {
			vcmd_klog(LOGLVL_ERROR, "copy_to_user failed, returned %li\n", tmp);
			return -EFAULT;
		}
		break;
	}
	case HANTRO_VCMD_IOCH_GET_VCMD_PARAMETER: {
		struct config_parameter param;
		struct proc_obj *po = NULL;
		u16 m_type;
		struct hantrovcmd_dev *dev;
		struct vcmd_subsys_info *info;

		vcmd_klog(LOGLVL_CONFIG, "VCMD get vcmd config parameter\n");
		tmp = copy_from_user(&param,
				   (struct config_parameter __user *)arg,
				   sizeof(struct config_parameter));
		if (tmp) {
			vcmd_klog(LOGLVL_ERROR, "copy_from_user failed, returned %li\n", tmp);
			return -EFAULT;
		}
		po = (struct proc_obj *)ctx->po;
		if (!po) {
			vcmd_klog(LOGLVL_ERROR, "%s: not find process obj!\n", __func__);
			return -1;
		}
		spin_lock(&po->spinlock);
		po->module_type = param.module_type;
		m_type = param.module_type;
		spin_unlock(&po->spinlock);
		if (vcmd_mgr->module_mgr[m_type].num) {
			dev = vcmd_mgr->module_mgr[m_type].dev[0];
			info = dev->subsys_info;
			param.submodule_main_addr = info->reg_off[SUB_MOD_MAIN];
			param.submodule_dec400_addr = info->reg_off[SUB_MOD_DEC400];
			param.submodule_MMU_addr = info->reg_off[SUB_MOD_MMU];
			param.submodule_MMUWrite_addr = info->reg_off[SUB_MOD_MMU_WR];
			param.submodule_axife_addr = info->reg_off[SUB_MOD_AXIFE];
			param.vcmd_hw_version_id =	dev->hw_version_id;
			param.vcmd_core_num = vcmd_mgr->module_mgr[m_type].num;
		} else {
			param.submodule_main_addr = 0xffff;
			param.submodule_dec400_addr = 0xffff;
			param.submodule_MMU_addr = 0xffff;
			param.submodule_MMUWrite_addr = 0xffff;
			param.submodule_axife_addr = 0xffff;
			param.vcmd_core_num = 0;
			param.vcmd_hw_version_id = HW_ID_1_0_C;
		}
		tmp = copy_to_user((struct config_parameter __user *)arg, &param,
				 sizeof(struct config_parameter));
		if (tmp) {
			vcmd_klog(LOGLVL_ERROR, "copy_to_user failed, returned %li\n", tmp);
			return -EFAULT;
		}

		break;
	}
	case HANTRO_VCMD_IOCH_RESERVE_CMDBUF: {
		long ret;
		struct exchange_parameter param;
		struct proc_obj *po = _GET_PO(filp);

		tmp = copy_from_user(&param,
				   (struct exchange_parameter __user *)arg,
				   sizeof(struct exchange_parameter));
		if (tmp) {
			vcmd_klog(LOGLVL_ERROR, "copy_from_user failed, returned %li\n", tmp);
			return -EFAULT;
		}
		ret = reserve_cmdbuf(vcmd_mgr, po, &param);
		if (ret == 0) {
			tmp = copy_to_user((struct exchange_parameter __user *)arg,
					 &param,
					 sizeof(struct exchange_parameter));
			if (tmp) {
				vcmd_klog(LOGLVL_ERROR, "copy_to_user failed, returned %li\n", tmp);
				return -EFAULT;
			}
		}
		vcmd_klog(LOGLVL_CONFIG, "VCMD Reserve CMDBUF %d\n", param.cmdbuf_id);
		return ret;
	}

	case HANTRO_VCMD_IOCH_LINK_RUN_CMDBUF: {
		struct exchange_parameter param;
		long retVal;
		struct proc_obj *po = _GET_PO(filp);

		tmp = copy_from_user(&param,
				   (struct exchange_parameter __user *)arg,
				   sizeof(struct exchange_parameter));
		if (tmp) {
			vcmd_klog(LOGLVL_ERROR, "copy_from_user failed, returned %li\n", tmp);
			return -EFAULT;
		}

		vcmd_klog(LOGLVL_CONFIG, "VCMD link and run CMDBUF %d\n", param.cmdbuf_id);
		retVal = link_and_run_cmdbuf(vcmd_mgr, po, &param);
		tmp = copy_to_user((struct exchange_parameter __user *)arg,
				 &param, sizeof(struct exchange_parameter));
		if (tmp) {
			vcmd_klog(LOGLVL_ERROR, "copy_to_user failed, returned %li\n", tmp);
			return -EFAULT;
		}
		return retVal;
	}

	case HANTRO_VCMD_IOCH_WAIT_CMDBUF: {
		u16 cmdbuf_id;
		long tmp;
		struct proc_obj *po = _GET_PO(filp);

		__get_user(cmdbuf_id, (u16 __user *)arg);
		/*high 16 bits are core id, low 16 bits are cmdbuf_id*/

		vcmd_klog(LOGLVL_FLOW, "VCMD wait for CMDBUF %d finishing.\n", cmdbuf_id);

		tmp = wait_cmdbuf_ready(vcmd_mgr, po, cmdbuf_id, &cmdbuf_id);
		if (tmp == 0) {
			__put_user(cmdbuf_id, (u16 __user *)arg);
			return tmp;
		}
		__put_user(0, (u16 __user *)arg);
		return -1;

		break;
	}

	case HANTRO_VCMD_IOCH_PUSH_SLICE_REG: {
		struct subsys_regs_desc slice_regs;

		vcmd_klog(LOGLVL_FLOW, "VCMD push slice reg for buffer empty.\n");
		/* get registers from user space*/
		tmp = copy_from_user(&slice_regs, (void __user *)arg,
				     sizeof(struct subsys_regs_desc));
		if (tmp) {
			PDEBUG("copy_from_user failed, returned %li\n", tmp);
			return -EFAULT;
		}
		return flush_slice_regs(vcmd_mgr, &slice_regs);
	}

	case HANTRO_VCMD_IOCH_ABORT_CMDBUF: {
		u16 cmdbuf_id;

		vcmd_klog(LOGLVL_FLOW, "VCMD abort slice for seek.\n");
		/* get registers from user space*/
		tmp = __get_user(cmdbuf_id, (u16 __user *)arg);
		if (tmp) {
			PDEBUG("copy_from_user failed, returned %li\n", tmp);
			return -EFAULT;
		}
		tmp = abort_cmdbuf(vcmd_mgr, cmdbuf_id);
		if (tmp) {
			PDEBUG("abort_cmdbuf failed, returned %li\n", tmp);
			return -EFAULT;
		}

		break;
	}

	case HANTRO_VCMD_IOCH_DROP_OWNER: {
		long dropped_cmdbuf_num = 0;
		struct proc_obj *po = _GET_PO(filp);

		vcmd_klog(LOGLVL_FLOW, "VCMD drop owner %p for seek.\n", (void *)arg);

		tmp = drop_owner(vcmd_mgr, po, (void *)arg);
		if (tmp < 0) {
			vcmd_klog(LOGLVL_ERROR, "drop_owner failed, returned %li\n", tmp);
			return -EFAULT;
		}
		dropped_cmdbuf_num = tmp;

		return dropped_cmdbuf_num;
	}

	case HANTRO_VCMD_IOCH_WAIT_OWNER_DONE: {
		struct proc_obj *po = _GET_PO(filp);

		vcmd_klog(LOGLVL_FLOW, "VCMD wait owner %p done.\n", (void *)arg);

		tmp = wait_owner_done(vcmd_mgr, po, (void *)arg);
		if (tmp) {
			PDEBUG("wait_cmdbuf_done failed, returned %li\n", tmp);
			return -EFAULT;
		}

		return 0;
	}

	case HANTRO_VCMD_IOCH_RELEASE_CMDBUF: {
		u16 cmdbuf_id;
		struct proc_obj *po = _GET_PO(filp);

		__get_user(cmdbuf_id, (u16 __user *)arg);
		/*16 bits are cmdbuf_id*/

		vcmd_klog(LOGLVL_FLOW, "VCMD release CMDBUF %d\n", cmdbuf_id);

		release_cmdbuf(vcmd_mgr, po, cmdbuf_id);
		return 0;
		//break;
	}
	case HANTRO_VCMD_IOCH_POLLING_CMDBUF: {
		u16 core_id;

		__get_user(core_id, (u16 __user *)arg);
		/*16 bits are cmdbuf_id*/
		if (core_id >= vcmd_mgr->subsys_num)
			return -1;
		if (down_interruptible(&vcmd_mgr->isr_polling_sema))
			return -ERESTARTSYS;
		hantrovcmd_isr(core_id, vcmd_mgr);
		up(&vcmd_mgr->isr_polling_sema);
		return 0;
	}
	default:
		break;
	}
	return 0;
}

#if defined SUPPORT_MMU && defined SUPPORT_48PA_MMU
int _vcmd_memory_map(void *_vcmd_mgr, struct file *filp)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	struct kernel_addr_desc mmu_addr;

	if (vcmd_mgr->mmu_enable) {
#if defined(PCIE_EN) && defined(PCI_DDR_BAR)
		mmu_addr.bus_address = vcmd_mgr->pcie_pool.pa - vcmd_mgr->pa_trans_offset;
		mmu_addr.size = vcmd_mgr->pcie_pool.size;
		if (MMUKernelMemNodeMap(&mmu_addr, filp) != MMU_STATUS_OK)
			return -EINVAL;
#else
		mmu_addr.bus_address = vcmd_mgr->mem_vcmd.pa;
		mmu_addr.size = vcmd_mgr->mem_vcmd.size;
		if (MMUKernelMemNodeMap(&mmu_addr, filp) != MMU_STATUS_OK)
			return -EINVAL;
		mmu_addr.bus_address = vcmd_mgr->mem_status.pa;
		mmu_addr.size = vcmd_mgr->mem_status.size;
		if (MMUKernelMemNodeMap(&mmu_addr, filp) != MMU_STATUS_OK)
			return -EINVAL;
		mmu_addr.bus_address = vcmd_mgr->mem_regs.pa;
		mmu_addr.size = vcmd_mgr->mem_regs.size;
		if (MMUKernelMemNodeMap(&mmu_addr, filp) != MMU_STATUS_OK)
			return -EINVAL;
#endif // PCIE_EN && PCI_DDR_BAR
	}
	return 0;
}
#endif // SUPPORT_MMU && SUPPORT_48PA_MMU

/**
 * @brief open hantro vcmd device.
 */
int hantrovcmd_open(struct inode *inode, struct file *filp)
{
	struct vcmd_priv_ctx *ctx = (struct vcmd_priv_ctx *)filp->private_data;
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)ctx->vcmd_mgr;
	struct proc_obj *po;
#ifdef SUPPORT_DBGFS
	/* for debugfs */
	_dbgfs_init_ctx(vcmd_mgr, 1);
#endif
	po = create_process_object();
	if (!po) {
		vcmd_klog(LOGLVL_ERROR, "Create process object failed!\n");
		return -EINVAL;
	}
	po->filp = filp;
	po->module_type = vcmd_mgr->core_array[0].sub_module_type;
	ctx->po = (void *)po;

	vcmd_klog(LOGLVL_FLOW, "dev opened\n");
	vcmd_klog(LOGLVL_FLOW, "process obj %p for filp opened %p\n", (void *)po, (void *)filp);
	return 0;
}

/**
 * @brief release hantro vcmd device.
 */
int hantrovcmd_release(struct inode *inode, struct file *filp)
{
	struct vcmd_priv_ctx *ctx = (struct vcmd_priv_ctx *)filp->private_data;
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)ctx->vcmd_mgr;
	struct proc_obj *po;

	u32 module_type;

	vcmd_klog(LOGLVL_FLOW, "%s process %p start release\n", __func__, (void *)filp);
	po = (struct proc_obj *)ctx->po;
	if (!po) {
		vcmd_klog(LOGLVL_ERROR, "%s: not find process obj!\n", __func__);
		return -1;
	}

	module_type = po->module_type;
	if (down_interruptible(&vcmd_mgr->module_mgr[module_type].sem))
		return -ERESTARTSYS;

	drop_release_cmdbufs(vcmd_mgr, po, NULL);

	vcmd_klog(LOGLVL_FLOW, "process obj %p for filp to be removed: %p\n",
			(void *)po, (void *)po->filp);
	free_process_object(ctx->po);
	ctx->po = NULL;
	vfree(ctx);
	up(&vcmd_mgr->module_mgr[module_type].sem);
	return 0;
}

/**
 * @brief process abnormal interrupt
 */
static void process_abnormal_irq(vcmd_mgr_t *vcmd_mgr,
									struct hantrovcmd_dev *dev,
									struct cmdbuf_obj *obj)
{
	u32 intr_src;

	/* check vcmd interrupt source. */
	intr_src = vcmd_read_reg((const void *)dev->hwregs,
								VCMD_REGISTER_SW_EXT_INT_SRC_OFFSET);
	/* abnormal interrupts source from VCD */
	if (intr_src & dev->vcd_abn_irq_mask)
		process_vcd_abn_irq(vcmd_mgr, dev, obj);
#ifdef AXI2TO1_SUPPORT
	/* abnormal interrupt source from AXI2TO1 */
	if (intr_src & AXI2TO1_ABN_IRQ_MASK)
		process_axi2to1_abn_irq(vcmd_mgr, dev);
	/*TODO*/
	/* 1. set the IP core exceptions interrup type as abnormal
	 * 2. IP core checked the exceptoions, then need do process_subsystem_exceptions
	 */
#endif
}

/**
 * @brief mark cmdbuf obj as run_done with specified exe_status,
 * remove it from device work_list, and add it to owner po's job_done_list.
 */
static int isr_process_node(vcmd_mgr_t *vcmd_mgr,
								bi_list_node *node,
								u32 exe_status)
{
	struct cmdbuf_obj *obj = (struct cmdbuf_obj *)node->data;
	struct hantrovcmd_dev *dev = &vcmd_mgr->dev_ctx[obj->core_id];

	if (obj->cmdbuf_run_done == 0) {
		obj->cmdbuf_run_done = 1;
		obj->executing_status = exe_status;
		dev_delink_job(dev, node);
		proc_add_done_job(vcmd_mgr, obj);
#ifdef SUPPORT_DBGFS
		if (exe_status == CMDBUF_EXE_STATUS_OK) {
			_dbgfs_remove_cmdbuf(dev->dbgfs_info, obj->cmdbuf_id);
			_dbgfs_record_vcd_cycles(dev->dbgfs_info, obj->cmdbuf_id,
						obj->module_type, dev->hw_feature.vcarb_ver);
		}
#endif
		return 0;
	} else {
		vcmd_klog(LOGLVL_BRIEF, "%s cmdbuf[%d] is already done!!\n",
				__func__, obj->cmdbuf_id);
		return -1;
	}
}

/**
 * @brief interrupt service routine of vcmd driver.
 */
#if (KERNEL_VERSION(2, 6, 18) > LINUX_VERSION_CODE)
static irqreturn_t hantrovcmd_isr(int irq, void *dev_id, struct pt_regs *regs)
#else
static irqreturn_t hantrovcmd_isr(int irq, void *dev_id)
#endif
{
	unsigned int handled = 0;
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)dev_id;
	struct hantrovcmd_dev *dev = NULL;
	u32 irq_status = 0;
	unsigned long flags;
	bi_list_node *node;
	addr_t exe_cmdbuf_ba;
	u32 curr_id = 0;
	struct cmdbuf_obj *curr_obj, *obj;
	bi_list_node *curr_node;

	u32 i;
	volatile u8 *hwregs;

	if (vcmd_mgr->vcmd_irq_enabled == 0) {
		/* all vcmd_irq==-1, there is no IRQ, use irq as dev id */
		if (irq < vcmd_mgr->subsys_num)
			dev = &vcmd_mgr->dev_ctx[irq];
	} else { /* there is assigned IRQ */
		for (i = 0; i < vcmd_mgr->subsys_num; i++) {
			if (vcmd_mgr->dev_ctx[i].subsys_info->irq == irq) {
				dev = &vcmd_mgr->dev_ctx[i];
				break;
			}
		}
	}

	if (dev == NULL)
		return IRQ_HANDLED;

#ifdef SUPPORT_DBGFS
	_dbgfs_reset_exe_cmdbuf_num(dev->dbgfs_info);
	_dbgfs_record_cmdbuf_num(dev->dbgfs_info);
#endif

	hwregs = dev->hwregs;

	spin_lock_irqsave(dev->spinlock, flags);
	if (dev->state == VCMD_STATE_POWER_OFF) {
		spin_unlock_irqrestore(dev->spinlock, flags);
		return IRQ_HANDLED;
	}
	irq_status = vcmd_read_reg((const void *)hwregs,
				   VCMD_REGISTER_INT_STATUS_OFFSET);

	if (dev->hw_version_id >= HW_ID_1_5_0 && irq_status == 0) {
		curr_id = vcmd_get_register_value((const void *)dev->hwregs,
							dev->reg_mirror,
							HWIF_VCMD_CMDBUF_EXE_ID);
		if (curr_id >= SLOT_NUM_CMDBUF) {
			vcmd_klog(LOGLVL_ERROR, "%s error cmdbuf_id %d !!\n",
						__func__, curr_id);
			spin_unlock_irqrestore(dev->spinlock, flags);
			return IRQ_HANDLED;
		}
		curr_obj = &vcmd_mgr->objs[curr_id];

		process_abnormal_irq(vcmd_mgr, dev, curr_obj);

		irq_status = vcmd_read_reg((const void *)dev->hwregs,
									VCMD_REGISTER_INT_STATUS_OFFSET);
		if (!irq_status) {
			spin_unlock_irqrestore(dev->spinlock, flags);
			return IRQ_HANDLED;
		}
	}

#ifdef VCMD_DEBUG_INTERNAL
	_dbg_log_dev_regs(dev, 1);
#endif

	if (irq_status == 0) {
		//no interrupt source from dev
		//vcmd_klog(LOGLVL_BRIEF, "%s warning, irq_status is zero!\n", __func__);
		spin_unlock_irqrestore(dev->spinlock, flags);
		return IRQ_HANDLED;
	}

	vcmd_klog(LOGLVL_FLOW, "%s: received IRQ!\n",  __func__);
	vcmd_klog(LOGLVL_FLOW, "irq_status of core[%d] is: 0x%x\n", dev->core_id, irq_status);

	vcmd_write_reg((const void *)hwregs,
						VCMD_REGISTER_INT_STATUS_OFFSET, irq_status);
	dev->reg_mirror[VCMD_REGISTER_INT_STATUS_OFFSET / 4] = irq_status;

	node = dev->work_list.head;

	if (node == NULL) {
		//dev is not in use, should not run to here
		vcmd_klog(LOGLVL_ERROR, "%s:received IRQ but core has nothing to do.\n", __func__);
		spin_unlock_irqrestore(dev->spinlock, flags);
		return IRQ_HANDLED;
	}

	// get current node/obj/id
	if (dev->hw_version_id < HW_ID_1_0_C) {
		exe_cmdbuf_ba = VCMDGetAddrRegisterValue((const void *)hwregs,
												dev->reg_mirror,
												HWIF_VCMD_CMDBUF_EXE_ADDR);
		//get the executing cmdbuf node.
		curr_node = get_cmdbuf_node_by_addr(vcmd_mgr, dev, exe_cmdbuf_ba);
		if (curr_node == NULL) {
			vcmd_klog(LOGLVL_ERROR, "%s no node bind to executing cmd ba 0x%llx!!\n",
											__func__, exe_cmdbuf_ba);
			spin_unlock_irqrestore(dev->spinlock, flags);
			return IRQ_HANDLED;
		}
		curr_obj = (struct cmdbuf_obj *)node->data;
		curr_id = curr_obj->cmdbuf_id;
	} else {
		if (irq_status & VCMD_IRQ_ERR_MASK) {
			//if error, read curr_id from register directly.
			curr_id = vcmd_get_register_value((const void *)hwregs,
									dev->reg_mirror,
									HWIF_VCMD_CMDBUF_EXE_ID);

		} else {
			//otherwise, read curr_id from vcmd reg_mem
			curr_id = *(dev->reg_mem_va + REG_ID_CMDBUF_EXE_ID);
		}

		if (curr_id >= SLOT_NUM_CMDBUF) {
			vcmd_klog(LOGLVL_ERROR, "%s error cmdbuf_id %d !!\n",  __func__, curr_id);
			spin_unlock_irqrestore(dev->spinlock, flags);
			return IRQ_HANDLED;
		}

		curr_node = &vcmd_mgr->nodes[curr_id];
		curr_obj = &vcmd_mgr->objs[curr_id];

#ifdef VCMD_DEBUG_INTERNAL
		_dbg_log_dev_regs(dev, 0);
#endif

	}

	if (curr_obj->core_id != dev->core_id) {
		vcmd_klog(LOGLVL_ERROR, "%s error cmdbuf_id, core_id[%d] is not dev id[%d] !!\n",
					  __func__, curr_id, dev->core_id);
		spin_unlock_irqrestore(dev->spinlock, flags);
		return IRQ_HANDLED;
	}

	/* process nodes between head node and curr_node (exclusive):
	 * 1. mark run_done = 1 & executing status = OK,
	 * 2. remove from dev work list.
	 * 3. add to owner's job_done_list
	 */
	if (curr_obj->cmdbuf_run_done == 0) {
		node = dev->work_list.head;
		while (node && node != curr_node) {
			obj = (struct cmdbuf_obj *)node->data;
			isr_process_node(vcmd_mgr, node, CMDBUF_EXE_STATUS_OK);

			node = node->next;
		}

		if (node == NULL) {
			vcmd_klog(LOGLVL_ERROR, "%s not find node[%d] in dev work_list!!\n",
						__func__, curr_obj->cmdbuf_id);
			spin_unlock_irqrestore(dev->spinlock, flags);
			return IRQ_HANDLED;
		}
	} else {
		// only occurs when for error irq
		if (!(irq_status & VCMD_IRQ_ERR_MASK)) {
			vcmd_klog(LOGLVL_ERROR, "%s normal irq trigger to already done cmdbuf[%d]\n",
						__func__, curr_obj->cmdbuf_id);
		}
	}

	if (dev->hw_feature.vcarb_ver == VCARB_VERSION_2_0  &&
		(irq_status & VCMD_IRQ_ARBITER_RESET)) {
		// vcmd arbiter reset err
		dev->arb_reset_irq = 1;
		spin_unlock_irqrestore(dev->spinlock, flags);
		return IRQ_HANDLED;
	}

	if (dev->hw_feature.vcarb_ver &&
		(irq_status & VCMD_IRQ_ARBITER_ERR)) {
		// vcmd arbiter err when access vpu core regs but not own arbiter
		dev->arb_err_irq = 1;
		spin_unlock_irqrestore(dev->spinlock, flags);
		return IRQ_HANDLED;
	}

	if (dev->hw_feature.has_cmdbuf_timeout &&
			irq_status & VCMD_IRQ_CMDBUF_TIMEOUT) {
		// cmdbuf execution timeout, need do subsystem reset process
		dev->state = VCMD_STATE_IDLE;
		isr_process_node(vcmd_mgr, curr_node, CMDBUF_EXE_STATUS_CMDBUF_TIMEOUT);
		dev->kthread_actions |= KT_ACT_CMDBUF_TIMEOUT;
		spin_unlock_irqrestore(dev->spinlock, flags);
		_vcmd_kthread_wakeup(vcmd_mgr);
		return IRQ_HANDLED;
	}

	//curr_node process
	if (irq_status & VCMD_IRQ_ABORT) {
#ifdef TIMEOUT_IRQ_TIMER
		/* if vcmd abort waited, del vcmd timeout timer */
		_vcmd_timeout_del_timer(dev);
#endif
#ifdef SUPPORT_WATCHDOG
		_vcmd_watchdog_stop(dev);
#endif
		//abort error
		dev->state = VCMD_STATE_IDLE;
		dev->aborted_cmdbuf_id = curr_id;

		if (dev->abort_mode == 0) {
			// curr node is done
			isr_process_node(vcmd_mgr, curr_node, CMDBUF_EXE_STATUS_OK);
		} else {
			// curr node is aborted
			/* if current obj is aborted imedialy in slice decoding pm suspend, set the
			 * executing_status as SLICE_DECODING_SUSPEND.
			 */
			if (curr_obj->executing_status != CMDBUF_EXE_STATUS_SLICE_DECODING_SUSPEND)
				curr_obj->executing_status = CMDBUF_EXE_STATUS_ABORTED;
		}

		spin_unlock_irqrestore(dev->spinlock, flags);

		//to notify owner which triggered the abort
		wake_up_interruptible_all(dev->abort_waitq);
		handled++;
		return IRQ_HANDLED;
	}

	/* before v1.6.0: not report bus err interrupt, because it will trigger abort
	 *                and ensure vcmd is idle.
	 * v1.6.0 - : when bus err, it will abort vcmd but not report abort interrupt,
	 *            and waiting bus clean, report bus err to CPU.
	 */
	if (irq_status & VCMD_IRQ_BUS_ERR) {
		//bus error, don't need to reset where to record status?
		dev->state = VCMD_STATE_IDLE;
		isr_process_node(vcmd_mgr, curr_node, CMDBUF_EXE_STATUS_BUSERR);

		/* will do futher process in kernel thread*/
		dev->kthread_actions |= KT_ACT_HW_BUS_ERR;
		//vcmd_start(dev);
		spin_unlock_irqrestore(dev->spinlock, flags);
		_vcmd_kthread_wakeup(vcmd_mgr);

		handled++;
		return IRQ_HANDLED;
	}

	if (irq_status & VCMD_IRQ_TIMEOUT) {
		//time out
#ifdef TIMEOUT_IRQ_TIMER
		if ((irq_status & VCMD_IRQ_END) == 0) {
			// start a timer to wait abort irq
			_vcmd_timeout_add_timer(dev);
		}
#else //TIMEOUT_IRQ_TIMER
		//reset dev and re-start from curr node
		dev->state = VCMD_STATE_IDLE;

		vcmd_reset_current_asic(dev);
		vcmd_start(dev);
#endif //TIMEOUT_IRQ_TIMER
		spin_unlock_irqrestore(dev->spinlock, flags);

		handled++;
		return IRQ_HANDLED;
	}
	if (irq_status & VCMD_IRQ_CMD_ERR) {
#ifdef TIMEOUT_IRQ_TIMER
		/* if vcmd cmderr waited, del vcmd timeout timer */
		_vcmd_timeout_del_timer(dev);
#endif
		//command error, re-start from next node
		dev->state = VCMD_STATE_IDLE;
		isr_process_node(vcmd_mgr, curr_node, CMDBUF_EXE_STATUS_CMDERR);

		vcmd_start(dev);
		spin_unlock_irqrestore(dev->spinlock, flags);

		handled++;
		return IRQ_HANDLED;
	}

	//JMP or END interrupt
	isr_process_node(vcmd_mgr, curr_node, CMDBUF_EXE_STATUS_OK);
	if (irq_status & VCMD_IRQ_END) {
#ifdef TIMEOUT_IRQ_TIMER
		/* if vcmd end waited, del vcmd timeout timer */
		_vcmd_timeout_del_timer(dev);
#endif
		//end command interrupt, start next node
		dev->state = VCMD_STATE_IDLE;
		vcmd_start(dev);
	} else {
#ifdef SUPPORT_WATCHDOG
		_vcmd_watchdog_feed(dev);
#endif
	}

	spin_unlock_irqrestore(dev->spinlock, flags);
	handled++;

#ifdef SUPPORT_DBGFS
	_dbgfs_update_index(dev->dbgfs_info);
#endif
	if (!handled)
		vcmd_klog(LOGLVL_BRIEF, "IRQ received, but not hantro's!\n");

	return IRQ_HANDLED;
}

/**
 * @brief suspend for vcmd driver power management
 */
int vcmd_pm_suspend(void *_vcmd_mgr)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	struct hantrovcmd_dev *dev;
	u32 aborted_id;
	int i;
	unsigned long flags;
	bi_list_node *node;
	struct cmdbuf_obj *obj;

	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		dev = &vcmd_mgr->dev_ctx[i];

		spin_lock_irqsave(dev->spinlock, flags);
		if (dev->state == VCMD_STATE_WORKING) {
			vcmd_get_executing_cmdbuf(vcmd_mgr, dev, &node);
			obj = (struct cmdbuf_obj *)node->data;
			spin_unlock_irqrestore(dev->spinlock, flags);

			vcmd_abort_mode_set(vcmd_mgr, dev, obj);
			vcmd_abort(vcmd_mgr, dev, &aborted_id);

			spin_lock_irqsave(dev->spinlock, flags);
			if (dev->abort_mode == 1)
				dev->abort_mode = 0;
			if (dev->state != VCMD_STATE_IDLE) {
				vcmd_klog(LOGLVL_ERROR, "suspend failed for dev [%d].", dev->core_id);
				spin_unlock_irqrestore(dev->spinlock, flags);
				return -EBUSY;
			}
			if (!obj->cmdbuf_run_done && obj->slice_run_done)
				obj->executing_status = CMDBUF_EXE_STATUS_SLICE_DECODING_SUSPEND;
		}
		dev->state = VCMD_STATE_POWER_OFF;
		spin_unlock_irqrestore(dev->spinlock, flags);
	}
	return 0;
}

/**
 * @brief resume for vcmd driver power management
 */
int vcmd_pm_resume(void *_vcmd_mgr)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	struct hantrovcmd_dev *dev;
	int i;
	unsigned long flags;
	struct cmdbuf_obj *obj;

#ifdef SUPPORT_MMU
	volatile u8 *mmu_hwregs[MAX_SUBSYS_NUM][2];

	for (i = 0; i < MAX_SUBSYS_NUM; i++) {
		mmu_hwregs[i][0] = vcmd_mgr->core_array[i].hwregs[SUB_MOD_MMU];
		mmu_hwregs[i][1] = vcmd_mgr->core_array[i].hwregs[SUB_MOD_MMU_WR];
	}
	MMUSetup(mmu_hwregs);
#endif

#ifdef SUPPORT_AXIFE
	for (i = 0; i < vcmd_mgr->subsys_num; i++)
		AXIFEEnable(vcmd_mgr->core_array[i].hwregs[SUB_MOD_AXIFE]);
#endif

	vcmd_reset_asic(vcmd_mgr);

	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		dev = &vcmd_mgr->dev_ctx[i];
		spin_lock_irqsave(dev->spinlock, flags);
		obj = &vcmd_mgr->objs[dev->aborted_cmdbuf_id];
		if (dev->state == VCMD_STATE_POWER_OFF &&
				obj->executing_status != CMDBUF_EXE_STATUS_SLICE_DECODING_SUSPEND) {
			dev->state = VCMD_STATE_POWER_ON;
			vcmd_start(dev);
		}
		spin_unlock_irqrestore(dev->spinlock, flags);
	}
	return 0;
}

/**
 * @brief check whether the mmap in vcmd memory pools region
 * @param unsigned long start: the start address of mmap
 * @param unsigned long end: (end - start) is the size of mmap
 * @return int: 0 - in vcmd buffer pool region, other - not in
 */
#define IN_MEM_RANGE(mem, s, e) ((s) >= (mem).pa && \
								 (e) <= ((mem).pa + (mem).size))
int in_vcmd_memory_region(void *_vcmd_mgr, unsigned long start, unsigned long end)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	int matched = 0;

	matched |= IN_MEM_RANGE(vcmd_mgr->mem_status, start, end);
	matched |= IN_MEM_RANGE(vcmd_mgr->mem_vcmd, start, end);
	matched |= IN_MEM_RANGE(vcmd_mgr->mem_regs, start, end);

	if (matched == 0)
		return -1;

	return 0;
}
