
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

#ifndef _HANTRO_VCMD_PRIV_H
#define _HANTRO_VCMD_PRIV_H
#ifdef __cplusplus
extern "C" {
#endif

#include <linux/ioctl.h> /* needed for the _IOW etc stuff used later */
#include <linux/types.h>

#include "bidirect_list.h"
#include "vcmdswhwregisters.h"
#include "subsys.h"

#define MAX_VCMD_NUM			(MAX_SUBSYS_NUM)

#define REG_ID_CMDBUF_EXE_CNT	(3)
#define REG_ID_CMDBUF_EXE_ID	(26)
/* read vcmd swreg26 (CMDBUF_EXE_ID) to reg-buf[REG_ID2_CMDBUF_EXE_ID] at
 * beginning of each cmdbuf to indicate which cmdbuf is executing in reg-buf
 */
#define REG_ID2_CMDBUF_EXE_ID	(REG_ID_CMDBUF_EXE_ID + 1)

#define VCMD_REG_NUM_READ			(27)

#define _ALIGN(X, Factor) ((((X) + ((Factor)-1)) / (Factor)) * (Factor))
#define ALIGN_4K(X) _ALIGN(X, 4096)

#define VCMD_STATE_POWER_OFF    0
#define VCMD_STATE_POWER_ON     1
#define VCMD_STATE_IDLE         2
#define VCMD_STATE_WORKING      3

#define HW_WORK_STATE_IDLE		0
#define HW_WORK_STATE_WORK		1
#define HW_WORK_STATE_STALL		2
#define HW_WORK_STATE_PEND		3
#define HW_WORK_STATE_ABORT		4

#define CMDBUF_EXE_STATUS_OK             0
#define CMDBUF_EXE_STATUS_CMDERR         1
#define CMDBUF_EXE_STATUS_BUSERR         2
#define CMDBUF_EXE_STATUS_ABORTED        3
#define CMDBUF_EXE_STATUS_CMDBUF_TIMEOUT 4
#define CMDBUF_EXE_STATUS_SLICE_DECODING_SUSPEND 5

#define _GET_PO(filp)	((struct proc_obj *)((struct vcmd_priv_ctx *)filp->private_data)->po)

#define CMDBUF_OFF(id)		((id) * SLOT_SIZE_CMDBUF)
#define STATUSBUF_OFF(id)	((id) * SLOT_SIZE_STATUSBUF)
#define CMDBUF_OFF_32(id)		(((id) * SLOT_SIZE_CMDBUF) / sizeof(u32))
#define STATUSBUF_OFF_32(id)	(((id) * SLOT_SIZE_STATUSBUF) / sizeof(u32))

/* external abnormal interrupt source definition */
/* version after v1.5.10 */
// VCD/VCDJ/VCE/VCEJ/IM: 0; AXI2TO1: 3
#define CORE_IP_INTR_SRC_BIT                     0
#define AXI2TO1_INTR_SRC_BIT                     3

/* version before v1.5.10 */
// VCE: 0; VCD: 8
#define ENC_INTR_SRC_BIT                         0
#define DEC_INTR_SRC_BIT                         8

#define ABN_IRQ_BIT_MASK(A)                      ((A)+16)
#define DEC_ABN_IRQ_MASK                                      \
	(1 << ABN_IRQ_BIT_MASK(DEC_INTR_SRC_BIT))
#define CORE_IP_ABN_IRQ_MASK                                  \
	(1 << ABN_IRQ_BIT_MASK(CORE_IP_INTR_SRC_BIT))
#define AXI2TO1_ABN_IRQ_MASK                                  \
	(1 << ABN_IRQ_BIT_MASK(AXI2TO1_INTR_SRC_BIT))

/* external sw reset corresponding ip in the subsystem */
enum ext_sw_reset {
	IP_RESET_CORE = 0, //VCE/IM/VCD/VCDJ
	IP_RESET_AXIF,
	IP_RESET_DEC400,
	IP_RESET_AXI2TO1,
	IP_RESET_MMU,
};
#define SUBSYSTEM_RESET(RST)            ((u32)(1 << ((RST)+16)))

/* device actions for vcmd driver kthread wake up */
#define KT_ACT_WATCHDOG             ((u32)(0x1 << 0))
#define KT_ACT_HW_TIMEOUT           ((u32)(0x1 << 1))
#define KT_ACT_CMDBUF_TIMEOUT       ((u32)(0x1 << 2))
#define KT_ACT_AXI2TO1_EXCEPTION    ((u32)(0x1 << 3))
#define KT_ACT_HW_BUS_ERR           ((u32)(0x1 << 4))

/* declarations */
extern int vsi_kloglvl;
#define vcmd_klog(lvl, fmt, ...) {\
	if (lvl == LOGLVL_ERROR)	\
		pr_err(DRIVER_NAME "_vcmd: " fmt, ##__VA_ARGS__);	\
	else if (lvl >= vsi_kloglvl)		\
		pr_info(DRIVER_NAME "_vcmd: " fmt, ##__VA_ARGS__);	\
}
/* ------------------------------------------------------
 *  single linked list
 *-------------------------------------------------------
 */
typedef struct si_linked_node {
	struct si_linked_node *next;
	void *data;
} si_linked_node;

struct si_linked_list {
	spinlock_t spinlock;
	struct si_linked_node *head;
	struct si_linked_node *tail;
	struct si_linked_node nodes[SLOT_NUM_CMDBUF];
};

struct proc_obj {
	u64 total_workload;
	spinlock_t spinlock;
	wait_queue_head_t resource_waitq;
	wait_queue_head_t job_waitq;
	u32 module_type;	/* correspond to filp, indicates subsys type */

	spinlock_t job_lock;
	struct file *filp;
	struct bi_list job_done_list;
	u32 in_wait;		/* user is waiting for a specified cmdbuf run done */
};


struct noncache_mem {
	u32 *va;
	u32 size;
	addr_t pa;		/* buffer physical address */
	mmu_iova mmu_ba;	/* buffer bus address in MMU*/
};

struct cmdbuf_obj {
	/* current CMDBUF type: input vce=0,
	 * IM=1,vcd=2, pege=3, jpegd=4
	 */
	u32 module_type;
	/* current CMDBUFpriority: normal=0, high=1 */
	u32 priority;
	/* workload = encoded_image_size*(rdoLevel+1)*(rdoq+1);*/
	u64 workload;
	/* current CMDBUF size, change to payload after linked  */
	u32 cmdbuf_size;
	/* current CMDBUF virtual address.*/
	u32 *cmd_va;
	/*current status CMDBUF virtual address.*/
	u32 *status_va;
	/*current status CMDBUF size*/
	u32 status_size;
	/*current CMDBUF executing status.*/
	u32 executing_status;
	/* which vcmd core is assigned to.*/
	u16 core_id;
	/* used to manage CMDBUF in driver.It is a handle
	 * to identify cmdbuf.also is an interrupt vector.
	 * position in pool,same as status position.
	 */
	u16 cmdbuf_id;
	/* cmdbuf node is in dev->work_list (1) or not (0) */
	u8 cmdbuf_linked;
	/* if 0, waiting for CMDBUF finish;
	 * if 1, op code in CMDBUF has finished one by one.
	 * HANTRO_VCMD_IOCH_WAIT_CMDBUF will check this variable.
	 */
	u8 cmdbuf_run_done;
	/* if 0, wait slice ready
	 * if 1, slice has ready
	 */
	u8 slice_run_done;
	/* if 0, not need to remove CMDBUF;
	 * if 1, CMDBUF can be removed if it is not used by vcmd hw;
	 */
	u8 cmdbuf_need_remove;
	/* The last command is JMP (1) or END (0). */
	u8 has_jmp_cmd;
	/* JMP command will trigger JMP interrupt (1) or not. */
	u8 jmp_ie;
	/* current CMDBUF physical address. */
	addr_t cmd_pa;
	/*current status CMDBUF physical address.*/
	addr_t status_pa;

	/* which cores can be uesd.*/
	u32 core_mask;
	/*file pointer occupying this obj.*/
	struct file *filp;
	/* pointer of process object occupying this obj*/
	struct proc_obj *po;
	/* pointer of the instance of process */
	void *owner;
	//current status CMDBUF mmu mapping address.
	size_t mmu_status_ba;
	//current CMDBUF mmu mapping address.
	size_t mmu_cmd_ba;
};

enum vcmd_sw_init_mode {
	VCMD_INIT_NORMAL = 0,		//Not run init commands
	VCMD_INIT_TRIGGER = 1,		//Run init commands only when it is triggered
	VCMD_INIT_EXE_CMDBUF = 2,	//Run init commands before execution of each CMDBUF
};

#define DEFAULT_VCMD_INIT_MODE VCMD_INIT_TRIGGER

struct vcmd_subsys_info {
	addr_t reg_base;		/* physical reg base addr of subsys */
	int irq;				/* irq of vcmd */

	/*input vce=0,IM=1,vcd=2,jpege=3, jpegd=4*/
	u32 sub_module_type;	/* type of main module */

	u16 reg_off[SUB_MOD_MAX];	/* reg offset of each module */
	u16 io_size[SUB_MOD_MAX]; /* reg size of each module, in bytes*/

	/* for dbgfs */
	volatile u8 *hwregs[SUB_MOD_MAX];
};

struct vcmd_hw_features {
	u8 vcarb_ver;	//hw support arbiter (vcarb version) or not (0)
	u8 has_init_mode;	//hw support init-mode (1) or not (0)
	u8 has_cmdbuf_timeout; //hw support cmdbuf execution timeout (1) or not (0)
};

struct hantrovcmd_dev {
	//config of each core,such as base addr, irq,etc
	struct vcmd_subsys_info *subsys_info;
	u32 hw_version_id;
	//vcmd core id for driver and sw internal use
	u32 core_id;
	struct vcmd_hw_features hw_feature;

	volatile u8 *hwregs; /* registers IO mem base */

	u32 reg_mirror[ASIC_VCMD_SWREG_AMOUNT];

	spinlock_t owner_lock_vcmd;
	spinlock_t *spinlock;			//point to owner_lock_vcmd
	bi_list work_list;

	u32 sw_cmdbuf_rdy_num;

	//number of cmdbufs without interrupt.
	u64 duration;
	volatile u32 state;
	u64 total_workload;

	//vcmd registers memory
	u32 *reg_mem_va;
	u32 reg_mem_sz;
	addr_t reg_mem_ba;
	mmu_iova mmu_reg_mem_ba;

	//translation offset from bus addr (ba) to physical addr (pa).
	addr_t pa_trans_offset;
	wait_queue_head_t abort_queue_vcmd;

	wait_queue_head_t *abort_waitq;	//point to abort_queue_vcmd

	u32 abort_mode;		//0: stop when JMP/END; 1: stop curr-cmd (imediately);
	enum vcmd_sw_init_mode init_mode;

	u32 init_cmd_idx;	//for setting init cmd

	u32 aborted_cmdbuf_id;

	u8 mmu_enable;

	void *handler;		// point to vcmd_mgr

	// abnormal interrupt related
	u32 abn_irq_mask;	// abnormal irq mask
	u32 vcd_abn_irq_mask;
	u32 intr_gate_mask;
	spinlock_t abn_irq_lock;

	// timeout interrupt post process related
	struct timer_list timeout_timer;
	u8 timeout_timer_active;

	//watchdog for monitor exceptions
	struct timer_list watchdog_timer;
	u8 watchdog_active;

	/* device actions for wake up vcmd driver kthread
	 * refer to KT_ACT_xxx
	 */
	u32 kthread_actions;

	// a flag to indicate arbiter reset irq received (< hw version 1.5.09)
	u32 arb_reset_irq;
	// a flag to indicate arbiter err irq received
	u32 arb_err_irq;

	/* for slice decoding, the wait queue is used to wait buffer empty
	 * interrupt in pm suspend process.
	 */
	wait_queue_head_t buff_empty_waitq; // buffer empty wait queue

#ifdef SUPPORT_DBGFS
	void *dbgfs_info;
#endif
};

struct vcmd_module_mgr {
	u32 num;
	struct hantrovcmd_dev *dev[MAX_VCMD_NUM];
	struct semaphore sem; //for reserve cmdbuf
};

typedef struct {
	/* input configuration to vcmd manager */
	int subsys_num;
	struct vcmd_subsys_info core_array[MAX_SUBSYS_NUM];
	struct platform_device *platformdev;

	/* three linear buffers: vcmd buffer / status / registers */
	struct noncache_mem mem_vcmd;
	struct noncache_mem mem_status;
	struct noncache_mem mem_regs;

	//translation offset from bus addr (ba) to physical addr (pa).
	addr_t pa_trans_offset;

	struct vcmd_module_mgr module_mgr[MAX_VCMD_TYPE];

	/* cmdbuf/obj/node management*/
	struct cmdbuf_obj objs[SLOT_NUM_CMDBUF];

	struct bi_list_node nodes[SLOT_NUM_CMDBUF];		//nodes for dev work-list
	struct bi_list_node po_jobs[SLOT_NUM_CMDBUF];	//node for po job-list

	struct semaphore free_obj_sema;
	struct si_linked_list free_obj_list;

	struct hantrovcmd_dev *dev_ctx;

	u8 mmu_enable;
	u8 vcmd_irq_enabled;

	//PCIE_EN defined
	struct noncache_mem pcie_pool;	//pool for mem_vcmd, mem_status and mem_regs

	struct proc_obj *init_po;

	struct semaphore isr_polling_sema;

	struct task_struct *kthread;
	u8 stop_kthread;
	wait_queue_head_t kthread_waitq;

#ifdef SUPPORT_DBGFS
	void *dbgfs_ctx;
#endif
} vcmd_mgr_t;


/******************************************************************************
 * VCMD Command Definitions
 ******************************************************************************/
#define OPCODE_MASK							((u32)(0x1F) << 27)
	#define OPCODE_WREG							((u32)(0x01) << 27)
	#define OPCODE_END							((u32)(0x02) << 27)
	#define OPCODE_NOP							((u32)(0x03) << 27)
	#define OPCODE_RREG							((u32)(0x16) << 27)
	#define OPCODE_INT							((u32)(0x18) << 27)
	#define OPCODE_JMP							((u32)(0x19) << 27)
	#define OPCODE_STALL						((u32)(0x09) << 27)
	#define OPCODE_CLRINT						((u32)(0x1a) << 27)
	#define OPCODE_M2M							((u32)(0x1b) << 27)
	#define OPCODE_MSET							((u32)(0x1c) << 27)
	#define OPCODE_M2MP							((u32)(0x1d) << 27)


#define RREG_ADDR_INC			(0)
#define RREG_ADDR_FIX			(1)
#define RREG_MODE(A)			(((A) & 1) << 26)
#define RREG_G_MODE(A)			(((A) >> 26) & 1)
#define RREG_LEN(A)				(((A) & 0x3FF) << 16)
#define RREG_G_LEN(A)			((((((A) >> 16) & 0x3FF) - 1) & 0x3FF) + 1)
#define RREG_START_ADDR(A)		((A) & 0xFFFF)
struct cmd_rreg_t {
	u32 opcode;					//refer to register spec.
	u32 lsb;					//reg value buf addr [31..0]
	u32 msb;					//reg value buf addr [63..32]
	u32 padding;
};

#define JMP_RDY(A)			(((A) & 1) << 26)
#define JMP_G_RDY(A)		(((A) >> 26) & 1)
#define JMP_IE(A)			(((A) & 1) << 25)
#define JMP_G_IE(A)			(((A) >> 25) & 1)
#define JMP_NEXT_LEN(A)		((A) & 0xFFFF)
struct cmd_jmp_t {
	u32 opcode;					//refer to register spec.
	u32 lsb;					//next cmd-buf addr [31..0]
	u32 msb;					//next cmd-buf addr [63..32]
	u32 id;						//next cmd-buf id
};

#define WREG_ADDR_INC			(0)
#define WREG_ADDR_FIX			(1)
#define WREG_MODE(A)			(((A) & 1) << 26)
#define WREG_G_MODE(A)			(((A) >> 26) & 1)
#define WREG_LEN(A)				(((A) & 0x3FF) << 16)
#define WREG_G_LEN(A)			((((((A) >> 16) & 0x3FF) - 1) & 0x3FF) + 1)
#define WREG_START_ADDR(A)		((A) & 0xFFFF)
struct cmd_wreg_t {
	u32 opcode;					//refer to register spec.
	u32 data[0];
};

struct cmd_end_t {
	u32 opcode;					//refer to register spec.
	u32 padding;
};

#define CMD_SET_ADDR(cmd, ba) do { \
	(cmd)->lsb = (u32)(ba); \
	(cmd)->msb = (sizeof(addr_t) == 4) ? 0 : ((u32)((u64)(ba) >> 32)); \
} while (0)



#ifdef __cplusplus
}
#endif
#endif
