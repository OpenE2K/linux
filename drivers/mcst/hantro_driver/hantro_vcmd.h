/* SPDX-License-Identifier: GPL-2.0 */
/*
 *    Hantro encoder hardware driver header file.
 *
 *    Copyright (c) 2017, VeriSilicon Inc.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License, version 2, as
 *    published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License version 2 for more details.
 *
 *    You may obtain a copy of the GNU General Public License
 *    Version 2 at the following locations:
 *    https://opensource.org/licenses/gpl-2.0.php
 */

#ifndef _HANTRO_VCMD_H_
#define _HANTRO_VCMD_H_

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <drm/drm_modeset_helper.h>
/* Our header */
#include "hantro_priv.h"
#include <linux/of_reserved_mem.h>
#include <linux/of_irq.h>
#include "hantro.h"
#include "hantro_device.h"
#include "bidirect_list.h"

#undef addr_t
typedef u64 addr_t;

#undef mmu_iova
#ifdef SUPPORT_48PA_MMU
typedef u64 mmu_iova;
#else
typedef u32 mmu_iova;
#endif

#undef PDEBUG /* undef it, just in case */
#ifdef HANTRO_VCMD_DRIVER_DEBUG
#ifdef __KERNEL__
/* This one if debugging is on, and kernel space */
#define PDEBUG(fmt, args...) pr_info("vcmd: " fmt, ##args)
#else
/* This one for user space */
#define PDEBUG(fmt, args...) printf(__FILE__ ":%d: " fmt, __LINE__, ##args)
#endif
#else
#define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

/********variables declaration related with race condition**********/
#define ASIC_VCMD_SWREG_AMOUNT 30
#define VCMD_REGISTER_CONTROL_OFFSET 0X40
#define VCMD_REGISTER_INT_STATUS_OFFSET 0X44
#define VCMD_REGISTER_INT_CTL_OFFSET 0X48

#define MAX_CORE_NUMBER 4
#define CMDBUF_MAX_SIZE (512 * 4 * 4)
#define MAX_VCMD_CORE_NUM 4

#ifndef VSI_FPGA_MEM
#define HLINA_TRANSL_VCMD_SIZE 0x600000
#else
#define HLINA_TRANSL_VCMD_SIZE 0x900000
#endif

//approximately=128x(320x240)=128x2k=128x8kbyte=1Mbytes
#define CMDBUF_POOL_TOTAL_SIZE                                                 \
	(2 * 1024 * 1024)

#define TOTAL_DISCRETE_CMDBUF_NUM (CMDBUF_POOL_TOTAL_SIZE / CMDBUF_MAX_SIZE)
#define MAX_CMDBUF_INT_NUMBER 1
#define INT_MIN_SUM_OF_IMAGE_SIZE                                              \
	(4096 * 2160 * MAX_CORE_NUMBER * MAX_CMDBUF_INT_NUMBER)
#define CMDBUF_VCMD_REGISTER_TOTAL_SIZE                                        \
	(HLINA_TRANSL_VCMD_SIZE - CMDBUF_POOL_TOTAL_SIZE * 2)
#define VCMD_REGISTER_SIZE (128 * 4)

#define MAX_SAME_MODULE_TYPE_CORE_NUMBER 4

#define MAX_VCMD_NUMBER (MAX_VCMD_TYPE * MAX_SAME_MODULE_TYPE_CORE_NUMBER)

#define MAX_PROCESS_CORE_NUMBER (4 * 8)
#define PROCESS_MAX_SUM_OF_IMAGE_SIZE                                          \
	(4096 * 2160 * MAX_SAME_MODULE_TYPE_CORE_NUMBER *                      \
	 MAX_PROCESS_CORE_NUMBER)

#define EXECUTING_CMDBUF_ID_ADDR 26
#define VCMD_EXE_CMDBUF_COUNT 3

#define WORKING_STATE_IDLE       0
#define WORKING_STATE_WORKING    1
#define CMDBUF_EXE_STATUS_OK     0
#define CMDBUF_EXE_STATUS_CMDERR 1
#define CMDBUF_EXE_STATUS_BUSERR 2
#define CMDBUF_EXE_STATUS_CMDBUF_TIMEOUT 3

#define HW_ID_1_0_C                  0x43421001
#define HW_ID_1_1_2                  0x43421102
#define HW_ID_1_2_1                  0x43421201
#define HW_ID_1_5_9                  0x43421509
#define HW_ID_1_5_10                 0x4342150A
#define HW_ID_1_6_0                  0x43421600
#define HW_ID_1_6_1                  0x43421601
#define VCMD_HW_ID                   0x4342

#define ANY_CMDBUF_ID                0xFFFF

#define VCMD_ARBITER_BANDWIDTH0      0x2
#define VCMD_ARBITER_TIME_WINDOW_EXP 0x1d
#define VCMD_ARBITER_PARAMS (VCMD_ARBITER_TIME_WINDOW_EXP << 4 | VCMD_ARBITER_BANDWIDTH0)

/*priority support*/

#define MAX_CMDBUF_PRIORITY_TYPE 2 //0:normal priority,1:high priority

#define CMDBUF_PRIORITY_NORMAL 0
#define CMDBUF_PRIORITY_HIGH 1

#define OPCODE_WREG (0x01 << 27)
#define OPCODE_END (0x02 << 27)
#define OPCODE_NOP (0x03 << 27)
#define OPCODE_RREG (0x16 << 27)
#define OPCODE_INT (0x18 << 27)
#define OPCODE_JMP (0x19 << 27)
#define OPCODE_STALL (0x09 << 27)
#define OPCODE_CLRINT (0x1a << 27)
#define OPCODE_JMP_RDY0 (0x19 << 27)
#define OPCODE_JMP_RDY1 ((0x19 << 27) | (1 << 26))
#define JMP_IE_1 (0x01 << 25)
#define JMP_RDY_1 (0x01 << 26)

#define CLRINT_OPTYPE_READ_WRITE_1_CLEAR 0
#define CLRINT_OPTYPE_READ_WRITE_0_CLEAR 1
#define CLRINT_OPTYPE_READ_CLEAR 2

#define VCE_FRAME_RDY_INT_MASK 0x0001
#define VCE_CUTREE_RDY_INT_MASK 0x0002
#define VCE_DEC400_INT_MASK 0x0004
#define VCE_L2CACHE_INT_MASK 0x0008
#define VCE_MMU_INT_MASK 0x0010
#define CUTREE_MMU_INT_MASK 0x0020

#define VCD_FRAME_RDY_INT_MASK 0x0100
#define VCD_DEC400_INT_MASK 0x0400
#define VCD_L2CACHE_INT_MASK 0x0800
#define VCD_MMU_INT_MASK 0x1000

#define VCD_DEC400_INT_MASK_1_1_1 0x0200
#define VCD_L2CACHE_INT_MASK_1_1_1 0x0400
#define VCD_MMU_INT_MASK_1_1_1 0x0800

/* device actions for vcmd driver kthread wake up */
#define KT_ACT_HW_TIMEOUT             ((u32)(0x1 << 0))
#define KT_ACT_CMDBUF_TIMEOUT         ((u32)(0x1 << 1))
#define KT_ACT_HW_BUS_ERR             ((u32)(0x1 << 3))

enum vcmd_module_type {
	VCMD_TYPE_ENCODER = 0,
	VCMD_TYPE_CUTREE,
	VCMD_TYPE_DECODER,
	VCMD_TYPE_JPEG_ENCODER,
	VCMD_TYPE_JPEG_DECODER,
	MAX_VCMD_TYPE
};

enum { HANTRO_DECODER = 0,
	   HANTRO_ENCODER = 1,
};

struct noncache_mem {
	u32 *virtualAddress;
	dma_addr_t busAddress;
	size_t mmu_bus_address;  /* buffer physical address in MMU*/
	u32 size;
	u16 cmdbuf_id;
};

struct cmdbuf_id_parameter {
	u16 cmdbuf_id;
	u32 id;
};

struct cmdbuf_mem_parameter {
	u32 *virt_cmdbuf_addr;
	//cmdbuf pool base physical address
	addr_t phy_cmdbuf_addr;
	//cmdbuf pool base mmu mapping address
	mmu_iova mmu_phy_cmdbuf_addr;
	//cmdbuf pool total size in bytes.
	u32 cmdbuf_total_size;
	//one cmdbuf size in bytes. all cmdbuf have same size.
	u16 cmdbuf_unit_size;
	u32 *virt_status_cmdbuf_addr;
	//status cmdbuf pool base physical address
	addr_t phy_status_cmdbuf_addr;
	//status cmdbuf pool base mmu mapping address
	mmu_iova mmu_phy_status_cmdbuf_addr;
	//status cmdbuf pool total size in bytes.
	u32 status_cmdbuf_total_size;
	//one status cmdbuf size in bytes. all status cmdbuf have same size.
	u16 status_cmdbuf_unit_size;
	//for pcie interface, hw can only access phy_cmdbuf_addr-pcie_base_ddr_addr.//for other interface, this value should be 0?
	size_t base_ddr_addr;
	//register cmdbuf pool base virtual address;
	u32 *reg_virt_addr;
	//register cmdbuf pool base physical address, it's for cpu
	size_t reg_phy_addr;
	//register cmdbuf pool base hardware address, it's for hardware ip
	size_t reg_hw_addr;
	//register cmdbuf pool total size in bytes.
	u32 reg_total_size;
	//one reg cmdbuf size in bytes. all status cmdbuf have same size.
	u32 reg_unit_size;
	//input [31~16] slice id, [15~0] type
	u32 id;
};

/*need to consider how many memory should be allocated for status.*/
struct exchange_parameter {
	/** control interrupt mode when generate JMP command
	 * bit31 is mode_flag.
	 *	- when mode_flag is 0, adapative interrupt mode is selected. in such
	 *	  mode, bit[30:0] is executing time estimated for current job;
	 *	- when mode_flag is 1, manual interrupt mode is selected. in such mode,
	 *	  bit[0] is used to set IE flag in JMP command.
	 */
	u32 interrupt_ctrl; //input ;executing_time=encoded_image_size*(rdoLevel+1)*(rdoq+1);
	/* input ;executing_time=encoded_image_size*(rdoLevel+1)*(rdoq+1) */
	u32 executing_time;
	u32 client_type;
	u16 module_type; //input input vce=0,IM=1,vcd=2，jpege=3, jpegd=4
	u16 cmdbuf_size; //input, reserve is not used; link and run is input.
	u16 priority; //input,normal=0, high/live=1
	u16 cmdbuf_id; //output ,it is unique in driver.
	u16 core_id; //just used for polling.
	u8 cmdbuf_reserve;
	u32 id;
	/* req_cores_info for user to select cores: [0,15]core mask. */
	u32 req_cores_info;
	u16 core_mask; //core_mask for user to select cores
	/* last cmd is JMP (0) or END (1) command */
	u16 has_end_cmd;
};

typedef struct {
	unsigned long base_addr;
	u32 iosize;
	/* indicate the core share resources with other cores or not.If 1,
	 * means cores can not work at the same time
	 */
	u32 resource_shared;
} SUBSYS_CONFIG;

typedef struct {
	SUBSYS_CONFIG cfg;
	SUBSYS_CORE_INFO core_info;
} SUBSYS_DATA;

struct process_manager_obj {
	struct file *filp;
	u32 total_exe_time;
	/* process lock */
	spinlock_t spinlock;
	wait_queue_head_t wait_queue;
	/* for mutli core multi stream */
	bi_list_node *cmdbuf_nodes[TOTAL_DISCRETE_CMDBUF_NUM];
};

struct cmdbuf_obj {
	/* current CMDBUF type: input vce=0,IM=1,vcd=2,
	 * jpege=3, jpegd=4
	 */
	u32 module_type;
	/* current CMDBUFpriority: normal=0, high=1 */
	u32 priority;
	/* current CMDBUFexecuting_time=
	 * encoded_image_size*(rdoLevel+1)*(rdoq+1)
	 */
	u32 executing_time;
	/* current CMDBUF size */
	u32 cmdbuf_size;
	/* current CMDBUF start virtual address */
	u32 *cmdbuf_virtualAddress;
	/* current CMDBUF start physical address */
	size_t cmdbuf_busAddress;
	size_t mmu_cmdbuf_bus_address;      //current CMDBUF start mmu mapping address.
	/* current status CMDBUF start virtual address */
	u32 *status_virtualAddress;
	/* current status CMDBUF start physical address */
	size_t status_busAddress;
	/* current status CMDBUF size */
	u32 status_size;
	/* current CMDBUF executing status */
	u32 executing_status;
	/* file pointer in the same process */
	struct file *filp;
	/* which vcmd core is used */
	u16 core_id;
	/* which core can be used */
	u32 req_cores_info;
	/* used to manage CMDBUF in driver.It is a handle to identify
	 * cmdbuf,also is an interrupt vector.position in pool,
	 * same as status position
	 */
	u16 cmdbuf_id;
	/* 0 means sw has not copied data into this CMDBUF;
	 * 1 means sw has copied data into this CMDBUF
	 */
	u8 cmdbuf_data_loaded;
	/* 0 :not linked, 1:linked */
	u8 cmdbuf_data_linked;
	/* if 0,waiting for CMDBUF finish; if 1, op code in CMDBUF has
	 * finished one by one.HANTRO_VCMD_IOCH_WAIT_CMDBUF will check
	 * this variable
	 */
	u8 cmdbuf_run_done;
	/* if 0, not need to remove CMDBUF; 1 CMDBUF can be removed if
	 * it is not the last CMDBUF
	 */
	u8 cmdbuf_need_remove;
	/* if 1, the last opcode is end opCode */
	u8 has_end_cmdbuf;
	/* if 1, JMP will not send normal interrupt */
	u8 no_normal_int_cmdbuf;
	/* if 0, no reserve; if 1 versrve */
	u8 cmdbuf_reserve;
	/* if 0, the cmd buf hasn't been waited, otherwise, has been waited */
	u32 waited;
	struct process_manager_obj *process_manager_obj;
};

struct vcmd_config {
	u64 vcmd_base_addr;
	u32 vcmd_iosize;
	int vcmd_irq;
	/*input vce=0,IM=1,vcd=2,jpege=3, jpegd=4*/
	u32 sub_module_type;
	/* in byte */
	u16 submodule_main_addr;
	/* in byte, if submodule addr == 0xffff,
	 * this submodule does not exist
	 */
	u16 submodule_dec400_addr;
	/* in byte */
	u16 submodule_L2Cache_addr;
	/* in byte */
	u16 submodule_MMU_addr;
	/* in byte */
	u16 submodule_MMUWrite_addr;
	/* in byte */
	u16 submodule_axife_addr[2];
};

struct subsys_addr {
	u64 vcmd_base_addr;
	u64 submodule_main_addr;
	u64 submodule_dec400_addr;
	u64 submodule_L2Cache_addr;
	u64 submodule_MMU_addr;
	u64 submodule_MMUWrite_addr;
	u64 submodule_axife_addr[2];
};

struct vcmd_cfg_par {
	/* input vce=0,cutree=1,vcd=2,jpege=3, jpegd=4 */
	u16 module_type;
	/* output, how many vcmd cores are there with
	 * corresponding module_type
	 */
	u16 vcmd_core_num;
	/* output,if submodule addr == 0xffff, this submodule does not exist */
	u16 submodule_main_addr;
	u16 status_main_addr;            //output, main ip offset instatus buffer.
	/* output ,if submodule addr == 0xffff, this submodule does not exist */
	u16 submodule_dec400_addr;
	u16 status_dec400_addr; //output, dec400 ip offset instatus buffer.
	/* output,if submodule addr == 0xffff, this submodule does not exist */
	u16 submodule_L2Cache_addr;
	u16 status_L2Cache_addr; //output, L2Cache ip offset instatus buffer.
	/* output,if submodule addr == 0xffff, this submodule does not exist */
	u16 submodule_MMU_addr;
	u16 status_MMU_addr; //output, MMU ip offset instatus buffer.
	u16 submodule_MMUWrite_addr;
	u16 status_MMUWrite_addr; //output, MMU ip offset instatus buffer.status_MMU_addr
	u16 submodule_axife_addr[2];
	/* output,if submodule addr == 0xffff, this submodule does not exist.*/
	u16 status_axife_addr[2]; //output, axife ip offset instatus buffer.
	u16 submodule_ufbc_addr; //output ,if submodule addr == 0xffff, this submodule does not exist.
	u16 status_ufbc_addr; //output, ufbc ip offset instatus buffer.
	u16 config_status_cmdbuf_id;
	u32 vcmd_hw_version_id;
	u32 vcmd_priority[MAX_VCMD_CORE_NUM]; //specify the priority of vcmd
	/* input [31~16] slice id, [15~0] type */
	u32 id;
};

typedef struct vcmd_core {
	u32 core_id;
	int type;
	u32 id_in_type;
	u32 useirq;
	struct vcmd_config vcmd_core_cfg;
	/* IO mem base */
	void  __iomem *hwregs;
	void  __iomem *main_hwregs;
	void  __iomem *axife_hwregs[2];

	u32 sw_cmdbuf_rdy_num;
	/* */
	spinlock_t spinlock;
	wait_queue_head_t wait_queue;
	wait_queue_head_t wait_abort_queue;
	bi_list list_manager;
	u32 reg_mirror[ASIC_VCMD_SWREG_AMOUNT];
	/* number of cmdbufs without interrupt */
	u32 duration_without_int;
	volatile u8 working_state;
	u32 total_exe_time;
	/* used for analyse configuration in cwl */
	u16 status_cmdbuf_id;
	/* megvii 0x43421001, later 0x43421102 */
	u32 hw_version_id;
	/* start virtual address of vcmd registers memory of  CMDBUF */
	u32 *vcmd_reg_mem_virtualAddress;
	/* start physical address of vcmd registers memory of  CMDBUF */
	size_t vcmd_reg_mem_busAddress;
	unsigned int mmu_vcmd_reg_mem_bus_address;
	/* size of vcmd registers memory of CMDBUF */
	u32 vcmd_reg_mem_size;

	// timeout interrupt post process related
	struct timer_list timeout_timer;
	u8 timeout_timer_active;
	u8 timeout_timer_expired;

	/* device actions for wake up vcmd driver kthread
	 * refer to KT_ACT_xxx
	 */
	u32 kthread_actions;

	struct vcmd_dev *parent_dev;
	struct vcmd_core *core_next;
} vcmd_core_str;

typedef struct vcmd_dev {
	int type;
	u32 sliceidx;
	u32 subsys_num;
	struct device *dev;
	struct noncache_mem *vcmd_buf_mem_pool;
	struct noncache_mem *vcmd_status_buf_mem_pool;
	struct noncache_mem *vcmd_registers_mem_pool;
	size_t base_ddr_addr;
	size_t base_reg_addr;
	u16 cmdbuf_used[TOTAL_DISCRETE_CMDBUF_NUM];
	u16 cmdbuf_used_pos;
	u16 cmdbuf_used_residual;
	struct vcmd_core *vcmd_manager[MAX_VCMD_TYPE][MAX_VCMD_NUMBER];
	bi_list_node * global_cmdbuf_node[TOTAL_DISCRETE_CMDBUF_NUM];
	bi_list global_process_manager;
	u16 vcmd_position[MAX_VCMD_TYPE];
	int vcmd_type_core_num[MAX_VCMD_TYPE];
	/* for reserve */
	struct semaphore vcmd_reserve_cmdbuf_sem[MAX_VCMD_TYPE];

	int software_triger_abort;

	wait_queue_head_t vcmd_cmdbuf_memory_wait;
	/* mc wait queue, used in wait_cmdbuf_ready with ANY_CMDBUF_ID */
	wait_queue_head_t mc_wait_queue;
	/* */
	spinlock_t vcmd_cmdbuf_alloc_lock;
	/* */
	spinlock_t vcmd_process_manager_lock;

	/* kernel thread */
	struct task_struct *kthread;
	u8 stop_kthread;
	wait_queue_head_t kthread_waitq;

	struct vcmd_core *vcmd_core;
} vcmd_dev_str;

typedef struct vcmd_slice {
	u32 sliceidx;
	struct vcmd_dev dec_vcmd;
	struct vcmd_dev enc_vcmd;
	u32 config;
	struct vcmd_slice *slice_next;
} vcmd_slice_str;

u32 get_vcmd_slice_config(u32 sliceidx);
void add_vcmd_slice_config(u32 sliceidx, u32 config);
int get_vcmd_slice_num(void);
void set_vcmd_slice_config(vcmd_slice_str *slice, struct vcmd_config *vcmd_cfg_p);
void add_vcmd_slice(struct device *dev, vcmd_slice_str *slice_node);
void transfer_vcmdslice_to_norslice(int sliceidx);
void add_vcmd_core(vcmd_slice_str *slice_node, vcmd_core_str *vcmd_core);
vcmd_slice_str *hantro_vcmd_analyze_subnode(struct platform_device *pdev, int useirq,
					    struct device_node *slice);
int hantro_vcmd_probe(struct platform_device *pdev, int useirq, struct device_node *slice, unsigned long ddr_base, unsigned long reg_base, int irq);
int hantro_vcmd_cleanup(void);
vcmd_slice_str *get_slice_by_sliceidx(u32 sliceidx);
vcmd_core_str *get_dev_of_core(vcmd_dev_str *vcmd_dev, u32 id);
vcmd_dev_str *get_dev_by_sliceidx(u32 sliceidx, u32 group_codec);
vcmd_slice_str *get_vcmd_slice_head(void);
void set_vcmd_slice_listnull(void);
long vcmd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
int hantrovcmd_release(struct inode *inode, struct file *filp);
int hantrovcmd_open(struct inode *inode, struct file *filp);
#ifdef USE_DTB_PROBE
int hantro_vcmd_init(u32 sliceidx);
#else
int hantro_vcmd_init(void *p);
#endif
int vcmd_pm_suspend(void *_dev);
int vcmd_pm_resume(void *_dev);

#endif
