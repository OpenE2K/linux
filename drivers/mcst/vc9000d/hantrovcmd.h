/*
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

#ifndef _VC8000_VCMD_DRIVER_H_
#define _VC8000_VCMD_DRIVER_H_
#include <linux/ioctl.h> /* needed for the _IOW etc stuff used later */

#undef addr_t
#define addr_t ADDR_T_VCMD
typedef u64 addr_t;

#undef mmu_iova
#define mmu_iova MMU_IOVA_VCMD
#ifdef SUPPORT_48PA_MMU
typedef u64 mmu_iova;
#else
typedef u32 mmu_iova;
#endif

/* Use 'v' as magic number for vcmd */
#define HANTRO_VCMD_IOC_MAGIC  'v'
/*
 * S means "Set" through a ptr,
 * T means "Tell" directly with the argument value
 * G means "Get": reply by setting through a pointer
 * Q means "Query": response is on the return value
 * X means "eXchange": G and S atomically
 * H means "sHift": T and Q atomically
 */

#define HANTRO_VCMD_IOCH_GET_CMDBUF_PARAMETER                                  \
	_IOWR(HANTRO_VCMD_IOC_MAGIC, 20, struct cmdbuf_mem_parameter *)
#define HANTRO_VCMD_IOCH_GET_CMDBUF_POOL_SIZE                                  \
	_IOWR(HANTRO_VCMD_IOC_MAGIC, 21, unsigned long)
#define HANTRO_VCMD_IOCH_SET_CMDBUF_POOL_BASE                                  \
	_IOWR(HANTRO_VCMD_IOC_MAGIC, 22, unsigned long)

#define HANTRO_VCMD_IOCH_GET_VCMD_PARAMETER                                    \
	_IOWR(HANTRO_VCMD_IOC_MAGIC, 24, struct config_parameter *)

#define HANTRO_VCMD_IOCH_RESERVE_CMDBUF                                        \
	_IOWR(HANTRO_VCMD_IOC_MAGIC, 25, struct exchange_parameter *)
#define HANTRO_VCMD_IOCH_DROP_OWNER                                          \
	_IOWR(HANTRO_VCMD_IOC_MAGIC, 43, void *)

#define HANTRO_VCMD_IOCH_LINK_RUN_CMDBUF _IOR(HANTRO_VCMD_IOC_MAGIC, 26, u16 *)
#define HANTRO_VCMD_IOCH_WAIT_CMDBUF _IOR(HANTRO_VCMD_IOC_MAGIC, 27, u16 *)
#define HANTRO_VCMD_IOCH_RELEASE_CMDBUF _IOR(HANTRO_VCMD_IOC_MAGIC, 28, u16 *)

#define HANTRO_VCMD_IOCH_POLLING_CMDBUF _IOR(HANTRO_VCMD_IOC_MAGIC, 40, u16 *)
#define HANTRO_VCMD_IOCH_PUSH_SLICE_REG _IOR(HANTRO_VCMD_IOC_MAGIC, 41, void *)
#define HANTRO_VCMD_IOCH_ABORT_CMDBUF _IOR(HANTRO_VCMD_IOC_MAGIC, 42, u16 *)
#define HANTRO_VCMD_IOCH_WAIT_OWNER_DONE                                       \
	_IOR(HANTRO_VCMD_IOC_MAGIC, 44, void *)

#define HANTRO_VCMD_IOC_MAXNR 50

/*priority support*/

/* 0:normal priority,1:high priority */
#define MAX_CMDBUF_PRIORITY_TYPE          2

#define CMDBUF_PRIORITY_NORMAL            0
#define CMDBUF_PRIORITY_HIGH              1

/* exchange parameter input bit mask */
#define EXCH_PRIO_BIT                    0
#define EXCH_END_CMD_BIT                 1

#define EXCH_BIT_MASK(bit)               (1 << (bit))
#define EXCH_S_BIT(param, bit)           ((param) |= EXCH_BIT_MASK(bit)) // set bit
#define EXCH_G_BIT(param, bit)           (((param) & EXCH_BIT_MASK(bit)) >> (bit)) // get bit

/* TBD: need to match with MAX_VCMD_ENTRIES in user space */
#define SLOT_NUM_CMDBUF						(256)

/* VCMD memory pool layout as:
 *	0: CMDBUF memory, size is SLOT_NUM_CMDBUF * SLOT_SIZE_CMDBUF
 *	1: STATUSBUF memory, size is SLOT_NUM_CMDBUF * SLOT_SIZE_STATUSBUF
 *	2: REGBUF memory, size is MAX_VCMD_NUM * SLOT_SIZE_REGBUF
 */
#define VCMD_POOL_TOTAL_SIZE	(5 * 1024 * 1024)	/* match with vcmd_size which is module param of memalloc */

#define SLOT_SIZE_CMDBUF		(512 * 4 * 4)
#define SLOT_SIZE_STATUSBUF		(512 * 4 * 4)
#define SLOT_SIZE_REGBUF		(64 * 1024)

/******************************************************************************
 * VCMD HW version IDs
 ******************************************************************************/
#define VCMD_HW_ID                  0x4342
#define HW_ID_1_0_C                 0x43421001
#define HW_ID_1_1_1                 0x43421101
#define HW_ID_1_1_2                 0x43421102
#define HW_ID_1_1_3                 0x43421103
#define HW_ID_1_2_1                 0x43421201
#define HW_ID_1_5_0                 0x43421500
#define HW_ID_1_5_9                 0x43421509
#define HW_ID_1_5_10                0x4342150A
#define HW_ID_1_6_0                 0x43421600

/****************************************************************************
 * VCARB version
 ****************************************************************************/
#define VCARB_VERSION_2_0         0x2  // arbiter2.0, dual-os version
#define VCARB_VERSION_3_0         0x3  // arbiter3.0, virtulization version

#define ANY_CMDBUF_ID 0xFFFF

/* platform frequency: need adjust it according your platform
 *   such as define it as 5000000 for 5Mhz fpga platform
 */
#define PLATFORM_FREQUENCY                        (5 * 1000000L)
/* for 5Mhz fpga platform, one hw cycle is 200ns
 */
#define CYCLE_TO_CPU_TIME                     (1000000000L / PLATFORM_FREQUENCY) //ns
/* if vcmd arbiter is hang, reset it.
 * reset time is one time_window.
 */
extern u32 arbiter_timewindow;
#define VCMD_ARBITER_RESET_TIME ((1 << arbiter_timewindow) * \
								  CYCLE_TO_CPU_TIME / 1000000) //ms
/* time to wotchdog wait for one job */
#define ONE_JOB_WAIT_TIME                        (100 * 1000)	//For FPGA platform (in ms)
//#define ONE_JOB_WAIT_TIME                        (500)	//For SoC platform

#define ONE_SLICE_WAIT_TIME                      (500) //ms

/* VF timeout time for arbiter fe_timeout/bus_hack to reset vcmd */
#define SW_TIMEOUT_TIME_FOR_ARBITER              (ONE_JOB_WAIT_TIME * 10) // customer to set.

/*module_type support*/

enum vcmd_module_type {
	VCMD_TYPE_ENCODER = 0,
	VCMD_TYPE_CUTREE,
	VCMD_TYPE_DECODER,
	VCMD_TYPE_JPEG_ENCODER,
	MAX_VCMD_TYPE
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
	mmu_iova mmu_phy_status_cmdbuf_addr; //->addr_t
	//status cmdbuf pool total size in bytes.
	u32 status_cmdbuf_total_size;
	//one status cmdbuf size in bytes. all status cmdbuf have same size.
	u16 status_cmdbuf_unit_size;
	// reg regbuf pool virtual adress
	u32 *virt_vcmd_regbuf_addr;
	// reg regbuf pool base physical address
	addr_t phy_vcmd_regbuf_addr;
	// reg regbuf pool base mmu mapping address
	mmu_iova mmu_phy_vcmd_regbuf_addr;
	// reg regbuf pool total size in bytes.
	u32 vcmd_regbuf_total_size;
	//one reg regbuf size in bytes. all status cmdbuf have same size.
	u32 vcmd_regbuf_unit_size;
	/* for pcie interface, hw can only access
	 * phy_cmdbuf_addr-pcie_base_ddr_addr.
	 * for other interface, this value should be 0?
	 */
	addr_t base_ddr_addr;
};

struct config_parameter {
	/*input vce=0,cutree=1,vcd=2,jpege=3, jpegd=4 */
	u16 module_type;
	/* output, how many vcmd cores are there
	 * with corresponding module_type.
	 */
	u16 vcmd_core_num;
	/*output,if submodule addr == 0xffff, this submodule does not exist.*/
	u16 submodule_main_addr;
	/* output ,if submodule addr == 0xffff, this submodule does not exist.*/
	u16 submodule_dec400_addr;
	/* output,if submodule addr == 0xffff, this submodule does not exist. */
	u16 submodule_MMU_addr;
	/* output,if submodule addr == 0xffff, this submodule does not exist. */
	u16 submodule_MMUWrite_addr;
	/* output,if submodule addr == 0xffff, this submodule does not exist. */
	u16 submodule_axife_addr;
	u32 vcmd_hw_version_id;
};

/*need to consider how many memory should be allocated for status.*/
struct exchange_parameter {
	/* the instance ctx */
	void *owner;
	//input ;executing_time=encoded_image_size*(rdoLevel+1)*(rdoq+1);
	u64 executing_time;
	/*input input vce=0,IM=1,vcd=2, jpege=3, jpegd=4 */
	u16 module_type;
	/*input, reserve is not used; link and run is input.*/
	u16 cmdbuf_size;
	/* output, it is unique in driver.*/
	u16 cmdbuf_id;
	/* just used for polling. */
	u16 core_id;
	/* core_mask for user to select cores: [0,15]core mask, [16,31]client type. */
	u16 core_mask;
	/* input, bit[0]: priority    - normal=0, high/live=1
	 *        bit[1]: has_end_cmd - last cmd is JMP (0) or END (1) command
	 */
	u16 input_mask;
};

struct vcmd_priv_ctx {
	void *vcmd_mgr;
	/* process object */
	void *po;
};

enum {
	LOGLVL_VERBOSE = 0,		// log all
	LOGLVL_FLOW,			// log all debug msg
	LOGLVL_CONFIG,			// log ctrl/config info, mostly at beginning
	LOGLVL_BRIEF,			// log critical point
	LOGLVL_WARNING,			// log warning msg
	LOGLVL_ERROR,			// log error
};

#endif /* !_VC8000_VCMD_DRIVER_H_ */
