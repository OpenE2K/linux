/*
 * Copyright (c) 2015, Verisilicon Inc. - All Rights Reserved
 *
 * This software is dual licensed, either GPL-2.0 or BSD-3-Clause, at your
 * option.
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

#ifndef _HANTRODEC_H_
#define _HANTRODEC_H_

#define DRIVER_NAME "vc9000d"

#include <linux/ioctl.h>
#include <linux/types.h>
#ifdef SUPPORT_MMU
#include "hantrommu.h"
#endif
#include "hantrovcmd.h"

enum CoreType {
	/* Decoder */
	HW_VCD = 0,
	HW_VCDJ,
	HW_BIGOCEAN,
	HW_VCMD,
	HW_MMU, //if set HW_MMU_WR, then HW_MMU means HW_MMU_RD
	HW_MMU_WR,
	HW_DEC400,
	/* Encoder*/
	/* Auxiliary IPs */
	HW_AXIFE,
	HW_AFBC,
	HW_ARB,
	HW_AXI2TO1,
	HW_CORE_MAX /* max number of cores supported */
};

struct core_desc {
	__u32 id; /* id of the subsystem */
	__u32 type; /* type of core to be written */
	__u32 *regs; /* pointer to user registers */
	__u32 size; /* size of register space */
	__u32 reg_id; /* id of reigster to be read/written */
};

struct regsize_desc {
	__u32 slice; /* id of the slice */
	__u32 id; /* id of the subsystem */
	__u32 type; /* type of core to be written */
	__u32 size; /* iosize of the core */
};

struct core_param {
	__u32 slice; /* id of the slice */
	__u32 id; /* id of the subsystem */
	__u32 type; /* type of core to be written */
	__u32 size; /* iosize of the core */
	__u32 asic_id; /* asic id of the core */
};

struct subsys_desc {
	__u32 subsys_num; /* total subsystems count */
	__u32 subsys_vcmd_num; /* subsystems with vcmd */
};

struct axife_cfg {
	__u8 axi_rd_chn_num;
	__u8 axi_wr_chn_num;
	__u8 axi_rd_burst_length;
	__u8 axi_wr_burst_length;
	__u8 fe_mode;
	__u32 id;
};

struct apbfilter_cfg {
	__u32 nbr_mask_regs;
	__u32 mask_reg_offset;
	__u32 page_sel_addr;
	__u8 num_mode;
	__u8 mask_bits_per_reg;
	__u32 id; /* id of the subsystem */
	__u32 type; /* type of core to be written */
	__u32 has_apbfilter;
};

#define ANY_ID ANY_CMDBUF_ID

struct reg_desc {
	__u32 reg_id; //id of the register
	__u32 reg_data; // data of register
};

#define STORE_REGS_NUM     16
struct subsys_regs_desc {
	__u32 id; /* id of the subsystem */
	__u32 reg_num; /* num of reg to access */
	/* store some user registers id and data */
	struct reg_desc regs[STORE_REGS_NUM];
};

struct req_core_info {
	__u32 format;
	void *dec_inst;
};

/* Use 'k' as magic number */
#define HANTRODEC_IOC_MAGIC 'k'

/*
 * S means "Set" through a ptr,
 * T means "Tell" directly with the argument value
 * G means "Get": reply by setting through a pointer
 * Q means "Query": response is on the return value
 * X means "eXchange": G and S atomically
 * H means "sHift": T and Q atomically
 */

#define HANTRODEC_PP_INSTANCE       _IO(HANTRODEC_IOC_MAGIC, 1)
#define HANTRODEC_HW_PERFORMANCE    _IO(HANTRODEC_IOC_MAGIC, 2)
#define HANTRODEC_IOCGHWOFFSET _IOR(HANTRODEC_IOC_MAGIC, 3, unsigned long *)
#define HANTRODEC_IOCGHWIOSIZE                                                 \
	_IOR(HANTRODEC_IOC_MAGIC, 4, struct regsize_desc *)

#define HANTRODEC_IOC_CLI _IO(HANTRODEC_IOC_MAGIC, 5)
#define HANTRODEC_IOC_STI _IO(HANTRODEC_IOC_MAGIC, 6)
#define HANTRODEC_IOC_MC_OFFSETS _IOR(HANTRODEC_IOC_MAGIC, 7, unsigned long *)
#define HANTRODEC_IOC_MC_CORES _IOR(HANTRODEC_IOC_MAGIC, 8, unsigned int *)

#define HANTRODEC_IOCS_DEC_PUSH_REG                                            \
	_IOW(HANTRODEC_IOC_MAGIC, 9, struct core_desc *)
#define HANTRODEC_IOCS_PP_PUSH_REG                                             \
	_IOW(HANTRODEC_IOC_MAGIC, 10, struct core_desc *)

#define HANTRODEC_IOCH_DEC_RESERVE _IOR(HANTRODEC_IOC_MAGIC, 11, struct req_core_info *)
#define HANTRODEC_IOCT_DEC_RELEASE _IO(HANTRODEC_IOC_MAGIC, 12)
#define HANTRODEC_IOCQ_PP_RESERVE _IO(HANTRODEC_IOC_MAGIC, 13)
#define HANTRODEC_IOCT_PP_RELEASE _IO(HANTRODEC_IOC_MAGIC, 14)

#define HANTRODEC_IOCX_DEC_WAIT                                                \
	_IOWR(HANTRODEC_IOC_MAGIC, 15, struct core_desc *)
#define HANTRODEC_IOCX_PP_WAIT                                                 \
	_IOWR(HANTRODEC_IOC_MAGIC, 16, struct core_desc *)

#define HANTRODEC_IOCS_DEC_PULL_REG                                            \
	_IOWR(HANTRODEC_IOC_MAGIC, 17, struct core_desc *)
#define HANTRODEC_IOCS_PP_PULL_REG                                             \
	_IOWR(HANTRODEC_IOC_MAGIC, 18, struct core_desc *)

#define HANTRODEC_IOCG_CORE_WAIT _IOR(HANTRODEC_IOC_MAGIC, 19, int *)

#define HANTRODEC_IOX_ASIC_ID                                                  \
	_IOWR(HANTRODEC_IOC_MAGIC, 20, struct core_param *)

#define HANTRODEC_IOCG_CORE_ID _IOR(HANTRODEC_IOC_MAGIC, 21, unsigned long)

#define HANTRODEC_IOCS_DEC_WRITE_REG                                           \
	_IOW(HANTRODEC_IOC_MAGIC, 22, struct core_desc *)

#define HANTRODEC_IOCS_DEC_READ_REG                                            \
	_IOWR(HANTRODEC_IOC_MAGIC, 23, struct core_desc *)

#define HANTRODEC_IOX_ASIC_BUILD_ID _IOWR(HANTRODEC_IOC_MAGIC, 24, __u32 *)

#define HANTRODEC_IOX_SUBSYS                                                   \
	_IOWR(HANTRODEC_IOC_MAGIC, 25, struct subsys_desc *)

#define HANTRODEC_IOCX_POLL _IO(HANTRODEC_IOC_MAGIC, 26)

#define HANTRODEC_IOX_GHW_PCI_POS                                              \
        _IOWR(HANTRODEC_IOC_MAGIC, 28, __u32 *)

#define HANTRODEC_DEBUG_STATUS _IO(HANTRODEC_IOC_MAGIC, 29)

#define HANTRODEC_IOCS_DEC_WRITE_APBFILTER_REG                                 \
	_IOW(HANTRODEC_IOC_MAGIC, 30, struct core_desc *)

#define HANTRODEC_IOC_APBFILTER_CONFIG                                         \
	_IOR(HANTRODEC_IOC_MAGIC, 31, struct apbfilter_cfg *)

#define HANTRODEC_IOC_AXIFE_CONFIG                                             \
	_IOR(HANTRODEC_IOC_MAGIC, 32, struct axife_cfg *)

#define HANTRODEC_IOCH_WAIT_OWNER_DONE                                             \
	_IOR(HANTRODEC_IOC_MAGIC, 33, void *)

#define HANTRODEC_IOC_MAXNR 33

#endif /* !_HANTRODEC_H_ */
