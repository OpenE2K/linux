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

#ifndef _HANTRO_VCMD_DBGFS_H
#define _HANTRO_VCMD_DBGFS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <linux/ioctl.h>
#include <linux/types.h>

/* for debugfs */
#define MAX_RESERVED_TIME 100
#define IDLE              0
#define RESERVED          1
#define DECODING          2
#define DONE              3
#define RECORD_N_HW_REGS  4

struct dev_dbgfs_info {
	u32 decode_cycles[MAX_RESERVED_TIME];
	int cycle_index;
	int num_cmdbuf_linked;
	u32 num_cmdbuf_exe[MAX_RESERVED_TIME];
	int exe_cmdbuf_index;
	u32 processed_cmdbuf_num;
	u32 num_cmdbuf_twoidle;
	u32 pre_hw_rdy_cmdbuf_num;
	u64 reserved_time[MAX_RESERVED_TIME];
	u32 reserved_cmdbufid[MAX_RESERVED_TIME];
	int reserved_index;
	u64 link_time[MAX_RESERVED_TIME];
	u32 link_cmdbufid[MAX_RESERVED_TIME];
	int link_index;
	u64 interrupt_time[MAX_RESERVED_TIME];
	int interrupt_index;
	u64 vcmd_workload;
	u64 active_start_time[MAX_RESERVED_TIME];
	u64 active_return_time[MAX_RESERVED_TIME];
	u32 active_hw_index;
	u32 active_state;
	u32 cmdbuf_num_done[MAX_RESERVED_TIME];
	u32 prev_cmdbuf_done[MAX_RESERVED_TIME];
	void *vcmd_mgr;
	void *dev;
	/* char *subsys_name =
	 * {"reg_subsys0", "reg_subsys1",
	 *  "reg_subsys2", "reg_subsys3"};
	 */
};

struct dbgfs_priv {
	struct dev_dbgfs_info *dev_dbgfs_info;
	u64 vcd_cycles;
	int N_reserved;
	/*dbgfs dentry pointer*/
	struct dentry *debugfs_root;
	struct dentry *root_cmdbuf[SLOT_NUM_CMDBUF];
};

int _dbgfs_init(void *vcmd_mgr);
void _dbgfs_init_ctx(void *vcmd_mgr, u32 store_hw_rdy_cmdbuf);
void _dbgfs_cleanup(void *_vcmd_mgr);
void _dbgfs_record_reserved_time(void *_dev_dbgfs, u32 cmdbuf_id);
void _dbgfs_record_link_time(void *_dev_dbgfs, u32 cmdbuf_id,
							u32 sw_cmdbuf_rdy_num, u64 exe_time);
void _dbgfs_record_active_start_time(void *_dev_dbgfs);
void _dbgfs_record_cmdbuf_num(void *_dev_dbgfs);
void _dbgfs_remove_cmdbuf(void *_dev_dbgfs, u32 cmdbuf_id);
void _dbgfs_reset_exe_cmdbuf_num(void *_dev_dbgfs);
void _dbgfs_record_vcd_cycles(void *_dev_dbgfs, u32 cmdbuf_id,
							  u32 module_type, u32 has_arbiter);
void _dbgfs_update_index(void *_dev_dbgfs);

#ifdef __cplusplus
}
#endif

#endif
