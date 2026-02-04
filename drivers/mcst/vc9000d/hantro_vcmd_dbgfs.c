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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <asm/io.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/of_device.h>

#include <linux/debugfs.h>

#include "subsys.h"
#include "hantrovcmd_priv.h"
#include "hantrovcmddbgfs.h"

#define DBGFS_ROOT_DIR         dec_dev_n
#define DBGFS_HW_CYCLE_FILE    "hw_cycle"
#define DBGFS_PERFORMANCE_FILE "performance"
#define DBGFS_REGPRINT_FILE    "regprint"
#define DBGFS_VCD_MEM_REGS_FILE "vcd_mem_regs"

#define _GET_DBGFS_CTX(dev_dbgfs)                                 \
	((struct dbgfs_priv *)((vcmd_mgr_t *)dev_dbgfs->vcmd_mgr)->dbgfs_ctx)

static int _dbgfs_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private; // inode->i_private == vcmd_mgr
	return 0;
}

static void _dev_record_cycles(struct dev_dbgfs_info *dev_dbgfs, u32 intr_num,
			char *out)
{
	int i;
	char str[100];
	u32 index = dev_dbgfs->cycle_index;

	sprintf(str, "decode total cmdbuf cycles of recent N interruption\t\tinterrupt_time /ms\n");
	strcat(out, str);

	if (index >= intr_num)
		index -= intr_num;
	else
		index =  index + MAX_RESERVED_TIME - intr_num - 1;
	for (i = 0; i < intr_num; i++) {
		sprintf(str, "%u\t\t\t\t\t\t\t\t", dev_dbgfs->decode_cycles[index]);
		strcat(out, str);
		sprintf(str, "%llu\n", dev_dbgfs->interrupt_time[index]);
		strcat(out, str);

		index = (index + 1) % MAX_RESERVED_TIME;

	}
}

static void _dev_record_exe_cmdbuf(struct dev_dbgfs_info *dev_dbgfs,
			u32 intr_num, char *out)
{
	int i;
	char str[100];
	u32 index = dev_dbgfs->exe_cmdbuf_index;

	sprintf(str, "\ncmdbuffer executed number between recent N interrupt time\n");
	strcat(out, str);

	if (index >= intr_num)
		index -= intr_num;
	else
		index = index + MAX_RESERVED_TIME - intr_num - 1;
	for (i = 0; i < intr_num; i++) {
		sprintf(str, "%u\n", dev_dbgfs->num_cmdbuf_exe[index]);
		strcat(out, str);

		index = (index + 1) % MAX_RESERVED_TIME;
	}
}

static void _dev_record_reserved_cmdbuf(struct dev_dbgfs_info *dev_dbgfs,
			u32 intr_num, char *out)
{
	u32 index = dev_dbgfs->reserved_index;
	char str[100];
	int i;

	sprintf(str, "\ncmdbuf id\tcmdbuffer reserved time /ms\n");
	strcat(out, str);

	if (index >= intr_num)
		index -= intr_num;
	else
		index = index + MAX_RESERVED_TIME - intr_num - 1;
	for (i = 0; i < intr_num; i++) {
		sprintf(str, "%-4u\t\t", dev_dbgfs->reserved_cmdbufid[index]);
		strcat(out, str);
		sprintf(str, "%-25llu\n", dev_dbgfs->reserved_time[index]);
		strcat(out, str);

		index = (index + 1) % MAX_RESERVED_TIME;
	}
}

static void _dev_record_link_cmdbuf(struct dev_dbgfs_info *dev_dbgfs,
			u32 intr_num, char *out)
{
	u32 index = dev_dbgfs->link_index;
	u32 core_id = ((struct hantrovcmd_dev *)dev_dbgfs->dev)->core_id;
	char str[100];
	int i;

	sprintf(str, "\ncmdbuf id\tcore_id\t\t\tcmdbuffer link time /ms\t\t\t\n");
	strcat(out, str);

	if (index >= intr_num)
		index -= intr_num;
	else
		index = index + MAX_RESERVED_TIME - intr_num - 1;
	for (i = 0; i < intr_num; i++) {
		sprintf(str, "%-4u\t\t", dev_dbgfs->link_cmdbufid[index]);
		strcat(out, str);
		sprintf(str, "%-10u\t\t\t", core_id);
		strcat(out, str);
		sprintf(str, "%-10llu\t\t\n", dev_dbgfs->link_time[index]);
		strcat(out, str);

		index = (index + 1) % MAX_RESERVED_TIME;
	}
}

static void _dev_record_start_idle_time_and_done_cmdbuf(struct dev_dbgfs_info *dev_dbgfs,
			u32 intr_num, char *out)
{
	u32 core_id = ((struct hantrovcmd_dev *)dev_dbgfs->dev)->core_id;
	struct dev_dbgfs_info *dev_dbgfs0, *dev_dbgfs1;
	int subsys_num = ((vcmd_mgr_t *)dev_dbgfs->vcmd_mgr)->subsys_num;
	u32 index = dev_dbgfs->active_hw_index, tmp_index;
	u64 first_start_time = 0;
	char str[100];
	int i;

	sprintf(str, "\nVCMD\t\tstart time /ms\t\t\tidle time /ms\t\t\tcmdbuf num\t\t\n");
	strcat(out, str);

	if (index >= intr_num) {
		index -= intr_num;
		tmp_index = index;
		/* will record from index - n, ..., index - 1
		 */
	} else {
		index = index + MAX_RESERVED_TIME - intr_num - 1;
		tmp_index = 0;
		/* will record from index + MAX_RESERVED_TIME - intr_num - 1,
		 *  index + MAX_RESERVED_TIME - intr_num, MAX_RESERVED_TIME - 1, ... ,
		 *  0, ... , index - 1
		 */
	}
	dev_dbgfs0 = dev_dbgfs - core_id;
	if (subsys_num > 1) {
		dev_dbgfs1 = dev_dbgfs - core_id + 1;
		if (dev_dbgfs0->active_start_time[tmp_index] >
			dev_dbgfs1->active_start_time[tmp_index])
			first_start_time = dev_dbgfs1->active_start_time[tmp_index];
	} else {
		first_start_time = dev_dbgfs0->active_start_time[tmp_index];
	}
	for (i = 0; i < intr_num; i++) {
		sprintf(str, "%-4u\t\t", core_id);
		strcat(out, str);
		sprintf(str, "%-10llu\t\t\t", dev_dbgfs[core_id].active_start_time[index] ?
			dev_dbgfs[core_id].active_start_time[index] - first_start_time : 0);
		strcat(out, str);
		sprintf(str, "%-10llu\t\t\t", dev_dbgfs[core_id].active_return_time[index] ?
			dev_dbgfs[core_id].active_return_time[index] - first_start_time : 0);
		strcat(out, str);
		sprintf(str, "%u\t\t\n", dev_dbgfs[core_id].cmdbuf_num_done[index]);
		strcat(out, str);

		index = (index + 1) % MAX_RESERVED_TIME;
	}
}

static void _dev_record_vcmd_workload(struct dev_dbgfs_info *dev_dbgfs, char *out)
{
	char str[100];

	sprintf(str, "\nvcmd workload: %llu\n", dev_dbgfs->vcmd_workload);
	strcat(out, str);
}

static void _dev_record_linked_and_processed_cmdbuf(
			struct dev_dbgfs_info *dev_dbgfs, char *out)
{
	u32 hw_rdy_cmdbuf_num;
	char str[100];
	struct hantrovcmd_dev *dev = (struct hantrovcmd_dev *)dev_dbgfs->dev;

	hw_rdy_cmdbuf_num = ioread32((void __iomem *)(dev->hwregs + 3 * 4));
		sprintf(str, "\nthe number of cmdbuffer linked: %u\n",
			dev->sw_cmdbuf_rdy_num);
		strcat(out, str);
		if (dev->sw_cmdbuf_rdy_num - hw_rdy_cmdbuf_num)
			sprintf(str, "\nVCD state: decoding\n");
		else
			sprintf(str, "\nVCD state: idle\n");

		strcat(out, str);
		sprintf(str, "\nnumber of unprocessed cmdbuf remaining: %u\n",
			dev->sw_cmdbuf_rdy_num - hw_rdy_cmdbuf_num);
		strcat(out, str);
		sprintf(str, "\nnumber of processed cmdbuf between latest two idle time:%u\n",
			dev_dbgfs->num_cmdbuf_twoidle);
		strcat(out, str);

}

/* debugfs for VCD cycles */
static ssize_t vcd_cycles_read(struct file *file, char __user *user_buf,
			size_t count, loff_t *ppos)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)file->private_data;
	struct dev_dbgfs_info *dev_dbgfs;
	int subsys_num = vcmd_mgr->subsys_num;
	char v[100], *t;
	int j, ret;
	int N_reserved = ((struct dbgfs_priv *)vcmd_mgr->dbgfs_ctx)->N_reserved;

	t = kzalloc(N_reserved * 1500 * subsys_num, GFP_KERNEL);
	for (j = 0; j < subsys_num; j++) {
		dev_dbgfs = &((struct dbgfs_priv *)vcmd_mgr->dbgfs_ctx)->dev_dbgfs_info[j];
		sprintf(v, "vcmdcore[%d]\n", j);
		strcat(t, v);
		sprintf(v, "********************************************************************************\n");
		strcat(t, v);

		_dev_record_cycles(dev_dbgfs, N_reserved, t);
		_dev_record_exe_cmdbuf(dev_dbgfs, N_reserved, t);
		_dev_record_reserved_cmdbuf(dev_dbgfs, N_reserved * 2, t);
		_dev_record_link_cmdbuf(dev_dbgfs, N_reserved, t);
		_dev_record_start_idle_time_and_done_cmdbuf(dev_dbgfs, N_reserved, t);
		_dev_record_vcmd_workload(dev_dbgfs,  t);
		_dev_record_linked_and_processed_cmdbuf(dev_dbgfs, t);

		sprintf(v, "********************************************************************************\n\n");
		strcat(t, v);
	}

	ret = simple_read_from_buffer(user_buf, count, ppos, t, strlen(t));
	kfree(t);
	return ret;
}

static ssize_t vcd_cycles_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)file->private_data;
	struct dbgfs_priv *dbgfs_ctx = vcmd_mgr->dbgfs_ctx;
	char In_fo[10];
	int ret;

	simple_write_to_buffer(In_fo, count, ppos, user_buf, 4);
	ret = kstrtoint(In_fo, 10, &dbgfs_ctx->N_reserved);
	if (ret)
		return ret;

	return count;
}

const struct file_operations fileop_N_vcd_cycles = {
	.write = vcd_cycles_write,
	.read = vcd_cycles_read,
	.open = _dbgfs_open,
};

extern void _dbg_log_instr(u32 offset, u32 instr, u32 *size, char *str);

static ssize_t cmdbuf_parse(struct file *file, char __user *user_buf,
				size_t count, loff_t *ppos)
{
	vcmd_mgr_t *vcmd_mgr_dbgfs = (vcmd_mgr_t *)file->private_data;
	u16 cmdbuf_id = 0;
	char *v0, *v1;
	int ret, i, b = 0, pow = 1, j;
	struct cmdbuf_obj *cmdbuf_obj = NULL;
	bi_list_node *new_cmdbuf_node = NULL;
	char *v = file->f_path.dentry->d_iname;
	u32 inst = 0, size = 0;

	for (i = 0; i < strlen(v); i++) {
		b = v[i] - '0';
		pow = 1;
		for (j = 0; j < i; j++)
			pow *= 10;
		b *= pow;
		cmdbuf_id += b;
	}
	new_cmdbuf_node = &vcmd_mgr_dbgfs->nodes[cmdbuf_id];
	v0 = kzalloc(50000, GFP_KERNEL);
	v1 = kzalloc(1500, GFP_KERNEL);
	if (!new_cmdbuf_node) {
		//should not happen
		sprintf(v0, "%s", DRIVER_NAME "_vcmd: ERROR cmdbuf_id !!\n");
		ret = simple_read_from_buffer(user_buf, count, ppos, v0, strlen(v0));
		kfree(v0);
		kfree(v1);
		return ret;
	}
	cmdbuf_obj = (struct cmdbuf_obj *)new_cmdbuf_node->data;

	sprintf(v1, "%s", "vcmd link, current cmdbuf content\n");
	strcat(v0, v1);
	for (i = 0; i < cmdbuf_obj->cmdbuf_size / 4; i++) {
		if (i == inst) {
			_dbg_log_instr(i, *(cmdbuf_obj->cmd_va + i), &size, v1);
			strcat(v0, v1);
			inst += size;
		} else {
			sprintf(v1, "current cmdbuf data %d = 0x%x\n", i, *(cmdbuf_obj->cmd_va + i));
			strcat(v0, v1);
		}
	}
	ret = simple_read_from_buffer(user_buf, count, ppos, v0, strlen(v0));
	kfree(v0);
	kfree(v1);
	return ret;
}

const struct file_operations cmdbuf_op = {
	.read = cmdbuf_parse,
	.open = _dbgfs_open,
};

static void _dev_record_hw_regs(volatile u8 *hwregs, u32 reg_num, u32 *start,
			char *out)
{
	int swreg_mes, i;
	u32 j = *start;
	char str[50];

	if (!hwregs)
		return;

	for (i = 0; i < reg_num; i++) {
		swreg_mes = ioread32((void __iomem *)(hwregs + j * 4));
		if ((j & 3) == 0)
			sprintf(str, "%04x: %08x ", j * 4, swreg_mes);
		else
			sprintf(str, "%08x ", swreg_mes);
		strcat(out, str);
		j++;
	}
	strcat(out, "\n");
	*start = j;
}

static void _dev_record_hw_regs_vcmd_mem_regs(u32 *hwregs_copy, u32 reg_num, u32 *start,
			char *out)
{
	int swreg_mes, i;
	u32 j = *start;
	char str[50];

	if (!hwregs_copy)
		return;

	for (i = 0; i < reg_num; i++) {
		swreg_mes = hwregs_copy[j];
		if ((j & 3) == 0)
			sprintf(str, "%04x: %08x ", j * 4, swreg_mes);
		else
			sprintf(str, "%08x ", swreg_mes);
		strcat(out, str);
		j++;
	}
	strcat(out, "\n");
	*start = j;
}


static ssize_t hw_register_print(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	char *v0, v1[50];
	int j, i, ret, num_regs = 0;
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)file->private_data;
	struct hantrovcmd_dev *dev = vcmd_mgr->dev_ctx;
	int subsys_num = vcmd_mgr->subsys_num;

	volatile u8 *hwregs;

	u32 record_num = RECORD_N_HW_REGS;

	for (i = 0; i < subsys_num; i++) {
		for (j = 0; j < SUB_MOD_MAX; j++)
			num_regs += dev[i].subsys_info->io_size[j];
	}
	num_regs /= 4;

	v0 = kzalloc(70 * num_regs, GFP_KERNEL);

	for (i = 0; i < subsys_num; i++) {
		sprintf(v1, "vcmdcore[%d]\n", i);
		strcat(v0, v1);
		num_regs = dev[0].subsys_info->io_size[SUB_MOD_VCMD] / 4;
		hwregs = dev[i].hwregs;
		for (j = 0; j < num_regs;) {
			if (num_regs - j < record_num)
				record_num = num_regs - j;
			_dev_record_hw_regs(hwregs, record_num, &j, v0);
		}

		num_regs = dev[i].subsys_info->io_size[SUB_MOD_MAIN] / 4;
		hwregs = dev[i].subsys_info->hwregs[SUB_MOD_MAIN];
		record_num = RECORD_N_HW_REGS;
		if (num_regs) {
			sprintf(v1, "[VCD]\n");
			strcat(v0, v1);
			for (j = 0; j < num_regs;) {
				if (MAX_REG_COUNT - j < record_num)
					record_num = MAX_REG_COUNT - j;
				_dev_record_hw_regs(hwregs, record_num, &j, v0);
			}
		}

		num_regs = dev[i].subsys_info->io_size[SUB_MOD_DEC400] / 4;
		hwregs = dev[i].subsys_info->hwregs[SUB_MOD_DEC400];
		record_num = RECORD_N_HW_REGS;
		if (num_regs) {
			sprintf(v1, "[DEC400]\n");
			strcat(v0, v1);
			for (j = 0; j < num_regs;) {
				if (num_regs - j < record_num)
					record_num = num_regs - j;
				_dev_record_hw_regs(hwregs, record_num, &j, v0);
			}
		}

		num_regs = dev[i].subsys_info->io_size[SUB_MOD_MMU] / 4;
		hwregs = dev[i].subsys_info->hwregs[SUB_MOD_MMU];
		record_num = RECORD_N_HW_REGS;
		if (num_regs) {
			sprintf(v1, "[MMU]\n");
			strcat(v0, v1);
			for (j = 0; j < num_regs;) {
				if (num_regs - j < record_num)
					record_num = num_regs - j;
				_dev_record_hw_regs(hwregs, record_num, &j, v0);
			}
		}
	}
	ret = simple_read_from_buffer(user_buf, count, ppos, v0, strlen(v0));
	kfree(v0);

	return ret;
}

static ssize_t hw_vcd_mem_regs_print(struct file *file, char __user *user_buf, size_t count,
				     loff_t *ppos)
{
	char *v0, v1[50];
	int j, i, ret, num_regs = 0;
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)file->private_data;
	struct hantrovcmd_dev *dev = vcmd_mgr->dev_ctx;
	int subsys_num = vcmd_mgr->subsys_num;

	u32 *hwregs_copy;

	u32 record_num = RECORD_N_HW_REGS;

	for (i = 0; i < subsys_num; i++) {
		for (j = 0; j < SUB_MOD_MAX; j++)
			num_regs += dev[i].subsys_info->io_size[j];
	}
	num_regs /= 4;

	v0 = kzalloc(70 * num_regs, GFP_KERNEL);

	for (i = 0; i < subsys_num; i++) {
		num_regs = dev[i].subsys_info->io_size[SUB_MOD_MAIN] / 4;
		hwregs_copy = vcmd_mgr->mem_regs.va +
				dev[i].subsys_info->reg_off[SUB_MOD_MAIN]/4 +
				(i * SLOT_SIZE_REGBUF) / 4;

		record_num = RECORD_N_HW_REGS;
		if (num_regs) {
			sprintf(v1, "[VCD]\n");
			strcat(v0, v1);
			for (j = 0; j < num_regs;) {
				if (MAX_REG_COUNT - j < record_num)
					record_num = MAX_REG_COUNT - j;
				_dev_record_hw_regs_vcmd_mem_regs(hwregs_copy, record_num, &j, v0);
			}
		}
	}
	ret = simple_read_from_buffer(user_buf, count, ppos, v0, strlen(v0));
	kfree(v0);

	return ret;
}

const struct file_operations fileop_vcmd_reg_print = {
	.read = hw_register_print,
	.open = _dbgfs_open,
};
const struct file_operations fileop_vcd_mem_regs_print = {
	.read = hw_vcd_mem_regs_print,
	.open = _dbgfs_open,
};

static u64 _dgbfs_get_time(void)
{
	u64 time_val = 0;
#if (KERNEL_VERSION(4, 19, 94) > LINUX_VERSION_CODE)
	struct timeval time_now;

	do_gettimeofday(&time_now);
	time_val = time_now.tv_sec * 1000 + time_now.tv_usec / 1000;
#else
	struct timespec64 time_now;

	ktime_get_real_ts64(&time_now);
	time_val = time_now.tv_sec * 1000 + time_now.tv_nsec / 1000000;
#endif

	return time_val;
}

void _dbgfs_record_reserved_time(void *_dev_dbgfs, u32 cmdbuf_id)
{
	u64 time_val = 0;
	struct dev_dbgfs_info *dev_dbgfs = (struct dev_dbgfs_info *)_dev_dbgfs;
	int r_index = dev_dbgfs->reserved_index;

	time_val = _dgbfs_get_time();
	dev_dbgfs->reserved_time[r_index] = time_val;
	dev_dbgfs->reserved_cmdbufid[r_index] = cmdbuf_id;
	dev_dbgfs->reserved_index = (r_index + 1) % MAX_RESERVED_TIME;
}

void _dbgfs_record_link_time(void *_dev_dbgfs, u32 cmdbuf_id,
							u32 sw_cmdbuf_rdy_num, u64 exe_time)
{
	u64 time_val = 0;
	u32 hw_rdy_cmdbuf_num = 0;
	char v[5];
	struct dev_dbgfs_info *dev_dbgfs = (struct dev_dbgfs_info *)_dev_dbgfs;
	struct hantrovcmd_dev *dev = (struct hantrovcmd_dev *)dev_dbgfs->dev;
	struct dbgfs_priv *dbgfs_ctx = _GET_DBGFS_CTX(dev_dbgfs);
	int l_index = dev_dbgfs->link_index;

	time_val = _dgbfs_get_time();
	hw_rdy_cmdbuf_num =
		ioread32((void __iomem *)(dev->hwregs + 3 * 4));
	dev_dbgfs->num_cmdbuf_linked = sw_cmdbuf_rdy_num - hw_rdy_cmdbuf_num;

	sprintf(v, "%u", cmdbuf_id);
	dbgfs_ctx->root_cmdbuf[cmdbuf_id] = debugfs_create_file(v, 0444,
		dbgfs_ctx->debugfs_root, dev_dbgfs->vcmd_mgr, &cmdbuf_op);

	dev_dbgfs->link_time[l_index] = time_val;
	dev_dbgfs->link_cmdbufid[l_index] = cmdbuf_id;
	dev_dbgfs->vcmd_workload += exe_time;
	dev_dbgfs->link_index = (l_index + 1) % MAX_RESERVED_TIME;
}

void _dbgfs_record_active_start_time(void *_dev_dbgfs)
{
	u64 time_val = 0;
	struct dev_dbgfs_info *dev_dbgfs = (struct dev_dbgfs_info *)_dev_dbgfs;

	if (dev_dbgfs->active_state == 0) {
		time_val = _dgbfs_get_time();
		dev_dbgfs->active_start_time[dev_dbgfs->active_hw_index] = time_val;
		dev_dbgfs->active_state = 1;
		dev_dbgfs->active_hw_index %= MAX_RESERVED_TIME;
	}
}

int _dbgfs_init(void *_vcmd_mgr)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	struct dev_dbgfs_info *dev_dbgfs_info;
	struct dbgfs_priv *dbgfs_ctx;
	int i;

	dbgfs_ctx = vmalloc(sizeof(struct dbgfs_priv));
	if (!dbgfs_ctx)
		return -1;
	memset(dbgfs_ctx, 0, sizeof(struct dbgfs_priv));

	dev_dbgfs_info =
		vmalloc(sizeof(struct dev_dbgfs_info) * vcmd_mgr->subsys_num);
	if (!dev_dbgfs_info)
		goto err;
	memset(dev_dbgfs_info, 0,
		sizeof(struct dev_dbgfs_info) * vcmd_mgr->subsys_num);

	dbgfs_ctx->dev_dbgfs_info = dev_dbgfs_info;
	dbgfs_ctx->N_reserved = 10;
	dbgfs_ctx->vcd_cycles = 0;
	vcmd_mgr->dbgfs_ctx = (void *)dbgfs_ctx;
	for (i = 0; i < vcmd_mgr->subsys_num; i++) {
		dev_dbgfs_info[i].dev = (void *)&vcmd_mgr->dev_ctx[i];
		dev_dbgfs_info[i].vcmd_mgr = (void *)vcmd_mgr;
		vcmd_mgr->dev_ctx[i].dbgfs_info = (void *)&dev_dbgfs_info[i];
	}

	dbgfs_ctx->debugfs_root = debugfs_create_dir(DBGFS_ROOT_DIR, NULL);
	if (!dbgfs_ctx->debugfs_root)
		goto err;
	/* if has apb_arbiter */
	debugfs_create_u64(DBGFS_HW_CYCLE_FILE, 0644, dbgfs_ctx->debugfs_root,
		&dbgfs_ctx->vcd_cycles);
	/* will assign vcmd_mgr to inode->i_private */
	debugfs_create_file(DBGFS_PERFORMANCE_FILE, 0444, dbgfs_ctx->debugfs_root,
		(void *)vcmd_mgr, &fileop_N_vcd_cycles);
	debugfs_create_file(DBGFS_REGPRINT_FILE, 0444, dbgfs_ctx->debugfs_root,
		(void *)vcmd_mgr, &fileop_vcmd_reg_print);
	debugfs_create_file(DBGFS_VCD_MEM_REGS_FILE, 0444, dbgfs_ctx->debugfs_root,
		(void *)vcmd_mgr, &fileop_vcd_mem_regs_print);

	return 0;
err:
	if (dbgfs_ctx) {
		vfree(dbgfs_ctx);
		dbgfs_ctx = NULL;
	}
	if (dev_dbgfs_info) {
		vfree(dev_dbgfs_info);
		dev_dbgfs_info = NULL;
	}
	return -1;
}

void _dbgfs_init_ctx(void *_vcmd_mgr, u32 store_hw_rdy_cmdbuf)
{
	u32 hw_rdy_cmdbuf_num = 0;
	u32 i, k;
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	u32 subsys_num = vcmd_mgr->subsys_num;
	struct dev_dbgfs_info *dev_dbgfs =
		((struct dbgfs_priv *)vcmd_mgr->dbgfs_ctx)->dev_dbgfs_info;
	struct hantrovcmd_dev *dev = vcmd_mgr->dev_ctx;

	for (i = 0; i < subsys_num; i++) {
		dev_dbgfs[i].cycle_index = 0;
		dev_dbgfs[i].exe_cmdbuf_index = 0;
		dev_dbgfs[i].reserved_index = 0;
		dev_dbgfs[i].link_index = 0;
		dev_dbgfs[i].interrupt_index = 0;
		dev_dbgfs[i].num_cmdbuf_linked = 0;
		dev_dbgfs[i].vcmd_workload = 0;
		dev_dbgfs[i].active_hw_index = 0;
		dev_dbgfs[i].active_state = 0;

		for (k = 0; k < MAX_RESERVED_TIME; k++) {
			dev_dbgfs[i].decode_cycles[k] = 0;
			dev_dbgfs[i].num_cmdbuf_exe[k] = 0;
			dev_dbgfs[i].reserved_time[k] = 0;
			dev_dbgfs[i].reserved_cmdbufid[k] = 0;
			dev_dbgfs[i].link_time[k] = 0;
			dev_dbgfs[i].link_cmdbufid[k] = 0;
			dev_dbgfs[i].interrupt_time[k] = 0;
			dev_dbgfs[i].active_start_time[k] = 0;
			dev_dbgfs[i].active_return_time[k] = 0;
			dev_dbgfs[i].cmdbuf_num_done[k] = 0;
			dev_dbgfs[i].prev_cmdbuf_done[k] = 0;
		}
		if (store_hw_rdy_cmdbuf) {
			hw_rdy_cmdbuf_num =
				ioread32((void __iomem *)(dev[i].hwregs + 3 * 4));
			dev_dbgfs[i].prev_cmdbuf_done[0] = hw_rdy_cmdbuf_num;
		} else {
			dev_dbgfs[i].num_cmdbuf_twoidle = 0;
			dev_dbgfs[i].pre_hw_rdy_cmdbuf_num = 0;
		}
	}
}

void _dbgfs_cleanup(void *_vcmd_mgr)
{
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)_vcmd_mgr;
	struct dbgfs_priv *dbgfs_ctx = vcmd_mgr->dbgfs_ctx;

	debugfs_remove_recursive(dbgfs_ctx->debugfs_root);
	dbgfs_ctx->debugfs_root = NULL;
	if (dbgfs_ctx->dev_dbgfs_info) {
		vfree(dbgfs_ctx->dev_dbgfs_info);
		dbgfs_ctx->dev_dbgfs_info = NULL;
	}
	if (vcmd_mgr->dbgfs_ctx) {
		vfree(vcmd_mgr->dbgfs_ctx);
		vcmd_mgr->dbgfs_ctx = NULL;
	};
}

void _dbgfs_record_cmdbuf_num(void *_dev_dbgfs)
{
	u32 hw_rdy_cmdbuf_num = 0;
	u64 time_val = 0;
	u32 index;
	struct dev_dbgfs_info *dev_dbgfs = (struct dev_dbgfs_info *)_dev_dbgfs;
	struct hantrovcmd_dev *dev = (struct hantrovcmd_dev *)dev_dbgfs->dev;

	if (dev->hw_version_id <= HW_ID_1_0_C)
		hw_rdy_cmdbuf_num = vcmd_get_register_value(
			(const void *)dev->hwregs, dev->reg_mirror,
			HWIF_VCMD_EXE_CMDBUF_COUNT);
	else {
		hw_rdy_cmdbuf_num = *(dev->reg_mem_va + REG_ID_CMDBUF_EXE_CNT);
		if (hw_rdy_cmdbuf_num != dev->sw_cmdbuf_rdy_num)
			hw_rdy_cmdbuf_num += 1;
	}

	index = dev_dbgfs->active_hw_index;

	if ((dev_dbgfs->active_state == 1) &&
		(dev->sw_cmdbuf_rdy_num == hw_rdy_cmdbuf_num)) {
		if (vcmd_get_register_value(
					(const void *)dev->hwregs, dev->reg_mirror,
					HWIF_VCMD_IRQ_JMP)) {
			time_val = _dgbfs_get_time();
			dev_dbgfs->active_return_time[index] = time_val;
			dev_dbgfs->cmdbuf_num_done[index] =
				hw_rdy_cmdbuf_num - dev_dbgfs->prev_cmdbuf_done[index];

			dev_dbgfs->active_hw_index = (index + 1) % MAX_RESERVED_TIME;
			dev_dbgfs->active_state = 0;
			dev_dbgfs->prev_cmdbuf_done[index] = hw_rdy_cmdbuf_num;
		}

		dev_dbgfs->num_cmdbuf_twoidle = hw_rdy_cmdbuf_num -
			dev_dbgfs->pre_hw_rdy_cmdbuf_num;
		dev_dbgfs->pre_hw_rdy_cmdbuf_num = hw_rdy_cmdbuf_num;
	}
}

void _dbgfs_reset_exe_cmdbuf_num(void *_dev_dbgfs)
{
	struct dev_dbgfs_info *dev_dbgfs = (struct dev_dbgfs_info *)_dev_dbgfs;

	dev_dbgfs->processed_cmdbuf_num = 0;
}

void _dbgfs_remove_cmdbuf(void *_dev_dbgfs, u32 cmdbuf_id)
{
	struct dev_dbgfs_info *dev_dbgfs = (struct dev_dbgfs_info *)_dev_dbgfs;
	struct dbgfs_priv *dbgfs_ctx = _GET_DBGFS_CTX(dev_dbgfs);

	debugfs_remove(dbgfs_ctx->root_cmdbuf[cmdbuf_id]);
	dbgfs_ctx->root_cmdbuf[cmdbuf_id] = NULL;
}

void _dbgfs_record_vcd_cycles(void *_dev_dbgfs, u32 cmdbuf_id,
		u32 module_type, u32 has_arbiter)
{
	struct dev_dbgfs_info *dev_dbgfs = (struct dev_dbgfs_info *)_dev_dbgfs;
	vcmd_mgr_t *vcmd_mgr = (vcmd_mgr_t *)dev_dbgfs->vcmd_mgr;
	u32 *status_va = NULL;
	u64 time_val = 0;
	struct vcmd_subsys_info *subsys;
	int e_index = dev_dbgfs->exe_cmdbuf_index;
	int i_index = dev_dbgfs->interrupt_index;
	int c_index = dev_dbgfs->cycle_index;

	dev_dbgfs->processed_cmdbuf_num++;
	dev_dbgfs->num_cmdbuf_exe[e_index] = dev_dbgfs->processed_cmdbuf_num;
	dev_dbgfs->exe_cmdbuf_index = (e_index + 1) % MAX_RESERVED_TIME;

	subsys = vcmd_mgr->module_mgr[module_type].dev[0]->subsys_info;
	status_va = vcmd_mgr->mem_status.va + STATUSBUF_OFF_32(cmdbuf_id);
	status_va = (u32 *)((u8 *)status_va + (subsys->reg_off[SUB_MOD_MAIN] / 2 + 0));

	if (*(status_va + 1)) {
		time_val = _dgbfs_get_time();
		dev_dbgfs->interrupt_time[i_index] = time_val;
		/* in dwlenablecmdbuf just config 8 rreg cmd, corresponding to
		 * 8 status buffers, and read status[5] for vcd cycles
		 */
		dev_dbgfs->decode_cycles[c_index] += *(status_va + 5);
	}
	if (has_arbiter) {
		if (*(status_va + 1))
			((struct dbgfs_priv *)vcmd_mgr->dbgfs_ctx)->vcd_cycles += *(status_va + 5);
	}
}

void _dbgfs_update_index(void *_dev_dbgfs)
{
	struct dev_dbgfs_info *dev_dbgfs = (struct dev_dbgfs_info *)_dev_dbgfs;

	dev_dbgfs->interrupt_index =
		(dev_dbgfs->interrupt_index + 1) % MAX_RESERVED_TIME;
	dev_dbgfs->cycle_index = (dev_dbgfs->cycle_index + 1) % MAX_RESERVED_TIME;
}
