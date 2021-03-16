/*!
 *****************************************************************************
 *
 * @File       vxd_debugfs.h
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 *
 * The contents of this file are subject to the MIT license as set out below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above.
 *
 * If you wish to allow use of your version of this file only under the terms
 * of GPL, and not to allow others to use your version of this file under the
 * terms of the MIT license, indicate your decision by deleting the provisions
 * above and replace them with the notice and other provisions required by GPL
 * as set out in the file called "GPLHEADER" included in this distribution. If
 * you do not delete the provisions above, a recipient may use your version of
 * this file under the terms of either the MIT license or GPL.
 *
 * This License is also included in this distribution in the file called
 * "MIT_COPYING".
 *
 *****************************************************************************/

#ifndef VXD_DEBUGFS_H
#define VXD_DEBUGFS_H

#include <linux/debugfs.h>
#include <linux/kfifo.h>
#include <linux/mutex.h>

/* Max number of regions exported via debug fs */
#define DBGFS_REGIO_MAX 10

/* Number of regio dwords to dump in raw mode */
#define DBGFS_REGIO_RAW_DWORDS (64*1024)

/* Default values for MTX RAM dump */
#define DBGFS_DEFAULT_DWORDS_TO_DUMP 0x400
#define DBGFS_DEFAULT_OFFSET 0

/* Debug fs context */
struct vxd_dbgfs_ctx {
	/* /sys/kernel/debug entry */
	struct dentry *root_dir;

	wait_queue_head_t queue;

	/* Mtx fifo */
	struct {
		struct task_struct *reader;
		struct kfifo pipe;
		struct mutex lock;
		int attached;

	} mtx_fifo;

	/* Mtx Ram dump definition */
	int mtx_ram_dwords;
	int mtx_ram_offs;

	/* Pvdec region definition */
	struct debugfs_regset32 regio_set[VXD_MAX_PIPES][DBGFS_REGIO_MAX];

	/* MMU page table walk info */
	char *ptedump_buf;
	size_t ptedump_size;

	/* Custom firmware info */
	char *cfw_buf;
	size_t cfw_size;
	int cfw_ref;

};

int vxd_dbgfs_populate(struct vxd_dev *vxd, const char *root);
void vxd_dbgfs_cleanup(struct vxd_dev *vxd);
void vxd_dbgfs_wake(struct vxd_dev *vxd);
int vxd_dbgfs_wait(struct vxd_dev *vxd);
int vxd_dbgfs_request_fw(struct vxd_dev *vxd, const char *name,
		const struct firmware **fw);
int vxd_dbgfs_release_fw(struct vxd_dev *vxd, const struct firmware *fw);

#endif /* VXD_DEBUGFS_H */

/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
