/*!
 *****************************************************************************
 *
 * @File       vxekm_debug.c
 * @Title      Kernel module debugging features
 * @Description    Kernel module debugging features
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

#ifndef _VXE_KM_DEBUG_C_
#define _VXE_KM_DEBUG_C_

#include "img_types.h"
#include "img_errors.h"

#include "tal.h"

#include "vxe_fw_if.h"
#include "vxe_KM.h"
#include "vxe_common.h"
#include "coreflags.h"


#if defined (DEBUG_REG_OUTPUT)
void DBG_init_reg_looper(void);
void DBG_destroy_reg_looper(void);
void DBG_dump_reg_and_page(void *pvDevContext);
#endif


#if defined(IMG_KERNEL_MODULE)
#include <linux/kthread.h>
#include <linux/delay.h>

#if defined(DEBUG_REG_OUTPUT)
static int img_pg_table_dump(IMG_UINT32 ui32MMU_DIR_LIST_BASE_ADDR, IMG_UINT32 ui32AddrRange);
#endif
#endif /*defined(IMG_KERNEL_MODULE)*/


/* Pipe registers */
#define PIPE_REGISTERS(szBank) \
	{szBank, "INT_STATUS", 0x010}, \
	{szBank, "PIPE_CLKGATESTATUS", 0x040}, \
	{szBank, "SEQ_CUR_PIC_LUMA_BASE_ADDR", 0x120}, \
	{szBank, "SEQ_CUR_PIC_CB_BASE_ADDR", 0x124}, \
	{szBank, "SEQ_CUR_PIC_CR_BASE_ADDR", 0x128}, \
	{szBank, "SEQ_REF_PIC0_LUMA_BASE_ADDR", 0x220}, \
	{szBank, "SEQ_REF_PIC1_LUMA_BASE_ADDR", 0x230}, \
	{szBank, "SEQ_RECON_LUMA_BASE_ADDR", 0x0240}, \
	{szBank, "VLC_OUTPUT_STATUS", 0x0848}, \
	{szBank, "VLC_WRITE_ADDR", 0x0850}

struct register_info
{
	char *szBank;
	char *szReg;
	int offset;
};

static struct register_info vxe_registers[] =
{
	/* Multipipe level registers */
	{"REG_QUARTZ_MULTIPIPE", "MULTIPIPE_INT_STAT", 0x10},
	{"REG_QUARTZ_MULTIPIPE", "MULTIPIPE_HOST_INT_ENAB", 0x18},
	{"REG_QUARTZ_MULTIPIPE", "MULTIPIPE_IDLE_PWR_MAN", 0x44},

	/* MMU registers */
	{"REG_MMU", "MMU_ADDRESS_CONTROL", 0x70},
	{"REG_MMU", "MMU_CONFIG0", 0x80},
	{"REG_MMU", "MMU_CONFIG1", 0x84},
	{"REG_MMU", "MMU_STATUS0", 0x88},
	{"REG_MMU", "MMU_STATUS1", 0x8c},
	{"REG_MMU", "MMU_MEM_REQ", 0x90},
	{"REG_MMU", "MMU_CONTROL0", 0x00},
	{"REG_MMU", "MMU_CONTROL1", 0x08},

	/* LTP RAM registers */
	{"REG_PROC_DATA_RAM", "FW_HW_FIFO_READER", 0x00},
	{"REG_PROC_DATA_RAM", "FW_HW_FIFO_WRITER", 0x04},
	{"REG_PROC_DATA_RAM", "FW_SCRATCHREG_IDLE", 0x08},
	{"REG_PROC_DATA_RAM", "FW_SCRATCHREG_FWTRACE", 0x0c},
	{"REG_PROC_DATA_RAM", "FW_REG_FW_BOOTSTATUS", 0x10},
	{"REG_PROC_DATA_RAM", "FW_REG_FEEDBACK_PRODUCER", 0x14},
	{"REG_PROC_DATA_RAM", "FW_REG_FEEDBACK_CONSUMER", 0x18},
	{"REG_PROC_DATA_RAM", "FW_REG_FW_FEEDBACK", 0x1c},

	/* Pipe 1 registers */
	PIPE_REGISTERS("REG_ENCODER_PIPE_1"),
	/* Pipe 2, 3.. */

	/* DMAC registers */
	{"REG_DMAC", "DMA_Setup", 0x0000},
	{"REG_DMAC", "DMA_Count", 0x0004},
	{"REG_DMAC", "DMA_Peripheral_param", 0x0008},
	{"REG_DMAC", "DMA_IRQ_Stat", 0x000c},
	{"REG_DMAC", "DMA_2D_Mode", 0x0010},
	{"REG_DMAC", "DMA_Peripheral_addr", 0x0014},
};

#define DUMP(value, offset, name) \
	printk("0x%08x (0x%04x) %s\n", value, offset, name);

#define DUMP_CORE(value, name) \
	printk("0x%08x %s\n", value, name);


/* Reading a core reg like the PC is trickier, maybe it should come from proc_fwif.c directly with an extern */
IMG_UINT32 ltp_readCoreReg(const IMG_UINT32 ui32Reg);


#if defined(IMG_KERNEL_MODULE)
#define MASK_IMG_BUS4_MMU_ENABLE_EXT_ADDRESSING 0x00000010
#define SHIFT_IMG_BUS4_MMU_ENABLE_EXT_ADDRESSING 4

#define MASK_IMG_BUS4_EXTENDED_ADDR_RANGE 0x000000F0
#define SHIFT_IMG_BUS4_EXTENDED_ADDR_RANGE 4

typedef enum _dump_type_
{
	e_BOTH_ON_PAGE_FAULT = 0,
	e_ONLY_REG_ALL_THE_TIME,
	e_BOTH_ALL_THE_TIME,
} dump_type;

/*!
* @brief Dump some registers and walk the page table
*/
IMG_UINT32 vxekm_dumpall(IMG_UINT32 dump_type, void *pvDevContext)
{
	unsigned i;
	char name[128];
	IMG_UINT32 reg_value = 0, core_idx = 0;

	IMG_HANDLE hRegBank;
	IMG_HANDLE hMMUBank;
	VXE_KM_DEVCONTEXT *psDevContext = (VXE_KM_DEVCONTEXT*)pvDevContext;

	if (NULL != pvDevContext)
	{
		core_idx = psDevContext->sDevSpecs.ui32CoreDevIdx;
	}

	/* Get handle on banks containing information about HW */
	sprintf(name, "REG_QUARTZ_MULTIPIPE_%d", core_idx);
	hRegBank = TAL_GetMemSpaceHandle(name);
	sprintf(name, "REG_MMU_%d", core_idx);
	hMMUBank = TAL_GetMemSpaceHandle(name);

	if (hRegBank)
	{
		if (hMMUBank)
		{
			/* Check page fault */
			TALREG_ReadWord32(hMMUBank, 0x88, &reg_value);
		}
		else
		{
			printk("Failed to get MMU memspace\n");
		}
	}
	else
	{
		printk("Fail namespace MMU\n");
	}

	/* No page fault means no dump */
	if (!reg_value && dump_type == e_BOTH_ON_PAGE_FAULT)
	{
		return 0;
	}

	/* If there is a page fault, give more information about it */
	if (reg_value)
	{
		IMG_UINT32 faulty_requestor = 0xbaad;
		/* Find out which requestor flagged the page fault */
		TALREG_ReadWord32(hMMUBank, 0x0090, &reg_value);
		for (i = 16; i <= 31; i++)
		{
			if (reg_value & (1 << i))
			{
				/* Found the faulty requestor*/
				faulty_requestor = (i - 16);
				break;
			}
		}

		/* Actually found a culprit */
		if (0xbaad != faulty_requestor)
		{
			TALREG_ReadWord32(hMMUBank, 0x00a0, &i);
			TALREG_WriteWord32(hMMUBank, 0x00a0, faulty_requestor);
			TALREG_ReadWord32(hMMUBank, 0x00a8, &reg_value);
			printk("=> MMU PROTOCOL FAULT: %08x\n", reg_value);
			/* Reset the PROTOCOL_FAULT register */
			TALREG_WriteWord32(hMMUBank, 0x00a0, i);
		}
	}


	printk("===============================================================================================\n");
	printk("===============================================================================================\n");
	printk("========================================= REGISTER DUMP =======================================\n");
	printk("===============================================================================================\n");
	printk("===============================================================================================\n");

	printk("=> VXE REGISTERS\n");
	for (i = 0; i < sizeof(vxe_registers) / sizeof(vxe_registers[0]); i++)
	{
		sprintf(name, "%s_%d", vxe_registers[i].szBank, core_idx);
		hRegBank = TAL_GetMemSpaceHandle(name);
		if (hRegBank)
		{
			TALREG_ReadWord32(hRegBank, vxe_registers[i].offset, &reg_value);
			DUMP(reg_value, vxe_registers[i].offset, vxe_registers[i].szReg);
		}
		else
			printk("Couldn't find namespace : %s\n", vxe_registers[i].szBank);
	}

	//printk("=> PROC REGISTERS\n");
	//DUMP_CORE(mtx_readCoreReg(namespace, 5), "PC");

	printk("===============================================================================================\n");
	printk("===============================================================================================\n");
	printk("===============================================================================================\n");

	{
		/* There has been a page fault */
		IMG_UINT32 ui32DirListAddr;
		IMG_UINT32 tmp;
		IMG_UINT32 ui32AddrRange = 32; // 32, 36 or 40
		IMG_BOOL bUseExtendedAddr = IMG_FALSE;

		/* debug page table dumping */
		PRINT("Dumping page tables\n");
		/* read directory 0 base address */
		TALREG_ReadWord32(hMMUBank, 0x0020, &ui32DirListAddr);
		PRINT("MMU_DIR_LIST_BASE(0) is %08X\n", ui32DirListAddr);

		/* are we using extended addressing */
		TALREG_ReadWord32(hMMUBank, 0x0070, &tmp);
		bUseExtendedAddr = F_DECODE(tmp, IMG_BUS4_MMU_ENABLE_EXT_ADDRESSING);
		if (bUseExtendedAddr)
		{
			TALREG_ReadWord32(hMMUBank, 0x0080, &tmp);
			ui32AddrRange += F_EXTRACT(tmp, IMG_BUS4_EXTENDED_ADDR_RANGE);
		}

		PRINT("Using %d bit addressing\n", ui32AddrRange);

		if (dump_type != e_ONLY_REG_ALL_THE_TIME)
		{
#if defined(DEBUG_REG_OUTPUT)
			img_pg_table_dump(ui32DirListAddr, ui32AddrRange);
#endif
		}
	}

	return 1;
}


#if defined(DEBUG_REG_OUTPUT)
static int register_looper(void *arg)
{
	while (!kthread_should_stop())
	{
		msleep(8000);
		if (vxekm_dumpall(e_BOTH_ON_PAGE_FAULT, NULL))
		{
			/* if we have actually output anything then wait longer before doing it again (15 seconds should be enough) */
			msleep(15000);
		}
	}
	return 0;
}

static struct task_struct *looper = NULL;

/* Init */
void DBG_init_reg_looper(void)
{
	looper = kthread_run(register_looper, NULL, "REGISTER_LOOPER");
}

/* on_free_bucket */
void DBG_destroy_reg_looper(void)
{
	if (looper)
	{
		kthread_stop(looper);
		looper = NULL;
	}
}

/* single call for dumping */
void DBG_dump_reg_and_page(void *pvDevContext)
{
	vxekm_dumpall(e_BOTH_ALL_THE_TIME, pvDevContext);
}

/* single call for dumping */
void DBG_dump_reg(void *pvDevContext)
{
	vxekm_dumpall(e_ONLY_REG_ALL_THE_TIME, pvDevContext);
}

#endif /*defined(DEBUG_REG_OUTPUT)*/
#endif /* defined(IMG_KERNEL_MODULE) */


#if defined(DEBUG_REG_OUTPUT)
/* DEBUG page table dumping code */
#include <linux/module.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/page.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>

/* Provide a default memoffset which might be overridden by another part of the kernel back-end */
unsigned long __attribute__((weak)) memoffset = 0;

static char large_buffer[512 * 1024];
static int buffer_len = 0;

/* Device uses 4k pages, it could be a parameter if needed */
#define LOG2_DEV_PAGE_SIZE (12)

#define VALIDENTRY_MASK 1
#define FLAGS_MASK      0x0f
#define DIR_SHIFT       (2 * LOG2_DEV_PAGE_SIZE - 2) /*22 for 4k*/
// Override linux define
#undef PTE_SHIFT
#define PTE_SHIFT       (LOG2_DEV_PAGE_SIZE)

static unsigned long mmu_to_phys(unsigned long mmu, IMG_UINT32 ui32AddrRange)
{
	return (unsigned long)(mmu & ~((unsigned long)FLAGS_MASK)) << (ui32AddrRange - 32);
}
static int valid_phys(unsigned long phys, IMG_UINT32 ui32AddrRange)
{
	return ((phys << (ui32AddrRange - 32)) & ~PAGE_MASK) == 0;
}

static void * map_phys(unsigned long phys)
{
	if (memoffset)
		return ioremap(phys + memoffset, PAGE_SIZE);
	else
		return phys_to_virt(phys);
}

static void unmap_phys(void* v)
{
	if (memoffset) {
		iounmap(v);
	}
	else
	{
		// do nothing if unified memory
	}
}

static int pgtable_walk(unsigned long root, u32 * rootptr, IMG_UINT32 ui32AddrRange)
{
	unsigned      i;
	char *        buf = large_buffer;

	// go through the valid page table directories, 
	for (i = 0; i < PAGE_SIZE / sizeof(u32); i++) {
		// map a dir 
		if (rootptr[i] & VALIDENTRY_MASK) {
			unsigned      j;
			u32 *         dirptr;
			unsigned long dir;
			pr_info("dir %08lx %08x\n", root + sizeof(u32)*i, rootptr[i]);
			dir = rootptr[i];
			if (!valid_phys(dir & ~FLAGS_MASK, ui32AddrRange)) {
				pr_err("%s invalid phys address entry:%08lx\n", __func__, dir);
			}
			dirptr = map_phys(mmu_to_phys(dir, ui32AddrRange));

			// map a set of page table entries
			for (j = 0; j < PAGE_SIZE / sizeof(u32); j++) {
				unsigned long devvirt = i << DIR_SHIFT;
				unsigned int  flags = dirptr[j] & FLAGS_MASK;
				devvirt += j << PTE_SHIFT;
				if (dirptr[j] & VALIDENTRY_MASK) {

					buf += sprintf(buf, "PTE: v:%08lx p:%08lx flags:%04x\n", devvirt, mmu_to_phys(dirptr[j], ui32AddrRange), flags);
					printk("PTE: v:%08lx p:%08lx flags:%04x\n", devvirt, mmu_to_phys(dirptr[j], ui32AddrRange), flags);
					if (buf - large_buffer + 30 > sizeof(large_buffer))
						break;
				}
				else if (dirptr[j])
				{
					printk("Non zero invalid PTE v:%08lx entry:%08lx\n", devvirt, (unsigned long)(dirptr[j]));
				}
			}
			unmap_phys(dirptr);
		}
		else if (rootptr[i])
		{
			pr_info("Non-zero invalid page directory entry dir %08lx %08x\n", root + sizeof(u32)*i, rootptr[i]);
		}
		if (buf - large_buffer + 30 > sizeof(large_buffer))
			break;
	}
	return  buf - large_buffer;
}

static int img_pg_table_dump(IMG_UINT32 ui32Dir0BaseAddr, IMG_UINT32 ui32AddrRange)
{
	void * mmurootptr = map_phys(mmu_to_phys(ui32Dir0BaseAddr, ui32AddrRange));
	buffer_len = pgtable_walk(ui32Dir0BaseAddr, mmurootptr, ui32AddrRange);
	unmap_phys(mmurootptr);
	pr_info("len:%d\n", buffer_len);

	return 1;
}
#else
void DBG_dump_reg_and_page(void *pvDevContext) {}
void DBG_dump_reg(void *pvDevContext) { (void)vxe_registers; }
#endif /*defined(DEBUG_REG_OUTPUT)*/


#if defined (DEBUG_FS_SUPPORT)
#include <linux/debugfs.h>

static VXE_KM_DEVCONTEXT* dev_contexts [VXE_KM_SUPPORTED_DEVICES] = {0};

struct debugfs_dev_to_output
{
	void *dev_context;
	char *buf;
};

/*
 * ui32MMUFaultReg (10)
 * - VXE_KM_DEVICE_SPECIFIC_INFO
 * ui32CoreRev (10)
 * ui32CoreConfig (10)
 * ui32CoreConfig2 (10)
 * ui32CoreConfig3 (10)
 * ui32MMUFlags (10)
 * - for each stream
 * ui8OutgoingFIFOConsumer (3)
 * ui8OutgoingFIFOProducer (3)
 * ui8CmdQueueProducer (3)
 * ui8CmdQueueConsumer (3)
 * ui32StreamStateFlags (10)
 */
#define DEBUGFS_DEV_CONTEXT_SPECS_BUFFER_SIZE \
( \
	((10 + 1) * 6) + /*32bit entries + '\n'*/ \
	7/*fault: */ + \
	5/*rev: */ + \
	4/*c1: */ +  \
	4/*c2: */ +  \
	4/*c3: */ +  \
	6/*flgs: */  \
)

#define DEBUGFS_STREAM_ENTRIES_BUFFER_SIZE \
( \
	((10 + 1) * 1) /*32bit entries + '\n'*/ +	\
	((3 + 1) * 4) /*8bit entries + '\n'*/ +		\
	7/*cmd_c: */ + \
	7/*cmd_p: */ + \
	6/*fb_c: */ +  \
	6/*fb_p: */ +  \
	8/*sflags: */  \
)

/****
 ======== DEVICE SPECIFIC ENTRIES
 ****/

static int debugfs_format_dev_context_specs_output(struct debugfs_dev_to_output *link, size_t *out)
{
	VXE_KM_DEVCONTEXT *psContext;
	char *buf;
	size_t ret, buf_size, len;
	psContext = *(VXE_KM_DEVCONTEXT **)link->dev_context;

	ret = 0;
	buf = link->buf;
	buf_size = DEBUGFS_DEV_CONTEXT_SPECS_BUFFER_SIZE;

	if (psContext)
	{
		/* Report MMU faults if any */
		len = snprintf(buf, buf_size, "fault: %08x\n", psContext->ui32MMUFaultReg0);
		ret += len;
		buf += len;
		buf_size -= len;
		/* Device status */
		len = snprintf(buf, buf_size, "rev: %08x\nc1: %08x\nc2: %08x\nc3: %08x\n", psContext->sDevSpecs.sHWConfig.ui32CoreRev,
			psContext->sDevSpecs.sHWConfig.ui32CoreConfig, psContext->sDevSpecs.sHWConfig.ui32CoreConfig2, psContext->sDevSpecs.sHWConfig.ui32CoreConfig3);
		ret += len;
		buf += len;
		buf_size -= len;
		/* Device configuration */
		len = snprintf(buf, buf_size, "flgs: %08x\n", psContext->sDevSpecs.ui32MMUFlags);
		ret += len;
		buf += len;
		buf_size -= len;
	}

	if (ret > DEBUGFS_DEV_CONTEXT_SPECS_BUFFER_SIZE)
		return -EOVERFLOW;

	*out = ret;
	return 0;
}

static int debugfs_vxe_dev_specs_open (struct inode *inode, struct file *file)
{
	struct debugfs_dev_to_output *link;
	size_t filled_size = 0;

	link = (struct debugfs_dev_to_output *)kmalloc(sizeof(*link), GFP_KERNEL);
	if (!link)
	{
		goto error_private_data;
	}

	link->dev_context = inode->i_private;
	link->buf = (char*)kzalloc(DEBUGFS_DEV_CONTEXT_SPECS_BUFFER_SIZE + 1 /*'\0'*/, GFP_KERNEL);
	if (!link->buf)
	{
		goto error_private_buf;
	}

	if (0 != debugfs_format_dev_context_specs_output(link, &filled_size))
	{
		goto error_format_buf;
	}

	file->private_data = link;

	return nonseekable_open(inode, file);

error_format_buf:
	kfree(link->buf);
error_private_buf:
	kfree(link);
error_private_data:

	return -ENOMEM;
}

static int debugfs_vxe_dev_specs_release (struct inode *inode, struct file *file)
{
	struct debugfs_dev_to_output *link;

	link = (struct debugfs_dev_to_output *)file->private_data;

	kfree(link->buf);
	kfree(link);

	return 0;
}

static ssize_t debugfs_vxe_dev_specs_read (struct file *file, char __user *buf, size_t size, loff_t *offset)
{
	size_t len;
	struct debugfs_dev_to_output *link;

	link = (struct debugfs_dev_to_output *)file->private_data;
	len = strlen(link->buf);

	return simple_read_from_buffer(buf, size, offset, link->buf, len);
}

static const struct file_operations debugfs_vxe_dev_context_specs_ops = {
		.owner = THIS_MODULE,
		.open = debugfs_vxe_dev_specs_open,
		.release = debugfs_vxe_dev_specs_release,
		.read = debugfs_vxe_dev_specs_read,
		.llseek = no_llseek,
};

/****
 ======== STREAM SPECIFIC INFORMATION
 ****/

static int debugfs_format_dev_streams_output(struct debugfs_dev_to_output *link, size_t *out)
{
	VXE_KM_DEVCONTEXT *psContext;
	VXE_KM_COMM_SOCKET *psSocket;
	char *buf;
	size_t ret, buf_size, len;
	int i;
	psContext = *(VXE_KM_DEVCONTEXT **)link->dev_context;

	ret = 0;
	buf = link->buf;
	buf_size = DEBUGFS_STREAM_ENTRIES_BUFFER_SIZE;

	if (psContext)
	{
		for (i = 0; i < VXE_MAX_SOCKETS; i++)
		{
			psSocket = psContext->apsDeviceSockets[i];
			/* Give a status about the device */
			if (psSocket)
			{
				len = snprintf(buf, buf_size, "sflags: %08x\ncmd_c: %u|cmd_p: %u|fb_c: %u|fb_p: %u\n", psSocket->ui32StreamStateFlags,
					psSocket->ui8CmdQueueConsumer, psSocket->ui8CmdQueueProducer, psSocket->ui8OutgoingFIFOConsumer, psSocket->ui8OutgoingFIFOProducer);
				ret += len;
				buf += len;
				buf_size -= len;
			}
		}
	}

	if (ret > DEBUGFS_STREAM_ENTRIES_BUFFER_SIZE)
		return -EOVERFLOW;

	*out = ret;
	return 0;
}

static int debugfs_vxe_dev_streams_open(struct inode *inode, struct file *file)
{
	struct debugfs_dev_to_output *link;
	size_t filled_size = 0;

	link = (struct debugfs_dev_to_output *)kmalloc(sizeof(*link), GFP_KERNEL);
	if (!link)
	{
		goto error_private_data;
	}

	link->dev_context = inode->i_private;
	link->buf = (char*)kzalloc(DEBUGFS_STREAM_ENTRIES_BUFFER_SIZE + 1 /*'\0'*/, GFP_KERNEL);
	if (!link->buf)
	{
		goto error_private_buf;
	}

	if (0 != debugfs_format_dev_streams_output(link, &filled_size))
	{
		goto error_format_buf;
	}

	file->private_data = link;

	return nonseekable_open(inode, file);

error_format_buf:
	kfree(link->buf);
error_private_buf:
	kfree(link);
error_private_data:

	return -ENOMEM;
}

/*recycle read and release because they do exactly the same thing*/
static const struct file_operations debugfs_vxe_dev_streams_ops = {
		.owner = THIS_MODULE,
		.open = debugfs_vxe_dev_streams_open,
		.release = debugfs_vxe_dev_specs_release,
		.read = debugfs_vxe_dev_specs_read,
		.llseek = no_llseek,
};

/****
======== LAST 10 CMD
****/
#define MAX_COMMAND_HISTORY (10)
static struct _command_history_
{
	u32 command_history [HW_FIFO_WORDS_PER_COMMANDS * MAX_COMMAND_HISTORY];
	unsigned next_command_index;
} all_commands_history [VXE_KM_SUPPORTED_DEVICES] = {{.command_history = {0}}};

#define CMD_HIST_BUF_SIZE \
( \
	((4/*w1: */ + 4/*w2: */ + 4/*w3: */ + 4/*w4: */ + 4 * 3/*[ '|' |'\n']*/) + 8 * 4/*hex value UUUUUUUU*/) * MAX_COMMAND_HISTORY \
	+ 2 /*'\n''\0'*/ \
)

static int debugfs_cmd_history_format_buffer(struct _command_history_ *s_entry, char *buf, size_t *filled_size)
{
	int i;
	size_t ret, buf_size, len;
	char *buf_ptr;
	u32 *entries;
	u32 *all_entries;
	unsigned next;

	all_entries = &s_entry->command_history[0];

	/* start at the beginning */
	ret = 0;
	buf_ptr = buf;
	buf_size = CMD_HIST_BUF_SIZE;

	/*where is the circular buffer? */
	next = s_entry->next_command_index;

	for (i = 0; i < MAX_COMMAND_HISTORY; i++)
	{
		/* the last cmd sent is (next - 1) % MAX_COMMAND_HISTORY */
		if (next == 0) {
			next = (MAX_COMMAND_HISTORY - 1); /*loop back*/
		}
		else {
			next--;
		}
		entries = &all_entries[next * HW_FIFO_WORDS_PER_COMMANDS]; /*next command*/

		len = snprintf(buf_ptr, buf_size, "w1: %08x | w2: %08x | w3: %08x | w4 %08x\n", entries[0], entries[1], entries[2], entries[3]);
		ret += len;
		buf_ptr += len;
		buf_size -= len;
	}

	if (ret >= CMD_HIST_BUF_SIZE)
	{
		return -EOVERFLOW;
	}

	*filled_size = ret;

	return 0;
}

static int debugfs_cmd_history_open(struct inode *inode, struct file *file)
{
	char *buf;
	size_t len;
	struct _command_history_ *entry;

	buf = kzalloc(CMD_HIST_BUF_SIZE + 1/*'\0'*/, GFP_KERNEL);
	if (!buf)
	{
		goto malloc_failed;
	}

	entry = inode->i_private;
	if (0 != debugfs_cmd_history_format_buffer(entry, buf, &len))
	{
		goto format_failed;
	}

	file->private_data = buf;

	return nonseekable_open(inode, file);

format_failed:
	kfree(buf);
malloc_failed:
	return -ENOMEM;
}

static int debugfs_cmd_history_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);

	return 0;
}

static ssize_t debugfs_cmd_history_read(struct file *file, char * __user buf, size_t size, loff_t *offset)
{
	size_t len;
	len = strlen(file->private_data);
	return simple_read_from_buffer(buf, size, offset, file->private_data, len);
}

static const struct file_operations debugfs_cmd_history_ops = {
	.owner = THIS_MODULE,
	.open = debugfs_cmd_history_open,
	.release = debugfs_cmd_history_release,
	.read = debugfs_cmd_history_read,
	.llseek = no_llseek,
};

void debugfs_write_last_cmd(unsigned dev_id, unsigned w1, unsigned w2, unsigned w3, unsigned w4)
{
	if (dev_id < VXE_KM_SUPPORTED_DEVICES)
	{
		/* command are stored in a circular buffer */
		unsigned next = all_commands_history[dev_id].next_command_index;

		all_commands_history[dev_id].command_history[next * HW_FIFO_WORDS_PER_COMMANDS + 0] = (u32)w1;
		all_commands_history[dev_id].command_history[next * HW_FIFO_WORDS_PER_COMMANDS + 1] = (u32)w2;
		all_commands_history[dev_id].command_history[next * HW_FIFO_WORDS_PER_COMMANDS + 2] = (u32)w3;
		all_commands_history[dev_id].command_history[next * HW_FIFO_WORDS_PER_COMMANDS + 3] = (u32)w4;

		/* eventually loop back to the start */
		next++;
		if (next >= MAX_COMMAND_HISTORY)
		{
			next = 0;
		}
		/* update for next time this function is called */
		all_commands_history[dev_id].next_command_index = next;
	}
}


/****
 ======== FEEDBACK
 ****/

/* written by ISR */
static u32 feedback_per_device [FEEDBACK_FIFO_WORD_PER_COMMANDS*VXE_KM_SUPPORTED_DEVICES];

#define DEBUGFS_FEEDBACK_SIZE \
( \
	8/*UUUUUUUU*/ * 2 + 1/* */ + 2/*\n*/ + 4/*w1: */ + 4/*w2: */ \
)

static int debugfs_vxe_dev_fb_open(struct inode *inode, struct file *file)
{
	char *buf;
	u32 *feedback;
	size_t len;

	buf = kzalloc(DEBUGFS_FEEDBACK_SIZE + 1/*'\0'*/, GFP_KERNEL);
	if (!buf)
	{
		return -ENOMEM;
	}

	/* Point on the entries */
	feedback = (u32 *)inode->i_private;
	len = snprintf(buf, DEBUGFS_FEEDBACK_SIZE, "w1: %08x w2: %08x\n", feedback[0], feedback[1]);

	file->private_data = buf;

	/* Normal open */
	return nonseekable_open(inode, file);
}

static int debugfs_vxe_dev_fb_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static ssize_t debugfs_vxe_dev_fb_read(struct file *file, char* __user buf, size_t size, loff_t *offset)
{
	size_t len;
	len = strlen(file->private_data);
	return simple_read_from_buffer(buf, size, offset, file->private_data, len);
}

static const struct file_operations debugfs_vxe_dev_context_fb_ops = {
		.owner = THIS_MODULE,
		.open = debugfs_vxe_dev_fb_open,
		.release = debugfs_vxe_dev_fb_release,
		.read = debugfs_vxe_dev_fb_read,
		.llseek = no_llseek,
};

/* root entry in /sys/kernel/debug */
static struct dentry *debugfs_root = NULL;

int create_debugfs_vxekm(void)
{
	int i;
	char base_name [64];
	struct dentry *devs_base_dir = NULL, *tmp = NULL;

	debugfs_root = debugfs_create_dir("img_vxe_km", NULL);
	if (!debugfs_root)
	{
		printk(KERN_ALERT "Failed to create /sys/kernel/debug/img_vxe_km\n");
		return -ENOMEM;
	}

	for (i = 0; i < VXE_KM_SUPPORTED_DEVICES; i++)
	{
		sprintf(base_name, "dev_%u", i);

		devs_base_dir = debugfs_create_dir(base_name, debugfs_root);
		if (!devs_base_dir)
		{
			printk(KERN_ALERT "Failed to create /sys/kernel/debug/img_vxe_km/%s\n", base_name);
			return -ENOMEM;
		}

		/* inode->i_private = &feedback_per_device[i] */
		tmp = debugfs_create_file("last_fb", 0444, devs_base_dir, &feedback_per_device[i * FEEDBACK_FIFO_WORD_PER_COMMANDS], &debugfs_vxe_dev_context_fb_ops);
		if (!tmp)
		{
			printk(KERN_ALERT "Failed to create /sys/kernel/debug/img_vxe_km/%s/last_fb\n", base_name);
			return -ENOMEM;
		}

		/* inode->i_private = &all_commands_history[i] */
		tmp = debugfs_create_file("last_cmds", 0444, devs_base_dir, &all_commands_history[i], &debugfs_cmd_history_ops);
		if (!tmp)
		{
			printk(KERN_ALERT "Failed to create /sys/kernel/debug/img_vxe_km/%s/last_cmds\n", base_name);
			return -ENOMEM;
		}

		/* inode->i_private = &dev_contexts[i] */
		tmp = debugfs_create_file("specs", 0444, devs_base_dir, &dev_contexts[i], &debugfs_vxe_dev_context_specs_ops);
		if (!tmp)
		{
			printk(KERN_ALERT "Failed to create /sys/kernel/debug/img_vxe_km/%s/specs\n", base_name);
			return -ENOMEM;
		}

		/* inode->i_private = &dev_contexts[i] */
		tmp = debugfs_create_file("streams", 0444, devs_base_dir, &dev_contexts[i], &debugfs_vxe_dev_streams_ops);
		if (!tmp)
		{
			printk(KERN_ALERT "Failed to create /sys/kernel/debug/img_vxe_km/%s/streams\n", base_name);
			return -ENOMEM;
		}
	}

	return 0;
}

void destroy_debugfs_vxekm(void)
{
	debugfs_remove_recursive(debugfs_root);
}

void debugfs_write_last_feedback(unsigned dev_id, unsigned fb_1, unsigned fb_2)
{
	if (dev_id < VXE_KM_SUPPORTED_DEVICES)
	{
		feedback_per_device[dev_id * FEEDBACK_FIFO_WORD_PER_COMMANDS + 0] = (u32)fb_1;
		feedback_per_device[dev_id * FEEDBACK_FIFO_WORD_PER_COMMANDS + 1] = (u32)fb_2;
	}
}

int debugfs_link_context_to_debugfs(VXE_KM_DEVCONTEXT *psContext)
{
	if (!psContext)
	{
		return -EINVAL;
	}

	if (psContext->sDevSpecs.ui32CoreDevIdx < VXE_KM_SUPPORTED_DEVICES)
	{
		/* Only update the pointer if not already set */
		if (NULL == dev_contexts[psContext->sDevSpecs.ui32CoreDevIdx])
		{
			dev_contexts[psContext->sDevSpecs.ui32CoreDevIdx] = psContext;
		}
	}

	return 0;
}

int debugfs_unlink_context_to_debugfs(VXE_KM_DEVCONTEXT *psContext)
{
	if (!psContext)
	{
		return -EINVAL;
	}

	if (psContext->sDevSpecs.ui32CoreDevIdx < VXE_KM_SUPPORTED_DEVICES)
	{
		/* Only update the pointer if it matches */
		if (psContext == dev_contexts[psContext->sDevSpecs.ui32CoreDevIdx])
		{
			dev_contexts[psContext->sDevSpecs.ui32CoreDevIdx] = NULL;
		}
	}

	return 0;
}

#else
int create_debugfs_vxekm(void) {return 0;}
void destroy_debugfs_vxekm(void) {}
void debugfs_write_last_feedback(unsigned dev_id, unsigned fb_1, unsigned fb_2) {(void)dev_id;(void)fb_1;(void)fb_2;}
void debugfs_write_last_cmd(unsigned dev_id, unsigned w1, unsigned w2, unsigned w3, unsigned w4) {(void)dev_id; (void)w1; (void)w2; (void)w3; (void)w4;}
int debugfs_link_context_to_debugfs(VXE_KM_DEVCONTEXT *psContext) {(void)psContext; return 0;}
int debugfs_unlink_context_to_debugfs(VXE_KM_DEVCONTEXT *psContext) {(void)psContext; return 0;}
#endif


#endif /*_VXE_KM_DEBUG_C_*/
