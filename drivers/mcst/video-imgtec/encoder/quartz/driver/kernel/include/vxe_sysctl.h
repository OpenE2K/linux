/*!
 *****************************************************************************
 *
 * @File       vxe_sysctl.h
 * @Description    This file contains the sysctl definition for the VXE kernel module
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

#if ! defined (__VXE_SYSCTL_H__)
#define __VXE_SYSCTL_H__

#if defined (CONFIG_SYSCTL)
/*
* We can completely strip out sysctl from the kernel module 
* if is not supported (or we don't want/need it)
*/
#define VXE_KM_SYSCTL_SUPPORT (1)
#endif

#if defined (VXE_KM_SYSCTL_SUPPORT)

#include <linux/sysctl.h>

/* There is only ever one sysctl table per kernel module */
static struct ctl_table_header * vxe_img_sysctl_header;

/***************** Define value holders *****************/

static unsigned max_device_support = VXE_KM_SUPPORTED_DEVICES;

static unsigned min_device_support_bound = 0;
static unsigned max_device_support_bound = VXE_KM_SUPPORTED_DEVICES;
static unsigned min_mmu_flags_bound = VXE_KM_DEFAULT_MMU_FLAGS;
static unsigned max_mmu_flags_bound = (MMU_USE_MMU_FLAG|MMU_TILED_FLAG|MMU_EXTENDED_ADDR_FLAG|MMU_SECURE_FW_UPLOAD|MMU_TILED_INTERLEAVED); /*all bits set*/
static unsigned min_km_sched_model_bound = e_NO_SCHEDULING_SCENARIO;
static unsigned max_km_sched_model_bound = e_SCHEDULING_SCENARII - 1;

/* More generic bounds */
static unsigned zero = 0;
static unsigned one = 1;


/***************** Folder structure definition *****************/

/*
* sysctl table is structured as follows:
* <img_vxe_ctrl>
*	<max_device_support> (ro => from compilation flags)
*	<mmu_flags> (rw => hex number)
*		- 0x00000001: mmu present
*		- 0x00000002: mmu tiling supported
*		- 0x00000004: extended range (40 if set, 32 otherwise)
*		- 0x00000008: secure fw upload
*		- 0x00000010: mmu tiling interleaved
*	<mmu_tile_stride> (rw)
*	<ppm_state> (rw)
*	<scheduling_model> (rw)
*/

static struct ctl_table vxe_img_setting_table[] =
{
	/*max_device_support*/
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.ctl_name		= CTL_UNNUMBERED,
#endif
		.procname		= "max_device_support",
		.data			= &max_device_support,
		.maxlen			= sizeof(max_device_support),
		.mode			= 0444,
		.proc_handler	= &proc_dointvec_minmax,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.strategy		= &sysctl_intvec,
#endif
		.extra1			= &min_device_support_bound,
		.extra2			= &max_device_support_bound
	},
	/*mmu_flags*/
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.ctl_name		= CTL_UNNUMBERED,
#endif
		.procname		= "mmu_flags",
		.data			= &g_ui32MMUFlags,
		.maxlen			= sizeof(g_ui32MMUFlags),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec_minmax,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.strategy		= &sysctl_intvec,
#endif
		.extra1			= &min_mmu_flags_bound,
		.extra2			= &max_mmu_flags_bound
	},
	/*mmu_tile_stride*/
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.ctl_name		= CTL_UNNUMBERED,
#endif
		.procname		= "mmu_tile_stride",
		.data			= &g_ui32MMUTileStride,
		.maxlen			= sizeof(g_ui32MMUTileStride),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.strategy		= &sysctl_intvec,
#endif
	},
	/*ppm_state*/
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.ctl_name		= CTL_UNNUMBERED,
#endif
		.procname		= "ppm_state",
		.data			= &g_bKMPPM,
		.maxlen			= sizeof(g_bKMPPM),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec_minmax,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.strategy = &sysctl_intvec,
#endif
		.extra1 = &zero,
		.extra2 = &one
	},
	/*scheduling_model*/
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.ctl_name		= CTL_UNNUMBERED,
#endif
		.procname		= "scheduling_model",
		.data			= &g_eSchedulingModel,
		.maxlen			= sizeof(g_eSchedulingModel),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec_minmax,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.strategy = &sysctl_intvec,
#endif
		.extra1 = &min_km_sched_model_bound,
		.extra2 = &max_km_sched_model_bound
	},
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.ctl_name = 0
#endif
	} /*end of leaf*/
};


#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,17)
/* We shall see /proc/sys/img_vxe_ctrl being created */
static struct ctl_table vxe_img_root_table[] =
{
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "img_vxe_ctrl",
		.mode		= 0555,
		.child		= vxe_img_setting_table
	},
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
		.ctl_name = 0
#endif
	} /*end of leaf*/
};
#endif

/*!
 * \fn img_vxe_km_register_sysctl_table
 * \brief Create the vxe km entry in /proc/sys/
 * \details Abstract the details of the implementation and the restriction on kernel version
 * \return Reference on the sysctl table (used for cleanup)
 */
static struct ctl_table_header * img_vxe_km_register_sysctl_table(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,17)
	/* .child has been marked "deprecated" since kernels 3.4, ready our code to deal with this situation */
	return register_sysctl("img_vxe_ctrl", vxe_img_setting_table);
#else
	return register_sysctl_table(vxe_img_root_table);
#endif
}

/*!
* \fn img_vxe_km_unregister_sysctl_table
* \brief Clear the vxe km entry in /proc/sys/
* \param ptable_to_unregister Reference on the sysctl table to clean up
*/
static void img_vxe_km_unregister_sysctl_table(struct ctl_table_header * ptable_to_unregister)
{
	unregister_sysctl_table(ptable_to_unregister);
}


#endif /*defined (VXE_KM_SYSCTL_SUPPORT)*/

#endif /* ! defined(__VXE_SYSCTL_H__) */
