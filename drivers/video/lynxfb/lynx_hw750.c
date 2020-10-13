/*******************************************************************
*Copyright (c) 2012 by Silicon Motion, Inc. (SMI)
*Permission is hereby granted, free of charge, to any person obtaining a copy
*of this software and associated documentation files (the "Software"), to deal
*in the Software without restriction, including without limitation the rights to
*use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
*of the Software, and to permit persons to whom the Software is furnished to
*do so, subject to the following conditions:
*
*THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
*EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
*OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
*NONINFRINGEMENT.  IN NO EVENT SHALL Mill.Chen and Monk.Liu OR COPYRIGHT
*HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
*WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
*OTHER DEALINGS IN THE SOFTWARE.
*******************************************************************/
#include<linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 10)
#include<linux/config.h>
#endif
#include <linux/version.h>
#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/errno.h>
#include<linux/string.h>
#include<linux/mm.h>
#include<linux/slab.h>
#include<linux/delay.h>
#include<linux/fb.h>
#include<linux/ioport.h>
#include<linux/init.h>
#include<linux/pci.h>
#include<linux/vmalloc.h>
#include<linux/pagemap.h>
#include <linux/console.h>
#ifdef CONFIG_MTRR
#include <asm/mtrr.h>
#endif

#ifdef CONFIG_FB_LYNXFB_DOMAINS
#include <asm-l/iolinkmask.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
/* no below two header files in 2.6.9 */
#include<linux/platform_device.h>
#include<linux/screen_info.h>
#else
/* nothing by far */
#endif

#include "lynx_drv.h"
#include "lynx_hw750.h"
#include "ddk750.h"
#include "lynx_accel.h"

int hw_sm750_map(struct lynx_share *share, struct pci_dev *pdev)
{
	int ret;
	struct sm750_share *spec_share;

#ifdef CONFIG_FB_LYNXFB_DOMAINS
        int domain;
#endif /* CONFIG_FB_LYNXFB_DOMAINS */

	ENTER();

	spec_share = container_of(share, struct sm750_share, share);
	ret = 0;

	share->vidreg_start = pci_resource_start(pdev, 1);
	share->vidreg_size = MB(2);

	/* reserve the vidreg space of smi adaptor
	 * if you do this, u need to add release region code
	 * in lynxfb_remove, or memory will not be mapped again
	 * successfully
	 * */


	/* now map mmio and vidmem */
	share->pvReg =
	    ioremap_nocache(share->vidreg_start, share->vidreg_size);
	if (!share->pvReg) {
		err_msg("mmio failed\n");
		ret = -EFAULT;
		goto exit;
	}

	share->accel.dprBase = share->pvReg + DE_BASE_ADDR_TYPE1;
	share->accel.dpPortBase = share->pvReg + DE_PORT_ADDR_TYPE1;
#ifdef CONFIG_FB_LYNXFB_DOMAINS
	domain = pci_domain_nr(pdev->bus);
	ddk750_set_mmio(share->pvReg, share->devid, share->revid, domain);
#else
	ddk750_set_mmio(share->pvReg, share->devid, share->revid);
#endif /* CONFIG_FB_LYNXFB_DOMAINS */

	share->vidmem_start = pci_resource_start(pdev, 0);
	/* don't use pdev_resource[x].end - resource[x].start to
	 * calculate the resource size, its only the maximum available
	 * size but not the actual size, use
	 * @hw_sm750_getVMSize function can be safe.
	 * */
#ifdef CONFIG_FB_LYNXFB_DOMAINS
	share->vidmem_size = hw_sm750_getVMSize(share, domain);
#else
	share->vidmem_size = hw_sm750_getVMSize(share);
#endif /* CONFIG_FB_LYNXFB_DOMAINS */
	inf_msg("video memory size = %lld mb\n", share->vidmem_size >> 20);

	/* reserve the vidmem space of smi adaptor */

	share->pvMem = ioremap(share->vidmem_start, share->vidmem_size);

	if (!share->pvMem) {
		err_msg("Map video memory failed\n");
		ret = -EFAULT;
		goto exit;
	}

	inf_msg("video memory vaddr = %p\n", share->pvMem);
      exit:
	LEAVE(ret);
}

#ifdef CONFIG_FB_LYNXFB_DOMAINS

int hw_sm750_inithw(struct lynx_share *share, struct pci_dev *pdev)
{
	struct sm750_share *spec_share;
	struct init_status *parm;
	int domain;

	ENTER();

	domain = pci_domain_nr(pdev->bus);

	spec_share = container_of(share, struct sm750_share, share);
	parm = &spec_share->state.initParm;
	if (parm->chip_clk == 0)
		parm->chip_clk = (getChipType(domain) == SM750LE) ?
		    DEFAULT_SM750LE_CHIP_CLOCK : DEFAULT_SM750_CHIP_CLOCK;

	if (parm->mem_clk == 0)
		parm->mem_clk = parm->chip_clk;
	if (parm->master_clk == 0)
		parm->master_clk = parm->chip_clk / 3;

	ddk750_initHw((initchip_param_t *) & spec_share->state.initParm,
								 domain);
	/* for sm718, open pci burst */
	if (share->devid == 0x718) {
		POKE32(SYSTEM_CTRL,
		       PEEK32(SYSTEM_CTRL, domain) | (1 <<
			      SYSTEM_CTRL_PCI_BURST_LSB), domain);
	}

	/* sm750 use sii164, it can be setup with default value
	 * by on power, so initDVIDisp can be skipped */

	if (getChipType(domain) != SM750LE) {
		/* does user need CRT ? */
		if (spec_share->state.nocrt) {
			POKE32(MISC_CTRL,
			       PEEK32(MISC_CTRL, domain) |
			       (1 << MISC_CTRL_DAC_POWER_LSB), domain);
			/* shut off dpms */
			POKE32(SYSTEM_CTRL,
			       PEEK32(SYSTEM_CTRL, domain) |
			       (3 << SYSTEM_CTRL_DPMS_LSB), domain);
		} else {
			POKE32(MISC_CTRL,
			       PEEK32(MISC_CTRL, domain) &
			       (~(1 << MISC_CTRL_DAC_POWER_LSB)), domain);
			/* turn on dpms */
			POKE32(SYSTEM_CTRL,
			       PEEK32(SYSTEM_CTRL, domain) &
			       (~(3 << SYSTEM_CTRL_DPMS_LSB)), domain);
		}

		switch (spec_share->state.pnltype) {
		case sm750_doubleTFT:
		case sm750_24TFT:
		case sm750_dualTFT:
			POKE32(PANEL_DISPLAY_CTRL,
			       PEEK32(PANEL_DISPLAY_CTRL, domain) &
			       (~(3 << PANEL_DISPLAY_CTRL_TFT_DISP_LSB)),
								 domain);
			POKE32(PANEL_DISPLAY_CTRL,
			       PEEK32(PANEL_DISPLAY_CTRL, domain) |
			       (spec_share->state.
				pnltype <<
				PANEL_DISPLAY_CTRL_TFT_DISP_LSB), domain);
			break;
		}
	} else {
		/* for 750LE , no DVI chip initilization makes Monitor no signal */
		/* Set up GPIO for software I2C to program DVI chip in the
		   Xilinx SP605 board, in order to have video signal.
		 */
		swI2CInit(0, 1, domain);


		/* Customer may NOT use CH7301 DVI chip, which has to be
		   initialized differently.
		 */
		if (swI2CReadReg(0xec, 0x4a, domain) == 0x95) {
			/* The following register values for CH7301 are from
			   Chrontel app note and our experiment.
			 */
			inf_msg("yes, CH7301 DVI chip found\n");
			swI2CWriteReg(0xec, 0x1d, 0x16, domain);
			swI2CWriteReg(0xec, 0x21, 0x9, domain);
			swI2CWriteReg(0xec, 0x49, 0xC0, domain);
			inf_msg("okay, CH7301 DVI chip setup done\n");
		}
	}

	/* init 2d engine */
	if (!share->accel_off) {
		hw_sm750_initAccel(share, domain);
	}

	LEAVE(0);
}

resource_size_t hw_sm750_getVMSize(struct lynx_share *share, int domain)
{
	resource_size_t ret;
	ENTER();
	ret = ddk750_getVMSize(domain);
	LEAVE(ret);
}



int hw_sm750_output_checkMode(struct lynxfb_output *output,
			      struct fb_var_screeninfo *var, int domain)
{
	ENTER();
	LEAVE(0);
}


int hw_sm750_output_setMode(struct lynxfb_output *output,
			    struct fb_var_screeninfo *var,
			    struct fb_fix_screeninfo *fix,
			    int domain)
{
	int ret;
	disp_output_t dispSet;
	int channel;
	ENTER();
	ret = 0;
	dispSet = 0;
	channel = *output->channel;


	if (getChipType(domain) != SM750LE) {
		if (channel == sm750_primary) {
			inf_msg("primary channel\n");
			if (output->paths & sm750_panel)
				dispSet |= do_LCD1_PRI;
			if (output->paths & sm750_crt)
				dispSet |= do_CRT_PRI;

		} else {
			inf_msg("secondary channel\n");
			if (output->paths & sm750_panel)
				dispSet |= do_LCD1_SEC;
			if (output->paths & sm750_crt)
				dispSet |= do_CRT_SEC;

		}
		ddk750_setLogicalDispOut(dispSet, domain);
	} else {
		/* just open DISPLAY_CONTROL_750LE register bit 3:0 */
		u32 reg;
		reg = PEEK32(DISPLAY_CONTROL_750LE, domain);
		reg |= 0xf;
		POKE32(DISPLAY_CONTROL_750LE, reg, domain);
	}

	inf_msg("ddk setlogicdispout done \n");
	LEAVE(ret);
}

void hw_sm750_output_clear(struct lynxfb_output *output, int domain)
{
	ENTER();
	LEAVE();
}

int hw_sm750_crtc_checkMode(struct lynxfb_crtc *crtc,
			    struct fb_var_screeninfo *var, int domain)
{
	struct lynx_share *share;
	ENTER();

	share = container_of(crtc, struct lynxfb_par, crtc)->share;

	switch (var->bits_per_pixel) {
	case 8:
	case 16:
		break;
	case 32:
		if (share->revid == (unsigned char) SM750LE_REVISION_ID) {
			dbg_msg("750le do not support 32bpp\n");
			LEAVE(-EINVAL);
		}
		break;
	default:
		LEAVE(-EINVAL);

	}

	LEAVE(0);
}


/*
   set the controller's mode for @crtc charged with @var and @fix parameters
   */
int hw_sm750_crtc_setMode(struct lynxfb_crtc *crtc,
			  struct fb_var_screeninfo *var,
			  struct fb_fix_screeninfo *fix, int domain)
{
	int ret, fmt;
	u32 reg;
	mode_parameter_t modparm;
	clock_type_t clock;
	struct lynx_share *share;
	struct lynxfb_par *par;

	ENTER();
	ret = 0;
	par = container_of(crtc, struct lynxfb_par, crtc);
	share = par->share;

	if (!share->accel_off) {
		/* set 2d engine pixel format according to mode bpp */
		switch (var->bits_per_pixel) {
		case 8:
			fmt = 0;
			break;
		case 16:
			fmt = 1;
			break;
		case 32:
		default:
			fmt = 2;
			break;
		}
		hw_set2dformat(&share->accel, fmt);
	}


	/* set timing */
	modparm.pixel_clock = ps_to_hz(var->pixclock);
	modparm.vertical_sync_polarity =
	    (var->sync & FB_SYNC_HOR_HIGH_ACT) ? POS : NEG;
	modparm.horizontal_sync_polarity =
	    (var->sync & FB_SYNC_VERT_HIGH_ACT) ? POS : NEG;
	modparm.clock_phase_polarity =
	    (var->sync & FB_SYNC_COMP_HIGH_ACT) ? POS : NEG;
	modparm.horizontal_display_end = var->xres;
	modparm.horizontal_sync_width = var->hsync_len;
	modparm.horizontal_sync_start = var->xres + var->right_margin;
	modparm.horizontal_total =
	    var->xres + var->left_margin + var->right_margin +
	    var->hsync_len;
	modparm.vertical_display_end = var->yres;
	modparm.vertical_sync_height = var->vsync_len;
	modparm.vertical_sync_start = var->yres + var->lower_margin;
	modparm.vertical_total =
	    var->yres + var->upper_margin + var->lower_margin +
	    var->vsync_len;

	/* choose pll */
	if (crtc->channel != sm750_secondary)
		clock = PRIMARY_PLL;
	else
		clock = SECONDARY_PLL;

	dbg_msg("Request pixel clock = %lu\n", modparm.pixel_clock);
	ret = ddk750_setModeTiming(&modparm, clock, domain);
	if (ret) {
		err_msg("Set mode timing failed\n");
		goto exit;
	}

	if (crtc->channel != sm750_secondary) {
		/* set pitch, offset , width, start address , etc... */
		POKE32(PANEL_FB_ADDRESS,
		       crtc->oScreen << PANEL_FB_ADDRESS_ADDRESS_LSB, domain);
		reg = var->xres * (var->bits_per_pixel >> 3);
		/* crtc->channel is not equal to par->index on numeric, be aware of that */
		reg = PADDING(crtc->line_pad, reg);
		POKE32(PANEL_FB_WIDTH,
		       (reg << PANEL_FB_WIDTH_WIDTH_LSB) |
		       (fix->line_length << PANEL_FB_WIDTH_OFFSET_LSB),
		       domain);

		POKE32(PANEL_WINDOW_WIDTH,
		       ((var->xres - 1) << PANEL_WINDOW_WIDTH_WIDTH_LSB) |
		       (var->xoffset << PANEL_WINDOW_WIDTH_X_LSB),
		       domain);

		POKE32(PANEL_WINDOW_HEIGHT,
		((var->yres_virtual - 1) << PANEL_WINDOW_HEIGHT_HEIGHT_LSB) |
				(var->yoffset << PANEL_WINDOW_HEIGHT_Y_LSB),
				domain);

		POKE32(PANEL_PLANE_TL, 0, domain);

		POKE32(PANEL_PLANE_BR,
		       ((var->yres - 1) << PANEL_PLANE_BR_BOTTOM_LSB) |
		       ((var->xres - 1) << PANEL_PLANE_BR_RIGHT_LSB),
		       domain);

		/* set pixel format */
		reg = PEEK32(PANEL_DISPLAY_CTRL, domain);
		POKE32(PANEL_DISPLAY_CTRL,
		       (reg & (~(3 << PANEL_DISPLAY_CTRL_FORMAT_LSB))) |
		       ((var->bits_per_pixel >> 4) <<
			PANEL_DISPLAY_CTRL_FORMAT_LSB),
		       domain);
	} else {
		/* not implemented now */
		POKE32(CRT_FB_ADDRESS, crtc->oScreen, domain);
		reg = var->xres * (var->bits_per_pixel >> 3);
		/* crtc->channel is not equal to par->index on numeric, be aware of that */
		reg = PADDING(crtc->line_pad, reg);
		POKE32(CRT_FB_WIDTH,
		       (reg << CRT_FB_WIDTH_WIDTH_LSB) |
		       (fix->line_length << CRT_FB_WIDTH_OFFSET_LSB), domain);

		/* SET PIXEL FORMAT */
		reg = PEEK32(CRT_DISPLAY_CTRL, domain);
		reg |=
		    (var->
		     bits_per_pixel >> 4) << CRT_DISPLAY_CTRL_FORMAT_LSB;
		POKE32(CRT_DISPLAY_CTRL, reg, domain);
	}


      exit:
	LEAVE(ret);
}

void hw_sm750_crtc_clear(struct lynxfb_crtc *crtc, int domain)
{
	ENTER();
	LEAVE();
}

int hw_sm750_setColReg(struct lynxfb_crtc *crtc, ushort index,
		       ushort red, ushort green, ushort blue, int domain)
{
	static unsigned int add[] = { PANEL_PALETTE_RAM, CRT_PALETTE_RAM };
	POKE32(add[crtc->channel] + index * 4,
	       (red << 16) | (green << 8) | blue, domain);
	return 0;
}

int hw_sm750le_setBLANK(struct lynxfb_output *output, int blank, int domain)
{
	int dpms, crtdb;
	ENTER();
	switch (blank) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_UNBLANK:
#else
	case VESA_NO_BLANKING:
#endif
		dpms = CRT_DISPLAY_CTRL_DPMS_0;
		crtdb = CRT_DISPLAY_CTRL_BLANK_OFF;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_NORMAL:
		dpms = CRT_DISPLAY_CTRL_DPMS_0;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_VSYNC_SUSPEND:
#else
	case VESA_VSYNC_SUSPEND:
#endif
		dpms = CRT_DISPLAY_CTRL_DPMS_2;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_HSYNC_SUSPEND:
#else
	case VESA_HSYNC_SUSPEND:
#endif
		dpms = CRT_DISPLAY_CTRL_DPMS_1;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_POWERDOWN:
#else
	case VESA_POWERDOWN:
#endif
		dpms = CRT_DISPLAY_CTRL_DPMS_3;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
	default:
		LEAVE(-1);
	}

	if (output->paths & sm750_crt) {
		POKE32(CRT_DISPLAY_CTRL,
		       (PEEK32(CRT_DISPLAY_CTRL, domain) &
		       (~(3 << CRT_DISPLAY_CTRL_DPMS_LSB))) | (dpms <<
					     CRT_DISPLAY_CTRL_DPMS_LSB), domain);
		POKE32(CRT_DISPLAY_CTRL,
		       (PEEK32(CRT_DISPLAY_CTRL, domain) &
		       (~(1 << CRT_DISPLAY_CTRL_BLANK_LSB))) | (crtdb <<
					     CRT_DISPLAY_CTRL_BLANK_LSB), domain);
	}
	LEAVE(0);
}

int hw_sm750_setBLANK(struct lynxfb_output *output, int blank, int domain)
{
	unsigned int dpms, pps, crtdb;
	ENTER();
	dpms = pps = crtdb = 0;

	switch (blank) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_UNBLANK:
#else
	case VESA_NO_BLANKING:
#endif
		dbg_msg("flag = FB_BLANK_UNBLANK \n");
		dpms = SYSTEM_CTRL_DPMS_VPHP;
		pps = PANEL_DISPLAY_CTRL_DATA_ENABLE;
		crtdb = CRT_DISPLAY_CTRL_BLANK_OFF;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_NORMAL:
		dbg_msg("flag = FB_BLANK_NORMAL \n");
		dpms = SYSTEM_CTRL_DPMS_VPHP;
		pps = PANEL_DISPLAY_CTRL_DATA_DISABLE;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_VSYNC_SUSPEND:
#else
	case VESA_VSYNC_SUSPEND:
#endif
		dpms = SYSTEM_CTRL_DPMS_VNHP;
		pps = PANEL_DISPLAY_CTRL_DATA_DISABLE;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_HSYNC_SUSPEND:
#else
	case VESA_HSYNC_SUSPEND:
#endif
		dpms = SYSTEM_CTRL_DPMS_VPHN;
		pps = PANEL_DISPLAY_CTRL_DATA_DISABLE;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_POWERDOWN:
#else
	case VESA_POWERDOWN:
#endif
		dpms = SYSTEM_CTRL_DPMS_VNHN;
		pps = PANEL_DISPLAY_CTRL_DATA_DISABLE;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
	}

	if (output->paths & sm750_crt) {
		POKE32(SYSTEM_CTRL,
		       (PEEK32(SYSTEM_CTRL, domain) & (~(3 << SYSTEM_CTRL_DPMS_LSB)))
		       | (dpms << SYSTEM_CTRL_DPMS_LSB), domain);
		POKE32(CRT_DISPLAY_CTRL,
		       (PEEK32(CRT_DISPLAY_CTRL, domain) &
		       (~(1 << CRT_DISPLAY_CTRL_BLANK_LSB)))	
		       | (crtdb << CRT_DISPLAY_CTRL_BLANK_LSB), domain);
	}

	if (output->paths & sm750_panel) {
		POKE32(PANEL_DISPLAY_CTRL,
		       (PEEK32(PANEL_DISPLAY_CTRL, domain) &
		       (~(1 << PANEL_DISPLAY_CTRL_DATA_LSB)))
		       | (pps << PANEL_DISPLAY_CTRL_DATA_LSB), domain);
	}

	LEAVE(0);
}


void hw_sm750_initAccel(struct lynx_share *share, int domain)
{
	u32 reg;
	enable2DEngine(1, domain);

	if (getChipType(domain) == SM750LE) {
		reg = PEEK32(DE_STATE1, domain);
		reg |= 1 << DE_STATE1_DE_ABORT_LSB;
		POKE32(DE_STATE1, reg, domain);

		reg = PEEK32(DE_STATE1, domain);
		reg &= ~(1 << DE_STATE1_DE_ABORT_LSB);
		POKE32(DE_STATE1, reg, domain);

	} else {
		/* engine reset */
		reg = PEEK32(SYSTEM_CTRL, domain);
		reg |= 1 << SYSTEM_CTRL_DE_ABORT_LSB;
		POKE32(SYSTEM_CTRL, reg, domain);

		reg = PEEK32(SYSTEM_CTRL, domain);
		reg &= ~(1 << SYSTEM_CTRL_DE_ABORT_LSB);
		POKE32(SYSTEM_CTRL, reg, domain);
	}

	/* call 2d init */
	share->accel.de_init(&share->accel);
}

int hw_sm750le_deWait(int domain)
{
	int i = 0x10000000;
	while (i--) {
		unsigned int dwVal = PEEK32(DE_STATE2, domain);
		if (((1 & (dwVal >> DE_STATE2_DE_STATUS_LSB)) ==
		     DE_STATE2_DE_STATUS_IDLE)
		    && ((1 & (dwVal >> DE_STATE2_DE_FIFO_LSB)) ==
			DE_STATE2_DE_FIFO_EMPTY)
		    && ((1 & (dwVal >> DE_STATE2_DE_MEM_FIFO_LSB)) ==
			DE_STATE2_DE_MEM_FIFO_EMPTY)) {
			return 0;
		}
	}
	/* timeout error */
	return -1;
}


int hw_sm750_deWait(int domain)
{
	int i = 0x10000000;
	while (i--) {
		unsigned int dwVal = PEEK32(SYSTEM_CTRL, domain);
		if (((1 & (dwVal >> SYSTEM_CTRL_DE_STATUS_LSB)) ==
		     SYSTEM_CTRL_DE_STATUS_IDLE)
		    && ((1 & (dwVal >> SYSTEM_CTRL_DE_FIFO_LSB)) ==
			SYSTEM_CTRL_DE_FIFO_EMPTY)
		    && ((1 & (dwVal >> SYSTEM_CTRL_DE_MEM_FIFO_LSB)) ==
			SYSTEM_CTRL_DE_MEM_FIFO_EMPTY)) {
			return 0;
		}
	}
	/* timeout error */
	return -1;
}

int hw_sm750_pan_display(struct lynxfb_crtc *crtc,
			 const struct fb_var_screeninfo *var,
			 const struct fb_info *info,
			 int domain)
{
	uint32_t total;
	if ((var->xoffset + var->xres > var->xres_virtual) ||
	    (var->yoffset + var->yres > var->yres_virtual)) {
		return -EINVAL;
	}

	total = var->yoffset * info->fix.line_length +
	    ((var->xoffset * var->bits_per_pixel) >> 3);
	total += crtc->oScreen;
	if (crtc->channel == sm750_primary) {
		POKE32(PANEL_FB_ADDRESS,
		       (PEEK32(PANEL_FB_ADDRESS, domain) &
		       (~(0x3ffffff << PANEL_FB_ADDRESS_ADDRESS_LSB))) |
		       (total << PANEL_FB_ADDRESS_ADDRESS_LSB), domain);
	} else {
		POKE32(CRT_FB_ADDRESS,
		       (PEEK32(CRT_FB_ADDRESS, domain) &
		       (~(0x3ffffff << CRT_FB_ADDRESS_ADDRESS_LSB))) |
		       (total << CRT_FB_ADDRESS_ADDRESS_LSB), domain);
	}
	return 0;
}
#else /* !CONFIG_FB_LYNXFB_DOMAINS: */

int hw_sm750_inithw(struct lynx_share *share, struct pci_dev *pdev)
{
	struct sm750_share *spec_share;
	struct init_status *parm;

	ENTER();

	spec_share = container_of(share, struct sm750_share, share);
	parm = &spec_share->state.initParm;
	if (parm->chip_clk == 0)
		parm->chip_clk = (getChipType() == SM750LE) ?
		    DEFAULT_SM750LE_CHIP_CLOCK : DEFAULT_SM750_CHIP_CLOCK;

	if (parm->mem_clk == 0)
		parm->mem_clk = parm->chip_clk;
	if (parm->master_clk == 0)
		parm->master_clk = parm->chip_clk / 3;

	ddk750_initHw((initchip_param_t *) & spec_share->state.initParm);
	/* for sm718, open pci burst */
	if (share->devid == 0x718) {
		POKE32(SYSTEM_CTRL,
		       PEEK32(SYSTEM_CTRL) | (1 <<
					      SYSTEM_CTRL_PCI_BURST_LSB));
	}

	/* sm750 use sii164, it can be setup with default value
	 * by on power, so initDVIDisp can be skipped */

	if (getChipType() != SM750LE) {
		/* does user need CRT ? */
		if (spec_share->state.nocrt) {
			POKE32(MISC_CTRL,
			       PEEK32(MISC_CTRL) |
			       (1 << MISC_CTRL_DAC_POWER_LSB));
			/* shut off dpms */
			POKE32(SYSTEM_CTRL,
			       PEEK32(SYSTEM_CTRL) |
			       (3 << SYSTEM_CTRL_DPMS_LSB));
		} else {
			POKE32(MISC_CTRL,
			       PEEK32(MISC_CTRL) &
			       (~(1 << MISC_CTRL_DAC_POWER_LSB)));
			/* turn on dpms */
			POKE32(SYSTEM_CTRL,
			       PEEK32(SYSTEM_CTRL) &
			       (~(3 << SYSTEM_CTRL_DPMS_LSB)));
		}

		switch (spec_share->state.pnltype) {
		case sm750_doubleTFT:
		case sm750_24TFT:
		case sm750_dualTFT:
			POKE32(PANEL_DISPLAY_CTRL,
			       PEEK32(PANEL_DISPLAY_CTRL) &
			       (~(3 << PANEL_DISPLAY_CTRL_TFT_DISP_LSB)));
			POKE32(PANEL_DISPLAY_CTRL,
			       PEEK32(PANEL_DISPLAY_CTRL) |
			       (spec_share->state.
				pnltype <<
				PANEL_DISPLAY_CTRL_TFT_DISP_LSB));
			break;
		}
	} else {
		/* for 750LE , no DVI chip initilization makes Monitor no signal */
		/* Set up GPIO for software I2C to program DVI chip in the
		   Xilinx SP605 board, in order to have video signal.
		 */
		swI2CInit(0, 1);


		/* Customer may NOT use CH7301 DVI chip, which has to be
		   initialized differently.
		 */
		if (swI2CReadReg(0xec, 0x4a) == 0x95) {
			/* The following register values for CH7301 are from
			   Chrontel app note and our experiment.
			 */
			inf_msg("yes, CH7301 DVI chip found\n");
			swI2CWriteReg(0xec, 0x1d, 0x16);
			swI2CWriteReg(0xec, 0x21, 0x9);
			swI2CWriteReg(0xec, 0x49, 0xC0);
			inf_msg("okay, CH7301 DVI chip setup done\n");
		}
	}

	/* init 2d engine */
	if (!share->accel_off) {
		hw_sm750_initAccel(share);
	}

	LEAVE(0);
}

resource_size_t hw_sm750_getVMSize(struct lynx_share *share)
{
	resource_size_t ret;
	ENTER();
	ret = ddk750_getVMSize();
	LEAVE(ret);
}



int hw_sm750_output_checkMode(struct lynxfb_output *output,
			      struct fb_var_screeninfo *var)
{
	ENTER();
	LEAVE(0);
}


int hw_sm750_output_setMode(struct lynxfb_output *output,
			    struct fb_var_screeninfo *var,
			    struct fb_fix_screeninfo *fix)
{
	int ret;
	disp_output_t dispSet;
	int channel;
	ENTER();
	ret = 0;
	dispSet = 0;
	channel = *output->channel;


	if (getChipType() != SM750LE) {
		if (channel == sm750_primary) {
			inf_msg("primary channel\n");
			if (output->paths & sm750_panel)
				dispSet |= do_LCD1_PRI;
			if (output->paths & sm750_crt)
				dispSet |= do_CRT_PRI;

		} else {
			inf_msg("secondary channel\n");
			if (output->paths & sm750_panel)
				dispSet |= do_LCD1_SEC;
			if (output->paths & sm750_crt)
				dispSet |= do_CRT_SEC;

		}
		ddk750_setLogicalDispOut(dispSet);
	} else {
		/* just open DISPLAY_CONTROL_750LE register bit 3:0 */
		u32 reg;
		reg = PEEK32(DISPLAY_CONTROL_750LE);
		reg |= 0xf;
		POKE32(DISPLAY_CONTROL_750LE, reg);
	}

	inf_msg("ddk setlogicdispout done \n");
	LEAVE(ret);
}

void hw_sm750_output_clear(struct lynxfb_output *output)
{
	ENTER();
	LEAVE();
}

int hw_sm750_crtc_checkMode(struct lynxfb_crtc *crtc,
			    struct fb_var_screeninfo *var)
{
	struct lynx_share *share;
	ENTER();

	share = container_of(crtc, struct lynxfb_par, crtc)->share;

	switch (var->bits_per_pixel) {
	case 8:
	case 16:
		break;
	case 32:
		if (share->revid == (unsigned char) SM750LE_REVISION_ID) {
			dbg_msg("750le do not support 32bpp\n");
			LEAVE(-EINVAL);
		}
		break;
	default:
		LEAVE(-EINVAL);

	}

	LEAVE(0);
}


/*
   set the controller's mode for @crtc charged with @var and @fix parameters
   */
int hw_sm750_crtc_setMode(struct lynxfb_crtc *crtc,
			  struct fb_var_screeninfo *var,
			  struct fb_fix_screeninfo *fix)
{
	int ret, fmt;
	u32 reg;
	mode_parameter_t modparm;
	clock_type_t clock;
	struct lynx_share *share;
	struct lynxfb_par *par;

	ENTER();
	ret = 0;
	par = container_of(crtc, struct lynxfb_par, crtc);
	share = par->share;

	if (!share->accel_off) {
		/* set 2d engine pixel format according to mode bpp */
		switch (var->bits_per_pixel) {
		case 8:
			fmt = 0;
			break;
		case 16:
			fmt = 1;
			break;
		case 32:
		default:
			fmt = 2;
			break;
		}
		hw_set2dformat(&share->accel, fmt);
	}


	/* set timing */
	modparm.pixel_clock = ps_to_hz(var->pixclock);
	modparm.vertical_sync_polarity =
	    (var->sync & FB_SYNC_HOR_HIGH_ACT) ? POS : NEG;
	modparm.horizontal_sync_polarity =
	    (var->sync & FB_SYNC_VERT_HIGH_ACT) ? POS : NEG;
	modparm.clock_phase_polarity =
	    (var->sync & FB_SYNC_COMP_HIGH_ACT) ? POS : NEG;
	modparm.horizontal_display_end = var->xres;
	modparm.horizontal_sync_width = var->hsync_len;
	modparm.horizontal_sync_start = var->xres + var->right_margin;
	modparm.horizontal_total =
	    var->xres + var->left_margin + var->right_margin +
	    var->hsync_len;
	modparm.vertical_display_end = var->yres;
	modparm.vertical_sync_height = var->vsync_len;
	modparm.vertical_sync_start = var->yres + var->lower_margin;
	modparm.vertical_total =
	    var->yres + var->upper_margin + var->lower_margin +
	    var->vsync_len;

	/* choose pll */
	if (crtc->channel != sm750_secondary)
		clock = PRIMARY_PLL;
	else
		clock = SECONDARY_PLL;

	dbg_msg("Request pixel clock = %lu\n", modparm.pixel_clock);
	ret = ddk750_setModeTiming(&modparm, clock);
	if (ret) {
		err_msg("Set mode timing failed\n");
		goto exit;
	}

	if (crtc->channel != sm750_secondary) {
		/* set pitch, offset , width, start address , etc... */
		POKE32(PANEL_FB_ADDRESS,
		       crtc->oScreen << PANEL_FB_ADDRESS_ADDRESS_LSB);
		reg = var->xres * (var->bits_per_pixel >> 3);
		/* crtc->channel is not equal to par->index on numeric, be aware of that */
		reg = PADDING(crtc->line_pad, reg);
		POKE32(PANEL_FB_WIDTH,
		       (reg << PANEL_FB_WIDTH_WIDTH_LSB) |
		       (fix->line_length << PANEL_FB_WIDTH_OFFSET_LSB));

		POKE32(PANEL_WINDOW_WIDTH,
		       ((var->xres - 1) << PANEL_WINDOW_WIDTH_WIDTH_LSB) |
		       (var->xoffset << PANEL_WINDOW_WIDTH_X_LSB));

		POKE32(PANEL_WINDOW_HEIGHT,
		((var->yres_virtual - 1) << PANEL_WINDOW_HEIGHT_HEIGHT_LSB) |
				(var->yoffset << PANEL_WINDOW_HEIGHT_Y_LSB));

		POKE32(PANEL_PLANE_TL, 0);

		POKE32(PANEL_PLANE_BR,
		       ((var->yres - 1) << PANEL_PLANE_BR_BOTTOM_LSB) |
		       ((var->xres - 1) << PANEL_PLANE_BR_RIGHT_LSB));

		/* set pixel format */
		reg = PEEK32(PANEL_DISPLAY_CTRL);
		POKE32(PANEL_DISPLAY_CTRL,
		       (reg & (~(3 << PANEL_DISPLAY_CTRL_FORMAT_LSB))) |
		       ((var->bits_per_pixel >> 4) <<
			PANEL_DISPLAY_CTRL_FORMAT_LSB));
	} else {
		/* not implemented now */
		POKE32(CRT_FB_ADDRESS, crtc->oScreen);
		reg = var->xres * (var->bits_per_pixel >> 3);
		/* crtc->channel is not equal to par->index on numeric, be aware of that */
		reg = PADDING(crtc->line_pad, reg);
		POKE32(CRT_FB_WIDTH,
		       (reg << CRT_FB_WIDTH_WIDTH_LSB) |
		       (fix->line_length << CRT_FB_WIDTH_OFFSET_LSB));

		/* SET PIXEL FORMAT */
		reg = PEEK32(CRT_DISPLAY_CTRL);
		reg |=
		    (var->
		     bits_per_pixel >> 4) << CRT_DISPLAY_CTRL_FORMAT_LSB;
		POKE32(CRT_DISPLAY_CTRL, reg);
	}


      exit:
	LEAVE(ret);
}

void hw_sm750_crtc_clear(struct lynxfb_crtc *crtc)
{
	ENTER();
	LEAVE();
}

int hw_sm750_setColReg(struct lynxfb_crtc *crtc, ushort index,
		       ushort red, ushort green, ushort blue)
{
	static unsigned int add[] = { PANEL_PALETTE_RAM, CRT_PALETTE_RAM };
	POKE32(add[crtc->channel] + index * 4,
	       (red << 16) | (green << 8) | blue);
	return 0;
}

int hw_sm750le_setBLANK(struct lynxfb_output *output, int blank)
{
	int dpms, crtdb;
	ENTER();
	switch (blank) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_UNBLANK:
#else
	case VESA_NO_BLANKING:
#endif
		dpms = CRT_DISPLAY_CTRL_DPMS_0;
		crtdb = CRT_DISPLAY_CTRL_BLANK_OFF;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_NORMAL:
		dpms = CRT_DISPLAY_CTRL_DPMS_0;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_VSYNC_SUSPEND:
#else
	case VESA_VSYNC_SUSPEND:
#endif
		dpms = CRT_DISPLAY_CTRL_DPMS_2;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_HSYNC_SUSPEND:
#else
	case VESA_HSYNC_SUSPEND:
#endif
		dpms = CRT_DISPLAY_CTRL_DPMS_1;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_POWERDOWN:
#else
	case VESA_POWERDOWN:
#endif
		dpms = CRT_DISPLAY_CTRL_DPMS_3;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
	default:
		LEAVE(-1);
	}

	if (output->paths & sm750_crt) {
		POKE32(CRT_DISPLAY_CTRL,
		       (PEEK32(CRT_DISPLAY_CTRL) &
		       (~(3 << CRT_DISPLAY_CTRL_DPMS_LSB))) | (dpms <<
							      CRT_DISPLAY_CTRL_DPMS_LSB));
		POKE32(CRT_DISPLAY_CTRL,
		       (PEEK32(CRT_DISPLAY_CTRL) &
		       (~(1 << CRT_DISPLAY_CTRL_BLANK_LSB))) | (crtdb <<
							       CRT_DISPLAY_CTRL_BLANK_LSB));
	}
	LEAVE(0);
}

int hw_sm750_setBLANK(struct lynxfb_output *output, int blank)
{
	unsigned int dpms, pps, crtdb;
	ENTER();
	dpms = pps = crtdb = 0;

	switch (blank) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_UNBLANK:
#else
	case VESA_NO_BLANKING:
#endif
		dbg_msg("flag = FB_BLANK_UNBLANK \n");
		dpms = SYSTEM_CTRL_DPMS_VPHP;
		pps = PANEL_DISPLAY_CTRL_DATA_ENABLE;
		crtdb = CRT_DISPLAY_CTRL_BLANK_OFF;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_NORMAL:
		dbg_msg("flag = FB_BLANK_NORMAL \n");
		dpms = SYSTEM_CTRL_DPMS_VPHP;
		pps = PANEL_DISPLAY_CTRL_DATA_DISABLE;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_VSYNC_SUSPEND:
#else
	case VESA_VSYNC_SUSPEND:
#endif
		dpms = SYSTEM_CTRL_DPMS_VNHP;
		pps = PANEL_DISPLAY_CTRL_DATA_DISABLE;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_HSYNC_SUSPEND:
#else
	case VESA_HSYNC_SUSPEND:
#endif
		dpms = SYSTEM_CTRL_DPMS_VPHN;
		pps = PANEL_DISPLAY_CTRL_DATA_DISABLE;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	case FB_BLANK_POWERDOWN:
#else
	case VESA_POWERDOWN:
#endif
		dpms = SYSTEM_CTRL_DPMS_VNHN;
		pps = PANEL_DISPLAY_CTRL_DATA_DISABLE;
		crtdb = CRT_DISPLAY_CTRL_BLANK_ON;
		break;
	}

	if (output->paths & sm750_crt) {
		POKE32(SYSTEM_CTRL,
		       (PEEK32(SYSTEM_CTRL) & (~(3 << SYSTEM_CTRL_DPMS_LSB)))
		       | (dpms << SYSTEM_CTRL_DPMS_LSB));
		POKE32(CRT_DISPLAY_CTRL,
		       (PEEK32(CRT_DISPLAY_CTRL) &
		       (~(1 << CRT_DISPLAY_CTRL_BLANK_LSB)))	
		       | (crtdb << CRT_DISPLAY_CTRL_BLANK_LSB));
	}

	if (output->paths & sm750_panel) {
		POKE32(PANEL_DISPLAY_CTRL,
		       (PEEK32(PANEL_DISPLAY_CTRL) &
		       (~(1 << PANEL_DISPLAY_CTRL_DATA_LSB)))
		       | (pps << PANEL_DISPLAY_CTRL_DATA_LSB));
	}

	LEAVE(0);
}


void hw_sm750_initAccel(struct lynx_share *share)
{
	u32 reg;
	enable2DEngine(1);

	if (getChipType() == SM750LE) {
		reg = PEEK32(DE_STATE1);
		reg |= 1 << DE_STATE1_DE_ABORT_LSB;
		POKE32(DE_STATE1, reg);

		reg = PEEK32(DE_STATE1);
		reg &= ~(1 << DE_STATE1_DE_ABORT_LSB);
		POKE32(DE_STATE1, reg);

	} else {
		/* engine reset */
		reg = PEEK32(SYSTEM_CTRL);
		reg |= 1 << SYSTEM_CTRL_DE_ABORT_LSB;
		POKE32(SYSTEM_CTRL, reg);

		reg = PEEK32(SYSTEM_CTRL);
		reg &= ~(1 << SYSTEM_CTRL_DE_ABORT_LSB);
		POKE32(SYSTEM_CTRL, reg);
	}

	/* call 2d init */
	share->accel.de_init(&share->accel);
}

int hw_sm750le_deWait()
{
	int i = 0x10000000;
	while (i--) {
		unsigned int dwVal = PEEK32(DE_STATE2);
		if (((1 & (dwVal >> DE_STATE2_DE_STATUS_LSB)) ==
		     DE_STATE2_DE_STATUS_IDLE)
		    && ((1 & (dwVal >> DE_STATE2_DE_FIFO_LSB)) ==
			DE_STATE2_DE_FIFO_EMPTY)
		    && ((1 & (dwVal >> DE_STATE2_DE_MEM_FIFO_LSB)) ==
			DE_STATE2_DE_MEM_FIFO_EMPTY)) {
			return 0;
		}
	}
	/* timeout error */
	return -1;
}


int hw_sm750_deWait()
{
	int i = 0x10000000;
	while (i--) {
		unsigned int dwVal = PEEK32(SYSTEM_CTRL);
		if (((1 & (dwVal >> SYSTEM_CTRL_DE_STATUS_LSB)) ==
		     SYSTEM_CTRL_DE_STATUS_IDLE)
		    && ((1 & (dwVal >> SYSTEM_CTRL_DE_FIFO_LSB)) ==
			SYSTEM_CTRL_DE_FIFO_EMPTY)
		    && ((1 & (dwVal >> SYSTEM_CTRL_DE_MEM_FIFO_LSB)) ==
			SYSTEM_CTRL_DE_MEM_FIFO_EMPTY)) {
			return 0;
		}
	}
	/* timeout error */
	return -1;
}

int hw_sm750_pan_display(struct lynxfb_crtc *crtc,
			 const struct fb_var_screeninfo *var,
			 const struct fb_info *info)
{
	uint32_t total;
	if ((var->xoffset + var->xres > var->xres_virtual) ||
	    (var->yoffset + var->yres > var->yres_virtual)) {
		return -EINVAL;
	}

	total = var->yoffset * info->fix.line_length +
	    ((var->xoffset * var->bits_per_pixel) >> 3);
	total += crtc->oScreen;
	if (crtc->channel == sm750_primary) {
		POKE32(PANEL_FB_ADDRESS,
		       (PEEK32(PANEL_FB_ADDRESS) &
		       (~(0x3ffffff << PANEL_FB_ADDRESS_ADDRESS_LSB))) |
		       (total << PANEL_FB_ADDRESS_ADDRESS_LSB));
	} else {
		POKE32(CRT_FB_ADDRESS,
		       (PEEK32(CRT_FB_ADDRESS) &
		       (~(0x3ffffff << CRT_FB_ADDRESS_ADDRESS_LSB))) |
		       (total << CRT_FB_ADDRESS_ADDRESS_LSB));
	}
	return 0;
}
#endif /* !CONFIG_FB_LYNXFB_DOMAINS */
