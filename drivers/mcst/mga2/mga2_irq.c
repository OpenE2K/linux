/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "mga2_drv.h"

#define	__rint(__addr) readl(mga2->regs + \
				mga2->info->int_regs_base + MGA2_ ## __addr)
#define	__wint(__v, __addr) writel(__v, mga2->regs + \
				mga2->info->int_regs_base + MGA2_ ## __addr)

#ifdef DEBUG
#define rint(__offset)				\
({								\
	unsigned __val = __rint(__offset);			\
	DRM_DEBUG_KMS("R: %x: %s\n", __val, # __offset);	\
	__val;							\
})

#define wwint(__val, __offset)					\
({								\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("W: %x: %s\n", __val2, # __offset);	\
	__wint(__val2, __offset);				\
})

#else
#define		rint		__rint
#define		wwint		__wint
#endif

irqreturn_t mga2_driver_irq_handler(int irq, void *arg)
{
	struct drm_device *drm = (struct drm_device *)arg;
	struct mga2 *mga2 = drm->dev_private;
	u32 status = rint(INTREQ);
	u32 ena = rint(INTENA);
	int ret = IRQ_HANDLED;
	if (!(status & ena))
		return IRQ_NONE;

	wwint(status & ena, INTREQ);

	if (mga25(mga2)) {
		/* VBLANK interrupt */
		if (status & MGA25_INT_B_DC0_V)
			mga2_handle_vblank(drm, 0);
		if (status & MGA25_INT_B_DC1_V)
			mga2_handle_vblank(drm, 1);
		if (status & MGA25_INT_B_DC2_V)
			mga2_handle_vblank(drm, 2);

		if (status & MGA25_INT_B_SOFTINT)
			mga2_update_ptr(mga2);

		if (status & MGA25_INT_B_V1HDMI) /* hdmi will handle it */
			ret = IRQ_NONE;
		if (status & MGA25_INT_B_V2HDMI) /* hdmi will handle it */
			ret = IRQ_NONE;
	} else {
		/* VBLANK interrupt */
		if (status & MGA2_INT_B_DC0_V)
			mga2_handle_vblank(drm, 0);
		if (status & MGA2_INT_B_DC1_V)
			mga2_handle_vblank(drm, 1);

		if (status & MGA2_INT_B_SOFTINT)
			mga2_update_ptr(mga2);

		if (status & MGA2_INT_B_V1HDMI) /* hdmi will handle it */
			ret = IRQ_NONE;
		if (status & MGA2_INT_B_V2HDMI) /* hdmi will handle it */
			ret = IRQ_NONE;
	}

	return ret;
}

static void mga2_disable_irq(struct mga2 *mga2, u32 mask)
{
	wwint(mask, INTENA);
}

static void mga2_enable_irq(struct mga2 *mga2, u32 mask)
{
	wwint(mask | MGA2_INT_B_SETRST, INTENA);
}

/**
 * mga2_irq_sw_irq_get - enable software interrupt
 *
 * @mga2: mga2 device pointer
 *
 * Enables the software interrupt for the ring.
 * The software interrupt is used to signal a fence on
 * the ring.
 */
void mga2_irq_sw_irq_get(struct mga2 *mga2)
{
	unsigned mask = mga25(mga2) ? MGA25_INT_B_SOFTINT : MGA2_INT_B_SOFTINT;
	if (atomic_inc_return(&mga2->ring_int) == 1) {
		mga2_enable_irq(mga2, mask);
	}
}

/**
 * mga2_irq_sw_irq_put - disable software interrupt
 *
 * @mga2: mga2 device pointer
 *
 * Disables the software interrupt for the ring.
 * The software interrupt is used to signal a fence on
 * the ring.
 */
void mga2_irq_sw_irq_put(struct mga2 *mga2)
{
	unsigned mask = mga25(mga2) ? MGA25_INT_B_SOFTINT : MGA2_INT_B_SOFTINT;
	if (atomic_dec_and_test(&mga2->ring_int))
		mga2_disable_irq(mga2, mask);
}

int mga2_crtc_enable_vblank(struct drm_crtc *crtc)
{
	struct mga2 *mga2 = crtc->dev->dev_private;
	unsigned pipe = crtc->index;
	u32 v = pipe == 0 ? MGA2_INT_B_DC0_V : pipe == 1 ? MGA2_INT_B_DC1_V : 0;
	if (mga25(mga2)) switch(pipe) {
		case 0:
			v = MGA25_INT_B_DC0_V;
			break;
		case 1:
			v = MGA25_INT_B_DC1_V;
			break;
		case 2:
			v = MGA25_INT_B_DC2_V;
			break;
		default:
			WARN_ON(1);
	}
	mga2_enable_irq(mga2, v);

	return 0;
}

void mga2_crtc_disable_vblank(struct drm_crtc *crtc)
{
	struct mga2 *mga2 = crtc->dev->dev_private;
	unsigned pipe = crtc->index;
	u32 v = pipe == 0 ? MGA2_INT_B_DC0_V : pipe == 1 ? MGA2_INT_B_DC1_V : 0;
	if (mga25(mga2)) switch(pipe) {
		case 0:
			v = MGA25_INT_B_DC0_V;
			break;
		case 1:
			v = MGA25_INT_B_DC1_V;
			break;
		case 2:
			v = MGA25_INT_B_DC2_V;
			break;
		default:
			WARN_ON(1);
	}
	mga2_disable_irq(mga2, v);
}

void mga2_driver_irq_preinstall(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;

	atomic_set(&mga2->ring_int, 0);
	/* Disable *all* interrupts */
	wwint(0x7FFFffff, INTENA);
	if (mga25(mga2)) {
		u32 v = MGA2_INT_B_SETRST |
			MGA25_INT_B_V1HDMI | MGA25_INT_B_V2HDMI |
			MGA25_INT_B_V1HDMI_WAKEUP | MGA25_INT_B_V2HDMI_WAKEUP |
			MGA25_INT_B_HDA1 | MGA25_INT_B_HDA2;
		wwint(v, INTLEVEL);
		wwint(v, INTMODE);
	}
	/* Clear *all* interrupts */
	wwint(0x7FFFffff, INTREQ);
}

int mga2_driver_irq_postinstall(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	u32 v = 0;

	switch (mga2->subdevice) {
	case MGA2_P2:
		v = MGA2_INT_B_V1HDMI | MGA2_INT_B_V2HDMI;
		break;
	case MGA25:
		v = MGA25_INT_B_V1HDMI | MGA25_INT_B_V2HDMI;
		break;
	}

	mga2_enable_irq(mga2, v);
	return 0;
}

void mga2_driver_irq_uninstall(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	atomic_set(&mga2->ring_int, 0);

	/* Disable *all* interrupts */
	wwint(0x7FFFffff, INTENA);
}
