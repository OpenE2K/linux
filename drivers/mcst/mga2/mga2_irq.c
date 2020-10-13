//#define DEBUG

#include "mga2_drv.h"

#define	 MGA2_INTENA		0x02000	/* разрешение генерации прерывания */
#define	 MGA2_INTREQ		0x02004	/* состояние запросов прерывания */
#define	 MGA2_INTLEVEL		0x02008	/* указывает активный уровень входного сигнала */
#define	 MGA2_INTMODE		0x0200C	/* указывает режим обработки входных сигналов */

#	define MGA2_INT_B_SETRST (1 << 31)

#	define MGA2_INT_B_VGA0_V (1 << 0)
#	define MGA2_INT_B_VGA1_V (1 << 1)

#	define MGA2_INT_B_DC0_V (1 << 2)
#	define MGA2_INT_B_DC1_V (1 << 3)
#	define MGA2_INT_B_DC0_H (1 << 4)
#	define MGA2_INT_B_DC1_H (1 << 5)

#	define MGA2_INT_B_DC0_WLOAD (1 << 6)
#	define MGA2_INT_B_DC1_WLOAD (1 << 7)

#	define MGA2_INT_B_ROP2_IDLE     (1 << 8)
#	define MGA2_INT_B_ROP2_CANSTART (1 << 9)

#	define MGA2_INT_B_AUC (1 << 10)

#	define MGA2_INT_B_SOFTINT (1 << 11)

#	define MGA2_INT_B_DC0I2C   (1 << 30)
#	define MGA2_INT_B_DC1I2C   (1 << 29)

#	define MGA2_INT_B_V0DDCI2C (1 << 28)
#	define MGA2_INT_B_V1DDCI2C (1 << 27)
#	define MGA2_INT_B_V2DDCI2C (1 << 26)
#	define MGA2_INT_B_V3DDCI2C (1 << 25)

#	define MGA2_INT_B_V0TXI2C (1 << 24)
#	define MGA2_INT_B_V3TXI2C (1 << 23)

#	define MGA2_INT_B_V1HDMI     (1 << 22)
#	define MGA2_INT_B_V1HDMIWUP  (1 << 21)
#	define MGA2_INT_B_V2HDMI     (1 << 20)
#	define MGA2_INT_B_V2HDMIWUP  (1 << 19)

#define	__rint(__addr) readl(mga2->regs + MGA2_ ## __addr)
#define	__wint(__v, __addr) writel(__v, mga2->regs + MGA2_ ## __addr)

#ifdef DEBUG
#define rint(__offset)				\
({								\
	unsigned __val = __rint(__offset);			\
	DRM_DEBUG_KMS("R: %x: %s\n", __val, # __offset);	\
	__val;							\
})

#define wint(__val, __offset)					\
({								\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("W: %x: %s\n", __val2, # __offset);	\
	__wint(__val2, __offset);				\
})

#else
#define		rint		__rint
#define		wint		__wint
#endif

static void mga2_finish_page_flip(struct drm_device *dev, int crtc)
{
	unsigned long flags;
	struct mga2 *mga2 = dev->dev_private;
	struct drm_pending_vblank_event *event = mga2->event[crtc];

	if (!event)
		return;
	spin_lock_irqsave(&dev->event_lock, flags);
	drm_send_vblank_event(dev, event->pipe, event);
	drm_vblank_put(dev, event->pipe);
	mga2->event[crtc] = NULL;
	spin_unlock_irqrestore(&dev->event_lock, flags);
}

irqreturn_t mga2_driver_irq_handler(int irq, void *arg)
{
	struct drm_device *dev = (struct drm_device *)arg;
	struct mga2 *mga2 = dev->dev_private;
	u32 status = rint(INTREQ);
	u32 ena = rint(INTENA);
	if (!(status & ena)) {
		return IRQ_NONE;
	}
	wint(status & ena, INTREQ);
	rint(INTREQ);

	/* VBLANK interrupt */
	if (status & MGA2_INT_B_DC0_V) {
		drm_handle_vblank(dev, 0);
		mga2_finish_page_flip(dev, 0);
	}
	if (status & MGA2_INT_B_DC1_V) {
		drm_handle_vblank(dev, 1);
		mga2_finish_page_flip(dev, 1);
	}

	return IRQ_HANDLED;
}

int mga2_enable_vblank(struct drm_device *dev, int crtc)
{
	struct mga2 *mga2 = dev->dev_private;
	u32 v = crtc == 0 ? MGA2_INT_B_DC0_V : crtc == 1 ? MGA2_INT_B_DC1_V : 0;

	wint(rint(INTLEVEL) | v, INTLEVEL);
	wint(rint(INTMODE) & ~v, INTMODE);
	wint(v | MGA2_INT_B_SETRST, INTENA);

	return 0;
}

void mga2_disable_vblank(struct drm_device *dev, int crtc)
{
	struct mga2 *mga2 = dev->dev_private;
	u32 v = crtc == 0 ? MGA2_INT_B_DC0_V : crtc == 1 ? MGA2_INT_B_DC1_V : 0;

	wint(v, INTENA);
}

void mga2_driver_irq_preinstall(struct drm_device *dev)
{
	struct mga2 *mga2 = dev->dev_private;

	/* Disable *all* interrupts */
	wint(0x7FFFffff, INTENA);
	/* Clear *all* interrupts */
	wint(0x7FFFffff, INTREQ);
}

int mga2_driver_irq_postinstall(struct drm_device *dev)
{
	return 0;
}

void mga2_driver_irq_uninstall(struct drm_device *dev)
{
	struct mga2 *mga2 = dev->dev_private;

	/* Disable *all* interrupts */
	wint(0x7FFFffff, INTENA);
}
