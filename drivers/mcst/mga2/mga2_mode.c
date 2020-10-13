#define DEBUG

#include "mga2_drv.h"


#define	MGA2_DC0_REG_SZ		0x800

#define	__rcrtc(__addr) readl(mga2_crtc->regs + MGA2_DC0_ ## __addr)
#define	__wcrtc(__v, __addr) writel(__v, mga2_crtc->regs + MGA2_DC0_ ## __addr)

#define	__rvidc(__addr) readl(mga2_encoder->regs +  \
				(MGA2_VID0_ ## __addr - MGA2_VID0_BASE))
#define	__wvidc(__v, __addr) writel(__v, mga2_encoder->regs + \
				(MGA2_VID0_ ## __addr - MGA2_VID0_BASE))

#ifdef DEBUG
#define rcrtc(__offset)				\
({								\
	unsigned __val = __rcrtc(__offset);			\
	DRM_DEBUG_KMS("R: %x: %s\n", __val, # __offset);	\
	__val;							\
})

#define wcrtc(__val, __offset)					\
({								\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("W: %x: %s\n", __val2, # __offset);	\
	/*printk(KERN_DEBUG"%x %x\n",  MGA2_DC0_ ## __offset, __val2);*/	\
	__wcrtc(__val2, __offset);				\
})

#else
#define		rcrtc		__rcrtc
#define		wcrtc		__wcrtc
#endif

#ifdef DEBUG
#define rvidc(__offset)				\
({								\
	unsigned __val = __rvidc(__offset);			\
	DRM_DEBUG_KMS("R: %x: %s\n", __val, # __offset);	\
	__val;							\
})

#define wvidc(__val, __offset)					\
({								\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("W: %x: %s\n", __val2, # __offset);	\
	__wvidc(__val2, __offset);				\
})

#else
#define		rvidc		__rvidc
#define		wvidc		__wvidc
#endif


#define  MGA2_VDID		0x00000	/* повторяет Vendor ID и Device ID из PCI config space */
#define  MGA2_REVISION_ID	0x00004	/* повторяет Revision ID из PCI config space */
#define  MGA2_POSSIB0		0x00008
#define  MGA2_POSSIB1		0x0000C	/* указывает на возможности поддерживаемые картой MGA2 (в рамках всей линейки MGA2). */

#define	 MGA2_DC0_CTRL		0x00800	/* общее управление работой дисплейного контроллера */
#define MGA2_DC_B_NO_FETCH	(1 << 16)
#define MGA2_DC_CTRL_NATIVEMODE        (1 << 0)
#define MGA2_DC_CTRL_DIS_VGAREGS       (1 << 1)
#define MGA2_DC_CTRL_LINEARMODE        (1 << 2)
#define MGA2_DC_CTRL_NOSCRRFRSH        (1 << 16)
#define MGA2_DC_CTRL_SOFT_RESET        (1 << 31)

#define	 MGA2_DC0_VGAWINOFFS		0x00804	/* сдвиг отображаемой в VGA-MEM области памяти. */
#define	 MGA2_DC0_VGABASE		0x00808	/* адрес в видеопамяти дисплейного контроллер */
#define	 MGA2_DC0_VGAREGS		0x0080С	/* доступ в VGA-IO пространство регистров. */
#define	 MGA2_DC0_TMPADDR		0x00810	/* Адрес off-screen области видеопамяти для различных временных буферов видеоконтроллера */

#define	 MGA2_DC0_PIXFMT		0x00820	/* формат изображаемых пикселей */
#define MGA2_DC_B_EXT_TXT		(1 << 31)
#define MGA2_DC_B_BGR			(0x24 << 4)
#define MGA2_DC_B_RGB			(6 << 4)
#define MGA2_DC_B_32BPP_FMT		(1 << 3)
#define MGA2_DC_B_16BPP_FMT		(1 << 2)
#define MGA2_DC_B_8BPP			0
#define MGA2_DC_B_16BPP			1
#define MGA2_DC_B_24BPP			2
#define MGA2_DC_B_32BPP			3

#ifdef __LITTLE_ENDIAN
#define MGA2_DC_B_COLOR_ORDER	MGA2_DC_B_RGB
#elif __BIG_ENDIAN
#define MGA2_DC_B_COLOR_ORDER	(MGA2_DC_B_BGR | MGA2_DC_B_32BPP_FMT)
#else
#error byte order not defined
#endif

#define	 MGA2_DC0_WSTART		0x00830	/* текущий стартовый адрес экрана (R/O) */
#define	 MGA2_DC0_WOFFS		0x00834	/* текущий шаг строк экрана (R/O) */
#define	 MGA2_DC0_WCRSADDR		0x00838	/* текущий адрес и управление курсором (R/O) */
#define	 MGA2_DC0_WCRSCOORD		0x0083C	/* текущие координаты курсора (R/O) */
#define	 MGA2_DC0_WPALID		0x00840	/* текущая страница палитры и ID (R/O) */
#define	 MGA2_DC0_NSTART		0x00850	/* следующий стартовый адрес экрана (R/W) */
#define	 MGA2_DC0_NOFFS		0x00854	/* следущий шаг строк экрана (R/W) */

#define	 MGA2_DC0_NCRSADDR		0x00858	/* следущий адрес и управление курсором (R/W) */
#define	 MGA2_DC_B_CRS_ENA		(1 << 0)

#define	 MGA2_DC0_NCRSCOORD		0x0085C	/* следущие координаты курсора (R/W) */
#define	 MGA2_DC0_NPALID		0x00860	/* следущая страница палитры и ID (R/W) */
#define	 MGA2_DC0_DISPCTRL		0x00864	/* управление переключением дисплейных буферов курсора и палитры */
#define MGA2_DC_B_STROB        (1 << 31)

#define	 MGA2_DC0_HVCTRL		0x00870	/* управление развёртками */

#define MGA2_DC_B_CSYNC_MODE    (1 << 16)
#define MGA2_DC_B_HSYNC_ENA     (1 << 11)
#define MGA2_DC_B_VSYNC_ENA     (1 << 10)
#define MGA2_DC_B_CSYNC_ENA     (1 << 9)
#define MGA2_DC_B_DE_ENA        (1 << 8)
#define MGA2_DC_B_HSYNC_POL     (1 << 3)
#define MGA2_DC_B_VSYNC_POL     (1 << 2)
#define MGA2_DC_B_CSYNC_POL     (1 << 1)
#define MGA2_DC_B_DE_POL        (1 << 0)

#define	 MGA2_DC0_HSYNC		0x00874	/* ширина сигнала горизонтальной синхронизации */
#define	 MGA2_DC0_HDELAY		0x00878	/* задержка между горизонтальным синхроиспульс */
#define	 MGA2_DC0_HVIS		0x0087C	/* ширина видимой области */
#define	 MGA2_DC0_HTOT		0x00880	/* полная ширина строки */
#define	 MGA2_DC0_VSYNC		0x00884	/* высота сигнала вертикальной синхронизации */
#define	 MGA2_DC0_VDELAY		0x00888	/* задержка между вертикальным синхроиспульсом и видимой областью */
#define	 MGA2_DC0_VVIS		0x0088C	/* высота видимой области */
#define	 MGA2_DC0_VTOT		0x00890	/* полный размер кадра */
#define	 MGA2_DC0_HCOUNT		0x00894	/* счётчик горизонтальной развёртки */
#define	 MGA2_DC0_VCOUNT		0x00898	/* счётчик вертикальной развёртки */
#define	 MGA2_DC0_PALADDR		0x008A0	/* регистр адреса палитры */

#define	 MGA2_DC_B_AUTOINC       (1 << 31)

#define	 MGA2_DC0_PALDATA		0x008A4	/* регистр данных палитры */
#define	 MGA2_DC0_GAMCTRL		0x008A8	/* регистр управления гамма-коррекцией */
#define MGA2_DC_GAMCTRL_ENABLE		(1 << 31)

#define	 MGA2_DC0_GAMSET		0x008AC	/* регистр установки таблиц гамма-коррекции */
#define MGA2_DC_GAMSET_SEL_BLUE        (1 << 8)
#define MGA2_DC_GAMSET_SEL_GREEN       (1 << 9)
#define MGA2_DC_GAMSET_SEL_RED         (1 << 10)
#define MGA2_DC_GAMSET_SEL_ALL         (7 << 8)
#define MGA2_DC_GAMSET_ADDR_OFFSET     16

#define	 MGA2_DC0_DITCTRL		0x008B0	/* регистр управления дизерингом */
#define MGA2_DC_DITCTRL_ENABLE         (1 << 31)
#define MGA2_DC_DITCTRL_DISABLE        (0 << 31)

#define	 MGA2_DC0_DITSET0		0x008B4	/* регистр установки таблицы дизеринга */
#define	 MGA2_DC0_DITSET1		0x008B8	/* регистр установки таблицы дизеринга */

#define	 MGA2_DC0_CLKCTRL		0x008C0	/* регистр управления пиксельной частотой */
#define MGA2_DC_B_ARST          (1 << 31)
#define MGA2_DC_B_AUTOCLK       (1 << 30)
#define MGA2_DC_B_EXTDIV_ENA    (1 << 29)
#define MGA2_DC_B_EXTDIV_BYPASS (1 << 28)
#define MGA2_DC_B_EXTDIV_UPD    (1 << 27)
#define MGA2_DC_B_EXTDIV_SEL_OFFSET    25
#define MGA2_DC_B_PIXDIV_ENA    (1 << 24)
#define MGA2_DC_B_PIXDIV_BYPASS (1 << 23)
#define MGA2_DC_B_PIXDIV_UPD    (1 << 22)
#define MGA2_DC_B_PIXDIV_SEL_OFFSET    20
#define MGA2_DC_B_AUXDIV_ENA    (1 << 19)
#define MGA2_DC_B_AUXDIV_BYPASS (1 << 18)
#define MGA2_DC_B_AUXDIV_UPD    (1 << 17)
#define MGA2_DC_B_AUXDIV_SEL_OFFSET    15
#define MGA2_DC_B_PLLMUX_BYPASS (1 << 14)
#define MGA2_DC_B_PLLMUX_UPD    (1 << 13)
#define MGA2_DC_B_PLLMUX_SENSE0 (1 << 10)
#define MGA2_DC_B_PIXMUX_BYPASS (1 << 9)
#define MGA2_DC_B_PIXMUX_UPD    (1 << 8)
#define MGA2_DC_B_PIXMUX_SEL_OFFSET	7
#define MGA2_DC_B_PIXMUX_SENSE1 (1 << 6)
#define MGA2_DC_B_PIXMUX_SENSE0 (1 << 5)
#define MGA2_DC_B_AUXMUX_BYPASS (1 << 4)
#define MGA2_DC_B_AUXMUX_UPD    (1 << 3)
#define MGA2_DC_B_AUXMUX_SEL_OFFSET	2
#define MGA2_DC_B_AUXMUX_SENSE1 (1 << 1)
#define MGA2_DC_B_AUXMUX_SENSE0 (1 << 0)

#define MGA2_DC_B_CLKDIV_ALL	3
#define MGA2_DC_B_CLKDIV_DIV2	0
#define MGA2_DC_B_CLKDIV_DIV4	1
#define MGA2_DC_B_CLKDIV_DIV6	2
#define MGA2_DC_B_CLKDIV_DIV7	3
#define MGA2_DC_B_CLKMUX_ALL	1
#define MGA2_DC_B_CLKMUX_SELPLL	1
#define MGA2_DC_B_CLKMUX_SELEXT	0

#define	 MGA2_DC0_CLKCTRL_ACLKON	0x008C4	/* автоматическое переключение частоты в процессе */
#define	 MGA2_DC0_INTPLLCTRL		0x008D0	/* управление внутренним PLL общий контроль */
#define	 MGA2_DC0_INTPLLCLKF0		0x008E0	/* управление внутренним PLL, CLKF #0 */
#define	 MGA2_DC0_INTPLLCLKR0		0x008E4	/* управление внутренним PLL, CLKR #0 */
#define	 MGA2_DC0_INTPLLCLKOD0		0x008E8	/* управление внутренним PLL, CLKOD #0 */
#define	 MGA2_DC0_INTPLLBWADJ0		0x008EC	/* управление внутренним PLL, BWADJ #0 */
#define	 MGA2_DC0_INTPLLCLKF1		0x008F0	/* управление внутренним PLL, CLKF #1 */
#define	 MGA2_DC0_INTPLLCLKR1		0x008F4	/* управление внутренним PLL, CLKR #1 */
#define	 MGA2_DC0_INTPLLCLKOD1		0x008F8	/* управление внутренним PLL, CLKOD #1 */
#define	 MGA2_DC0_INTPLLBWADJ1		0x008FC	/* управление внутренним PLL, BWADJ #1 */

#define MGA2_DC_B_INTPLL_TEST	( 1 << 0 )
#define MGA2_DC_B_INTPLL_BYPASS	( 1 << 8 )
#define MGA2_DC_B_INTPLL_RESET	( 1 << 16 )
#define MGA2_DC_B_INTPLL_PWRDN	( 1 << 24 )
#define MGA2_DC_B_INTPLL_LOCK	( 1 << 31 )
#define MGA2_DC_B_INTPLL_ACLKON	( 1 << 0 )

#define MGA2_25175_CLKF		430
#define MGA2_25175_CLKR		61
#define MGA2_25175_CLKOD	14
#define MGA2_25175_BWADJ	215
#define MGA2_28322_CLKF		341
#define MGA2_28322_CLKR		43
#define MGA2_28322_CLKOD	14
#define MGA2_28322_BWADJ	170

#define MGA2_DC0_EXTPLLI2C                      0x00900
# define MGA2_DC_EXTPLLI2C_RD            (0 << 31)
# define MGA2_DC_EXTPLLI2C_WR            (1 << 31)
# define MGA2_DC_EXTPLLI2C_ADDR_OFFSET   8L

#define	MGA2_DC0_GPIO_MUX		0x00920	/* мультиплексирование GPIO. */
#define MGA2_DC_B_GPIOMUX_CS1		(1 << 1)
#define MGA2_DC_B_GPIOMUX_CS0		(1 << 0)
#define	MGA2_DC0_GPIO_MUXSETRST		0x00924	/* побитовая установка или очистка регистра \
							   MGA2_DC0_GPIO_MUX. */
#define	 MGA2_DC0_GPIO_PUP		0x00928	/* управление пуллапами GPIO. */
#define	 MGA2_DC0_GPIO_PUPSETRST		0x0092C	/* побитовая установка или очистка регистра \
							   MGA2_DC0_GPIO_PUP */
#define	 MGA2_DC0_GPIO_DIR		0x00930	/* управление направлением пина (вход или выход). */
#define	 MGA2_DC0_GPIO_DIRSETRST		0x00934	/* побитовая установка или очистка регистра \
							   MGA2_DC0_GPIO_DIR */
#define	 MGA2_DC0_GPIO_OUT		0x00938	/* установка уровня пина при его работе на выход. */
#define	 MGA2_DC0_GPIO_OUTSETRST		0x0093C	/* побитовая установка или очистка регистра \
							   MGA2_DC0_GPIO_OUT */
#define	 MGA2_DC0_GPIO_IN		0x00940	/* чтение состояния пинов. */

#define	 MGA2_VID0_BASE		0x02400
#define	 MGA2_VID0_SZ		0x400

#define MGA2_VID0_B_MODE_OFFSET	0
#define MGA2_VID0_B_MODE_ALL	3
#define MGA2_VID0_B_MODE_2XDDR	2
#define MGA2_VID0_B_MODE_1XDDR	1
#define MGA2_VID0_B_MODE_SDR	0
#define MGA2_VID0_B_STROBE_DELAY_OFFSET	8
#define MGA2_VID0_B_STROBE_DELAY_ALL	3
#define MGA2_VID0_B_STROBE_DELAY_0	0
#define MGA2_VID0_B_STROBE_DELAY_1_4	1
#define MGA2_VID0_B_STROBE_DELAY_1_2	2
#define MGA2_VID0_B_STROBE_DELAY_3_4	3
#define MGA2_VID0_B_DDR_LOW_FIRST	( 1 << 10 )
#define MGA2_VID0_B_2XDDR_EN_RESYNC	( 1 << 11 )
#define MGA2_VID0_B_1XDDR_EN_COPY	( 1 << 16 )
#define MGA2_VID0_B_ENABLE	( 1 << 31 )

#define MGA2_VID_B_SAFE_EXC_WR	( 1 << 0 )
#define MGA2_VID_B_SAFE_EXC_RD	( 1 << 1 )
#define MGA2_VID_B_EXC_WR	( 1 << 2 )
#define MGA2_VID_B_EXC_RD	( 1 << 3 )
#define MGA2_VID_B_SAFE_MODESET	( 1 << 31 )

#define MGA2_VID_B_MUX_OFFSET	0
#define MGA2_VID_B_MUX_ALL	3
#define MGA2_VID_B_MUX_NONE	0
#define MGA2_VID_B_MUX_DC0	2
#define MGA2_VID_B_MUX_DC1	3
#define MGA2_VID0_B_GPIOMUX_I2C	3
#define MGA2_VID0_B_GPIOMUX_GPIO	0

#define	 MGA2_VID0_MUX		0x02400	/* мультиплексор видеовыходов */
#define	 MGA2_VID0_CTRL		0x02410	/* управление видеовыходом #0 */
#define	 MGA2_VID0_RESYNC_CTRL		0x02414	/* управление пересинхронизацией через FIFO. */
#define	 MGA2_VID0_TXI2C		0x02420	/* управление I2C-контроллером DVI-передатчиков. */
#define	 MGA2_VID0_DDCI2C		0x02430	/* управление I2C-контроллером DDC. */
#define	 MGA2_VID0_GPIO_MUX		0x02440	/* мультиплексирование GPIO. */
#define	 MGA2_VID0_GPIO_MUXSETRST		0x02444	/* побитовая установка или очистка регистра MGA2_VID0_GPIO_MUX. */
#define	 MGA2_VID0_GPIO_PUP		0x02448	/* управление пуллапами GPIO. */
#define	 MGA2_VID0_GPIO_PUPSETRST		0x0244C	/* побитовая установка или очистка регистра MGA2_VID0_GPIO_PUP */
#define	 MGA2_VID0_GPIO_DIR		0x02450	/* управление направлением пина (вход или выход). */
#define	 MGA2_VID0_GPIO_DIRSETRST		0x02454	/* побитовая установка или очистка регистра MGA2_VID0_GPIO_DIR */
#define	 MGA2_VID0_GPIO_OUT		0x02458	/* установка уровня пина при его работе на выход. */
#define	 MGA2_VID0_GPIO_OUTSETRST		0x0245C	/* побитовая установка или очистка регистра MGA2_VID0_GPIO_OUT */
#define	 MGA2_VID0_GPIO_IN		0x02460	/* чтение состояния пинов. */


#define	DVO_SIL1178_MASTER_ADDR	 (0x70 >> 1)	/* 7 bit addressing */
#define	DVO_SIL1178_SLAVE_ADDR	 (0x72 >> 1)	/* 7 bit addressing */

static struct mga2_i2c_chan *mga2_i2c_create(struct drm_device *dev,
					     void __iomem * regs, char *name);
static void mga2_i2c_destroy(struct mga2_i2c_chan *i2c);

static int mga2_cursor_init(struct drm_crtc *crtc);
static void mga2_cursor_fini(struct drm_crtc *crtc);

static void mga2_pll_init_pixclock(struct mga2_i2c_chan *i2c);
static void mga2_pll_set_pixclock(int pll, struct mga2_i2c_chan *i2c,
				  uint32_t pixclock);


static u8 mga2_i2c_rd(struct mga2_i2c_chan *i2c_bus, u8 slave_addr, u8 addr)
{
	u8 val = 0;
	u8 out_buf[2];
	u8 in_buf[2];
	struct i2c_msg msgs[] = {
		{
		 .addr = slave_addr,
		 .flags = 0,
		 .len = 1,
		 .buf = out_buf,
		 },
		{
		 .addr = slave_addr,
		 .flags = I2C_M_RD,
		 .len = 1,
		 .buf = in_buf,
		 }
	};

	out_buf[0] = addr;
	out_buf[1] = 0;

	if (i2c_transfer(&i2c_bus->adapter, msgs, 2) == 2) {
		val = in_buf[0];
		DRM_DEBUG("%s: rd: 0x%02x: 0x%02x\n", i2c_bus->adapter.name,
			  addr, val);
	} else {
		DRM_DEBUG("i2c 0x%02x 0x%02x read failed\n", addr, val);
	}
	return val;
}

static void mga2_i2c_wr(struct mga2_i2c_chan *i2c_bus,
			u8 slave_addr, u8 addr, u8 val)
{
	uint8_t out_buf[2];
	struct i2c_msg msg = {
		.addr = slave_addr,
		.flags = 0,
		.len = 2,
		.buf = out_buf,
	};

	out_buf[0] = addr;
	out_buf[1] = val;

	DRM_DEBUG("%s: wr: 0x%02x: 0x%02x\n", i2c_bus->adapter.name, addr, val);
	if (i2c_transfer(&i2c_bus->adapter, &msg, 1) != 1)
		DRM_DEBUG("i2c 0x%02x 0x%02x write failed\n", addr, val);
}

static void mga2_crtc_load_lut(struct drm_crtc *crtc)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	int i;
	if (!crtc->enabled)
		return;

	wcrtc(MGA2_DC_B_AUTOINC, PALADDR);

	for (i = 0; i < 256; i++) {
		__wcrtc((mga2_crtc->lut_r[i] << 16) |
			(mga2_crtc->lut_g[i] << 8) |
			(mga2_crtc->lut_b[i] << 0), PALDATA);
	}
	wcrtc(MGA2_DC_B_STROB, DISPCTRL);
	wcrtc(MGA2_DC_CTRL_NATIVEMODE | MGA2_DC_CTRL_DIS_VGAREGS, CTRL);
}

void mga2_set_start_address_crt1(struct drm_crtc *crtc, unsigned offset)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	wcrtc(offset, NSTART);
	wcrtc(MGA2_DC_B_STROB, DISPCTRL);
}

static void mga2_crtc_dpms(struct drm_crtc *crtc, int mode)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	u32 ctrl = rcrtc(CTRL);
	u32 hvctrl = rcrtc(HVCTRL);
	hvctrl &= ~(MGA2_DC_B_HSYNC_ENA | MGA2_DC_B_VSYNC_ENA |
		    MGA2_DC_B_DE_ENA);
	switch (mode) {
	case DRM_MODE_DPMS_ON:
		ctrl &= ~MGA2_DC_CTRL_SOFT_RESET;
		hvctrl |= MGA2_DC_B_HSYNC_ENA | MGA2_DC_B_VSYNC_ENA |
		    MGA2_DC_B_DE_ENA;
		break;
	case DRM_MODE_DPMS_STANDBY:
		hvctrl |= MGA2_DC_B_VSYNC_ENA;
		break;
	case DRM_MODE_DPMS_SUSPEND:
		hvctrl |= MGA2_DC_B_HSYNC_ENA;
		break;
	case DRM_MODE_DPMS_OFF:
		ctrl |= MGA2_DC_CTRL_SOFT_RESET;
		break;
	}

	wcrtc(hvctrl, HVCTRL);
	wcrtc(ctrl, CTRL);
}

static bool mga2_crtc_mode_fixup(struct drm_crtc *crtc,
				 const struct drm_display_mode *mode,
				 struct drm_display_mode *adjusted_mode)
{
	return true;
}

static int mga2_crtc_do_set_base(struct drm_crtc *crtc,
				 struct drm_framebuffer *old_fb,
				 int x, int y, int atomic)
{
	struct mga2_framebuffer *mga2_fb = to_mga2_framebuffer(crtc->fb);
	struct mga2 *mga2 = crtc->dev->dev_private;
	struct drm_mm_node *node = mga2_fb->gobj->driver_private;

	mga2_set_start_address_crt1(crtc, node->start - mga2->vram_paddr);

	return 0;
}

static int mga2_crtc_mode_set_base(struct drm_crtc *crtc, int x, int y,
				   struct drm_framebuffer *old_fb)
{
	return mga2_crtc_do_set_base(crtc, old_fb, x, y, 0);
}

#define TIMEOUT_PLL_USEC	(50 * 1000)

#define mga2_wait_bit(__reg, __bitmask) do {		\
	int __i;					\
	for(__i = 0; __i < TIMEOUT_PLL_USEC / 10; __i++) {	\
		if(__rcrtc(__reg) & __bitmask)		\
			break;				\
		udelay(10);				\
	}						\
	if (__i == TIMEOUT_PLL_USEC) {			\
		DRM_ERROR("timeout on waiting %s bit \n", #__bitmask);	\
		ret = -ETIME;				\
		goto out;				\
	}						\
} while(0)

#define mga2_wait_bit_clear(__reg, __bitmask) do {	\
	int __i;					\
	for(__i = 0; __i < TIMEOUT_PLL_USEC / 10; __i++) {\
		if((__rcrtc(__reg) & __bitmask) == 0)	\
			break;				\
		udelay(10);				\
	}						\
	if (__i == TIMEOUT_PLL_USEC) {			\
		DRM_ERROR("timeout on waiting %s bit \n", #__bitmask);	\
		ret = -ETIME;				\
		goto out;				\
	}						\
} while(0)


#if 1 // MGA2_USE_EXT_PLL
#define MGA2_PIXMUX_SEL MGA2_DC_B_CLKMUX_SELEXT
#define MGA2_AUXMUX_SEL MGA2_DC_B_CLKMUX_SELEXT
#else /* !MGA2_USE_EXT_PLL */
#define MGA2_PIXMUX_SEL MGA2_DC_B_CLKMUX_SELPLL
#define MGA2_AUXMUX_SEL MGA2_DC_B_CLKMUX_SELPLL
#endif /* MGA2_USE_EXT_PLL */

static int mga2_crtc_mode_set(struct drm_crtc *crtc,
			      struct drm_display_mode *mode,
			      struct drm_display_mode *adjusted_mode,
			      int x, int y, struct drm_framebuffer *old_fb)
{
	u32 val;
	struct mga2 *mga2 = crtc->dev->dev_private;
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	uint32_t pixclock = KHZ2PICOS(mode->clock * mga2_crtc->clk_mult);
	uint32_t hvctrl, pixfmt, clkctrl;
	int bpp = crtc->fb->bits_per_pixel, ret = 0;

	/* The Horizontal Syncronization Time (Sync Pulse) */
	int hsync = mode->hsync_end - mode->hsync_start;

	/* The Horizontal Gate Delay Time (Back Porch) */
	int hgdel = mode->htotal - mode->hsync_end;

	/* The Horizontal Gate Time (Active Time) */
	int hgate = mode->hdisplay;

	/* The Horizontal Length Time (Line Total) */
	int hlen = mode->htotal;

	/* The Vertical Syncronization Time (Sync Pulse) */
	int vsync = mode->vsync_end - mode->vsync_start;

	/* The Vertical Gate Delay Time (Back Porch) */
	int vgdel = mode->vtotal - mode->vsync_end;

	/* The Vertical Gate Time (Active Time) */
	int vgate = mode->vdisplay;

	/* The Vertical Length Time (Frame total) */
	int vlen = mode->vtotal;

	//1. Установить синхронный сброс в регистре MGA2_DC*_CTRL.
	wcrtc(MGA2_DC_CTRL_SOFT_RESET, CTRL);

/* internal PLL doesn't work
	wcrtc(CLKCTRL, 0);
	wcrtc(INTPLLCTRL, (rcrtc(INTPLLCTRL)
		| MGA2_DC_B_PD | MGA2_DC_B_FOUTVCOPD | MGA2_DC_B_FOUT4PHASEPD)
		& ~(MGA2_DC_B_FOUTPOSTDIVPD | MGA2_DC_B_DACPD));
	wcrtc(INTPLLSET0);
	wcrtc(INTPLLFRAC0);
	udelay(1);
	wcrtc(INTPLLCTRL, rcrtc(INTPLLCTRL) & ~MGA2_DC_B_PD);
	for(i = 0; i < TIMEOUT_PLL_USEC; i++) {
		if(rcrtc(INTPLLCTRL) & MGA2_DC_B_LOCK)
			break;
		udelay(1);
	}
	if (i == TIMEOUT_PLL_USEC)
		return -1;
*/
	/*
	2. Настроить м/сх внешней PLL CY22394 через регистр MGA2_DC0_EXTPLLI2C.
	Частота должна выдаваться на порт PCLK и иметь диапазон 125-375
	МГц. Следует настроить PLL так, чтобы входные сигналы S0,S1,S2
	не влияли на частоту. Для дисплейного контроллера #1 используется
	ещё одна м/сх, управляемая регистром MGA2_DC1_EXTPLLI2C.
	*/
	mga2_pll_set_pixclock(mga2_crtc->pll, mga2_crtc->i2c, pixclock);

	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_EXTDIV_UPD);
	clkctrl = rcrtc(CLKCTRL) & ~(MGA2_DC_B_ARST | MGA2_DC_B_EXTDIV_BYPASS |
				     (3 << MGA2_DC_B_EXTDIV_SEL_OFFSET));
	clkctrl |= mga2->subdevice == MGA2_P2_PROTO ?
			(1 << MGA2_DC_B_EXTDIV_SEL_OFFSET) :
			 MGA2_DC_B_EXTDIV_BYPASS;
	clkctrl |= MGA2_DC_B_EXTDIV_ENA;
	wcrtc(clkctrl, CLKCTRL);
	clkctrl |= MGA2_DC_B_EXTDIV_UPD;
	wcrtc(clkctrl, CLKCTRL);

	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_EXTDIV_UPD);
	mga2_wait_bit(CLKCTRL, MGA2_DC_B_AUXMUX_SENSE0);
	mga2_wait_bit(CLKCTRL, MGA2_DC_B_PIXMUX_SENSE0);

	/*
	3. Настроить PIXMUX и AUXMUX ([5],[4],[1]) на пропуск клока от EXTDIV
	(см. первый рисунок в [4]) ? регистр MGA2_DC0_CLKCTRL
	*/
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXMUX_UPD);
	val = rcrtc(CLKCTRL) & ~(MGA2_DC_B_PIXMUX_BYPASS |
			(MGA2_DC_B_CLKMUX_ALL << MGA2_DC_B_PIXMUX_SEL_OFFSET));
	val |= (MGA2_PIXMUX_SEL << MGA2_DC_B_PIXMUX_SEL_OFFSET);
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_PIXMUX_UPD;
	wcrtc(val, CLKCTRL);
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXMUX_UPD);

	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_AUXMUX_UPD);
	val = rcrtc(CLKCTRL) & ~(MGA2_DC_B_AUXMUX_BYPASS |
		(MGA2_DC_B_CLKMUX_ALL << MGA2_DC_B_AUXMUX_SEL_OFFSET));
	val |= (MGA2_AUXMUX_SEL << MGA2_DC_B_AUXMUX_SEL_OFFSET);
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_AUXMUX_UPD;
	wcrtc(val, CLKCTRL);
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_AUXMUX_UPD);
	/*
	4. Настроить EXTDIV, PIXDIV и AUXDIV в соответствии с таблицами
	в [4] (настройка зависит от режима работы видеовыходов) ? регистр
	MGA2_DC0_CLKCTRL
	*/
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXDIV_UPD);
	val = rcrtc(CLKCTRL) & ~(MGA2_DC_B_PIXDIV_BYPASS |
		(MGA2_DC_B_CLKDIV_ALL << MGA2_DC_B_PIXDIV_SEL_OFFSET));
	val |= (MGA2_DC_B_CLKDIV_DIV2 << MGA2_DC_B_PIXDIV_SEL_OFFSET) |
			 MGA2_DC_B_PIXDIV_ENA;
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_PIXDIV_UPD;
	wcrtc(val, CLKCTRL);
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_PIXDIV_UPD);

	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_AUXDIV_UPD);
	val = rcrtc(CLKCTRL) & ~(MGA2_DC_B_CLKDIV_ALL <<
			 		MGA2_DC_B_AUXDIV_SEL_OFFSET);
	val |= MGA2_DC_B_AUXDIV_BYPASS | MGA2_DC_B_AUXDIV_ENA;
	wcrtc(val, CLKCTRL);
	val |= MGA2_DC_B_AUXDIV_UPD;
	wcrtc(val, CLKCTRL);
	mga2_wait_bit_clear(CLKCTRL, MGA2_DC_B_AUXDIV_UPD);
	/*
	5. Запретить автоматическое переключение частоты (регистры MGA2_DC0_CLKCTRL,
	MGA2_DC0_CLKCTRL_ACLKON)
	6. установить источник сигнала для видеовыхода 0 ? дисплейный контроллер
	0 (регистр MGA2_VID0_MUX) [1]
	7. Настроить требуемый режим работы видеовыхода, в т.ч. разрешить
	его (MGA2_VID0_CTRL) [1], руководствоваться таблицей в [4] в зависимости
	от требуемого формата сигналов на видеовыходе.
	8. Что-то сделать с регистром MGA2_VID0_RESYNC_CTRL [1]. Предположение:
	установить бит 31 в 0, посмотреть, что будет.
	*/

	/*
	4. Очистить биты 0, 16 и при необходимости установить бит 2 в регистре
	MGA2_DC*_CTRL. Бит 1 установить, если планируются обращения
	в VGA-регистры через MEMBAR, для обращения через IO-space этот
	бит очистить.
	5. При необходимости установить регистр MGA2_DC0_VGAWINOFFS.
	6. Установить регистры MGA2_DC*_VGABASE, MGA2_DC*_TMPADDR.
	7. При необходимости настроить гамма-коррекцию и дизеринг так же,
	как описано в 2.3.
	8. Убрать синхронный сброс в регистре MGA2_DC*_CTRL.
	9. Произвести настройку VGA-видеорежима, используя VGA-регистры.
	Доступ в регистры производится в соответствии с битом 1 регистра
	MGA2_DC*_CTRL ? либо через IO-space, либо через регистр MGA2_DC*_VGAREGS.
	Примечание: для DC1 отсутствует возможность доступа через IO-
	space.
	*/

	pixfmt = MGA2_DC_B_COLOR_ORDER;
	switch (bpp) {
	case 8:
		pixfmt |= MGA2_DC_B_8BPP;
		break;
	case 16:
		if (crtc->fb->depth == 16)
			pixfmt |= MGA2_DC_B_16BPP_FMT;
		pixfmt |= MGA2_DC_B_16BPP;
		break;
	case 24:
		pixfmt |= MGA2_DC_B_24BPP;
		break;
	case 32:
		pixfmt |= MGA2_DC_B_32BPP;
		break;
	default:
		DRM_ERROR("Invalid color depth: %d\n", bpp);
		return -EINVAL;
	}

	wcrtc(pixfmt, PIXFMT);
	wcrtc(hsync, HSYNC);
	wcrtc(hgdel, HDELAY);
	wcrtc(hgate, HVIS);
	wcrtc(hlen, HTOT);
	wcrtc(vsync, VSYNC);
	wcrtc(vgdel, VDELAY);
	wcrtc(vgate, VVIS);
	wcrtc(vlen, VTOT);
	wcrtc(mode->hdisplay * (bpp / 8), NOFFS);

	hvctrl = MGA2_DC_B_DE_ENA;
	if (mode->flags & DRM_MODE_FLAG_NVSYNC)
		hvctrl |= MGA2_DC_B_VSYNC_POL | MGA2_DC_B_VSYNC_ENA;
	else if (mode->flags & DRM_MODE_FLAG_PVSYNC)
		hvctrl |= MGA2_DC_B_VSYNC_ENA;

	if (mode->flags & DRM_MODE_FLAG_NHSYNC)
		hvctrl |= MGA2_DC_B_HSYNC_POL | MGA2_DC_B_HSYNC_ENA;
	else if (mode->flags & DRM_MODE_FLAG_PHSYNC)
		hvctrl |= MGA2_DC_B_HSYNC_ENA;

	if (mode->flags & DRM_MODE_FLAG_CSYNC ||
	    mga2->subdevice == MGA2_P2_PROTO)
		hvctrl |= MGA2_DC_B_CSYNC_ENA | MGA2_DC_B_CSYNC_POL;

	wcrtc(hvctrl, HVCTRL);

	mga2_crtc_mode_set_base(crtc, x, y, old_fb);
	DRM_DEBUG("fb bpp: %d\n", bpp);
out:
	return ret;
}

static void mga2_crtc_disable(struct drm_crtc *crtc)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	wcrtc(MGA2_DC_CTRL_SOFT_RESET, CTRL);
}

static void mga2_crtc_prepare(struct drm_crtc *crtc)
{
}

static void mga2_crtc_commit(struct drm_crtc *crtc)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);

	wcrtc(MGA2_DC_CTRL_NATIVEMODE | MGA2_DC_CTRL_DIS_VGAREGS, CTRL);

	drm_vblank_post_modeset(crtc->dev, mga2_crtc->index);
}

static const struct drm_crtc_helper_funcs mga2_crtc_helper_funcs = {
	.dpms = mga2_crtc_dpms,
	.mode_fixup = mga2_crtc_mode_fixup,
	.mode_set = mga2_crtc_mode_set,
	.mode_set_base = mga2_crtc_mode_set_base,
	.load_lut = mga2_crtc_load_lut,
	.disable = mga2_crtc_disable,
	.prepare = mga2_crtc_prepare,
	.commit = mga2_crtc_commit,

};

static void mga2_crtc_reset(struct drm_crtc *crtc)
{
}

static void mga2_crtc_gamma_set(struct drm_crtc *crtc, u16 * red, u16 * green,
				u16 * blue, uint32_t start, uint32_t size)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	int end = (start + size > 256) ? 256 : start + size, i;
	wcrtc(MGA2_DC_GAMCTRL_ENABLE, GAMCTRL);
	for (i = 0; i < 256; i++) {
		unsigned v = MGA2_DC_GAMSET_SEL_ALL;
		v |= i;
		v |= i << MGA2_DC_GAMSET_ADDR_OFFSET;
		__wcrtc(v, GAMSET);
	}
	/* userspace palettes are always correct as is */
	for (i = start; i < end; i++) {
		mga2_crtc->lut_r[i] = red[i] >> 8;
		mga2_crtc->lut_g[i] = green[i] >> 8;
		mga2_crtc->lut_b[i] = blue[i] >> 8;
	}
	mga2_crtc_load_lut(crtc);
}

static void mga2_crtc_destroy(struct drm_crtc *crtc)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	mga2_i2c_destroy(mga2_crtc->i2c);
	mga2_cursor_fini(crtc);
	drm_crtc_cleanup(crtc);
	kfree(crtc);
}

static int mga2_crtc_page_flip(struct drm_crtc *crtc,
			       struct drm_framebuffer *fb,
			       struct drm_pending_vblank_event *event,
			       uint32_t page_flip_flags)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	struct drm_device *drm = crtc->dev;
	struct mga2 *mga2 = crtc->dev->dev_private;
	if (mga2->event[mga2_crtc->index])
		return -EBUSY;

	if (event) {
		event->pipe = mga2_crtc->index;
		mga2->event[mga2_crtc->index] = event;
		drm_vblank_get(drm, mga2_crtc->index);
	}

	crtc->fb = fb;
	return mga2_crtc_mode_set_base(crtc, 0, 0, NULL);
}

static const struct drm_crtc_funcs mga2_crtc_funcs = {
	.cursor_set = mga2_cursor_set,
	.cursor_move = mga2_cursor_move,
	.reset = mga2_crtc_reset,
	.set_config = drm_crtc_helper_set_config,
	.gamma_set = mga2_crtc_gamma_set,
	.destroy = mga2_crtc_destroy,
	.page_flip = mga2_crtc_page_flip,
};

int mga2_crtc_init(struct drm_device *dev, int index, void __iomem * regs)
{
	struct mga2_crtc *mga2_crtc;
	struct mga2 *mga2 = dev->dev_private;
	int i;

	mga2_crtc = kzalloc(sizeof(struct mga2_crtc), GFP_KERNEL);
	if (!mga2_crtc)
		return -ENOMEM;
	mga2_crtc->regs = regs;
	mga2_crtc->index = index;
		switch (mga2->subdevice) {
	case MGA2_PCI_PROTO:
		mga2_crtc->pll = 2;
		mga2_crtc->clk_mult = 1;
		break;
	case MGA2_P2_PROTO:
		mga2_crtc->pll = 1;
		mga2_crtc->clk_mult = 4;
		break;
	case MGA2_P2:
		mga2_crtc->pll = 1;
		mga2_crtc->clk_mult = 2;
		break;
	default:
		mga2_crtc->pll = 1;
		mga2_crtc->clk_mult = 2;
		break;
	}

	mga2_crtc->i2c =
	    mga2_i2c_create(dev, mga2_crtc->regs + MGA2_DC0_EXTPLLI2C,
			    "extpll");

	if (!mga2_crtc->i2c) {
		DRM_ERROR("failed to add pll i2c bus for display controller\n");
		return -1;
	}

	wcrtc(MGA2_DC_CTRL_SOFT_RESET, CTRL);
	mga2_pll_init_pixclock(mga2_crtc->i2c);

	wcrtc(MGA2_DC_CTRL_SOFT_RESET | MGA2_DC_CTRL_NATIVEMODE |
	      MGA2_DC_CTRL_DIS_VGAREGS, CTRL);
	wcrtc(MGA2_DC_DITCTRL_DISABLE, DITCTRL);

	drm_crtc_init(dev, &mga2_crtc->base, &mga2_crtc_funcs);
	drm_mode_crtc_set_gamma_size(&mga2_crtc->base, 256);
	drm_crtc_helper_add(&mga2_crtc->base, &mga2_crtc_helper_funcs);

	mga2_cursor_init(&mga2_crtc->base);
	for (i = 0; i < 256; i++) {
		mga2_crtc->lut_r[i] = i;
		mga2_crtc->lut_g[i] = i;
		mga2_crtc->lut_b[i] = i;
	}
	return 0;
}

static void mga2_encoder_destroy(struct drm_encoder *encoder)
{
	struct mga2_encoder *mga2_encoder = to_mga2_encoder(encoder);
	if (mga2_encoder->txi2c)
		mga2_i2c_destroy(mga2_encoder->txi2c);
	drm_encoder_cleanup(encoder);
	kfree(encoder);
}

static struct drm_encoder *mga2_best_single_encoder(struct drm_connector
						    *connector)
{
	int enc_id = connector->encoder_ids[0];
	struct drm_mode_object *gobj;
	struct drm_encoder *encoder;

	/* pick the encoder ids */
	if (enc_id) {
		gobj =
		    drm_mode_object_find(connector->dev, enc_id,
					 DRM_MODE_OBJECT_ENCODER);
		if (!gobj)
			return NULL;
		encoder = obj_to_encoder(gobj);
		return encoder;
	}
	return NULL;
}

static const struct drm_encoder_funcs mga2_enc_funcs = {
	.destroy = mga2_encoder_destroy,
};

static void mga2_encoder_dpms(struct drm_encoder *encoder, int mode)
{

}

static bool mga2_mode_fixup(struct drm_encoder *encoder,
			    const struct drm_display_mode *mode,
			    struct drm_display_mode *adjusted_mode)
{
	return true;
}

static void mga2_encoder_mode_set(struct drm_encoder *encoder,
				  struct drm_display_mode *mode,
				  struct drm_display_mode *adjusted_mode)
{
	struct mga2_encoder *mga2_encoder = to_mga2_encoder(encoder);
	u32 val;
	val = rvidc(MUX) & ~(MGA2_VID_B_MUX_ALL << MGA2_VID_B_MUX_OFFSET);
	val |= (MGA2_VID_B_MUX_DC0 << MGA2_VID_B_MUX_OFFSET);
	wvidc(val, MUX);
	val = rvidc(CTRL) & ~((MGA2_VID0_B_MODE_ALL << MGA2_VID0_B_MODE_OFFSET) |
		(MGA2_VID0_B_STROBE_DELAY_ALL << MGA2_VID0_B_STROBE_DELAY_OFFSET));
	val |= (MGA2_VID0_B_MODE_1XDDR << MGA2_VID0_B_MODE_OFFSET) |
		(MGA2_VID0_B_STROBE_DELAY_1_4 << MGA2_VID0_B_STROBE_DELAY_OFFSET) |
		MGA2_VID0_B_ENABLE;
	wvidc(val, CTRL);
	val = rvidc(RESYNC_CTRL);
	wvidc(MGA2_VID0_B_GPIOMUX_I2C, GPIO_MUX);
	wvidc(0x4, GPIO_DIR);
	wvidc(0x0, GPIO_OUT);
}

static void mga2_encoder_prepare(struct drm_encoder *encoder)
{
}

static void mga2_encoder_commit(struct drm_encoder *encoder)
{
	struct mga2_encoder *mga2_encoder = to_mga2_encoder(encoder);
	struct mga2_i2c_chan *i2c = mga2_encoder->txi2c;
	u8 dev = DVO_SIL1178_MASTER_ADDR;

	wvidc(0x4, GPIO_OUT);

	/*
	* SiI 1178 Magic from datashit
	*/
	mga2_i2c_wr(i2c, dev, 0x0F, 0x44);
	mga2_i2c_wr(i2c, dev, 0x0F, 0x4C);
	mga2_i2c_wr(i2c, dev, 0x0E, 0x10);
	mga2_i2c_wr(i2c, dev, 0x0A, 0x80);
	mga2_i2c_wr(i2c, dev, 0x09, 0x20);
	mga2_i2c_wr(i2c, dev, 0x0C, 0x89);
	mga2_i2c_wr(i2c, dev, 0x0D, 0x60);
	mga2_i2c_wr(i2c, dev, 0x08, 0x33);
}

static const struct drm_encoder_helper_funcs mga2_enc_helper_funcs = {
	.dpms = mga2_encoder_dpms,
	.mode_fixup = mga2_mode_fixup,
	.prepare = mga2_encoder_prepare,
	.commit = mga2_encoder_commit,
	.mode_set = mga2_encoder_mode_set,
};

static int mga2_transmitter_init(struct mga2_encoder *mga2_encoder)
{
	struct mga2_i2c_chan *i2c = mga2_encoder->txi2c;
	u8 dev = DVO_SIL1178_MASTER_ADDR;
#ifdef DEBUG
	int i;
	for (i = 0; i < 0x10; i++)
		mga2_i2c_rd(i2c, dev, i);
#endif
	mga2_i2c_wr(i2c, dev, 0x8, 0x34 | 3);	/*Power Up & Rising edge */
#ifdef DEBUG
	mga2_i2c_wr(i2c, dev, 0xe, 1);
	for (i = 0; i < 0x10; i++)
		mga2_i2c_rd(i2c, dev, i);
#endif
	return 0;
}

int mga2_encoder_init(struct drm_device *dev, void __iomem * regs)
{
	struct mga2_encoder *mga2_encoder;
	struct mga2 *mga2 = dev->dev_private;

	mga2_encoder = kzalloc(sizeof(struct mga2_encoder), GFP_KERNEL);
	if (!mga2_encoder)
		return -ENOMEM;

	drm_encoder_init(dev, &mga2_encoder->base, &mga2_enc_funcs,
			 DRM_MODE_ENCODER_DAC);

	drm_encoder_helper_add(&mga2_encoder->base, &mga2_enc_helper_funcs);

	mga2_encoder->base.possible_crtcs = MGA2_CRTS_MASK;
	mga2_encoder->regs = regs;

	if (mga2->subdevice != MGA2_PCI_PROTO) {
		mga2_encoder->txi2c =
		    mga2_i2c_create(dev,
				    regs + (MGA2_VID0_TXI2C - MGA2_VID0_BASE),
				    "SIL1178" " tx");

		if (!mga2_encoder->txi2c)
			DRM_ERROR("failed to add tx bus for connector\n");
		/*reset SIL1178 */
#define CONN_RST_PIN	2
		wvidc(3, GPIO_MUX);
		wvidc(0 << CONN_RST_PIN, GPIO_OUT);
		wvidc(1 << CONN_RST_PIN, GPIO_DIR);
		mdelay(1);
		wvidc(1 << CONN_RST_PIN, GPIO_OUT);
		mdelay(1);
		mga2_transmitter_init(mga2_encoder);
	}
	return 0;
}

static int mga2_get_modes(struct drm_connector *connector)
{
	struct mga2_connector *mga2_connector = to_mga2_connector(connector);
	struct edid *edid = NULL;
	int ret;
	if (!mga2_connector->ddci2c) {
		/* Just add a static list of modes */
		drm_add_modes_noedid(connector, 640, 480);
		drm_add_modes_noedid(connector, 800, 600);
		drm_add_modes_noedid(connector, 1024, 768);
		drm_add_modes_noedid(connector, 1280, 1024);
		return 1;
	}
	edid = drm_get_edid(connector, &mga2_connector->ddci2c->adapter);
	if (edid) {
		drm_mode_connector_update_edid_property(&mga2_connector->base,
							edid);
		ret = drm_add_edid_modes(connector, edid);
		return ret;
	} else
		drm_mode_connector_update_edid_property(&mga2_connector->base,
							NULL);
	return 0;
}

static int mga2_mode_valid(struct drm_connector *connector,
			   struct drm_display_mode *mode)
{
	return MODE_OK;
}

static void mga2_connector_destroy(struct drm_connector *connector)
{
	struct mga2_connector *mga2_connector = to_mga2_connector(connector);
	if (mga2_connector->ddci2c)
		mga2_i2c_destroy(mga2_connector->ddci2c);
	drm_sysfs_connector_remove(connector);
	drm_connector_cleanup(connector);
	kfree(connector);
}

static enum drm_connector_status
mga2_connector_detect(struct drm_connector *connector, bool force)
{
	return connector_status_connected;
}

static const struct drm_connector_helper_funcs mga2_connector_helper_funcs = {
	.mode_valid = mga2_mode_valid,
	.get_modes = mga2_get_modes,
	.best_encoder = mga2_best_single_encoder,
};

static const struct drm_connector_funcs mga2_connector_funcs = {
	.dpms = drm_helper_connector_dpms,
	.detect = mga2_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = mga2_connector_destroy,
};

static int mga2_connector_init(struct drm_device *dev, void __iomem * regs)
{
	struct mga2_connector *mga2_connector;
	struct drm_connector *connector;
	struct drm_encoder *encoder;
	struct mga2 *mga2 = dev->dev_private;

	mga2_connector = kzalloc(sizeof(struct mga2_connector), GFP_KERNEL);
	if (!mga2_connector)
		return -ENOMEM;

	connector = &mga2_connector->base;
	drm_connector_init(dev, connector, &mga2_connector_funcs,
			   DRM_MODE_CONNECTOR_VGA);

	drm_connector_helper_add(connector, &mga2_connector_helper_funcs);

	connector->interlace_allowed = 0;
	connector->doublescan_allowed = 0;

	drm_sysfs_connector_add(connector);

	connector->polled = DRM_CONNECTOR_POLL_CONNECT;

	encoder =
	    list_first_entry(&dev->mode_config.encoder_list, struct drm_encoder,
			     head);
	drm_mode_connector_attach_encoder(connector, encoder);

	if (mga2->subdevice != MGA2_PCI_PROTO) {
		mga2_connector->ddci2c =
		    mga2_i2c_create(dev,
				    regs + (MGA2_VID0_DDCI2C - MGA2_VID0_BASE),
				    "ddc");

		if (!mga2_connector->ddci2c)
			DRM_ERROR("failed to add ddc bus for connector\n");
	}

	return 0;
}

/* allocate cursor cache and pin at start of VRAM */

static int mga2_cursor_init(struct drm_crtc *crtc)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	struct mga2 *mga2 = crtc->dev->dev_private;
	struct drm_mm_node *node;
	struct drm_gem_object *gobj =
	    mga2_gem_create(crtc->dev, MGA2_HWC_SIZE, MGA2_GEM_DOMAIN_VRAM);

	if (IS_ERR(gobj))
		return PTR_ERR(gobj);
	node = gobj->driver_private;

	mga2_crtc->cursor_bo = gobj;
	mga2_crtc->cursor_offset = node->start - mga2->vram_paddr;
	mga2_crtc->cursor_addr = ioremap_wc(node->start, MGA2_HWC_SIZE);
	DRM_DEBUG_KMS("pinned cursor cache at %llx\n",
		      mga2_crtc->cursor_offset);
	return 0;
}

static void mga2_cursor_fini(struct drm_crtc *crtc)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	iounmap(mga2_crtc->cursor_addr);
	drm_gem_object_unreference_unlocked(mga2_crtc->cursor_bo);
}

int mga2_mode_init(struct drm_device *dev)
{
	int i, ret;
	struct mga2 *mga2 = dev->dev_private;

	switch (mga2->subdevice) {
	case MGA2_PCI_PROTO:
		mga2->base_freq = 133 * 1000 * 1000;
		break;
	case MGA2_P2_PROTO:
		mga2->base_freq = 6 * 1000 * 1000;
		break;
	case MGA2_P2:
		mga2->base_freq = 500 * 1000 * 1000;
		break;
	default:
		mga2->base_freq = 33 * 1000 * 1000;
		break;
	}

	for (i = 0; i < MGA2_CRTS_NR; i++) {
		mga2_crtc_init(dev, i, mga2->regs + i * MGA2_DC0_REG_SZ);
	}

	ret = drm_vblank_init(dev, MGA2_CRTS_NR);

	for (i = 0; i < MGA2_CRTS_NR; i++) {
		mga2_encoder_init(dev, mga2->regs + MGA2_VID0_BASE +
				    i * MGA2_VID0_SZ);
	}
	for (i = 0; i < MGA2_CONNECTOR_NR; i++) {
		mga2_connector_init(dev, mga2->regs + MGA2_VID0_BASE +
				    i * MGA2_VID0_SZ);
	}
	return ret;
}

void mga2_mode_fini(struct drm_device *dev)
{
}

void mga2_show_cursor(struct drm_crtc *crtc, u32 addr)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	__wcrtc(addr | MGA2_DC_B_CRS_ENA, NCRSADDR);
	__wcrtc(MGA2_DC_B_STROB, DISPCTRL);
}

void mga2_hide_cursor(struct drm_crtc *crtc)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	__wcrtc(0, NCRSADDR);
	__wcrtc(MGA2_DC_B_STROB, DISPCTRL);
}

int mga2_cursor_set(struct drm_crtc *crtc,
		    struct drm_file *file_priv,
		    uint32_t handle, uint32_t width, uint32_t height)
{
	struct drm_gem_object *gobj;
	struct drm_mm_node *node;
	struct mga2 *mga2 = crtc->dev->dev_private;
	if (!handle) {
		mga2_hide_cursor(crtc);
		return 0;
	}

	if (width > MGA2_MAX_HWC_WIDTH || height > MGA2_MAX_HWC_HEIGHT)
		return -EINVAL;

	gobj = drm_gem_object_lookup(crtc->dev, file_priv, handle);
	if (!gobj) {
		DRM_ERROR("Cannot find cursor object %x for crtc\n", handle);
		return -ENOENT;
	}
	node = gobj->driver_private;

	mga2_show_cursor(crtc, node->start - mga2->vram_paddr);

	drm_gem_object_unreference_unlocked(gobj);
	return 0;
}

int mga2_cursor_move(struct drm_crtc *crtc, int x, int y)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	__wcrtc((x << 16) | (y & 0xffff), NCRSCOORD);
	__wcrtc(MGA2_DC_B_STROB, DISPCTRL);
	return 0;
}

extern u32 mga2_vblank_count(struct drm_device *dev, int crtc)
{
	struct mga2 *mga2 = dev->dev_private;
	return readl(mga2->regs + crtc * MGA2_VID0_SZ + MGA2_DC0_VCOUNT);
}

#if 1
#define PLL_INFO DRM_INFO
#else
#define PLL_INFO(...)
#endif

#define DESIRED_SCL_FREQ_HZ (100*1000)

/*******************************************************************************
 * I2C Registers
 *******************************************************************************
 */
#define I2C_REG_PRER_LO (0x00)	/* Clock Prescale register lo-byte (RW) */
#define I2C_REG_PRER_HI (0x01)	/* Clock Prescale register hi-byte (RW) */
#define I2C_REG_CTR	(0x02)	/* Control Register (RW) */
#define I2C_REG_TXR	(0x03)	/* Transmit Register (W) */
#define I2C_REG_RXR	(0x03)	/* Receive Register (R)  */
#define I2C_REG_CR	(0x04)	/* Command Register (W)  */
#define I2C_REG_SR	(0x06)	/* Status Register (R)   */
#define I2C_REG_RESET	(0x07)	/* Reset Register        */

/* Prescaler divider evaluates as (PCICLK/(5*SCLK))-1 */
#define NORMAL_SCL 0x3F

/* Control Register bits */
#define I2C_CTR_EN	(1 << 7)	/* I2C core enable bit           */
#define I2C_CTR_IEN	(1 << 6)	/* I2C core interrupt enable bit */

/* Command Register bits */
#define I2C_CR_STA	(1 << 7)	/* generate (repeated) start condition */
#define I2C_CR_STO	(1 << 6)	/* generate stop condition             */
#define I2C_CR_RD	(1 << 5)	/* read from slave                     */
#define I2C_CR_WR	(1 << 4)	/* write to slave                      */
#define I2C_CR_NACK	(1 << 3)	/* when a receiver, sent I2C_CR_NACK   */
	       /* Interrupt acknowledge. When set, clears pending interrrupt */
#define I2C_CR_IACK	(1 << 0)

/* Status Register bits */
/* Receive acknowledge from slave. '1' - no acknowledge received */
#define I2C_SR_RxACK	(1 << 7)
/* I2C bus busy. '1' after START, '0' after STOP */
#define I2C_SR_BUSY	(1 << 6)
#define I2C_SR_AL	(1 << 5)	/* Arbitration lost */
/* Transfer in progress. '1' when transferring data */
#define I2C_SR_TIP	(1 << 1)
#define I2C_SR_IF	(1 << 0)	/* Interrupt flag */

/* Transmit Register operations */
#define I2C_READ_OP	0x01	/* Reading from slave (x << 1 | I2C_READ_OP) */
#define I2C_WRITE_OP	0xFE	/* Writing to slave (x << 1 & I2C_WRITE_OP) */

/*******************************************************************************
 * RAMDAC
 *******************************************************************************
 */
#define I2C_RAMDAC_ADDR 0x69

#define FS_REF		0x0	/* Reference clock [000] */
#define FS_PLL1_0	0x2	/* PLL1 0* Phase   */
#define FS_PLL1_180	0x3	/* PLL1 180* Phase */
#define FS_PLL2_0	0x4	/* PLL2 0* Phase   */
#define FS_PLL2_180	0x5	/* PLL2 180* Phase */
#define FS_PLL3_0	0x6	/* PLL3 0* Phase   */
#define FS_PLL3_180	0x7	/* PLL3 180* Phase */

/* The reciprocal of the reference oscillator (14.3181 Mhz) in picoseconds */
#define PIXCLOCK_EXT 69841

/*******************************************************************************
 * TMDS
 *******************************************************************************
 */
#define I2C_TMDS_ADDR	0x38

#define TMDS_0x00_RVAL	0x01	/* VND_IDL */
#define TMDS_0x01_RVAL	0x00	/* VND_IDH */
#define TMDS_0x02_RVAL	0x06	/* DEV_IDL */
#define TMDS_0x03_RVAL	0x00	/* DEV_IDH */
#define TMDS_0x04_RVAL	0x00	/* DEV_REV */
#define TMDS_0x08_WVAL	\
	((1<<5/*VEN*/) |\
	 (1<<4/*HEN*/) |\
	 (0<<3/*DSEL*/)|\
	 (1<<2/*BSEL*/)|\
	 (1<<1/*EDGE*/)|\
	 (0<<0/*nPD*/))
#define TMDS_0x09_WVAL	((0x2<<4/*MSEL[2:0]*/)|(0<<3/*TSEL*/)|(0<<0/*MDI*/))
#define TMDS_0x0A_WVAL	0x90	/* Default */
#define TMDS_0x0C_WVAL	0x89	/* Default */

typedef struct {
	int div;		/* [6:0] Linear output divider */

	int q;			/* [7:0] PPL*_Q */
	int p;			/* [9:0] PPL*_P */
	int po;			/* [0:0] PPL_PO */

	int pixclock;
} clk_t;

static inline void i2c_write(void __iomem * regs, unsigned long reg, u8 val)
{
#ifdef MGA_TRACE
	uint32_t rdval;
#endif
#ifdef MGA_TRACE
	PLL_INFO(" i2c_write: I2C[0x%03lx] <= 0x%02x\n", reg, val);
#endif
	writel(MGA2_DC_EXTPLLI2C_WR | (reg << 8) | val, regs);
#ifdef MGA_TRACE
	rdval = readl(regs);
	PLL_INFO(" i2c_write: I2C[0x%03lx] => 0x%02x\n", reg, rdval);
#endif
}

static inline u8 i2c_read(void __iomem * regs, unsigned long reg)
{
	uint32_t result = 0;
	writel(MGA2_DC_EXTPLLI2C_RD | (reg << 8), regs);
	result = readl(regs);
#ifdef MGA_TRACE
	PLL_INFO(" i2c_read: I2C[0x%03lx] => 0x%02x\n", reg, result);
#endif
	return result;
}

#define	MGA2_I2C_TIMEOUT_MSEC	1000
static int i2c_send(void __iomem * regs, int cmd, int data)
{
#ifndef CONFIG_E2K_SIM
	int i;
#endif
	if (cmd & I2C_CR_WR) {
		i2c_write(regs, I2C_REG_TXR, data);
	}
	i2c_write(regs, I2C_REG_CR, cmd);

#ifndef CONFIG_E2K_SIM
	for (i = 0; i < MGA2_I2C_TIMEOUT_MSEC; i++) {
		unsigned status = i2c_read(regs, I2C_REG_SR);
		if (status & I2C_SR_AL) {
			DRM_ERROR(" i2c_send: busy: arbitration lost\n");
			return -EBUSY;
		}
		if (!(status & I2C_SR_TIP))
			return 0;
		mdelay(1);
	}
	DRM_ERROR(" i2c_send: timeout: transfer in progress.\n");
	return -ETIME;
#endif
}

#define ramdac_read(__i2c, __addr)	mga2_i2c_rd(__i2c, I2C_RAMDAC_ADDR, __addr)
#define ramdac_write(__i2c, __addr, __val)	mga2_i2c_wr(__i2c, I2C_RAMDAC_ADDR, __addr, __val)

static void set_prescaler(void __iomem * regs, int value)
{
	i2c_write(regs, I2C_REG_PRER_LO, value & 0xFF);
	i2c_write(regs, I2C_REG_PRER_HI, (value >> 8) & 0xFF);
}

/*
 * Assumes:
 *    DivSel = 0
 */
static void __set_clk_fs(void __iomem * i2c, u8 a, u8 b, u8 c)
{
	u8 d = FS_REF;

	/* ClkA_FS[2:0] */
	ramdac_write(i2c, 0x08, (ramdac_read(i2c, 0x08) & 0x7F)
		     | ((a & 0x01) << 7));
	ramdac_write(i2c, 0x0E, (ramdac_read(i2c, 0x0E) & 0xFC)
		     | ((a & 0x06) >> 1));
	/* ClkB_FS[2:0] */
	ramdac_write(i2c, 0x0A, (ramdac_read(i2c, 0x0A) & 0x7F)
		     | ((b & 0x01) << 7));
	ramdac_write(i2c, 0x0E, (ramdac_read(i2c, 0x0E) & 0xF3)
		     | ((b & 0x06) << 1));
	/* ClkC_FS[2:0] */
	ramdac_write(i2c, 0x0C, (ramdac_read(i2c, 0x0C) & 0x7F)
		     | ((c & 0x01) << 7));
	ramdac_write(i2c, 0x0E, (ramdac_read(i2c, 0x0E) & 0xCF)
		     | ((c & 0x06) << 3));
	/* ClkD_FS[2:0] */
	ramdac_write(i2c, 0x0D, (ramdac_read(i2c, 0x0D) & 0x7F)
		     | ((d & 0x01) << 7));
	ramdac_write(i2c, 0x0E, (ramdac_read(i2c, 0x0E) & 0x3F)
		     | ((d & 0x06) << 5));
}

static inline unsigned pll_to_reg_offset(int pll)
{
	unsigned base;

	switch (pll) {
	case 1:
		base = 0x40;
		break;
	case 2:
		base = 0x11;
		break;
	case 3:
		base = 0x14;
		break;
	default:
		DRM_ERROR("Invalid PLL index %d\n", pll);
		return 0x11;
	}
	return base;
}

static void
__mga2_set_pll(struct mga2_i2c_chan *i2c, int base, u8 Q, uint16_t P, u8 PO)
{
	/* PLL*_Q[7:0] */
	ramdac_write(i2c, base + 0, Q);

	/* PLL*_P[7:0] */
	ramdac_write(i2c, base + 1, P & 0xFF);
	{
		u8 val;
		u8 LF = 0x0;

		int P_T = (2 * ((P & 0x3FF) + 3)) + (PO & 0x01);

		if (P_T <= 231)
			LF = 0x0;
		else if (P_T <= 626)
			LF = 0x1;
		else if (P_T <= 834)
			LF = 0x2;
		else if (P_T <= 1043)
			LF = 0x3;
		else if (P_T <= 1600)
			LF = 0x4;

		/* PLL*_En, PLL*_LF, PLL*_PO, PLL*_P[9:8] */
		val = (P & 0x300) >> 8;
		val |= (PO & 0x1) << 2;
		val |= LF << 3;
		/* val |= (enabled & 0x01) << 6; */

		ramdac_write(i2c, base + 2, val);
	}
}

static void
mga2_set_pll(struct mga2_i2c_chan *i2c, int pll, u8 Q, uint16_t P, u8 PO)
{
	unsigned base = pll_to_reg_offset(pll);
	int i;
	int nr = (pll == 1) ? 8 : 1;
	for (i = 0; i < nr; i++, base += 3)
		__mga2_set_pll(i2c, base, Q, P, PO);

}

static void __mga2_set_pll_enabled(struct mga2_i2c_chan *i2c, u32 base,
				   u8 enabled)
{
	u8 val;
	val = ramdac_read(i2c, base + 2);
	val = val & (~(0x01 << 6));
	val |= (enabled & 0x01) << 6;
	ramdac_write(i2c, base + 2, val);
}

static void mga2_set_pll_enabled(struct mga2_i2c_chan *i2c, int pll, u8 enabled)
{
	unsigned base = pll_to_reg_offset(pll);
	int i;
	int nr = (pll == 1) ? 8 : 1;
	for (i = 0; i < nr; i++, base += 3)
		__mga2_set_pll_enabled(i2c, base, enabled);

}

/*
 * Calculation of parameters PLL (here pixclock given in picoseconds,
 * so the argument 39,721 means the frequency of 10**12 / 39721 = 25175600 Hz
 */
static clk_t mga2_pll_calc(int pixclock, int use_div)
{
	clk_t res = { };
	clk_t cur;
	int delta = INT_MAX;
	int tmp_pixclock, tmp_delta;
	int mn_div = use_div ? 2 : 1;
	int mx_div = use_div ? 0x80 : 2;

#ifdef __e2k__
	/* If run under simulator skip long loops */
	if (IS_MACHINE_SIM) {
		goto calculated;
	}
#endif
	for (cur.p = 0; cur.p < 0x400; cur.p++) {
		for (cur.po = 0; cur.po < 0x2; cur.po++) {
			for (cur.div = mn_div; cur.div < mx_div; cur.div += 2) {
				for (cur.q = 0; cur.q < 0x100; cur.q++) {

					tmp_pixclock = (PIXCLOCK_EXT * cur.div
							* (cur.q + 2))
					    / (2 * (cur.p + 3) + cur.po);

					tmp_delta =
					    abs(pixclock - tmp_pixclock);
					if (tmp_delta < delta) {
						delta = tmp_delta;
						res = cur;
						res.pixclock = tmp_pixclock;
					}
					if (tmp_delta == 0) {
						goto calculated;
					}
				}
			}
		}
	}
	DRM_ERROR("Can't calculate constants for pixclock=%d\n, use default\n",
		  pixclock);
	return res;

      calculated:
	DRM_DEBUG_KMS
	    ("Calculated: pixclock %d (%ld kHz) => %d (%ld kHz) PLL setup: "
	     "div=0x%02x q=0x%02x p=0x%02x po=0x%x\n", pixclock,
	     PICOS2KHZ(pixclock), res.pixclock, PICOS2KHZ(res.pixclock),
	     res.div, res.q, res.p, res.po);

	return res;
}

static void mga2_pll_init_pixclock(struct mga2_i2c_chan *i2c)
{
	int reg = 0;

//      set_prescaler(i2c, NORMAL_SCL);

	/* Enable I2C core */
//      i2c_write(i2c, I2C_REG_CTR, I2C_CTR_EN);

	/* Init all i2c */
	for (reg = 0x08; reg <= 0x17; reg++)
		ramdac_write(i2c, reg, 0x0);

	for (reg = 0x40; reg <= 0x57; reg++)
		ramdac_write(i2c, reg, 0x0);

	ramdac_write(i2c, 0x17, 0x0);
//      ramdac_write(i2c, 0x0F, (0x01 << 6) | (0x01 << 4) | 0x01);
	ramdac_write(i2c, 0x0F, (0x01 << 6) | (0x01 << 4) | (0x01 << 2) | 0x01);
	ramdac_write(i2c, 0x0D, 0x01);
	ramdac_write(i2c, 0x10, 0);

	/* Disable I2C core */
//      i2c_write(i2c, I2C_REG_CTR, 0x0);
}

static void mga2_pll_set_pixclock(int pll, struct mga2_i2c_chan *i2c,
				  uint32_t pixclock)
{
	clk_t vidclk = mga2_pll_calc(pixclock, pll != 1);

//      set_prescaler(regs, NORMAL_SCL);

	/* Enable I2C core */
//      i2c_write(regs, I2C_REG_CTR, I2C_CTR_EN);

	switch (pll) {
	case 2:
		ramdac_write(i2c, 0x08, 0x0);
		__set_clk_fs(i2c, FS_REF, FS_REF, FS_PLL3_0);
		{
			/* Reset vidclk enabled bit */
			mga2_set_pll_enabled(i2c, 2, 0);
			mga2_set_pll(i2c, 2, vidclk.q, vidclk.p, vidclk.po);
		}
		__set_clk_fs(i2c, FS_PLL2_0, FS_REF, FS_PLL3_0);
		ramdac_write(i2c, 0x08, ((FS_PLL2_0 & 0x01) << 7)
			     | (vidclk.div & 0x7F));

		/* Set vidclk enabled bit */
		mga2_set_pll_enabled(i2c, 2, 1);
		break;

	case 3:
		ramdac_write(i2c, 0x0C, 0x0);
		__set_clk_fs(i2c, FS_PLL2_0, FS_REF, FS_REF);
		{
			/* Reset vidclk enabled bit */
			mga2_set_pll_enabled(i2c, 3, 0);
			mga2_set_pll(i2c, 3, vidclk.q, vidclk.p, vidclk.po);
		}
		__set_clk_fs(i2c, FS_PLL2_0, FS_REF, FS_PLL3_0);
		ramdac_write(i2c, 0x0C, ((FS_PLL3_0 & 0x01) << 7)
			     | (vidclk.div & 0x7F));

		/* Set vidclk enabled bit */
		mga2_set_pll_enabled(i2c, 3, 1);
		break;
	case 1:
		ramdac_write(i2c, 0x0A, 0x0);
		__set_clk_fs(i2c, FS_REF, FS_PLL1_0, FS_REF);
		/* Reset vidclk enabled bit */
		mga2_set_pll_enabled(i2c, 1, 0);
		mga2_set_pll(i2c, 1, vidclk.q, vidclk.p, vidclk.po);

		__set_clk_fs(i2c, FS_PLL2_0, FS_PLL1_0, FS_PLL3_0);
		ramdac_write(i2c, 0x0A, ((FS_PLL1_0 & 0x01) << 7)
			     | (vidclk.div & 0x7F));

		/* Set vidclk enabled bit */
		mga2_set_pll_enabled(i2c, 1, 1);
		break;
	}

	/* Disable I2C core */
//      i2c_write(regs, I2C_REG_CTR, 0x0);
}

static int mga2_i2c_read(struct i2c_adapter *adap, unsigned char *buf,
			 int length)
{
	int ret = 0;
	struct mga2_i2c_chan *i2c = i2c_get_adapdata(adap);
	void __iomem *regs = i2c->regs;
	while (length--) {
		int ret;
		int v = I2C_CR_RD;

		if (!length)
			v |= I2C_CR_STO | I2C_CR_NACK;
		ret = i2c_send(regs, v, 0);
		if (ret)
			break;
		*buf++ = i2c_read(regs, I2C_REG_RXR);
	}
	return ret;
}

static int mga2_i2c_write(struct i2c_adapter *adap, unsigned char *buf,
			  int length)
{
	struct mga2_i2c_chan *i2c = i2c_get_adapdata(adap);
	void __iomem *regs = i2c->regs;
	while (length--) {
		int v = I2C_CR_WR;

		if (!length)
			v |= I2C_CR_STO;
		if (i2c_send(regs, v, *buf++)) {
			return -1;
		}
		if (i2c_read(regs, I2C_REG_SR) & I2C_SR_RxACK) {
			DRM_ERROR("%s: no acknowledge from slave.\n",
				  adap->name);
			return -1;
		}
	}

	return 0;
}

static int mga2_i2c_xfer(struct i2c_adapter *adap, struct i2c_msg *pmsg,
			 int num)
{
	int i, ret;
	struct mga2_i2c_chan *i2c = i2c_get_adapdata(adap);
	void __iomem *regs = i2c->regs;

	/* check for bus probe */
	if ((num == 1) && (pmsg->len == 0)) {
		DRM_ERROR("i2c: check for bus probe.\n");
		return -1;
	}

	if (0)
		dev_dbg(&adap->dev, "%s: processing %d messages:\n", adap->name,
			num);

	for (i = 0; i < num; i++, pmsg++) {
		int addr = pmsg->addr << 1;
		if (pmsg->flags & I2C_M_RD)
			addr |= I2C_READ_OP;
		else
			addr &= I2C_WRITE_OP;

		if (0)
			dev_dbg(&adap->dev, " #%d: %sing %d byte%s %s 0x%02x\n",
				i, pmsg->flags & I2C_M_RD ? "read" : "writ",
				pmsg->len, pmsg->len > 1 ? "s" : "",
				pmsg->flags & I2C_M_RD ? "from" : "to",
				pmsg->addr);

		/* Sending device address */
		if (i2c_send(regs, I2C_CR_STA | I2C_CR_WR, addr)) {
			return -1;
		}

		if (i2c_read(regs, I2C_REG_SR) & I2C_SR_RxACK) {
			DRM_ERROR("i2c: no acknowledge from slave.\n");
			return -1;
		}
		if (pmsg->flags & I2C_M_RD)
			ret = mga2_i2c_read(adap, pmsg->buf, pmsg->len);
		else
			ret = mga2_i2c_write(adap, pmsg->buf, pmsg->len);

		if (ret)
			return ret;
	}
	return i;
}

static u32 mga2_i2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm mga2_i2c_algo = {
	.master_xfer = mga2_i2c_xfer,
	.functionality = mga2_i2c_func,
};

static struct mga2_i2c_chan *mga2_i2c_create(struct drm_device *dev,
					     void __iomem * regs, char *name)
{
	struct mga2_i2c_chan *i2c;
	struct mga2 *mga2 = dev->dev_private;
	int ret;

	i2c = kzalloc(sizeof(struct mga2_i2c_chan), GFP_KERNEL);
	if (!i2c)
		return NULL;

	i2c->adapter.owner = THIS_MODULE;
	i2c->adapter.class = I2C_CLASS_DDC;
	i2c->adapter.dev.parent = &dev->pdev->dev;
	i2c->dev = dev;
	i2c->regs = regs;
	i2c_set_adapdata(&i2c->adapter, i2c);
	snprintf(i2c->adapter.name, sizeof(i2c->adapter.name),
		 "MGA2 %s i2c bus", name);

	i2c->adapter.algo = &mga2_i2c_algo;
	ret = i2c_add_adapter(&i2c->adapter);
	if (ret) {
		DRM_ERROR("Failed to register bit i2c\n");
		goto out_free;
	}

	/* Prescaler divider evaluates as (BASE_FREQ/(4*SCLK))-1 */
	set_prescaler(regs, mga2->base_freq / 4 / DESIRED_SCL_FREQ_HZ - 1);

	/* Enable I2C core */
	i2c_write(regs, I2C_REG_CTR, I2C_CTR_EN);

	return i2c;
      out_free:
	kfree(i2c);
	return NULL;
}

static void mga2_i2c_destroy(struct mga2_i2c_chan *i2c)
{
	if (!i2c)
		return;
	i2c_del_adapter(&i2c->adapter);
	kfree(i2c);
}
