/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * driver for CY14B101P SPI RTC chip
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bcd.h>
#include <linux/module.h>
#include <linux/rtc.h>
#include <linux/workqueue.h>
#include <linux/spi/spi.h>
#include <linux/delay.h>
#ifdef CONFIG_MCST
#include <linux/kthread.h>
#include <linux/clocksource.h>
# ifdef CONFIG_E2K
#include <asm/sclkr.h>
# endif
#if defined(CONFIG_E90S)
#include <asm-l/clk_rt.h>
#endif
#include <asm/bootinfo.h>
#endif
#if defined(CONFIG_MCST) && defined(CONFIG_NVRAM_PANIC)
#include <linux/panic2nvram.h>
#endif

#define DEBUG

#define        CY14B101P_WREN          	0x06    // set write enable latch
#define        CY14B101P_WRDI          	0x04    // reset write enable latch
#define        CY14B101P_RDSR		0x05	// read status register
#define        CY14B101P_WRSR		0x01	// write status register
#define        CY14B101P_READ		0x03	// read sram
#define        CY14B101P_WRITE		0x02	// write sram
#define        CY14B101P_WRTC		0x12	// write rtc register
#define        CY14B101P_RDRTC		0x13	// read rtc register
#define        CY14B101P_STORE		0x3C	// software store
#define        CY14B101P_RECALL		0x60	// software recall
#define        CY14B101P_ASENB		0x59	// autostore enable
#define        CY14B101P_ASDISB		0x11	// autostore disable

#define        CY14B101P_NVRAM_LEN	128 * 1024
#define        CY14B101P_RTC_LEN    	16

#define        CY14B101P_FLAGS      	0x00
#define        CY14B101P_CENT       	0x01
#define        CY14B101P_ALM_SEC    	0x02
#define        CY14B101P_ALM_MIN    	0x03
#define        CY14B101P_ALM_HOUR   	0x04
#define        CY14B101P_ALM_WDAY   	0x05
#define        CY14B101P_INT        	0x06
#define        CY14B101P_WDT        	0x07
#define        CY14B101P_CAL		0x08
#define        CY14B101P_SEC        	0x09
#define        CY14B101P_MIN        	0x0A
#define        CY14B101P_HOUR       	0x0B
#define        CY14B101P_WDAY       	0x0C
#define        CY14B101P_MDAY       	0x0D
#define        CY14B101P_MON        	0x0E
#define        CY14B101P_YEAR       	0x0F

/* CY14B101P_FLAGS: */
#define        CY14B101P_R		(1 << 0)
#define        CY14B101P_W		(1 << 1)
#define        CY14B101P_OSCF		(1 << 4)
/* CY14B101P_CAL: */
#define        CY14B101P_OSCEN		(1 << 7)
/* CY14B101P_INT: */
#define        CY14B101P_SQ0		(1 << 0)
#define        CY14B101P_SQ1		(1 << 1)
#define        CY14B101P_PL		(1 << 2)
#define        CY14B101P_HL		(1 << 3)
#define        CY14B101P_SQWE		(1 << 4)
#define        CY14B101P_AIE		(1 << 6)
#define        CY14B101P_ALM_DIS	(1 << 7)

#if defined(CONFIG_MCST) && defined(CONFIG_NVRAM_PANIC)
struct spi_device *nvram_for_panic;
#endif
#define	       FLAG_EXITING		0
#if defined(CONFIG_MCST)
static atomic_t rtc4clk_src = ATOMIC_INIT(0); 
#endif

struct cy14b101p {
	struct spi_device	*spi;
	struct rtc_device	*rtc;
	struct work_struct	work; 
	unsigned long		flags;
};

static int cy14b101p_get_time(struct device *dev, struct rtc_time *time);

int cy14b101p_read_len_rtc(struct device *dev, u8 reg, u8 *val, unsigned len)
{
	struct spi_device *spi = to_spi_device(dev);
	u8 txbuf[2];
	int ret = 0;

	txbuf[0] = CY14B101P_RDRTC;
	txbuf[1] = reg;
	ret = spi_write_then_read(spi, txbuf, 2, val, len);
	return ret;
}

#define cy14b101p_read_rtc(dev, reg, val) \
	cy14b101p_read_len_rtc(dev, reg, val, 1)

inline int cy14_wait_rdy(struct device *dev)
{
	struct spi_device *spi = to_spi_device(dev);
	u8 cmd, val;
	int i;
	int ret;

	cmd = CY14B101P_RDSR;
	for (i = 0; i < 100; i++) {
		ret = spi_write_then_read(spi, &cmd, 1, &val, 1);
		if ((ret < 0) || (val & 1) == 0)
			return ret;
		udelay(100);
	}
	return ret;
}

inline int cy14b101p_wren(struct device *dev){
	struct spi_device *spi = to_spi_device(dev);
	u8 txbuf;
	int ret;

	ret = cy14_wait_rdy(dev);
	txbuf = CY14B101P_WREN;
	ret = ret ? : spi_write(spi, &txbuf, 1);
	return ret;
}

inline int cy14b101p_store(struct device *dev)
{
	struct spi_device *spi = to_spi_device(dev);
	u8 cmd;
	int ret;

	ret = cy14b101p_wren(dev);
	ret = ret ? : cy14_wait_rdy(dev);
	cmd = CY14B101P_STORE;
	ret = ret ? : spi_write(spi, &cmd, 1);
	udelay(8000);
	return ret;
}

int cy14b101p_write_rtc(struct device *dev, u8 reg, u8 val)
{
	struct spi_device *spi = to_spi_device(dev);
	u8 txbuf[3];
	int ret;

	txbuf[0] = CY14B101P_WRTC;
	txbuf[1] = reg;
	txbuf[2] = val;

	ret = cy14_wait_rdy(dev);
	ret = ret ?: cy14b101p_wren(dev);
	ret = ret ?: spi_write(spi, txbuf, 3);
	return ret;
}

#define cy14b101p_rtc_write_flags(dev, val) \
	cy14b101p_write_rtc(dev, CY14B101P_FLAGS, val)

#define cy14b101p_rtc_write_lock(dev) \
	cy14b101p_rtc_write_flags(dev, CY14B101P_W)

#define cy14b101p_rtc_read_lock(dev) \
	cy14b101p_rtc_write_flags(dev, CY14B101P_R)

#define cy14b101p_rtc_unlock(dev) \
	cy14b101p_rtc_write_flags(dev, 0)

#define epoch	2000

static int cy14b101p_set_time(struct device *dev, struct rtc_time *time)
{
	int ret;

        dev_vdbg(dev, "%s secs=%d, mins=%d, "
                "hours=%d, mday=%d, mon=%d, year=%d, wday=%d\n",
                "write", time->tm_sec, time->tm_min,
                time->tm_hour, time->tm_mday,
                time->tm_mon, time->tm_year, time->tm_wday);
#if defined(CONFIG_MCST)
	//if (atomic_read(&rtc4clk_src) && dev->id == 0 &&  pps_debug & 1) {
	if (atomic_read(&rtc4clk_src) &&  pps_debug & 1) {
		pr_warn("cy14b101p_set_time while RTC is for clocksource. "
			" %02d.%02d.%d %02d:%02d:%02d\n",
			time->tm_mday, time->tm_mon + 1,
			time->tm_year + 1900,
			time->tm_hour, time->tm_min, time->tm_sec);
	}
#endif
	ret = cy14b101p_rtc_write_lock(dev);
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_SEC,  bin2bcd(time->tm_sec));
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_MIN,  bin2bcd(time->tm_min));
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_HOUR, bin2bcd(time->tm_hour));
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_MDAY, bin2bcd(time->tm_mday));
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_MON,  bin2bcd(time->tm_mon + 1));
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_YEAR,
					bin2bcd(time->tm_year + 1900 - epoch));
	cy14b101p_rtc_unlock(dev);
	udelay(1000);
	ret = ret ?: cy14b101p_store(dev);
	return ret;
}

static int cy14b101p_get_time(struct device *dev, struct rtc_time *time)
{
        u8              buf[16];
        int             ret;

        ret = cy14b101p_rtc_read_lock(dev);
	if (ret < 0)
		return ret;
	ret = cy14b101p_read_len_rtc(dev, CY14B101P_SEC,
					buf + CY14B101P_SEC, 7);

        time->tm_sec = bcd2bin(buf[CY14B101P_SEC]);
        time->tm_min = bcd2bin(buf[CY14B101P_MIN]);
        time->tm_hour = bcd2bin(buf[CY14B101P_HOUR]);
        time->tm_mday = bcd2bin(buf[CY14B101P_MDAY]);
	time->tm_mon = bcd2bin(buf[CY14B101P_MON]);
	time->tm_year = bcd2bin(buf[CY14B101P_YEAR]) + epoch;

        dev_vdbg(dev, "%s secs=%d, mins=%d, "
                "hours=%d, mday=%d, mon=%d, year=%d, wday=%d\n",
                "read", time->tm_sec, time->tm_min,
                time->tm_hour, time->tm_mday,
                time->tm_mon, time->tm_year, time->tm_wday);

	cy14b101p_rtc_unlock(dev);
        if (ret < 0)
                return ret;

	/*
	 * Account for differences between how the RTC uses the values
	 * and how they are defined in a struct rtc_time;
	 */
	time->tm_mon -= 1;
	time->tm_year -= 1900;

        return rtc_valid_tm(time);
}

#ifdef CONFIG_RTC_INTF_DEV

static int cy14b101p_ioctl(struct device *dev, unsigned cmd, unsigned long arg)
{
        u8              val = CY14B101P_HL | CY14B101P_PL;
        int             ret = -ENOIOCTLCMD;

        switch (cmd) {
        case RTC_AIE_OFF:
                ret = 0;
                val &= ~CY14B101P_AIE;
                break;
        case RTC_AIE_ON:
                ret = 0;
                val |= CY14B101P_AIE;
                break;
	default:
		return -ENOIOCTLCMD;
        }
#if defined(CONFIG_MCST)
	if (atomic_read(&rtc4clk_src)) {
		pr_warn("cy14b101p_ioctl: "
			"RTC is used for clocksource. "
			"Alarm functionality is disabled\n");
		return -EINVAL;
	}
#endif
        if (ret == 0) {
		ret = ret ?: cy14b101p_rtc_write_lock(dev);
                ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_INT, val);
		ret = ret ?: cy14b101p_rtc_unlock(dev);
        }
        return ret;
}

#else
#define cy14b101p_ioctl	NULL
#endif

static int cy14b101p_set_alarm(struct device *dev, struct rtc_wkalrm *alm)
{
        int             ret;
#if defined(CONFIG_MCST)
	if (atomic_read(&rtc4clk_src)) {
		pr_warn("cy14b101p_set_alarm: "
			"RTC is used for clocksource. "
			"Alarm functionality is disabled\n");
		return -EINVAL;
	}
#endif
	ret = cy14b101p_rtc_write_lock(dev);
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_ALM_SEC, bin2bcd(alm->time.tm_sec));
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_ALM_MIN, bin2bcd(alm->time.tm_min));
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_ALM_HOUR, bin2bcd(alm->time.tm_hour));
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_ALM_WDAY, CY14B101P_ALM_DIS);
	ret = ret ?: cy14b101p_write_rtc(dev, CY14B101P_INT, 
			CY14B101P_HL | CY14B101P_PL | ((alm->enabled) ? CY14B101P_AIE : 0));
	cy14b101p_rtc_unlock(dev);
        return ret;
}

static int cy14b101p_get_alarm(struct device *dev, struct rtc_wkalrm *alm)
{
        int             ret;
        u8              buf[16];

	ret = cy14b101p_rtc_write_lock(dev);
	if (ret < 0) return ret;

	ret = cy14b101p_read_rtc(dev, CY14B101P_FLAGS, buf);
        if (ret < 0) return ret;
	alm->pending = !!(*buf & CY14B101P_AIE);
   
	ret = cy14b101p_read_rtc(dev, CY14B101P_INT, buf);
        if (ret < 0) return ret;
	alm->enabled = !!(*buf & CY14B101P_AIE);

	ret = cy14b101p_read_len_rtc(dev, CY14B101P_ALM_SEC, 
                        buf + CY14B101P_ALM_SEC, 4);
        if (ret < 0) return ret;

	ret = cy14b101p_rtc_unlock(dev);
	if (ret < 0) return ret;

        dev_vdbg(dev, "%s: %02x %02x %02x %02x\n",
                "alm0 read", buf[CY14B101P_ALM_SEC], buf[CY14B101P_ALM_MIN],
                buf[CY14B101P_ALM_HOUR], buf[CY14B101P_ALM_WDAY]);

        if ((CY14B101P_ALM_DIS & buf[CY14B101P_ALM_SEC])
                        || (CY14B101P_ALM_DIS & buf[CY14B101P_ALM_MIN])
                        || (CY14B101P_ALM_DIS & buf[CY14B101P_ALM_HOUR]))
                return -EIO;

        /* Stuff these values into alm->time and let RTC framework code
         * fill in the rest ... and also handle rollover to tomorrow when
         * that's needed.
         */
        alm->time.tm_sec = bcd2bin(buf[CY14B101P_ALM_SEC]);
        alm->time.tm_min = bcd2bin(buf[CY14B101P_ALM_MIN]);
        alm->time.tm_hour = bcd2bin(buf[CY14B101P_ALM_HOUR]);
        alm->time.tm_mday = -1;
        alm->time.tm_mon = -1;
        alm->time.tm_year = -1;
        /* next three fields are unused by Linux */
        alm->time.tm_wday = -1;
        alm->time.tm_mday = -1;
        alm->time.tm_isdst = -1;

        return 0;
}

static struct rtc_class_ops cy14b101p_ops = {
        .ioctl          = cy14b101p_ioctl,
        .read_time      = cy14b101p_get_time,
        .set_time       = cy14b101p_set_time,
        .read_alarm     = cy14b101p_get_alarm,
        .set_alarm      = cy14b101p_set_alarm,
        .proc           = NULL,
};

static irqreturn_t cy14b101p_irq(int irq, void *p)
{
        struct cy14b101p           *cy14b101p = p;
        disable_irq(irq);
        schedule_work(&cy14b101p->work);
        return IRQ_HANDLED;
}

static void cy14b101p_work(struct work_struct *work)
{
        struct cy14b101p   *cy14b101p = container_of(work, struct cy14b101p, work);
        struct mutex    *lock = &cy14b101p->rtc->ops_lock;
        struct spi_device *spi = cy14b101p->spi;
	struct device	*dev = &spi->dev;

#if defined(CONFIG_MCST)
	if (atomic_read(&rtc4clk_src)) {
		pr_warn("cy14b101p_work: "
			"RTC is used for clocksource. "
			"Alarm functionality is disabled\n");
		return;
	}
#endif
	printk("now we in cy14b101p_work!\n");
        /* lock to protect cy14b101p->ctrl */
        mutex_lock(lock);

	cy14b101p_rtc_write_lock(dev);
	cy14b101p_write_rtc(dev, CY14B101P_INT,  CY14B101P_HL | CY14B101P_PL);
	cy14b101p_rtc_unlock(dev);

        mutex_unlock(lock);

        if (!test_bit(FLAG_EXITING, &cy14b101p->flags))
                enable_irq(spi->irq);

        rtc_update_irq(cy14b101p->rtc, 1, RTC_AF | RTC_IRQF);
}

/*
static void msg_init_cy14b101p(struct spi_message *m, struct spi_transfer *x,
		char *cmd, size_t count1, char *tx, char *rx, size_t count2)
{
	spi_message_init(m);
	memset(x, 0, 2 * sizeof(*x));

	x->tx_buf = cmd;
	x->len = count1;
	spi_message_add_tail(x, m);

	if (!count2) return;

	x++;

	x->tx_buf = tx;
	x->rx_buf = rx;
	x->len = count2;
	spi_message_add_tail(x, m);
}
*/

#if defined(CONFIG_MCST) && defined(CONFIG_NVRAM_PANIC)

static ssize_t
cy14b101p_nvram_generic_write(struct spi_device *spi,
		char *buf, loff_t off, size_t count)
{
	int i;
	int			status;
	char			cmd[6];

	
	if (unlikely(off >= CY14B101P_NVRAM_LEN))
		return -EFBIG;
	if (count >= CY14B101P_NVRAM_LEN)
		count = CY14B101P_NVRAM_LEN;
	if ((off + count) > CY14B101P_NVRAM_LEN)
		count = CY14B101P_NVRAM_LEN - off;
	if (unlikely(!count))
		return count;

	status = 0;

	for (i = 0; i < count && !status; ++i){
//		status = status?: cy14b101p_wren(&spi->dev);
		cmd[0] = CY14B101P_WREN;
		status = status?:spi_write(spi, cmd, 1);
		cmd[0] = CY14B101P_WRITE;
		cmd[1] = ((i + off) >> 16) & 0x01;
		cmd[2] = ((i + off) >> 8) & 0xff;
		cmd[3] = ((i + off) >> 0) & 0xff;
		cmd[4] = buf[i];
		status = status?:spi_write(spi, cmd, 5);

	}

	if (status < 0)
		dev_err(&spi->dev, "nvram %s error %d\n", "write", status);

	return (status < 0) ? status : count;
}

static ssize_t
cy14b101p_nvram_write(struct file *file, struct kobject *kobj,
		struct bin_attribute *attr,
		char *buf, loff_t off, size_t count)
{
	struct spi_device	*spi;
	
	spi = container_of(kobj, struct spi_device, dev.kobj);
	return cy14b101p_nvram_generic_write(spi, buf, off, count);
}


static void 
cy14b101p_nvram_write_for_panic2nvram(u_int off, unsigned char *buf, int count)
{
	cy14b101p_nvram_generic_write(nvram_for_panic, (char *)buf,
		(loff_t)off, (size_t)count);
}

#if 0
extern int l_raw_write_panic_to_nvram(struct spi_device *spi, int rdsr, int wren, int wrcmd,
                                u_int off);

static int cy14b101p_raw_write_panic_to_nvram(u_int off, u_char *buf, int sz)
{
	int i;
	for (i = 0; i < sz; i++) {
		if (!l_raw_write_panic_to_nvram(nvram_for_panic,
			CY14B101P_RDSR, CY14B101P_WREN, CY14B101P_WRITE,
			(((off + i) & 0x1ffff) | (buf[i])<< 24))) {
			break;
		}
	}
	return i;
}
#endif


static ssize_t
cy14b101p_nvram_generic_read(struct spi_device *spi,
		char *buf, loff_t off, size_t count)
{
	int i;
	u8			cmd[4];

	memset(buf, 0xff, count);

	if (unlikely(off >= CY14B101P_NVRAM_LEN))
		return 0;
	if (count >= CY14B101P_NVRAM_LEN)
		count = CY14B101P_NVRAM_LEN;
	if ((off + count) > CY14B101P_NVRAM_LEN)
		count = CY14B101P_NVRAM_LEN - off;
	if (unlikely(!count))
		return count;

	cmd[0] = CY14B101P_READ;
	for (i = 0; i < count; ++i){
		cmd[1] = ((i + off) >> 16) & 0x01;
		cmd[2] = ((i + off) >> 8) & 0xff;
		cmd[3] = ((i + off) >> 0) & 0xff;
		dev_dbg(&spi->dev,
		   "cmd read %02x %02x %02x %02x\n",
		   cmd[0], cmd[1], cmd[2], cmd[3]);
		spi_write_then_read(spi, cmd, sizeof cmd, buf + i, 1);
	}

	return count;
}

static ssize_t
cy14b101p_nvram_read(struct file *file, struct kobject *kobj,
		struct bin_attribute *attr,
		char *buf, loff_t off, size_t count)
{
	struct spi_device	*spi;
	
	spi = container_of(kobj, struct spi_device, dev.kobj);
	return cy14b101p_nvram_generic_read(spi, buf, off, count);
}


static int
cy14b101p_nvram_read_for_panic2nvram(u_int off, unsigned char *buf, int count)
{
	return (int)cy14b101p_nvram_generic_read(nvram_for_panic, (char *)buf,
		(loff_t)off, (size_t)count);
}

#else	/* defined(CONFIG_MCST) && defined(CONFIG_NVRAM_PANIC) */

static ssize_t
cy14b101p_nvram_read(struct file *file, struct kobject *kobj,
		struct bin_attribute *attr,
		char *buf, loff_t off, size_t count)
{
	struct spi_device	*spi;
	int i;
	u8			cmd[4];

	spi = container_of(kobj, struct spi_device, dev.kobj);
	memset(buf, 0xff, count);

	if (unlikely(off >= CY14B101P_NVRAM_LEN))
		return 0;
	if (count >= CY14B101P_NVRAM_LEN)
		count = CY14B101P_NVRAM_LEN;
	if ((off + count) > CY14B101P_NVRAM_LEN)
		count = CY14B101P_NVRAM_LEN - off;
	if (unlikely(!count))
		return count;

	cmd[0] = CY14B101P_READ;
	for (i = 0; i < count; ++i) {
		cmd[1] = ((i + off) >> 16) & 0x01;
		cmd[2] = ((i + off) >> 8) & 0xff;
		cmd[3] = ((i + off) >> 0) & 0xff;
		dev_dbg(&spi->dev,
		   "cmd read %02x %02x %02x %02x\n",
		   cmd[0], cmd[1], cmd[2], cmd[3]);
		spi_write_then_read(spi, cmd, sizeof cmd, buf + i, 1);
	}

#if 0
	cmd[0] = CY14B101P_READ;
	cmd[1] = (off >> 16) & 0x01;
	cmd[2] = (off >> 8 ) & 0xff;
	cmd[3] = (off >> 0 ) & 0xff;

	msg_init_cy14b101p(&m, x, cmd, sizeof cmd, NULL, buf, count);
	status = spi_sync(spi, &m);
	/*status = spi_write_then_read(spi, cmd, sizeof cmd, buf, count);*/

	if (status < 0)
		dev_err(&spi->dev, "nvram %s error %d\n", "read", status);

	return (status < 0) ? status : count;
#endif
	return count;
}

static ssize_t
cy14b101p_nvram_write(struct file *file, struct kobject *kobj,
		struct bin_attribute *attr,
		char *buf, loff_t off, size_t count)
{
	int i;
	struct spi_device	*spi;
	int			status;
	char			cmd[6];


	spi = container_of(kobj, struct spi_device, dev.kobj);

	if (unlikely(off >= CY14B101P_NVRAM_LEN))
		return -EFBIG;
	if (count >= CY14B101P_NVRAM_LEN)
		count = CY14B101P_NVRAM_LEN;
	if ((off + count) > CY14B101P_NVRAM_LEN)
		count = CY14B101P_NVRAM_LEN - off;
	if (unlikely(!count))
		return count;

	status = 0;

	for (i = 0; i < count && !status; ++i) {
		cmd[0] = CY14B101P_WREN;
		status = status?:spi_write(spi, cmd, 1);
		cmd[0] = CY14B101P_WRITE;
		cmd[1] = ((i + off) >> 16) & 0x01;
		cmd[2] = ((i + off) >> 8) & 0xff;
		cmd[3] = ((i + off) >> 0) & 0xff;
		cmd[4] = buf[i];
		status = status?:spi_write(spi, cmd, 5);
	}

/*
	status = cy14b101p_wren(&spi->dev);
	if (status < 0){
		dev_err(&spi->dev, "nvram %s error %d\n", "write", status);
		return status;
	}

	cmd[0] = CY14B101P_WRITE;
	cmd[1] = (off >> 16) & 0x01;
	cmd[2] = (off >> 8 ) & 0xff;
	cmd[3] = (off >> 0 ) & 0xff;

	msg_init_cy14b101p(&m, x, cmd, sizeof cmd, buf, NULL, count);
	status = spi_sync(spi, &m);

*/
	if (status < 0)
		dev_err(&spi->dev, "nvram %s error %d\n", "write", status);

	return (status < 0) ? status : count;
}

#endif /* defined(CONFIG_MCST) && defined(CONFIG_NVRAM_PANIC) */


static struct bin_attribute nvram = {
	.attr.name	= "nvram",
	.attr.mode	= S_IRUGO | S_IWUSR,
	.read		= cy14b101p_nvram_read,
	.write		= cy14b101p_nvram_write,
	.size		= CY14B101P_NVRAM_LEN,
};

static int cy14b101p_remove(struct spi_device *spi)
{
	struct cy14b101p *cy14b101p = spi_get_drvdata(spi);

	sysfs_remove_bin_file(&spi->dev.kobj, &nvram);

	/* carefully shut down irq and workqueue, if present */
	if (spi->irq) {
		set_bit(FLAG_EXITING, &cy14b101p->flags);
		free_irq(spi->irq, cy14b101p);
		flush_scheduled_work();
	}

	spi_set_drvdata(spi, NULL);
	kfree(cy14b101p);
	return 0;
}

#if defined(CONFIG_MCST)
static void init_pps(struct spi_device *spi)
{
	struct cy14b101p *cy14b101p = spi_get_drvdata(spi);
	struct device	*dev = &spi->dev;
#if defined(CONFIG_E2K)
	if (machine.native_iset_ver >= E2K_ISET_V3 &&
		(sclkr_mode == -1 || sclkr_mode == SCLKR_RTC) &&
		/* only first RTC is used for SCLKR while there is now flag which */
		(atomic_cmpxchg(&rtc4clk_src, 0, 1) == 0)) {
		int	error;
		static struct task_struct *sclkregistask;

		cy14b101p_rtc_write_lock(dev);
		cy14b101p_write_rtc(dev, CY14B101P_INT,
			CY14B101P_SQWE | CY14B101P_AIE |  CY14B101P_HL |
			CY14B101P_PL);
		cy14b101p_rtc_unlock(dev);
		sclkregistask = kthread_run(sclk_register,
			(void *)SCLKR_RTC, "sclkregister");
		if (IS_ERR(sclkregistask)) {
			error = PTR_ERR(sclkregistask);
			dev_err(dev, "Failed to start sclk register thread, error: %d\n",
				error);
		}
		((struct rtc_class_ops *)
			cy14b101p->rtc->ops)->set_alarm = NULL;
		dev_warn(dev, "RTC dev.id=%d is used for clocksource."
					" Alarm functionality is disabled\n", dev->id);
	}
#endif	/* CONFIG_E2K */
#if defined(CONFIG_E90S)
	if (clk_rt_enabled() &&
		/* only first RTC is used for SCLKR while there is now flag which */
		atomic_cmpxchg(&rtc4clk_src, 0, 1) == 0) {
		int	error;
		static struct task_struct *clk_rt_registask;

		cy14b101p_rtc_write_lock(dev);
		cy14b101p_write_rtc(dev, CY14B101P_INT,
			CY14B101P_SQWE | CY14B101P_AIE |  CY14B101P_HL |
			CY14B101P_PL);
		cy14b101p_rtc_unlock(dev);
		if (atomic_inc_and_test(&num_clk_rt_register)) {
			clk_rt_registask = kthread_run(clk_rt_register,
				(void *)CLK_RT_RTC, "clk_rt_register");
			if (IS_ERR(clk_rt_registask)) {
				error = PTR_ERR(clk_rt_registask);
				dev_warn(dev, "Failed to start clk_rt register thread, error: %d\n",
					error);
			}
		}
		((struct rtc_class_ops *)
			cy14b101p->rtc->ops)->set_alarm = NULL;
		dev_warn(dev, "RTC is used for clocksource. Alarm functionality is disabled\n");
	}
#endif	/* CONFIG_E90S */
	return;
}
#endif	/* CONFIG_MCST */

static int cy14b101p_probe(struct spi_device *spi)
{
	struct cy14b101p		*cy14b101p;
	int				status;
	int				nvram_res;
	char txbuf[2] = {CY14B101P_WRSR, 0};
	int				ret = 0;
	u8				cy_register;
	struct rtc_time			time;
	struct device			*dev = &spi->dev;

	cy14b101p = kzalloc(sizeof *cy14b101p, GFP_KERNEL);
	if (!cy14b101p)
		return -ENOMEM;

	cy14b101p->spi = spi;
	spi_set_drvdata(spi, cy14b101p);

	status = cy14b101p_wren(dev);
	status = status?:spi_write(spi, txbuf, 2);
	if (status < 0) {
		status = -ENODEV;
		goto fail0;
	}

	cy14b101p->rtc = devm_rtc_allocate_device(dev);
	if (IS_ERR(cy14b101p->rtc)) {
		status = PTR_ERR(cy14b101p->rtc);
		goto fail0;
	}

	cy14b101p->rtc->ops = &cy14b101p_ops;

	/* register RTC ... */
	status = rtc_register_device(cy14b101p->rtc);
	if (status) {
		dev_dbg(dev, "register rtc --> %d\n", ret);
		goto fail0;
	}

	/* export NVRAM */
#if 0
#endif
	nvram_res = sysfs_create_bin_file(&dev->kobj, &nvram);
	if (nvram_res < 0) {
		dev_dbg(dev, "register nvram failed--> %d\n", nvram_res);
	}
	ret = cy14b101p_read_rtc(dev, CY14B101P_CAL, &cy_register);
	if (ret < 0) {
		dev_err(dev, "read rtc CY14B101P_CAL is failed\n");
		goto fail1;
	}
	if (cy_register & CY14B101P_OSCEN) {
		dev_err(dev, "rtc CY14B101P ERROR oscillator is stopped: OSCEN=1\n");
	}
	ret = cy14b101p_read_rtc(dev, CY14B101P_FLAGS, &cy_register);
	if (ret < 0) {
		dev_err(dev, "read rtc CY14B101P_FLAGS is failed\n");
		goto fail1;
	}
	if (cy_register & CY14B101P_OSCF) {
		cy14b101p_get_time(dev, &time);
		dev_err(dev, "rtc CY14B101P Oscillator Fail Flag is set. "
			"rtc= %d-%02d-%02d %02d:%02d:%02d  UTC. "
			" Sleeping 2 secs for oscillator run.\n",
			time.tm_year + 1900, time.tm_mon + 1, time.tm_mday,
			time.tm_hour, time.tm_min, time.tm_sec);
		cy14b101p_rtc_write_flags(dev, 0);
		msleep(2000);
	}
#if defined(CONFIG_MCST)
	init_pps(spi);
#ifdef CONFIG_NVRAM_PANIC
	panic2nvram_read = cy14b101p_nvram_read_for_panic2nvram;
	panic2nvram_write = cy14b101p_nvram_write_for_panic2nvram;
#if 0
	panic2nvram_raw_write = cy14b101p_raw_write_panic_to_nvram;
#endif
	nvram_for_panic = spi;
#endif
#endif	/* CONFIG_MCST */

	/* Maybe set up alarm IRQ; be ready to handle it triggering right
	 * away.  NOTE that we don't share this.  The signal is active low,
	 * and we can't ack it before a SPI message delay.  We temporarily
	 * disable the IRQ until it's acked, which lets us work with more
	 * IRQ trigger modes (not all IRQ controllers can do falling edge).
	 */
	if (spi->irq) {
		INIT_WORK(&cy14b101p->work, cy14b101p_work);
		status = request_irq(spi->irq, cy14b101p_irq,
				0, dev_name(&cy14b101p->rtc->dev), cy14b101p);
		if (status < 0) {
			dev_dbg(dev, "request_irq %d --> %d\n",
					spi->irq, status);
			goto fail1;
		}
		device_set_wakeup_capable(dev, 1);
		device_wakeup_enable(dev);
	} else {
		dev_warn(dev, "%s(): spi->irq is unset so RTC irq and "
			"CLOCK_REALTIME_ALARM is unsupported\n", __func__);
		cy14b101p->rtc->uie_unsupported = 1;
	}
	return 0;
fail1:
	if (nvram_res >= 0)
		sysfs_remove_bin_file(&dev->kobj, &nvram);
fail0:
	kfree(cy14b101p);
	return status;
}

#ifdef CONFIG_PM
static int cy14b101p_rtc_suspend(struct device *dev)
{
	dev_warn(dev, "DEBUG: cy14b101p_rtc_suspend.\n");
#if defined(CONFIG_E2K) && defined(CONFIG_MCST)
	if (strcmp(curr_clocksource->name, "sclkr") == 0) {
		if (timekeeping_notify(&lt_cs)) {
			pr_warn("susp_sclkr: can't set lt clocksourse\n");
		}
	}
#endif
	return 0;
}

static int cy14b101p_rtc_resume(struct device *dev)
{
	struct spi_device *spi = to_spi_device(dev);

	dev_warn(dev, "DEBUG: cy14b101p_rtc_resume.\n");
	init_pps(spi);
	return 0;
}
#else
#define cy14b101p_rtc_suspend NULL
#define cy14b101p_rtc_resume NULL
#endif
static const struct dev_pm_ops cy14b101p_rtc_pm_ops = {
	.suspend = cy14b101p_rtc_suspend,
	.resume = cy14b101p_rtc_resume,
};
static struct spi_driver cy14b101p_driver = {
	.driver = {
		.name = "rtc-cy14b101p",
		.owner  = THIS_MODULE,
		.pm = &cy14b101p_rtc_pm_ops,
	},
	.probe		= cy14b101p_probe,
	.remove		= cy14b101p_remove,
};

static int __init cy14b101p_init(void)
{
	return spi_register_driver(&cy14b101p_driver);
}
module_init(cy14b101p_init);

static void __exit cy14b101p_exit(void)
{
	spi_unregister_driver(&cy14b101p_driver);
}
module_exit(cy14b101p_exit);

MODULE_DESCRIPTION("RTC driver for CY14B101P chip");
MODULE_AUTHOR("MCST");
MODULE_LICENSE("GPL v2");
