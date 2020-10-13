/*
 * $Id: fm33256_rtc.c,v 1.6 2008/12/11 13:32:19 dima Exp $ FM33256 Real Time Clock interface for Linux
 */

#include <linux/bcd.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rtc.h>
#include <linux/spinlock.h>
#include <linux/spi/spi.h>
#if defined(CONFIG_MCST) && defined(CONFIG_SCLKR_CLOCKSOURCE)
#include <linux/kthread.h>
#include <linux/clocksource.h>
#endif

#ifdef CONFIG_E2K
#include <asm/rtc.h>
#endif
#include <asm/uaccess.h>


/******************************************************************
 * FM33256 registers
 *****************************************************************/
#define FM_RTC_SECONDS			0x2
#define FM_RTC_MINUTES			0x3
#define FM_RTC_HOURS			0x4
#define FM_RTC_DAY_OF_WEEK		0x5
#define FM_RTC_DAY_OF_MONTH		0x6
#define FM_RTC_MONTH			0x7
#define FM_RTC_YEARS			0x8

#define FM_RTC_SECONDS_ALARM		0x19
#define FM_RTC_MINUTES_ALARM		0x1A
#define FM_RTC_HOURS_ALARM		0x1B
#define FM_RTC_DATE_ALARM		0x1C
#define FM_RTC_MONTHS_ALARM		0x1D

#define FM_RTC_CONTROL		0x0
#define		FM_RTC_RT		0x01
#define		FM_RTC_WT		0x02
#define		FM_RTC_CAL		0x04
#define		FM_RTC_RWC_CHECK (FM_RTC_RT | FM_RTC_WT | FM_RTC_CAL)
#define		FM_RTC_AEN		0x10
#define		FM_RTC_CF		0x20
#define		FM_RTC_AF		0x40
#define		FM_RTC_OSCEN		0x80
#define	FM_CAL_CONTROL		0x1
#define		FM_CLC_CALS	0x20
#define FM_COMPANION_CONTROL	0x18
#define		FM_CC_SNL		0x80
#define		FM_CC_AL_SW		0x40
#define		FM_CC_F_RATE_SHIFT	4
#define		FM_CC_F_RATE_MASK	0x3
#define		fm_rtc_get_rate(reg) \
			((reg >> FM_CC_F_RATE_SHIFT) & FM_CC_F_RATE_MASK)
#define		FM_CC_F_RATE_32768HZ	0x30
#define		FM_CC_F_RATE_4096HZ	0x20
#define		FM_CC_F_RATE_512HZ	0x10
#define		FM_CC_F_RATE_1HZ	0x00	/* default */

/******************************************************************
 * FM33256 commands
 *****************************************************************/
#define WREN_CMD	6
#define WRDI_CMD	4
#define WRSR_CMD	5
#define RDSR_CMD	1
#define READ_CMD	3
#define WRITE_CMD	2
#define RDPC_CMD	0x13
#define WRPC_CMD	0x12

#define FM33256_VERSION		"1.0"


static int fm33256_get_alarm(struct device *dev, struct rtc_wkalrm *alm);
static int fm33256_set_alarm(struct device *dev, struct rtc_wkalrm *alm);
static int fm33256_get_time(struct device *dev, struct rtc_time *rtc_tm);
static int fm33256_set_time(struct device *dev, struct rtc_time *rtc_tm);

/*
 *	Bits in rtc_status. (7 bits of room for future expansion)
 */

#define RTC_IS_OPEN		0x01	/* means /dev/rtc is in use	*/
#define RTC_TIMER_ON		0x02	/* missed irq timer active	*/

#define ALARM_MATCH_BIT	0x80
#define ALARM_MASK	0x7f
#define match_bit(val)	(val & ALARM_MATCH_BIT)

static int irq_enabled = 0;
#if defined(CONFIG_MCST) && defined(CONFIG_SCLKR_CLOCKSOURCE)
static int rtc4sclkr = 0;
#endif

static unsigned long epoch = 2000;	/* year corresponding to 0x00	*/

static int fm33256_read_regs(struct device *dev, unsigned char *regs,
		int no_regs)
{
	struct spi_device *spi = to_spi_device(dev);
	u8 txbuf[2], rxbuf[1];
	int i, ret = 0;

	txbuf[0] = RDPC_CMD;
	for (i = 0; i < no_regs; i++) {
		txbuf[1] = regs[i];
		ret |= spi_write_then_read(spi, txbuf, 2, rxbuf, 1);
		regs[i] = rxbuf[0];
	}

	return ret;
}

int fm33256_read(struct device *dev, u8 reg, u8 *val)
{
	struct spi_device *spi = to_spi_device(dev);
	u8 txbuf[2];
	int ret;

	txbuf[0] = RDPC_CMD;
	txbuf[1] = reg;
	ret = spi_write_then_read(spi, txbuf, 2, val, 1);
	if (ret)
		dev_err(dev, "spi access returned %d\n", ret);

	return ret;
}

int fm33256_write(struct device *dev, u8 val, u8 reg)
{
	struct spi_device *spi = to_spi_device(dev);
	u8 txbuf[3];
	int ret;

	txbuf[0] = WREN_CMD;
	ret = spi_write(spi, txbuf, 1);
	if (ret) {
		dev_dbg(dev, "spi access returned %d\n", ret);
		return ret;
	}

	txbuf[0] = WRPC_CMD;
	txbuf[1] = reg;
	txbuf[2] = val;
	ret = spi_write(spi, txbuf, 3);
	if (ret)
		dev_dbg(dev, "spi access returned %d\n", ret);

	return ret;
}

irqreturn_t fm33256_interrupt(int irq, void *dev_id)
{
	struct device *dev = (struct device *) dev_id;
	struct rtc_device *rtc = dev_get_drvdata(dev);
	int ret;
	u8 val;

	dev_dbg(dev, "fm33256_interrupt: alarm reset\n");

	ret = fm33256_read(dev, FM_RTC_CONTROL, &val);
	if (ret)
		return ret;

	if (val & FM_RTC_AF) {
		rtc_update_irq(rtc, 1, RTC_IRQF | RTC_AF);

		ret = fm33256_write(dev, val & ~FM_RTC_AF, FM_RTC_CONTROL);
		if (ret)
			dev_err(dev, "could not reset alarm from "
					"interrupt handler\n");

		ret = IRQ_HANDLED;
	} else {
		ret = IRQ_NONE;
	}

	return ret;
}

static int fm33256_ioctl(struct device *dev,
		unsigned int cmd, unsigned long arg)
{
	int ret;

	switch (cmd) {
	case RTC_EPOCH_READ:	/* Read the epoch.	*/
		ret = put_user(epoch, (unsigned long __user *)arg);
		break;
	case RTC_EPOCH_SET:	/* Set the epoch.	*/
		if (arg < 1900)
			return -EINVAL;

		epoch = arg;
		ret = 0;
		break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}
	return ret;
}


#ifdef CONFIG_PROC_FS
static int fm33256_proc(struct device *dev, struct seq_file *seq)
{
	unsigned char control, ccontrol;
	int ret, n = 0;

	ret = fm33256_read(dev, FM_RTC_CONTROL, &control);
	ret = ret ?: fm33256_read(dev, FM_COMPANION_CONTROL, &ccontrol);
	if (!ret)
		n += seq_printf(seq,
			"oscillator\t: %s\n"
			"alarm selected\t: %s\n"
			"alarm enabled\t: %s\n"
			"alarm triggered\t: %s\n"
			"calibration\t: %s\n"
			"rate (frequency)\t: %s\n",
			(control & FM_RTC_OSCEN) ? "disabled" : "enabled",
			(ccontrol & FM_CC_AL_SW) ? "yes" : "no",
			(control & FM_RTC_AEN) ? "enabled" : "disabled",
			(control & FM_RTC_AF) ? "yes" : "no",
			(control & FM_RTC_CAL) ? "enabled" : "disabled",
			((ccontrol & FM_CC_F_RATE_MASK) == 0) ? "1 Hz" :
			    (ccontrol & FM_CC_F_RATE_512HZ) ? "512 Hz" :
			    (ccontrol & FM_CC_F_RATE_4096HZ) ? "4 096 Hz" :
			    (ccontrol & FM_CC_F_RATE_32768HZ) ? "32 760 Hz" :
			    "undefined"
			);

	return n;
}
#else
#define fm33256_proc	NULL
#endif

static int fm33256_alarm_irq_enable(struct device *dev, unsigned int enable)
{
	int ret;
	u8 val;

	if (!irq_enabled)
		return -EINVAL;

	if (enable) {
#if defined(CONFIG_MCST) && defined(CONFIG_SCLKR_CLOCKSOURCE)
		if (rtc4sclkr) {
			pr_warning("fm33256_alarm_irq_enable: "
				"RTC is used for SCLKR. "
				"Alarm functionality is disabled\n");
			WARN_ONCE(1, "RTC is used for SCLKR.");
			return -EINVAL;
		}
#endif
		ret = fm33256_read(dev, FM_RTC_CONTROL, &val);
		ret = ret ?: fm33256_write(dev, val | FM_RTC_AEN,
				FM_RTC_CONTROL);
		ret = ret ?: fm33256_read(dev, FM_COMPANION_CONTROL, &val);
		ret = ret ?: fm33256_write(dev, val | FM_CC_AL_SW,
				FM_COMPANION_CONTROL);
	} else {
		ret = fm33256_read(dev, FM_RTC_CONTROL, &val);
		ret = ret ?: fm33256_write(dev,
				val & (~FM_RTC_AEN & ~FM_RTC_AF),
				FM_RTC_CONTROL);
	}

	return ret;
}

static struct rtc_class_ops fm33256_ops = {
	.read_time		= fm33256_get_time,
	.set_time		= fm33256_set_time,
	.read_alarm		= fm33256_get_alarm,
	.set_alarm		= fm33256_set_alarm,
	.proc			= fm33256_proc,
	.ioctl			= fm33256_ioctl,
	.alarm_irq_enable	= fm33256_alarm_irq_enable,
};

static int fm33256_probe(struct spi_device *spi)
{
	struct rtc_device *rtc;
	int ret;
	u8 c;

	/* Disable alarm and calibration mode */
	ret = fm33256_read(&spi->dev, FM_RTC_CONTROL, &c);
	ret = ret ?: fm33256_write(&spi->dev, c & ~(FM_RTC_OSCEN | FM_RTC_AF |
			FM_RTC_AEN | FM_RTC_CAL | FM_RTC_WT | FM_RTC_RT),
			FM_RTC_CONTROL);
	if (ret)
		return ret;

	if (c & FM_RTC_OSCEN)
		dev_info(&spi->dev, "FM33256 oscillator disabled. Kickstart\n");
#ifdef DEBUG
	ret = fm33256_read(&spi->dev, FM_RTC_CONTROL, &c);
	if (ret)
		return ret;
	dev_dbg(&spi->dev, "Control register set to %hhx\n", c);
#endif

	rtc = rtc_device_register("fm33256", &spi->dev,
			&fm33256_ops, THIS_MODULE);
	if (IS_ERR(rtc))
		return PTR_ERR(rtc);

	ret = ret ?: fm33256_read(&spi->dev, FM_COMPANION_CONTROL, &c);
	c = (c & ~FM_CC_F_RATE_MASK) | FM_CC_F_RATE_1HZ;
#if defined(CONFIG_MCST) && defined(CONFIG_SCLKR_CLOCKSOURCE)
	if (!ret && machine.iset_ver >= E2K_ISET_V3) {
		static struct task_struct *sclkregistask;
		int error;

		c &= ~FM_CC_AL_SW;
		ret = fm33256_write(&spi->dev, c, FM_COMPANION_CONTROL);
		if (ret)
			return ret;
		sclkregistask = kthread_run(sclk_register, "rtc",
			"sclkregister");
		if (IS_ERR(sclkregistask)) {
			error = PTR_ERR(sclkregistask);
			pr_err(KERN_ERR "Failed to start sclk register thread,"
					"error: %d\n", error);
			return error;
		}
		rtc4sclkr = 1;
		((struct rtc_class_ops *)(rtc->ops))->set_alarm = NULL;
		pr_warning("RTC is used for SCLKR. "
			"Alarm functionality will be disabled\n");
		return 0;
	}
#endif
	/* Set frequency to 1 Hz, disable periodic interrupts */
	c |= FM_CC_AL_SW;
	ret = ret ?: fm33256_write(&spi->dev, c, FM_COMPANION_CONTROL);
	if (ret)
		return ret;

	rtc->max_user_freq = 1;
	rtc->irq_freq = 1;
	dev_set_drvdata(&spi->dev, rtc);

	if (spi->irq) {
		ret = request_irq(spi->irq, fm33256_interrupt, 0,
				dev_name(&rtc->dev), &spi->dev);
		if (ret) {
			dev_notice(&spi->dev, "alarm functionality will "
					"be disabled\n");
		} else {
			irq_enabled = 1;
			dev_info(&spi->dev, "using IRQ %d\n", spi->irq);
			device_set_wakeup_capable(&spi->dev, 1);
		}
	} else {
		rtc->uie_unsupported = 1;
	}

	return 0;
}

static int fm33256_remove(struct spi_device *spi)
{
	struct rtc_device *rtc = dev_get_drvdata(&spi->dev);

	rtc_device_unregister(rtc);
	return 0;
}


static struct spi_driver fm33256_driver = {
	.driver = {
		.name = "rtc-fm33256",
		.owner  = THIS_MODULE,
	},
	.probe = fm33256_probe,
	.remove = fm33256_remove,
};

static int __init fm33256_init(void)
{
	return spi_register_driver(&fm33256_driver);
}

static void __exit fm33256_exit(void)
{
	spi_unregister_driver(&fm33256_driver);
}


static int fm33256_get_time(struct device *dev, struct rtc_time *rtc_tm)
{
	u8 save_control, buf[] = { FM_RTC_SECONDS, FM_RTC_MINUTES,
		FM_RTC_HOURS, FM_RTC_DAY_OF_MONTH, FM_RTC_MONTH, FM_RTC_YEARS };
	int ret;

	/*
	 * Only the values that we read from the RTC are set. We leave
	 * tm_wday, tm_yday and tm_isdst untouched. Even though the
	 * RTC has RTC_DAY_OF_WEEK, we ignore it, as it is only updated
	 * by the RTC when initially set to a non-zero value.
	 */
	ret = fm33256_read(dev, FM_RTC_CONTROL, &save_control);
	ret = ret ?: fm33256_write(dev, save_control | FM_RTC_RT,
			FM_RTC_CONTROL);
	ret = ret ?: fm33256_read_regs(dev, buf, sizeof(buf));
	ret = ret ?: fm33256_write(dev, save_control, FM_RTC_CONTROL);
	if (unlikely(ret))
		return ret;

	rtc_tm->tm_sec = bcd2bin(buf[0]);
	rtc_tm->tm_min = bcd2bin(buf[1]);
	rtc_tm->tm_hour = bcd2bin(buf[2]);
	rtc_tm->tm_mday = bcd2bin(buf[3]);
	rtc_tm->tm_mon = bcd2bin(buf[4]);
	rtc_tm->tm_year = bcd2bin(buf[5]) + epoch;

	/* Print using the device's format */
	dev_dbg(dev, "fm33256_get_time: control reg 0x%x, date/time is "
			"%d-%d-%d, %02d:%02d:%02d.\n", save_control,
			rtc_tm->tm_mday, rtc_tm->tm_mon, rtc_tm->tm_year,
			rtc_tm->tm_hour, rtc_tm->tm_min, rtc_tm->tm_sec);

	/*
	 * Account for differences between how the RTC uses the values
	 * and how they are defined in a struct rtc_time;
	 */
	rtc_tm->tm_mon -= 1;
	rtc_tm->tm_year -= 1900;

	return rtc_valid_tm(rtc_tm);
}

static int fm33256_set_time(struct device *dev, struct rtc_time *rtc_tm)
{
	unsigned char mon, day, hrs, min, sec;
	unsigned char save_control;
	unsigned int yrs;
	int ret;

	if (unlikely(rtc_valid_tm(rtc_tm))) {
		dev_dbg(dev, "fm3256_set_time: Invalid time: %d/%d/%d %d:%d$%d\n",
				rtc_tm->tm_mday, rtc_tm->tm_mon,
				rtc_tm->tm_year, rtc_tm->tm_hour,
				rtc_tm->tm_min, rtc_tm->tm_sec);

		dev_dbg(dev, "set time: Invalid time\n");
		return -EINVAL;
	}

	yrs = rtc_tm->tm_year + 1900 - epoch;
	mon = rtc_tm->tm_mon + 1;   /* tm_mon starts at zero */
	day = rtc_tm->tm_mday;
	hrs = rtc_tm->tm_hour;
	min = rtc_tm->tm_min;
	sec = rtc_tm->tm_sec;

	if (yrs >= 100) {
		dev_dbg(dev, "year %d is too big (epoch = %ld)\n", yrs, epoch);
		return -EINVAL;
	}

	sec = bin2bcd(sec);
	min = bin2bcd(min);
	hrs = bin2bcd(hrs);
	day = bin2bcd(day);
	mon = bin2bcd(mon);
	yrs = bin2bcd(yrs);

	ret = fm33256_read(dev, FM_RTC_CONTROL, &save_control);
	ret = ret ?: fm33256_write(dev, (save_control | FM_RTC_WT),
					FM_RTC_CONTROL);
	ret = ret ?: fm33256_write(dev, yrs, FM_RTC_YEARS);
	ret = ret ?: fm33256_write(dev, mon, FM_RTC_MONTH);
	ret = ret ?: fm33256_write(dev, day, FM_RTC_DAY_OF_MONTH);
	ret = ret ?: fm33256_write(dev, hrs, FM_RTC_HOURS);
	ret = ret ?: fm33256_write(dev, min, FM_RTC_MINUTES);
	ret = ret ?: fm33256_write(dev, sec, FM_RTC_SECONDS);
	ret = ret ?: fm33256_write(dev, save_control, FM_RTC_CONTROL);

	return ret;
}

static int fm33256_get_alarm(struct device *dev, struct rtc_wkalrm *alm)
{
	int ret;
	u8 buf[] = { FM_RTC_CONTROL, FM_COMPANION_CONTROL,
			FM_RTC_SECONDS_ALARM, FM_RTC_MINUTES_ALARM,
			FM_RTC_HOURS_ALARM, FM_RTC_DATE_ALARM,
			FM_RTC_MONTHS_ALARM };

	if (!irq_enabled)
		return -EINVAL;

	ret = fm33256_read_regs(dev, buf, sizeof(buf));
	if (!ret) {
		alm->time.tm_sec = match_bit(buf[2]) ? INT_MAX :
				bcd2bin(buf[2] & ALARM_MASK);
		alm->time.tm_min = match_bit(buf[3]) ? INT_MAX :
				bcd2bin(buf[3] & ALARM_MASK);
		alm->time.tm_hour = match_bit(buf[4]) ? INT_MAX :
				bcd2bin(buf[4] & ALARM_MASK);
		alm->time.tm_mday = match_bit(buf[5]) ? INT_MAX :
				bcd2bin(buf[5] & ALARM_MASK);
		alm->time.tm_mon = match_bit(buf[6]) ? INT_MAX :
				(bcd2bin(buf[6] & ALARM_MASK) - 1);
		alm->time.tm_year = INT_MAX;
		alm->enabled = (buf[0] & FM_RTC_AEN) && (buf[1] & FM_CC_AL_SW);
		alm->pending = !!(buf[0] & FM_RTC_AF);

		/* Print using the device's format */
		dev_dbg(dev, "get_alarm: %d-%d, %02d:%02d:%02d, "
				"enabled: %d, pending : %d\n",
				match_bit(buf[6]) ? INT_MAX :
						alm->time.tm_mon + 1,
				alm->time.tm_mday,
				alm->time.tm_hour, alm->time.tm_min,
				alm->time.tm_sec, alm->enabled, alm->pending);
	}

	return 0;
}

static int fm33256_set_alarm(struct device *dev, struct rtc_wkalrm *alm)
{
	unsigned char mon, date, hrs, min, sec;
	int ret;

	if (!irq_enabled)
		return -EINVAL;

	mon = alm->time.tm_mon + 1;
	date = alm->time.tm_mday;
	hrs = alm->time.tm_hour;
	min = alm->time.tm_min;
	sec = alm->time.tm_sec;

	dev_dbg(dev, "Alarm from user: %d-%d, %02d:%02d:%02d\n",
			mon, date, hrs, min, sec);
	if (!mon || mon > 12)
		mon = 0x80;
	else
		mon = bin2bcd(mon);

	if (!date || date > 31)
		date = 0x80;
	else
		date = bin2bcd(date);

	if (hrs >= 24)
		hrs = 0x80;
	else
		hrs = bin2bcd(hrs);

	if (min >= 60)
		min = 0x80;
	else
		min = bin2bcd(min);

	if (sec >= 60)
		sec = 0x80;
	else
		sec = bin2bcd(sec);

	dev_dbg(dev, "Alarm after check: %x-%x, %02x:%02x:%02x\n",
			mon, date, hrs, min, sec);

	ret = fm33256_alarm_irq_enable(dev, 0);

	ret = ret ?: fm33256_write(dev, mon, FM_RTC_MONTHS_ALARM);
	ret = ret ?: fm33256_write(dev, date, FM_RTC_DATE_ALARM);
	ret = ret ?: fm33256_write(dev, hrs, FM_RTC_HOURS_ALARM);
	ret = ret ?: fm33256_write(dev, min, FM_RTC_MINUTES_ALARM);
	ret = ret ?: fm33256_write(dev, sec, FM_RTC_SECONDS_ALARM);

	if (!ret)
		ret = fm33256_alarm_irq_enable(dev, alm->enabled);

	return ret;
}

module_init(fm33256_init);
module_exit(fm33256_exit);

MODULE_AUTHOR("Alexander Fyodorov");
MODULE_LICENSE("GPL");
