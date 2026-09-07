/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/circ_buf.h>
#include <linux/delay.h>
#include <linux/regmap.h>

#define LTD_RING_SIZE (1 * PAGE_SIZE)

struct ltd_regs {
	union ltd_control {
		struct {
			u32 enable	     :1; /* 0     RW 0x0 - turn on data xfer to host.*/
			u32 enable_interrupt :1; /* 1     RW 0x0 - turn on sending interrupt */
						 /*                xfer to host.*/
			u32 reserved	     :6; /* 7:2   RO 0x0 -  reserve.*/
			u32 size	     :4; /* 11:8  RW 0x0 - size of ring buffer in bytes */
						 /*                (degree of 2 - 12) */
						 /*                0 = 4К,v 1 = 8K, ..., A–F = 4M.*/
			u32 reserved2	     :18;/* 29:12 RO 0x0 - reserve.*/
			u32 reset	     :1; /* 30    RW 0x0 - reset controller not stopping.*/
			u32 flush	     :1; /* 31    RW0x0  - immediate writing of */
						 /*                accumulated data to  */
						 /*	           a ring buffer	*/
		};
		u32 raw;
	} control;
	union ltd_status {
		struct {
			u32 data_available :1;	/* 0 	RW1C 0x0 - data has been output */
						/*                 to the ring buffer.*/
			u32 error	   :1;	/* 1 	RW1C 0x0 - error ocuured. */
						/*                 details in Fault Status */
						/*                 and Fault Offset regs.*/
			u32 reserved	   :30;	/* 31:2 RO   0x0 - reserve.*/
		};
		u32 raw;
	} status;
	/* sic! swap tail & head names in order to use linux marcos */
	u32 tail;		/*  RW 0x0 - offset of the first byte not read by host.*/
	u32 head;		/*  RO 0x0 - offset of the first byte not written by device0*/
	u32 buffer_base_low;	/*  RW 0x0 - ring buffer pointer, low bits.*/
	u32 buffer_base_high;   /*  RW 0x0 - ring buffer pointer, high bits */
	u32 aggregation_time_threshold;	/* RW 0x0 - minimum time interval between interrupts, */
					/*          in cycles.*/
	u32 aggregation_data_threshold;	/* RW 0x0 - minimum interval between interrupts in bytes.*/
	union ltd_fault_status {
		struct {
			u32 valid	   :1;	/* 0 	RW 0x0 	 - valid data in Fault Status & */
						/*                 Fault Offset regs. */
			u32 overwrite	   :1;	/* 1 	RW 0x0 	 - error occured when bit 'valid' */
						/*                 was on. Regs Fault Status &    */
						/*                 Fault Offsethold data ,        */
						/*                 corresponding error raised     */
						/*                 setting bit 'value' on         */
			u32 overflow_error :1;	/* 2 	RW 0x0 	 - data lost occured. */
			u32 memory_error   :1;	/* 3 	RW 0x0 	 - ECC error when write to DRAM.  */
			u32 parity_error   :1;	/* 4 	RW 0x0 	 - ECC error in internal buffers  */
						/*                 of device.                     */
			u32 reserved	   :27;	/* 31:5 RO 0x0 	 - reserve.                       */
		};
		u32 raw;
	} fault_status;
	u32 fault_offset;		/* 31:0 	RW 0x0 	 - offset of error.*/
} __packed;

struct ltd_tty {
	struct tty_port port;
	spinlock_t lock;
	struct ltd_regs __iomem *regs;
	struct device *dev;
	struct regmap *regmap;
	u32 irq;
	u32 head;
	u32 tail;
	char *buf;
};

static DEFINE_MUTEX(ltd_tty_lock);
static struct tty_driver *ltd_tty_driver;
static u32 ltd_tty_line_count = 8;
static u32 ltd_tty_current_line_count;
static struct ltd_tty *ltd_ttys;


#define CIRC_SIZE LTD_RING_SIZE
#define CIRC_MASK (CIRC_SIZE - 1)

#define circ_idle(circ)     ((circ)->head == (circ)->tail)
#define __circ_space(head, tail)      CIRC_SPACE(head, tail, CIRC_SIZE)
#define circ_space(circ)      __circ_space((circ)->head, (circ)->tail)
#define circ_cnt(circ)       CIRC_CNT((circ)->head, (circ)->tail, CIRC_SIZE)
#define circ_cnt_to_end(circ) \
	(CIRC_CNT_TO_END((circ)->head, (circ)->tail, CIRC_SIZE))
#define circ_clear(circ)	((circ)->tail = (circ)->head)
#define circ_add(__v, __i)	(((__v) + (__i)) & CIRC_MASK)
#define circ_inc(__v)	circ_add(__v, 1)
#define circ_dec(__v)	circ_add(__v, -1)


#define rltd(__addr)						\
({								\
	void __iomem *__a = __addr;				\
	unsigned __off = __a - (void __iomem *)l->regs;		\
	unsigned __val = readl(__addr);				\
	dev_dbg(l->dev, "r:%02x:%08x %s:%d\n",			\
		 __off, __val, __func__, __LINE__);		\
	__val;							\
})

#define wltd(__val, __addr) do {				\
	unsigned __val2 = __val;				\
	void __iomem *__a = __addr;				\
	unsigned __off = __a - (void __iomem *)l->regs;		\
	dev_dbg(l->dev, "w:%02x:%08x %s:%d\n",			\
		 __off, __val2, __func__, __LINE__);		\
	writel(__val2, __a);				\
} while (0)

static inline struct ltd_tty *to_ltd_tty(struct tty_port *port)
{
	return container_of(port, struct ltd_tty, port);
}

static irqreturn_t ltd_tty_interrupt(int irq, void *dev_id)
{
	unsigned long flags, tail;
	struct ltd_tty *l = dev_id;

	union ltd_status status = { .raw = rltd(&l->regs->status) };
	unsigned char *buf;
	u32 count, n;

	spin_lock_irqsave(&l->lock, flags);
	l->head = rltd(&l->regs->head);
	count = circ_cnt(l);
	spin_unlock_irqrestore(&l->lock, flags);

	if (!status.error && !status.data_available)
		return IRQ_NONE;
	if (status.error) {
		union ltd_fault_status fault_status = {
			.raw = rltd(&l->regs->fault_status)
		};
		u32 fault_offset = rltd(&l->regs->fault_offset);
		dev_err_ratelimited(l->dev, "got error : %x at offset %x\n",
					fault_status.raw, fault_offset);
	}

	if(!status.data_available || count == 0)
		goto out;

	count = tty_prepare_flip_string(&l->port, &buf, count);
	n = circ_cnt_to_end(l);

	if (count == 0)
		goto out;
	
	n = min(count, n);
	memcpy(buf, l->buf + l->tail, n);

	spin_lock_irqsave(&l->lock, flags);
	tail = circ_add(l->tail, count);
	l->tail = tail;
	spin_unlock_irqrestore(&l->lock, flags);
	if (count > n)
		memcpy(buf + n, l->buf, count - n);
	tty_flip_buffer_push(&l->port);

	wltd(tail, &l->regs->tail);

out:
	wltd(status.raw, &l->regs->status);
	return IRQ_HANDLED;
}

static int ltd_tty_activate(struct tty_port *port, struct tty_struct *tty)
{
	int ret, ord = get_order(LTD_RING_SIZE);
	struct ltd_tty *l = to_ltd_tty(port);
	union ltd_control control = { .raw = rltd(&l->regs->control) };
	unsigned long addr = __get_free_pages(GFP_KERNEL, ord);

	if (!addr)
		return -ENOMEM;

	l->buf = (void *)addr;

	ret = request_irq(l->irq, ltd_tty_interrupt, IRQF_SHARED,
			  dev_name(l->dev), l);
	if (ret) {
		dev_err(l->dev, "No IRQ (%d) available : %d\n",
					l->irq, ret);
		goto out;
	}
	l->head = 0;
	l->tail = 0;

	control.enable_interrupt = 1;
	control.enable = 0;
	control.reset = 0;
	control.size = ord;
	wltd(control.raw, &l->regs->control);

	control.raw = rltd(&l->regs->control);
	WARN_ON(control.reset);
	/*TODO: change to time */
	wltd(1000000, &l->regs->aggregation_time_threshold);
	wltd(1, &l->regs->aggregation_data_threshold); /* one byte */
	wltd(__pa(addr) >> 32, &l->regs->buffer_base_high);
	wltd(__pa(addr), &l->regs->buffer_base_low);
	control.enable = 1;
	wltd(control.raw, &l->regs->control);
out:
	return 0;
}

static void ltd_tty_shutdown(struct tty_port *port)
{
	int ord = get_order(LTD_RING_SIZE);
	struct ltd_tty *l = to_ltd_tty(port);
	union ltd_control control = { .raw = rltd(&l->regs->control) };
	control.enable_interrupt = 0;
	control.enable = 0;
	control.reset = 1;
	wltd(control.raw, &l->regs->control);
	free_irq(l->irq, l);
	free_pages((unsigned long)l->buf, ord);
	l->buf = NULL;
}

static int ltd_tty_open(struct tty_struct *tty, struct file *filp)
{
	struct ltd_tty *l = &ltd_ttys[tty->index];
	return tty_port_open(&l->port, tty, filp);
}

static void ltd_tty_close(struct tty_struct *tty, struct file *filp)
{
	tty_port_close(tty->port, tty, filp);
}

static void ltd_tty_hangup(struct tty_struct *tty)
{
	tty_port_hangup(tty->port);
}

static int ltd_tty_write(struct tty_struct *tty, const unsigned char *buf,
								int count)
{
	return count;
}

static unsigned int ltd_tty_write_room(struct tty_struct *tty)
{
	return 0x10000;
}

static unsigned int ltd_tty_chars_in_buffer(struct tty_struct *tty)
{
	unsigned long flags;
	unsigned cnt;
	struct ltd_tty *l = &ltd_ttys[tty->index];
	spin_lock_irqsave(&l->lock, flags);
	l->head = rltd(&l->regs->head);
	cnt = circ_cnt(l);
	spin_unlock_irqrestore(&l->lock, flags);

	return cnt;
}

static const struct tty_port_operations ltd_port_ops = {
	.activate = ltd_tty_activate,
	.shutdown = ltd_tty_shutdown
};

static const struct tty_operations ltd_tty_ops = {
	.open = ltd_tty_open,
	.close = ltd_tty_close,
	.hangup = ltd_tty_hangup,
	.write = ltd_tty_write,
	.write_room = ltd_tty_write_room,
	.chars_in_buffer = ltd_tty_chars_in_buffer,
};

static int ltd_tty_create_driver(void)
{
	int ret;
	struct tty_driver *tty;

	ltd_ttys = kcalloc(ltd_tty_line_count,
				sizeof(*ltd_ttys),
				GFP_KERNEL);
	if (ltd_ttys == NULL) {
		ret = -ENOMEM;
		goto err_alloc_ltd_ttys_failed;
	}
	tty = tty_alloc_driver(ltd_tty_line_count,
			TTY_DRIVER_RESET_TERMIOS | TTY_DRIVER_REAL_RAW |
			TTY_DRIVER_DYNAMIC_DEV);
	if (IS_ERR(tty)) {
		ret = PTR_ERR(tty);
		goto err_tty_alloc_driver_failed;
	}
	tty->driver_name = "ltd";
	tty->name = "ttyLTD";
	tty->type = TTY_DRIVER_TYPE_SERIAL;
	tty->subtype = SERIAL_TYPE_NORMAL;
	tty->init_termios = tty_std_termios;
	tty_set_operations(tty, &ltd_tty_ops);
	ret = tty_register_driver(tty);
	if (ret)
		goto err_tty_register_driver_failed;

	ltd_tty_driver = tty;
	return 0;

err_tty_register_driver_failed:
	tty_driver_kref_put(tty);
err_tty_alloc_driver_failed:
	kfree(ltd_ttys);
	ltd_ttys = NULL;
err_alloc_ltd_ttys_failed:
	return ret;
}

static void ltd_tty_delete_driver(void)
{
	tty_unregister_driver(ltd_tty_driver);
	tty_driver_kref_put(ltd_tty_driver);
	ltd_tty_driver = NULL;
	kfree(ltd_ttys);
	ltd_ttys = NULL;
}

static struct regmap_config ltd_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = 0x28,
};

static int ltd_tty_probe(struct platform_device *pdev)
{
	struct ltd_tty *l;
	struct device *dev = &pdev->dev;
	int ret, irq;
	struct resource *r;
	struct device *ttydev;
	void __iomem *base;
	int line = dev_to_node(dev);
	union ltd_control control;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		ret = irq;
		dev_err(dev, "No IRQ: %d\n", ret);
		return ret;
	}
	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!r) {
		dev_err(dev, "No MEM resource available!\n");
		return -ENOMEM;
	}
	base = devm_ioremap_resource(dev, r);
	if (IS_ERR(base)) {
		dev_err(dev, "Unable to ioremap base!\n");
		return PTR_ERR(base);
	}

	mutex_lock(&ltd_tty_lock);

	if (line < 0)
		line = 0;

	if (line >= ltd_tty_line_count) {
		dev_err(dev, "Reached maximum tty number of %d.\n",
		       ltd_tty_current_line_count);
		ret = -ENOMEM;
		goto err_unlock;
	}

	if (ltd_tty_current_line_count == 0) {
		ret = ltd_tty_create_driver();
		if (ret)
			goto err_unlock;
	}
	ltd_tty_current_line_count++;

	l = &ltd_ttys[line];
	spin_lock_init(&l->lock);
	tty_port_init(&l->port);
	l->port.ops = &ltd_port_ops;
	l->regs = base;
	l->irq = irq;
	l->dev = &pdev->dev;

	l->regmap = devm_regmap_init_mmio(dev, l->regs,
					   &ltd_regmap_config);
	if (WARN_ON(IS_ERR(l->regmap))) {
		ret = PTR_ERR(l->regmap);
		goto err_unlock;
	}
	control.raw = rltd(&l->regs->control);

	control.reset = 1;
	control.enable_interrupt = 0;
	control.enable = 0;
	wltd(control.raw, &l->regs->control);

	ttydev = tty_port_register_device(&l->port, ltd_tty_driver,
					  line, &pdev->dev);
	if (IS_ERR(ttydev)) {
		ret = PTR_ERR(ttydev);
		goto err_tty_register_device_failed;
	}

	platform_set_drvdata(pdev, l);

	mutex_unlock(&ltd_tty_lock);
	return 0;

err_tty_register_device_failed:
	tty_port_destroy(&l->port);
	ltd_tty_current_line_count--;
	if (ltd_tty_current_line_count == 0)
		ltd_tty_delete_driver();
err_unlock:
	mutex_unlock(&ltd_tty_lock);
	return ret;
}

static int ltd_tty_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct ltd_tty *l = platform_get_drvdata(pdev);
	int line = dev_to_node(dev);

	mutex_lock(&ltd_tty_lock);

	tty_unregister_device(ltd_tty_driver, line);
	l->regs = NULL;
	tty_port_destroy(&l->port);
	ltd_tty_current_line_count--;
	if (ltd_tty_current_line_count == 0)
		ltd_tty_delete_driver();
	mutex_unlock(&ltd_tty_lock);
	return 0;
}


static const struct of_device_id ltd_tty_of_match[] = {
	{ .compatible = "mcst,ltd-tty", },
	{},
};

MODULE_DEVICE_TABLE(of, ltd_tty_of_match);

static struct platform_driver ltd_tty_platform_driver = {
	.probe = ltd_tty_probe,
	.remove = ltd_tty_remove,
	.driver = {
		.name = "ltd_tty",
		.of_match_table = ltd_tty_of_match,
	}
};

module_platform_driver(ltd_tty_platform_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Log Transmission Device Driver for e32c & e8v7 MCST processors");
