/*
 * arch/l/kernel/gpio.c
 *
 * Copyright (C) 2012 Evgeny Kravtsunov MCST.
 *
 * GPIOLIB implementation for MCST-GPIO controller (part of Elbrus MCST).
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/io.h>
#include <linux/pci.h>

#if IS_ENABLED(CONFIG_INPUT_LTC2954)
#include <linux/platform_device.h>
#include <linux/gpio_keys.h>
#include <linux/input.h>
#endif /* CONFIG_INPUT_LTC2954 */

#include <asm/gpio.h>
#include <asm/iolinkmask.h>
#include <asm/io_apic.h>

#include <linux/mcst/gpio.h>
/* Offsets from BAR for MCST GPIO registers */
#define L_GPIO_CNTRL	0x00
#define L_GPIO_DATA		0x04
#define L_GPIO_INT_CLS	0x08
#define L_GPIO_INT_LVL	0x0c
#define L_GPIO_INT_EN	0x10
#define L_GPIO_INT_STS	0x14

#define L_GPIO_ONE_MASK(x)	(1 << (x))
#define L_GPIO_ZERO_MASK(x)	(~(1 << (x)))

/* Configuration values */
#define L_GPIO_CNTRL_IN		0x00000000	/* Input mode for all pins */
#define L_GPIO_CNTRL_OUT	0x0000ffff	/* Output mode for all pins */
#define L_GPIO_INT_ENABLE	0x0000ffff	/* Interrupts enabled for all */
#define L_GPIO_INT_DISABLE	0x00000000	/* Interrupts disabled for all*/
#define L_GPIO_INT_CLS_LVL	0x00000000	/* Enable level interrupts */
#define L_GPIO_INT_CLS_EDGE	0x0000ffff	/* Enable edge interrupts */
#define L_GPIO_INT_LVL_RISE	0x0000ffff     /* Rising edge detection (0->1)*/
#define L_GPIO_INT_LVL_FALL 0x00000000	/* Falling edeg detection */

/* Predefined default configuration values */
/* Input mode for all pins by default: */
#define L_GPIO_CNTRL_DEF	L_GPIO_CNTRL_IN
/* Interrupts from all pins disabled by default: */
#define L_GPIO_INT_EN_DEF	L_GPIO_INT_DISABLE
/* Interrupt mode for all pins - egde interrupts: */
#define L_GPIO_INT_CLS_DEF	L_GPIO_INT_CLS_EDGE
/* Interrupt mode for all pins - falling egde detection: */
#define L_GPIO_INT_LVL_DEF	L_GPIO_INT_LVL_FALL

/* Sets of gpios */
#define IOHUB_IRQ0_GPIO_START	0
#define IOHUB_IRQ0_GPIO_END	7
#define IOHUB_IRQ1_GPIO_START   8
#define IOHUB_IRQ1_GPIO_END	15

#define DRV_NAME "l-gpio"

#define IOHUB_BAR	1

#define IOHUB_GPIO_IRQ_DESCS	ARCH_NR_OWN_GPIOS

 #define L_GPIO_MAX_IRQS       2

struct l_gpio_data {
	int bar;
	int lines;
	struct {
		int nr;
		int start;
		int end;
	} irq[L_GPIO_MAX_IRQS];
};


struct l_gpio {
	struct gpio_chip chip;
	resource_size_t base;
	void __iomem *base_ioaddr;
	struct pci_dev *pdev;
	raw_spinlock_t lock;
	unsigned int irq_base;
	unsigned int irqchip0_start;
	unsigned int irqchip0_end;
	unsigned int irqchip1_start;
	unsigned int irqchip1_end;
	struct l_gpio *next;
	int		intr_assembl;
	gpio_intr_inf_t intr_inf[ARCH_MAX_NR_OWN_GPIOS];
	int		do_postpone[ARCH_MAX_NR_OWN_GPIOS];
	struct list_head wait_task_list[ARCH_MAX_NR_OWN_GPIOS];
	struct l_gpio_data data;
};

typedef struct __raw_wqueue {
	struct task_struct *task;
	struct list_head task_list;
} raw_wqueue_t;

/* Registering gpio-bound devices on board. This is embedded style. */
#if IS_ENABLED(CONFIG_INPUT_LTC2954)
static struct platform_device *pltc2954_dev;
#endif /* CONFIG_INPUT_LTC2954 */

static int register_l_gpio_bound_devices(void)
{

	int err = 0;

	if (HAS_MACHINE_E2K_IOHUB) {
#if IS_ENABLED(CONFIG_INPUT_LTC2954)
		/* Only power button is available today: */
		struct gpio_keys_platform_data *pltc2954_button_pdata;
		struct gpio_keys_button *pltc2954_descr;

		/* gpio_keys_button object initialization  */
		pltc2954_descr = kzalloc(sizeof(struct gpio_keys_button), GFP_KERNEL);
		if (!pltc2954_descr) {
			printk(KERN_ERR "failed to alloc pltc2954_descr\n");
			return -ENOMEM;
		}
		pltc2954_descr->code = KEY_SLEEP;
		pltc2954_descr->gpio = LTC2954_IRQ_GPIO_PIN;
		pltc2954_descr->active_low = 0;
		pltc2954_descr->type = EV_KEY;
		pltc2954_descr->wakeup = 0;
		pltc2954_descr->debounce_interval = 0;

		/* gpio_keys_platform_data object initialization */
		pltc2954_button_pdata = kzalloc(
			sizeof(struct gpio_keys_platform_data),
			GFP_KERNEL);
		if (!pltc2954_button_pdata) {
			printk(KERN_ERR "failed to alloc pltc2954_button_pdata\n");
			return -ENOMEM;
		}
		pltc2954_button_pdata->buttons = pltc2954_descr;
		pltc2954_button_pdata->nbuttons = 1;
		pltc2954_button_pdata->rep = 0;

		/* allocate ltc2954 platfrom_device object */
		pltc2954_dev = platform_device_alloc("ltc2954", -1);
		if (!pltc2954_dev) {
			printk(KERN_ERR "failed to alloc pltc2954_dev\n");
			return -ENOMEM;
		}
		pltc2954_dev->dev.platform_data = pltc2954_button_pdata;

		err = platform_device_add(pltc2954_dev);
		if (err < 0)
			printk(KERN_ERR "failed to register "
			       "ltc2954 device\n");
#endif /* CONFIG_INPUT_LTC2954_BUTTON */
	}

	return err;
}

/* Generic GPIO interface */

/*
 * Set the state of an output GPIO line.
 */
static void l_gpio_set_value(struct gpio_chip *c,
				unsigned int offset, int state)
{
	struct l_gpio *chip = (struct l_gpio *)c;
	unsigned long flags;
	unsigned int x;

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_DATA);
	if (state)
		x |= L_GPIO_ONE_MASK(offset);
	else
		x &= L_GPIO_ZERO_MASK(offset);

	writel(x, chip->base_ioaddr + L_GPIO_DATA);
	raw_spin_unlock_irqrestore(&chip->lock, flags);
}

/*
 * Read the state of a GPIO line.
 */
static int l_gpio_get_value(struct gpio_chip *c, unsigned int offset)
{
	struct l_gpio *chip = (struct l_gpio *)c;
	unsigned long flags;
	unsigned int x;

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_DATA);
	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return (x & L_GPIO_ONE_MASK(offset)) ? 1 : 0;
}

/*
 * Configure the GPIO line as an input.
 */
static int l_gpio_direction_input(struct gpio_chip *c, unsigned offset)
{
	struct l_gpio *chip = (struct l_gpio *)c;
	unsigned long flags;
	unsigned int x;

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_CNTRL);
	x &= L_GPIO_ZERO_MASK(offset);
	writel(x, chip->base_ioaddr + L_GPIO_CNTRL);
	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return 0;
}

/*
 * Configure the GPIO line as an output.
 */
static int l_gpio_direction_output(struct gpio_chip *c, unsigned offset,
				      int val)
{
	struct l_gpio *chip = (struct l_gpio *)c;
	unsigned long flags;
	unsigned int x;

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_CNTRL);
	x |= L_GPIO_ONE_MASK(offset);
	writel(x, chip->base_ioaddr + L_GPIO_CNTRL);
	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return 0;
}

/*
 * Map GPIO line to IRQ number.
 */
static int l_gpio_to_irq(struct gpio_chip *c, unsigned int pin)
{
	struct l_gpio *chip = (struct l_gpio *)c;

	return (chip->irq_base + pin);
}

/*
 * For ioctl(GPIO_WAIT_INTR)
 */
static int
l_gpio_wait_irq(struct gpio_chip *c, unsigned int offset,
					void *intr_inf_p)
{
	struct l_gpio *chip = (struct l_gpio *)c;
	gpio_intr_inf_t		*user_inf = (gpio_intr_inf_t *)intr_inf_p;
	raw_wqueue_t		wait_el = {.task = current};
	unsigned long		expire;
	unsigned long		flags;
	unsigned long long	cycls_limit, cycl_beg, cycl;
	int			interrupts;
	struct			timespec intr_real_tm;
	long long		beg_tm_ns, real_tm_ns = 0;

	raw_spin_lock_irqsave(&chip->lock, flags);
	getnstimeofday(&intr_real_tm);  /* 200 nsec */
	beg_tm_ns = timespec_to_ns(&intr_real_tm);
	if (chip->intr_assembl & L_GPIO_ONE_MASK(offset)) {
		user_inf->was_waiting_ns = 0;
		user_inf->was_oncpu_ns = 0;
		real_tm_ns = beg_tm_ns;
		goto finish;
	}
	/* adaptive wait on cpu */
	if (user_inf->period_ns &&
		 chip->intr_inf[offset].intr_driver_nsec &&
			((chip->intr_inf[offset].intr_driver_nsec +
				user_inf->period_ns - beg_tm_ns) <
					user_inf->may_on_cpu)) {
		cycl_beg = get_cycles();
		cycls_limit = cycl_beg + 2 *
				usecs_2cycles(user_inf->may_on_cpu);
		do {
			interrupts =
				readl(chip->base_ioaddr + L_GPIO_INT_STS) &
						L_GPIO_ONE_MASK(offset);
			cycl = get_cycles();
			if (interrupts)
				goto got;
		} while (cycl < cycls_limit);
		chip->do_postpone[offset] = 0;
		raw_spin_unlock_irq(&chip->lock);
		return -ETIME;
got:
		writel(interrupts,
			chip->base_ioaddr + L_GPIO_INT_STS);
		user_inf->was_oncpu_ns = cycles_2nsec(cycl - cycl_beg);
		user_inf->was_waiting_ns = 0;
		chip->intr_inf[offset].num_received_ints++;
		getnstimeofday(&intr_real_tm);
		chip->intr_inf[offset].prev_driver_nsec =
				chip->intr_inf[offset].intr_driver_nsec;
		real_tm_ns = timespec_to_ns(&intr_real_tm);
		chip->intr_inf[offset].intr_driver_nsec = real_tm_ns;
	} else {
		user_inf->was_oncpu_ns = 0;
		while (!(chip->intr_assembl & L_GPIO_ONE_MASK(offset))) {
			current->state = TASK_INTERRUPTIBLE;
			list_add(&wait_el.task_list,
					&chip->wait_task_list[offset]);
			chip->do_postpone[offset] = user_inf->postpone_tick_ns;
			raw_spin_unlock_irq(&chip->lock);
			expire = schedule_timeout(
				usecs_to_jiffies(user_inf->timeout_us));
			raw_spin_lock_irq(&chip->lock);
			list_del(&wait_el.task_list);
			current->state = TASK_RUNNING;
			if (signal_pending(current)) {
				raw_spin_unlock_irqrestore(&chip->lock, flags);
				return -EINTR;
			}
			if (!expire) {
				raw_spin_unlock_irqrestore(&chip->lock, flags);
				return -ETIME;
			}
			getnstimeofday(&intr_real_tm);
			real_tm_ns = timespec_to_ns(&intr_real_tm);
			user_inf->was_waiting_ns = real_tm_ns - beg_tm_ns;
		}
	}	/* wait_on_cpu? */
finish:
	user_inf->gpio_drv_ver = GPIO_DRV_VER;
	user_inf->intr_driver_nsec = chip->intr_inf[offset].intr_driver_nsec;
	user_inf->prev_driver_nsec = chip->intr_inf[offset].prev_driver_nsec;
	user_inf->num_received_ints = chip->intr_inf[offset].num_received_ints;
	chip->intr_assembl &= L_GPIO_ZERO_MASK(offset);
	user_inf->woken_nsec = real_tm_ns;
	raw_spin_unlock_irqrestore(&chip->lock, flags);
	return 0;
}

/* GPIOLIB interface */
static struct l_gpio *l_gpios_set;

/*
 * GPIO IRQ
 */

static int irq_to_gpio(unsigned int irq)
{
	struct l_gpio *chip = irq_get_handler_data(irq);

	return (irq - chip->irq_base);
}

static void l_gpio_irq_disable(struct irq_data *irq_data)
{
	unsigned long flags;
	unsigned int x;
	unsigned int irq = irq_data->irq;
	struct l_gpio *chip = irq_get_handler_data(irq);
	int offset = irq_to_gpio(irq);

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_INT_EN);
	x &= L_GPIO_ZERO_MASK(offset);
	writel(x, chip->base_ioaddr + L_GPIO_INT_EN);
	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return;
}

static void l_gpio_irq_enable(struct irq_data *irq_data)
{
	unsigned long flags;
	unsigned int x;
	unsigned int irq = irq_data->irq;
	struct l_gpio *chip = irq_get_handler_data(irq);
	int offset = irq_to_gpio(irq);

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_INT_EN);
	x |= L_GPIO_ONE_MASK(offset);
	writel(x, chip->base_ioaddr + L_GPIO_INT_EN);
	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return;
}

static int l_gpio_irq_type(struct irq_data *irq_data, unsigned trigger)
{
	unsigned long flags;
	unsigned int irq = irq_data->irq;
	struct l_gpio *chip = irq_get_handler_data(irq);
	int offset = irq_to_gpio(irq);
	unsigned int cls, lvl;

	if (offset < 0 || offset > chip->chip.ngpio) {
		return -EINVAL;
	}

	raw_spin_lock_irqsave(&chip->lock, flags);

	cls = readl(chip->base_ioaddr + L_GPIO_INT_CLS);
	lvl = readl(chip->base_ioaddr + L_GPIO_INT_LVL);

	if ((trigger & IRQ_TYPE_EDGE_BOTH) == IRQ_TYPE_EDGE_BOTH) {
		raw_spin_unlock_irqrestore(&chip->lock, flags);
		return -EINVAL;
	}

	if (trigger & (IRQ_TYPE_LEVEL_HIGH | IRQ_TYPE_LEVEL_LOW)) {
		/* level interrupt */
		cls &= L_GPIO_ZERO_MASK(offset);
		if (trigger & IRQ_TYPE_LEVEL_HIGH)
			lvl |= L_GPIO_ONE_MASK(offset);
		else
			lvl &= L_GPIO_ZERO_MASK(offset);
	} else if (trigger & (IRQ_TYPE_EDGE_RISING | IRQ_TYPE_EDGE_FALLING)) {
		/* edge interrupt */
		cls |= L_GPIO_ONE_MASK(offset);
		if (trigger & IRQ_TYPE_EDGE_RISING)
			lvl |= L_GPIO_ONE_MASK(offset);
		else
			lvl &= L_GPIO_ZERO_MASK(offset);
	}

	writel(lvl, chip->base_ioaddr + L_GPIO_INT_LVL);
	writel(cls, chip->base_ioaddr + L_GPIO_INT_CLS);

	raw_spin_unlock_irqrestore(&chip->lock, flags);

	return 0;
}

/* suspenders/resumers: only disable/enable gpio interrupts */
static void l_gpio_irq_unmask(struct irq_data *irq_data)
{
}

static void l_gpio_irq_mask(struct irq_data *irq_data)
{
}

static int l_gpio_irq_aff(struct irq_data *idata_arg,
		const struct cpumask *mask, bool force)
{
#ifdef CONFIG_SMP
	int ret = 0, i;
	struct l_gpio *chip = (struct l_gpio *)irq_data_get_irq_chip(idata_arg);
	for (i = 0; chip->data.irq[i].nr && ret == 0; i++) {
		struct irq_data *idata =
				irq_get_irq_data(chip->data.irq[i].nr);
		if (idata)
			ret = native_ioapic_set_affinity(idata, mask, force);
	else
		pr_alert("Error: gpio: could not set IRQ#%d affinity. Did not boot pass info about it?\n",
			chip->data.irq[i].nr);
	}
	return ret;
#else
	return IRQ_SET_MASK_OK;
#endif
}

static void l_gpio_irq_handler(unsigned irq, struct irq_desc *desc)
{
	unsigned long flags;
	unsigned int x;
	unsigned int i;
	struct l_gpio *chip = (struct l_gpio *)irq_get_handler_data(irq);
	unsigned start = 0, end = chip->chip.ngpio;
	raw_wqueue_t	*waiter_item;
	struct	list_head *tmp, *next;
	struct	timespec intr_real_tm;
	long long	real_tm_ns;

	raw_spin_lock_irqsave(&chip->lock, flags);
	x = readl(chip->base_ioaddr + L_GPIO_INT_STS);

	if (irq == IOHUB_GPIO_IRQ_0) { /* line 8 */
		start = chip->irqchip0_start;
		end = chip->irqchip0_end;
	} else if (irq == IOHUB_GPIO_IRQ_1) { /* line 9 */
		start = chip->irqchip1_start;
		end = chip->irqchip1_end;
	}
	getnstimeofday(&intr_real_tm);
	real_tm_ns = timespec_to_ns(&intr_real_tm);
	chip->intr_assembl |= x;
	for (i = start; i <= end; i++) {
		if (x & (1 << i)) {
			pr_debug("line %d pin %d triggered\n", irq, i);
			chip->intr_inf[i].prev_driver_nsec =
					chip->intr_inf[i].intr_driver_nsec;
			chip->intr_inf[i].intr_driver_nsec = real_tm_ns;
			chip->intr_inf[i].num_received_ints++;
			/* wake up ioctl(GPIO_WAIT_INTR) */
			list_for_each_safe(tmp, next,
						&chip->wait_task_list[i]) {
				waiter_item = list_entry(tmp, raw_wqueue_t,
								task_list);
				wake_up_process(waiter_item->task);
			}
			INIT_LIST_HEAD(&chip->wait_task_list[i]);
#ifdef CONFIG_MCST_RT
			if (chip->do_postpone[i])
				do_postpone_tick(real_tm_ns +
					chip->do_postpone[i]);
#endif
			generic_handle_irq(chip->irq_base + i);
		}
	}

	writel(x, chip->base_ioaddr + L_GPIO_INT_STS);
	raw_spin_unlock_irqrestore(&chip->lock, flags);
}

static struct irq_chip l_gpio_irqchip = {
	.name = "l-gpio-irqchip",
	.irq_enable = l_gpio_irq_enable,
	.irq_disable = l_gpio_irq_disable,
	.irq_mask = l_gpio_irq_mask,
	.irq_unmask = l_gpio_irq_unmask,
	.irq_set_type = l_gpio_irq_type,
	.irq_set_affinity = l_gpio_irq_aff,
};

static int __init l_gpio_probe(struct pci_dev *pdev,
							   const struct pci_device_id *pci_id,
							   struct l_gpio *c, int nr)
{
	int err;
	int i;
	int iohub = pci_id->driver_data;
	int bar = iohub ? IOHUB_BAR : 0;
	unsigned int cur_irq, irq;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "can't enable l-gpio device MEM\n");
		goto done;
	}

	err = pci_request_region(pdev, bar, DRV_NAME);
	if (err) {
		dev_err(&pdev->dev, "can't alloc PCI BAR #%d for l-gpio\n",
				bar);
		goto done;
 	}

	/* set up the driver-specific struct */
	c->base = pci_resource_start(pdev, bar);
	c->base_ioaddr = pci_iomap(pdev, bar, 0);
	c->pdev = pdev;
	raw_spin_lock_init(&(c->lock));

	c->irq_base = get_nr_irqs_gsi() + nr * ARCH_NR_OWN_GPIOS;
	if (iohub) {
		c->irqchip0_start = IOHUB_IRQ0_GPIO_START;
		c->irqchip0_end = IOHUB_IRQ0_GPIO_END;
		c->irqchip1_start = IOHUB_IRQ1_GPIO_START;
		c->irqchip1_end = IOHUB_IRQ1_GPIO_END;
	}

	dev_info(&pdev->dev, "allocated PCI BAR #%d: base 0x%llx\n", bar,
		 (unsigned long long)c->base);

	/* Default settings: */
	/* Default Input/Output mode for all pins: */
	writel(L_GPIO_CNTRL_DEF, c->base_ioaddr + L_GPIO_CNTRL);
	/* Default interrupt enable/disable for all pins: */
	writel(L_GPIO_INT_EN_DEF, c->base_ioaddr + L_GPIO_INT_EN);
	/* Default interrupt mode level/edge for all pins: */
	writel(L_GPIO_INT_CLS_DEF, c->base_ioaddr + L_GPIO_INT_CLS);
	/* Default rising/falling edge detection for all pins (if edge): */
	writel(L_GPIO_INT_LVL_DEF, c->base_ioaddr + L_GPIO_INT_LVL);

	/* finally, register with the generic GPIO API */
	err = gpiochip_add(&(c->chip));
	if (err)
		goto release_region;

	/* Create virtual irq_desc's for gpios */
	for (i = 0; i < (c->chip).ngpio; i++) {
		cur_irq = c->irq_base + i;
		irq = create_irq_nr(cur_irq, pcibus_to_node(pdev->bus));
		if (irq != cur_irq)
			goto release_irq;
	}

	if (iohub) {
		/* IRQ Line 8: */
		irq_set_handler_data(IOHUB_GPIO_IRQ_0, c);
		irq_set_chained_handler(IOHUB_GPIO_IRQ_0, l_gpio_irq_handler);

		/* IRQ Line 9: */
		irq_set_handler_data(IOHUB_GPIO_IRQ_1, c);
		irq_set_chained_handler(IOHUB_GPIO_IRQ_1, l_gpio_irq_handler);
 	}
 
	/* To virtual irq_desc's: */
	for (i = 0; i < (c->chip).ngpio; i++) {
		irq_set_chip_and_handler(i + c->irq_base,
					      &l_gpio_irqchip,
					      handle_simple_irq);
		irq_set_handler_data(i + c->irq_base, c);
		INIT_LIST_HEAD(&c->wait_task_list[i]);
		c->do_postpone[i] = 0;
		c->intr_inf[i].gpio_drv_ver = GPIO_DRV_VER;
		c->intr_inf[i].timeout_us = 0;
		c->intr_inf[i].num_received_ints = 0;
		c->intr_inf[i].intr_driver_nsec = 0;
		c->intr_inf[i].prev_driver_nsec = 0;
	}
	c->intr_assembl = 0;

	dev_info(&pdev->dev,
		 DRV_NAME ": L-GPIO support successfully loaded.\n");

	return 0;

release_irq:
	/* Cleanup virtual irq_desc's for gpios on error */
	for (; i > 0; i--) {
		cur_irq = c->irq_base + i - 1;
		destroy_irq(cur_irq);
	}
release_region:
	pci_iounmap(pdev, c->base_ioaddr);
	pci_release_region(pdev, bar);
done:
	return err;
}

static void __exit l_gpio_remove(struct l_gpio *p)
{
	unsigned int cur_irq;
	int i;
	struct pci_dev *pdev = p->pdev;
	int err;
	int bar = pdev->device == PCI_AC97GPIO_DEVICE_ID_ELBRUS ? IOHUB_BAR : 0;
	
	err = gpiochip_remove(&(p->chip));

	/* Free GPIO IRQs */
	for (i = 0; i < (p->chip).ngpio; i++) {
		cur_irq = p->irq_base + i;
		destroy_irq(cur_irq);
	}
	
	if (err) {
		dev_err(&pdev->dev, "unable to remove l gpio_chip\n");
	}
	pci_iounmap(pdev, p->base_ioaddr);
	pci_release_region(pdev, bar);
}

static struct l_gpio_data l_iohub_private_data = {
	.bar = 1,
	.lines = ARCH_NR_IOHUB_GPIOS,
	.irq = {
		{ .nr = 8, .start = 0, .end = 7, },
		{ .nr = 9, .start = 8, .end = ARCH_NR_IOHUB_GPIOS - 1, }
	},
};

static struct l_gpio_data l_pci_private_data = {
	.bar = 0,
	.lines = 16,
};

static struct l_gpio_data l_iohub2_private_data = {
	.bar = 0,
	.lines = ARCH_NR_IOHUB2_GPIOS,
	.irq = {
		{ .nr = 7 }
	},
};

static struct pci_device_id __initdata l_gpio_pci_tbl[] = {
	{PCI_DEVICE(PCI_AC97GPIO_VENDOR_ID_ELBRUS, PCI_AC97GPIO_DEVICE_ID_ELBRUS),
	 .driver_data = IOHUB_BAR},
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_GPIO),
	 .driver_data = (unsigned long)&l_pci_private_data},
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_GPIO_MPV),
	 .driver_data = (unsigned long)&l_iohub2_private_data},
	{},
};

MODULE_DEVICE_TABLE(pci, l_gpio_pci_tbl);

/*
 * We can't use the standard PCI driver registration stuff here, since
 * that allows only one driver to bind to each PCI device (and we want
 * multiple drivers to be able to bind to the device: AC97 and GPIO).  
 * Instead, manually scan for the PCI device, request a single region, 
 * and keep track of the devices that we're using.
 */

static int __init l_gpio_init(void)
{
	struct pci_dev *pdev = NULL;
	int err = -ENODEV;
	int i, j = 0;
	struct l_gpio *next, *old = NULL;

	for (i = 0; i < ARRAY_SIZE(l_gpio_pci_tbl) - 1; i++) {
		while ((pdev = pci_get_device(l_gpio_pci_tbl[i].vendor,
					      l_gpio_pci_tbl[i].device,
					      pdev))) {
			struct gpio_chip *c;
			if (!(next = kzalloc(sizeof(*next), GFP_KERNEL)))
				return -ENOMEM;
			c = (struct gpio_chip *)next;
			c->owner = THIS_MODULE;
			c->label = DRV_NAME;
			c->direction_input = l_gpio_direction_input;
			c->direction_output = l_gpio_direction_output;
			c->get = l_gpio_get_value;
			c->set = l_gpio_set_value;
			c->to_irq = l_gpio_to_irq;
			c->base = j * ARCH_NR_OWN_GPIOS;
			c->ngpio = ARCH_NR_OWN_GPIOS;
			c->can_sleep = 0;
#ifdef CONFIG_MCST
			c->wait_irq = l_gpio_wait_irq;
#endif
			err = l_gpio_probe(pdev, &l_gpio_pci_tbl[i], next, j);

			if (err)
				pci_dev_put(pdev);
			if (old)
				old->next = next;
			else
				l_gpios_set = next;
			old = next;
			j++;
		}
	}

	if (l_gpios_set)
		err = register_l_gpio_bound_devices();

	return err;
}

static void __exit l_gpio_exit(void)
{
	struct l_gpio *p;

	if (l_gpios_set) {
		if (pltc2954_dev)
			platform_device_unregister(pltc2954_dev);
	}
	
	for (p = l_gpios_set; p; p = p->next) {
		l_gpio_remove(p);
		pci_dev_put(p->pdev);
	}

}

module_init(l_gpio_init);
module_exit(l_gpio_exit);

MODULE_AUTHOR("Evgeny Kravtsunov <kravtsunov_e@mcst.ru>");
MODULE_DESCRIPTION("Elbrus MCST GPIO driver");
MODULE_LICENSE("GPL");
