/*
 * Driver for LTC2954 Pushbutton On/Off Controller. Supports both mP interrupt
 * and polls the state of GPIO.
 *
 * Copyright 2012 Evgeny Kravtsunov
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/pm.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/input-polldev.h>
#include <linux/input.h>
#include <linux/gpio_keys.h>
#include <linux/workqueue.h>
#include <linux/gpio.h>

#define ID_VALUE_STUB		0x0001
#define ID_VERSION_STUB		0x0100
#define GPIO_LTC2954_VENDOR_ID		ID_VALUE_STUB
#define GPIO_LTC2954_PRODUCT_ID		ID_VALUE_STUB
#define GPIO_LTC2954_VERSION_ID		ID_VERSION_STUB

#define LTC2954_BTN_RATE 500 /* msec */

static bool use_irq = 1;
module_param(use_irq, bool, 0);
MODULE_PARM_DESC(use_irq, "Detects either to use poll or request irq");

/* Polling is a temporary solution when we not abel to use irq.
 * We use the only poll_dev and the only button.
 */
struct ltc2954_poll_drvdata {
	struct input_polled_dev *poll_dev;
	struct gpio_keys_button *button;
};

static bool ltc2954_poll_button_pressed(struct gpio_keys_button *button)
{
	int val;

	val = gpio_get_value(button->gpio);

	if ((button->active_low && val == 0) || (!button->active_low && val))
		return 1;

	return 0;
}

static void ltc2954_poll(struct input_polled_dev *poll_dev)
{
	struct ltc2954_poll_drvdata *ddata = poll_dev->private;
	struct input_dev *input = poll_dev->input;
	int state;

	state = ltc2954_poll_button_pressed(ddata->button);

	input_event(input, ddata->button->type, ddata->button->code, !!state);
	input_sync(input);
}

/* Structures for the case when use_irq=1 */
struct ltc2954_button_data {
	struct gpio_keys_button *button;
	struct input_dev *input;
	struct work_struct work;
};

struct ltc2954_button_drvdata {
	struct input_dev *input;
	struct ltc2954_button_data data[0];
};

static void ltc2954_button_report_event(struct ltc2954_button_data *bdata)
{
	struct gpio_keys_button *button = bdata->button;
	struct input_dev *input = bdata->input;
	int state = (button->active_low ? 0 : 1);

	/* We play with values as it does not matter for is
	 * is button pressed or released - any button press
	 * must be caught by event handlers */
	if (state)
		button->active_low = 1;
	else
		button->active_low = 0;

	input_event(input, button->type, button->code, !!state);
	input_sync(input);
}

static void ltc2954_button_work_func(struct work_struct *work)
{
	struct ltc2954_button_data *bdata =
		container_of(work, struct ltc2954_button_data, work);

	ltc2954_button_report_event(bdata);
}

static irqreturn_t ltc2954_button_irq_handler(int irq, void *dev_id)
{
	struct ltc2954_button_data *bdata = dev_id;
	struct gpio_keys_button *button = bdata->button;

	BUG_ON(irq != gpio_to_irq(button->gpio));

	schedule_work(&bdata->work);

	return IRQ_HANDLED;
}

static int ltc2954_setup(struct device *dev,
				 struct ltc2954_button_data *bdata,
				 struct gpio_keys_button *button)
{
	char *desc = "ltc2954";
	int irq, error;

	if (use_irq)
		INIT_WORK(&bdata->work, ltc2954_button_work_func);

	error = gpio_request(button->gpio, desc);
	if (error < 0) {
		dev_err(dev, "ltc2954 failed to request GPIO %d, error %d\n",
			button->gpio, error);
		goto out_err;
	}

	error = gpio_direction_input(button->gpio);
	if (error < 0) {
		dev_err(dev, "ltc2954 failed to configure"
			" direction for GPIO %d, error %d\n",
			button->gpio, error);
		goto cleanup;
	}

	if (use_irq) {
		irq = gpio_to_irq(button->gpio);
		if (irq < 0) {
			error = irq;
			dev_err(dev, "ltc2954: unable to get irq number "
				"for GPIO %d, error %d\n", button->gpio, error);
			goto cleanup;
		}

		error = request_irq(irq, ltc2954_button_irq_handler,
				IRQF_TRIGGER_FALLING,
				desc, bdata);
		if (error) {
		    dev_err(dev, "ltc2954: unable to claim irq %d; error %d\n",
			irq, error);
		    goto cleanup;
		}
	}

	return 0;

cleanup:
	gpio_free(button->gpio);
out_err:
	return error;
}

static int ltc2954_probe(struct platform_device *pdev)
{
	struct gpio_keys_platform_data *pdata = pdev->dev.platform_data;
	struct ltc2954_poll_drvdata *ddata_poll = NULL;
	struct ltc2954_button_drvdata *ddata_irq = NULL;
	struct device *dev = &pdev->dev;
	struct input_polled_dev *poll_dev;
	struct input_dev *input;
	int i = 0, error;

	if (use_irq) {
		/* button on irq */
		ddata_irq = kzalloc(sizeof(struct ltc2954_button_drvdata) +
			    pdata->nbuttons*sizeof(struct ltc2954_button_data),
			    GFP_KERNEL);
		input = input_allocate_device();
		if (!ddata_irq || !input) {
			dev_err(dev, "failed to allocate state\n");
			error = -ENOMEM;
			goto out_err_free;
		}
		platform_set_drvdata(pdev, ddata_irq);

		input->name = pdev->name;
		input->phys = "ltc2954";
		input->dev.parent = &pdev->dev;
		input->id.bustype = BUS_HOST;
		input->id.vendor = GPIO_LTC2954_VENDOR_ID;
		input->id.product = GPIO_LTC2954_PRODUCT_ID;
		input->id.version = GPIO_LTC2954_VERSION_ID;

		__set_bit(EV_KEY, input->evbit);
		__set_bit(KEY_SLEEP, input->keybit);

		ddata_irq->input = input;

		for (i = 0; i < pdata->nbuttons; i++) {
			struct gpio_keys_button *button = &pdata->buttons[i];
			struct ltc2954_button_data *bdata = &ddata_irq->data[i];

			bdata->input = input;
			bdata->button = button;
			error = ltc2954_setup(dev, bdata, button);
			if (error)
				goto cleanup;
			input_set_capability(input, button->type, button->code);
		}

		error = input_register_device(input);
		if (error) {
			dev_err(dev, "Unable to register input device, "
				"error: %d\n", error);
			goto cleanup;
		}
	} else {
		/* poll the button */
		if (pdata->nbuttons > 1) {
			printk(KERN_ERR "Polling ltc2954 driver"
					" supports the only button!\n");
			return -ENXIO;
		}

		ddata_poll = kzalloc(sizeof(struct ltc2954_poll_drvdata),
								GFP_KERNEL);
		if (!ddata_poll)
			return -ENOMEM;

		poll_dev = input_allocate_polled_device();
		if (!poll_dev) {
			error = -ENOMEM;
			goto out_err_free;
		}

		poll_dev->poll = ltc2954_poll;
		poll_dev->poll_interval = LTC2954_BTN_RATE;
		poll_dev->input->name = pdev->name;
		poll_dev->input->phys = "ltc2954";
		poll_dev->input->dev.parent = &pdev->dev;
		poll_dev->input->id.bustype = BUS_HOST;
		poll_dev->input->id.vendor = GPIO_LTC2954_VENDOR_ID;
		poll_dev->input->id.product = GPIO_LTC2954_PRODUCT_ID;
		poll_dev->input->id.version = GPIO_LTC2954_VERSION_ID;

		ddata_poll->poll_dev = poll_dev;
		ddata_poll->button =  &pdata->buttons[0];

		poll_dev->private = ddata_poll;

		error = ltc2954_setup(dev, NULL, ddata_poll->button);
		if (error)
			goto out_err_free;

		platform_set_drvdata(pdev, ddata_poll);
		input_set_capability(poll_dev->input, ddata_poll->button->type,
						ddata_poll->button->code);

		__set_bit(ddata_poll->button->type, poll_dev->input->evbit);
		__set_bit(ddata_poll->button->code, poll_dev->input->keybit);

		error = input_register_polled_device(poll_dev);
		if (error) {
			dev_err(dev, "Unable to register poll device, "
				"error: %d\n", error);
			goto cleanup;
		}
	}
	return 0;

 cleanup:
	if (use_irq) {
		while (--i >= 0) {
			free_irq(gpio_to_irq(pdata->buttons[i].gpio),
							&ddata_irq->data[i]);
			cancel_work_sync(&ddata_irq->data[i].work);
			gpio_free(pdata->buttons[i].gpio);
		}
		platform_set_drvdata(pdev, NULL);
	} else {
		gpio_free(pdata->buttons[0].gpio);
		platform_set_drvdata(pdev, NULL);
		input_free_polled_device(poll_dev);
	}

 out_err_free:
	if (use_irq) {
		input_free_device(input);
		kfree(ddata_irq);
	} else {
		kfree(ddata_poll);
	}

	return error;
}

static int ltc2954_remove(struct platform_device *pdev)
{
	struct gpio_keys_platform_data *pdata = pdev->dev.platform_data;
	int i;

	if (use_irq) {
		struct ltc2954_button_drvdata *ddata_irq =
						platform_get_drvdata(pdev);
		struct input_dev *input = ddata_irq->input;

		for (i = 0; i < pdata->nbuttons; i++) {
			int irq = gpio_to_irq(pdata->buttons[i].gpio);
			free_irq(irq, &ddata_irq->data[i]);
			cancel_work_sync(&ddata_irq->data[i].work);
			gpio_free(pdata->buttons[i].gpio);
		}
		input_unregister_device(input);

	} else {
		struct ltc2954_poll_drvdata *ddata_poll =
						platform_get_drvdata(pdev);
		struct input_polled_dev *poll_dev = ddata_poll->poll_dev;

		gpio_free(pdata->buttons[0].gpio);
		input_unregister_polled_device(poll_dev);
		input_free_polled_device(poll_dev);
		dev_set_drvdata(&pdev->dev, NULL);
	}

	return 0;
}

static struct platform_driver ltc2954_device_driver = {
	.probe		= ltc2954_probe,
	.remove		= ltc2954_remove,
	.driver		= {
		.name	= "ltc2954",
		.owner	= THIS_MODULE,
	}
};

static int __init ltc2954_init(void)
{
	return platform_driver_register(&ltc2954_device_driver);
}

static void __exit ltc2954_exit(void)
{
	platform_driver_unregister(&ltc2954_device_driver);
}

module_init(ltc2954_init);
module_exit(ltc2954_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Evgeny Kravtsunov <kravtsunov_e@mcst.ru>");
MODULE_DESCRIPTION("Driver for LTC2954 bound to GPIO");
