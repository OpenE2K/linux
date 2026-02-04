/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Driver for LTC2954 Pushbutton On/Off Controller. Supports both mP interrupt
 * and polls the state of GPIO.
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
#include <linux/input.h>
#include <linux/gpio_keys.h>
#include <linux/workqueue.h>
#include <linux/gpio.h>

#define ID_VALUE_STUB		0x0001
#define ID_VERSION_STUB		0x0100
#define GPIO_LTC2954_VENDOR_ID	ID_VALUE_STUB
#define GPIO_LTC2954_PRODUCT_ID	ID_VALUE_STUB
#define GPIO_LTC2954_VERSION_ID	ID_VERSION_STUB

#define LTC2954_BTN_RATE 500 /* msec */

static bool use_irq = 1;
module_param(use_irq, bool, 0);
MODULE_PARM_DESC(use_irq, "Detects either to use poll or request irq");

/*
 * Polling is a temporary solution when we not able to use irq.
 */
struct ltc2954_poll_drvdata {
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

static void ltc2954_poll(struct input_dev *input)
{
	struct ltc2954_poll_drvdata *ddata = input_get_drvdata(input);
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

static int ltc2954_probe_irq(struct platform_device *pdev, struct input_dev *input)
{
	struct gpio_keys_platform_data *pdata = pdev->dev.platform_data;
	struct ltc2954_button_drvdata *ddata_irq = NULL;
	struct device *dev = &pdev->dev;
	int i = 0, error;

	ddata_irq = devm_kzalloc(dev, sizeof(struct ltc2954_button_drvdata) +
				 pdata->nbuttons*sizeof(struct ltc2954_button_data),
				 GFP_KERNEL);
	if (!ddata_irq) {
		dev_err(dev, "failed to allocate driver data\n");
		return -ENOMEM;
	}

	ddata_irq->input = input;

	__set_bit(EV_KEY, input->evbit);
	__set_bit(KEY_SLEEP, input->keybit);

	for (i = 0; i < pdata->nbuttons; i++) {
		struct ltc2954_button_data *bdata = &ddata_irq->data[i];
		struct gpio_keys_button *button =
				(struct gpio_keys_button *)&pdata->buttons[i];

		bdata->input = input;
		bdata->button = button;
		error = ltc2954_setup(dev, bdata, button);
		if (error)
			return error;

		input_set_capability(input, button->type, button->code);
	}

	platform_set_drvdata(pdev, ddata_irq);

	error = input_register_device(input);
	if (error) {
		dev_err(dev, "Unable to register input device, error: %d\n", error);
		goto cleanup;
	}

	return 0;

cleanup:
	while (--i >= 0) {
		free_irq(gpio_to_irq(pdata->buttons[i].gpio), &ddata_irq->data[i]);
		cancel_work_sync(&ddata_irq->data[i].work);
		gpio_free(pdata->buttons[i].gpio);
	}
	platform_set_drvdata(pdev, NULL);

	return error;
}

static int ltc2954_probe_poll(struct platform_device *pdev, struct input_dev *input)
{
	struct gpio_keys_platform_data *pdata = pdev->dev.platform_data;
	struct ltc2954_poll_drvdata *ddata_poll = NULL;
	struct device *dev = &pdev->dev;
	int error;

	if (pdata->nbuttons > 1) {
		pr_err("Polling ltc2954 driver supports the only button!\n");
		return -ENXIO;
	}

	ddata_poll = devm_kzalloc(dev, sizeof(struct ltc2954_poll_drvdata),
				  GFP_KERNEL);
	if (!ddata_poll) {
		dev_err(dev, "failed to allocate driver data\n");
		return -ENOMEM;
	}

	ddata_poll->button = (struct gpio_keys_button *)&pdata->buttons[0];

	__set_bit(ddata_poll->button->type, input->evbit);
	__set_bit(ddata_poll->button->code, input->keybit);

	input_set_drvdata(input, ddata_poll);
	input_set_capability(input, ddata_poll->button->type, ddata_poll->button->code);

	error = input_setup_polling(input, ltc2954_poll);
	if (error) {
		dev_err(dev, "failed to setup polling\n");
		return error;
	}

	input_set_poll_interval(input, LTC2954_BTN_RATE);

	error = ltc2954_setup(dev, NULL, ddata_poll->button);
	if (error)
		return error;

	platform_set_drvdata(pdev, ddata_poll);

	error = input_register_device(input);
	if (error) {
		dev_err(dev, "Unable to register input device, error: %d\n", error);
		platform_set_drvdata(pdev, NULL);
		gpio_free(pdata->buttons[0].gpio);
		return error;
	}

	return 0;
}

static int ltc2954_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct input_dev *input = devm_input_allocate_device(dev);

	if (!input) {
		dev_err(dev, "failed to allocate input device\n");
		return -ENOMEM;
	}

	input->name = pdev->name;
	input->phys = "ltc2954";
	input->id.bustype = BUS_HOST;
	input->id.vendor = GPIO_LTC2954_VENDOR_ID;
	input->id.product = GPIO_LTC2954_PRODUCT_ID;
	input->id.version = GPIO_LTC2954_VERSION_ID;

	if (use_irq)
		return ltc2954_probe_irq(pdev, input);
	else
		return ltc2954_probe_poll(pdev, input);
}

static int ltc2954_remove_irq(struct platform_device *pdev)
{
	struct ltc2954_button_drvdata *ddata_irq =
						platform_get_drvdata(pdev);
	struct gpio_keys_platform_data *pdata = pdev->dev.platform_data;
	int i = 0;

	for (; i < pdata->nbuttons; i++) {
		int irq = gpio_to_irq(pdata->buttons[i].gpio);

		free_irq(irq, &ddata_irq->data[i]);
		cancel_work_sync(&ddata_irq->data[i].work);
		gpio_free(pdata->buttons[i].gpio);
	}

	return 0;
}

static int ltc2954_remove_poll(struct platform_device *pdev)
{
	struct gpio_keys_platform_data *pdata = pdev->dev.platform_data;

	gpio_free(pdata->buttons[0].gpio);
	dev_set_drvdata(&pdev->dev, NULL);

	return 0;
}

static int ltc2954_remove(struct platform_device *pdev)
{
	if (use_irq)
		return ltc2954_remove_irq(pdev);
	else
		return ltc2954_remove_poll(pdev);
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

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Driver for LTC2954 bound to GPIO");
