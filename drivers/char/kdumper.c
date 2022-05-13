#include <linux/sched.h>
#include <linux/input.h>

/*
 * Keyboard dumper on F12 key press
 *
 * (c) 2013 Kirill Tkhai, thay_k@mcst.ru
 */

static int kdumper_enable = 0;

static void kdumper_event(struct input_handle *handle, unsigned int type,
			 unsigned int code, int value)
{
	if (type != EV_KEY || code != KEY_F12 || value != 1)
		return;

	show_state();
}

static int kdumper_connect(struct input_handler *handler, struct input_dev *dev,
			  const struct input_device_id *id)
{
	struct input_handle *handle;
	int error;

	handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "debug";

	error = input_register_handle(handle);
	if (error)
		goto err_free_handle;

	error = input_open_device(handle);
	if (error)
		goto err_unregister_handle;

	return 0;

 err_unregister_handle:
	input_unregister_handle(handle);
 err_free_handle:
	kfree(handle);
	return error;
}

static void kdumper_disconnect(struct input_handle *handle)
{
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

static const struct input_device_id kdumper_ids[] = {
	{
		.flags = INPUT_DEVICE_ID_MATCH_KEYBIT,
		.keybit = { BIT_MASK(KEY_F12) },
	},

	{ },    /* Terminating entry */
};

MODULE_DEVICE_TABLE(input, kdumper_ids);

static struct input_handler kdumper_handler = {
	.event		= kdumper_event,
	.connect	= kdumper_connect,
	.disconnect	= kdumper_disconnect,
	.name		= "kdumper",
	.id_table	= kdumper_ids,
};


int __init kdumper_init(void)
{
	int error;

	if (!kdumper_enable)
		return -ENODEV;

	error = input_register_handler(&kdumper_handler);

	if (error)
		printk(KERN_ALERT "Failed to register kdumper\n");

	return error;
}

late_initcall_sync(kdumper_init);

static int __devinit kdumper_setup(char *str)
{
	kdumper_enable = 1;
	return 1;
}

__setup("kdumper", kdumper_setup);
