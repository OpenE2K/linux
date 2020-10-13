/*
 *  linux/fs/proc/proc_console_ctrl.c
 *
 *  Copyright (C) 2014 MCST.
 *
 *  Author: Alexey Mukhin <if@mcst.ru>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include <linux/console.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <asm/uaccess.h>

#ifdef __DBG_PRINT__
#include <linux/tty.h>
#include <linux/tty_driver.h>

static void print_state(int state, char *str)
{
	sprintf(str, ">");
	if (state & CON_PRINTBUFFER)
		strcat(str, "CON_PRINTBUFFER ");

	if (state & CON_CONSDEV)
		strcat(str, "CON_CONSDEV ");

	if (state & CON_ENABLED)
		strcat(str, "CON_ENABLED ");

	if (state & CON_BOOT)
		strcat(str, "CON_BOOT ");

	if (state & CON_ANYTIME)
		strcat(str, "CON_ANYTIME ");

	if (state & CON_ATOMIC)
		strcat(str, "CON_ATOMIC ");
}
#endif

#define for_each_console(con) \
	for (con = console_drivers; con != NULL; con = con->next)

static int console_ctrl_show(struct seq_file *m, void *v)
{

	struct console *c = NULL;
	int count = 0;
#ifdef __DBG_PRINT__
	struct tty_driver *td = NULL;
	int ttynum = -1;
	char s[256];
#endif

	if (console_set_on_cmdline) {
		seq_printf(m, "cmdline > %s\n", saved_command_line);

		for_each_console(c) {
#ifdef __DBG_PRINT__
			print_state(c->flags, s);
			seq_printf(m, "\t%02d console: %s%d state %s\n",
				   count,
				   c->name, c->index,
				   s);
#endif
			seq_printf(m, "\t%d: %s%d: %s\n",
				   count,
				   c->name, c->index,
				   (c->flags & CON_ENABLED) ?
				   "enable" : "disable");
			count++;
		}
#ifdef __DBG_PRINT__
		td = console_device(&ttynum);
		if (td != NULL) {
			seq_printf(m, "\ntty: [%s] {%s %s %d:%d:%d}\n",
				   console_drivers[ttynum].name,
				   td->driver_name,
				   td->name,
				   td->major,
				   td->minor_start,
				   td->minor_num);
		}
#endif
	} else {
		seq_printf(m, "Console not setup from cmdline.\n");
	}
	/*
	  printk(KERN_ERR "................................\n");
	*/
	return 0;
}

static inline int isdigit(int ch)
{
	return (ch >= '0') && (ch <= '9');
}

/**
 * @param flag == 0 - off
 * @param flag == 0 - on
 */
static void console_action(char *buf, int flag)
{
	struct console *c = NULL;
	char tname[32];
	if (strlen(buf) == 0) {
		for_each_console(c) {
			(flag) ? console_start(c) : console_stop(c);
		}
	} else if (isdigit(buf[0])) {
		int count = 0;
		long number = simple_strtol(buf, NULL, 10);
		for_each_console(c) {
			if (number == count) {
				(flag) ? console_start(c) : console_stop(c);
				break;
			}
			count++;
		}
	} else {
		for_each_console(c) {
			sprintf(tname, "%s%d", c->name, c->index);
			if (!strcmp(tname, buf)) {
				(flag) ? console_start(c) : console_stop(c);
				break;
			}
		}
	}
}

#define INPUTSIZE 32

static ssize_t console_ctrl_write(struct file *f, const char __user *b,
				  size_t c, loff_t *o)
{
	int i = 0;
	char input[INPUTSIZE] = {0};
	char tbuf[INPUTSIZE] = {0};

	if (!console_set_on_cmdline)
		return c;

	for (i = 0; i < INPUTSIZE - 1 && i < c; i++) {
		if (get_user(input[i], b + i) != 0)
			return c;
	}

	switch (input[0]) {
	case '-':
		snprintf(tbuf, i - 1, "%s", input + 1);
		console_action(tbuf, 0);
		break;
	case '+':
		snprintf(tbuf, i - 1, "%s", input + 1);
		console_action(tbuf, 1);
		break;
	default:
		printk(KERN_NOTICE
		       "Help for /proc/console_ctrl:\n"
		       "\tstring must start with [-|+]\n"
		       "\t - or -[name] or -[digit]  - turn OFF target console\n"
		       "\t + or +[name] or +[digit]  - turn ON target console\n"
		       "Other symbols - print this help.\n"
		       "Example:\n"
		       "turn OFF all console:\n"
		       "\techo - >/proc/console_ctrl\n"
		       "turn ON ttyS0 console:\n"
		       "\techo +ttyS0 >/proc/console_ctrl\n");
	}

	return c;
}

static int console_ctrl_open(struct inode *inode, struct file *file)
{
	return single_open(file, console_ctrl_show, NULL);
}

static const struct file_operations console_ctrl_fops = {
	.open		= console_ctrl_open,
	.read		= seq_read,
	.write		= console_ctrl_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_console_ctrl(void)
{
	proc_create("console_ctrl", 0, NULL, &console_ctrl_fops);
	return 0;
}
module_init(proc_console_ctrl);
