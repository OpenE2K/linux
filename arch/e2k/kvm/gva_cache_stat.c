/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <asm/uaccess.h>
#include <asm/errno.h>

#include <asm/kvm/gva_cache.h>

#define STAT_DEV_NAME "gva_cache_stat"

/* Statcistics of access to gva->gpa cache */
gva_caches_stat_t caches_stat = {
	.accesses = 0,
	.hits = 0,
	.misses = 0,

	.sum_hit_time = 0,
	.sum_miss_pen = 0,
	.conflict_misses = 0,
	.cold_misses = 0,

	.flushes_gva = 0,
	.flushes_all = 0,
	.sum_flush_gva_time = 0,
	.sum_flush_all_time = 0,

	.fetches = 0,
	.update_fetches = 0,
	.conflict_fetches = 0,
	.cold_fetches = 0,
	.sum_fetch_time = 0
};

#define STAT_BUF_STR_LEN                64
#define STAT_BUF_NUM_STRS               (sizeof(gva_caches_stat_t)/sizeof(u64))
#define STAT_BUF_LEN			(STAT_BUF_NUM_STRS * STAT_BUF_STR_LEN)

static char gva_cache_stat_buf[STAT_BUF_LEN];
static u64 curr_stat_buf_pos;

static void gva_caches_stat(void)
{
	u64 avg_hit_time, avg_miss_pen,
		avg_flush_time, avg_fetch_time,
		str_end, sum_flush_time, flushes;
	char *buf = gva_cache_stat_buf;

	if (caches_stat.hits)
		avg_hit_time = caches_stat.sum_hit_time / caches_stat.hits;
	if (caches_stat.misses)
		avg_miss_pen = caches_stat.sum_miss_pen / caches_stat.misses;

	flushes = caches_stat.flushes_gva + caches_stat.flushes_all;
	sum_flush_time = caches_stat.sum_flush_gva_time +
			caches_stat.sum_flush_all_time;
	if (flushes)
		avg_flush_time = sum_flush_time / flushes;

	if (caches_stat.fetches)
		avg_fetch_time = caches_stat.sum_fetch_time /
				caches_stat.fetches;

	memset(buf, ' ', STAT_BUF_LEN);
	for (str_end = STAT_BUF_STR_LEN - 1; str_end < STAT_BUF_LEN;
			str_end += STAT_BUF_STR_LEN) {
		buf[str_end] = '\n';
	}

	snprintf(buf, STAT_BUF_STR_LEN, "accesses = %llu",
		caches_stat.accesses);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "hits = %llu", caches_stat.hits);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "misses = %llu", caches_stat.misses);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "avg_hit_time = %llu ns",
		avg_hit_time);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "avg_miss_pen = %llu ns",
		avg_miss_pen);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "conflict_misses = %llu",
		caches_stat.conflict_misses);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "cold_misses = %llu",
		caches_stat.cold_misses);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "flushes_gva = %llu",
		caches_stat.flushes_gva);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "flushes_all = %llu",
		caches_stat.flushes_all);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "avg_flush_time = %llu ns",
		avg_flush_time);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "fetches = %llu",
		caches_stat.fetches);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "avg_fetch_time = %llu ns",
		avg_fetch_time);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "update_fetches = %llu",
		caches_stat.update_fetches);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "conflict_fetches = %llu",
		caches_stat.conflict_fetches);
	buf += STAT_BUF_STR_LEN;
	snprintf(buf, STAT_BUF_STR_LEN, "cold_fetches = %llu",
		caches_stat.cold_fetches);
}


static int stat_dev_major;

static int stat_dev_open(struct inode *i_node, struct file *dev_f)
{
	gva_caches_stat();
	curr_stat_buf_pos = 0;

	return 0;
}

static int stat_dev_release(struct inode *i_node, struct file *dev_f)
{
	return 0;
}

static ssize_t stat_dev_read(struct file *dev_f, char *user_buf,
			size_t len, loff_t *off)
{
	u64 stat_buf_pos = curr_stat_buf_pos;
	u64 readed = 0;

	if (curr_stat_buf_pos == STAT_BUF_LEN - 1)
		return 0;

	while (stat_buf_pos < STAT_BUF_LEN &&
			stat_buf_pos < curr_stat_buf_pos + len) {
		put_user(gva_cache_stat_buf[stat_buf_pos], user_buf + readed);
		stat_buf_pos++;
		readed++;
	}

	curr_stat_buf_pos += readed;

	return readed;
}

static ssize_t stat_dev_write(struct file *dev_f, const char *buf,
				size_t len, loff_t *off)
{
	printk(KERN_INFO "Write to GVA STAT is not supported\n");
	return -EINVAL;
}


static const struct file_operations stat_dev_ops = {
	.open = stat_dev_open,
	.release = stat_dev_release,
	.read = stat_dev_read,
	.write = stat_dev_write,
	.owner = THIS_MODULE
};

int gva_cache_stat_dev_init(void)
{
	stat_dev_major = register_chrdev(0, STAT_DEV_NAME, &stat_dev_ops);
	curr_stat_buf_pos = 0;

	if (stat_dev_major < 0)
		printk(KERN_INFO "Registering the character device "
				"failed with %d\n", stat_dev_major);
	else
		printk(KERN_INFO "Registering the character device "
				"major %d\n", stat_dev_major);

	return stat_dev_major;
}
