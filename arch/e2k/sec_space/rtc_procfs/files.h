/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once
#include <linux/fs.h>
#include <linux/poll.h>

int rtcfs_seqfile_release(struct inode *inode, struct file *file);
int rtcfs_maps_open(struct inode *inode, struct file *file);
int rtcfs_smaps_open(struct inode *inode, struct file *file);
ssize_t rtcfs_cmdline_read(struct file *file, char __user *buf,
					size_t count, loff_t *pos);
int rtcfs_mounts_open(struct inode *inode, struct file *file);
int rtcfs_mountinfo_open(struct inode *inode, struct file *file);
int rtcfs_mountstats_open(struct inode *inode, struct file *file);
__poll_t rtcfs_mounts_poll(struct file *file, poll_table *wait);
const char *rtcfs_exe_get_link(struct dentry *dentry, struct inode *inode,
						struct delayed_call *done);
int rtcfs_exe_readlink(struct dentry *dentry, char __user *buffer, int buflen);
int rtcfs_limits_open(struct inode *inode, struct file *file);
loff_t rtcfs_mem_lseek(struct file *file, loff_t offset, int orig);
ssize_t rtcfs_pagemap_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos);
int rtcfs_pagemap_open(struct inode *inode, struct file *file);
int rtcfs_pagemap_release(struct inode *inode, struct file *file);
int rtcfs_cpuinfo_open(struct inode *inode, struct file *file);

