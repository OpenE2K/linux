/*!
 *****************************************************************************
 *
 * @File       vxd_api.c
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 *
 * The contents of this file are subject to the MIT license as set out below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above.
 *
 * If you wish to allow use of your version of this file only under the terms
 * of GPL, and not to allow others to use your version of this file under the
 * terms of the MIT license, indicate your decision by deleting the provisions
 * above and replace them with the notice and other provisions required by GPL
 * as set out in the file called "GPLHEADER" included in this distribution. If
 * you do not delete the provisions above, a recipient may use your version of
 * this file under the terms of either the MIT license or GPL.
 *
 * This License is also included in this distribution in the file called
 * "MIT_COPYING".
 *
 *****************************************************************************/


#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <asm/current.h>

#include <img_mem_man.h>
#include "vxd_common.h"
#include "vxd_plat.h"
#include "vxd_debugfs.h"

static ssize_t vxd_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct vxd_link *link = (struct vxd_link *)file->private_data;
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;
	struct vxd_item *item;
	int ret;

	dev_dbg(miscdev->this_device, "%s: PID: %d, vxd: %p, link: %p\n",
			__func__, current->pid, vxd, link);

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret)
		return ret;

	dev_dbg(miscdev->this_device, "%s: got mutex, list empty: %d\n",
			__func__, list_empty(&link->items_done));

	while (list_empty(&link->items_done) && !list_empty(&link->streams)) {
		mutex_unlock(&vxd->mutex);

		if (file->f_flags & O_NONBLOCK) {
			dev_dbg(miscdev->this_device,
				"%s: returning, no block!\n", __func__);
			return -EAGAIN;
		}
		dev_dbg(miscdev->this_device, "%s: going to sleep\n", __func__);
		if (wait_event_interruptible(link->queue,
					     (!list_empty(&link->items_done) ||
					      list_empty(&link->streams)))) {
			dev_dbg(miscdev->this_device, "%s: signal!\n",
					__func__);
			return -ERESTARTSYS;
		}

		dev_dbg(miscdev->this_device, "%s: woken up\n", __func__);

		ret = mutex_lock_interruptible(&vxd->mutex);
		if (ret)
			return ret;
	}

	if (list_empty(&link->items_done)) {
		ret = 0;
		goto out_unlock;
	}

	item = list_first_entry(&link->items_done, struct vxd_item, list);
	if (VXD_MSG_SIZE(item->msg) > count) {
		ret = -EFAULT;
		goto out_unlock;
	}

	item->msg.out_flags &= VXD_FW_MSG_RD_FLAGS_MASK;

	dev_dbg(miscdev->this_device,
			"%s: item: %p, payload_size: %d, flags: 0x%x\n",
			__func__, item, item->msg.payload_size,
			item->msg.out_flags);

	ret = copy_to_user(buf, &item->msg, VXD_MSG_SIZE(item->msg));
	if (ret) {
		ret = -EFAULT;
		goto out_unlock;
	}

	list_del(&item->list);
	mutex_unlock(&vxd->mutex);
	ret = VXD_MSG_SIZE(item->msg);

	dev_dbg(miscdev->this_device, "%s: returning %d (%zu + %d) bytes\n",
		__func__, ret, sizeof(struct vxd_fw_msg),
		item->msg.payload_size);

	{
		int i;

		for (i = 0; i < item->msg.payload_size/sizeof(u32); i++)
			dev_dbg(miscdev->this_device, "%s: %d: 0x%08x\n",
				__func__, i, item->msg.payload[i]);
	}

	kfree(item);

	return ret;

out_unlock:
	mutex_unlock(&vxd->mutex);
	return ret;
}

static int vxd_get_single_msg(const char __user *buf, size_t size,
		struct vxd_fw_msg *msg)
{
	size_t msg_size;

	if (size > VXD_MAX_INPUT_SIZE)
		return -EFBIG;

	if (copy_from_user(msg, buf, sizeof(struct vxd_fw_msg)))
		return -EFAULT;

	pr_debug("%s: size: %zu, payload: %u, vxd_fw_msg: %zu\n",
			__func__, size, msg->payload_size,
			sizeof(struct vxd_fw_msg));

	/* 2 words at least for message header */
	if (msg->payload_size < VXD_MIN_INPUT_SIZE)
		return -EINVAL;

	msg_size = VXD_MSG_SIZE(*msg);

	/* Are size of the input buffer and declared payload size consistent? */
	if (msg_size != size)
		return -EINVAL;

	return 0;
}


static ssize_t vxd_write(struct file *file, const char __user *buf,
		size_t size, loff_t *offset)
{
	struct vxd_link *link = (struct vxd_link *)file->private_data;
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;
	int ret;
	struct vxd_item *item;
	struct vxd_fw_msg msg;

	dev_dbg(miscdev->this_device,
		"%s: PID: %d, vxd: %p, link: %p, size: %zu\n",
		__func__, current->pid, vxd, link, size);

	/*
	 * TODO: At the moment, we are only able to handle single message
	 * per input buffer
	 */
	ret = vxd_get_single_msg(buf, size, &msg);
	if (ret) {
		dev_err(miscdev->this_device, "%s: invalid input! (%d)\n",
			__func__, ret);
		return ret;
	}

	item = kmalloc(sizeof(struct vxd_item) + msg.payload_size, GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	ret = copy_from_user(&item->msg, buf, size);
	if (ret) {
		dev_err(miscdev->this_device, "%s: copy failed!\n", __func__);
		ret = -EFAULT;
		goto out_free_item;
	}

	/* Verify that the gap was left for stream PTD */
	if (item->msg.payload[VXD_PTD_MSG_OFFSET] != 0) {
		dev_err(miscdev->this_device, "%s: PTD gap missing!\n",
				__func__);
		ret = -EINVAL;
		goto out_free_item;
	}

	msg.out_flags &= VXD_FW_MSG_WR_FLAGS_MASK;
	item->str_id = msg.stream_id;
	item->msg_id = 0;
	item->msg.out_flags = msg.out_flags;
	item->destroy = 0;

	ret = vxd_send_msg(vxd, item, link);
	if (ret) {
		dev_err(miscdev->this_device, "%s: failed to send!\n",
			__func__);
		goto out_free_item;
	}

	return size;

out_free_item:
	kfree(item);

	return ret;
}

static int vxd_release(struct inode *inode, struct file *file)
{
	struct vxd_link *link = (struct vxd_link *)file->private_data;
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;

	dev_dbg(miscdev->this_device, "%s: PID: %d, vxd: %p, link: %p\n",
		__func__, current->pid, vxd, link);

	vxd_rm_link(vxd, link);

	img_mem_destroy_proc_ctx(link->mem_ctx);

	devm_kfree(miscdev->this_device, link);
	file->private_data = NULL;

	return 0;
}

static int vxd_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = (struct miscdevice *)file->private_data;
	struct vxd_dev *vxd = container_of(miscdev, struct vxd_dev, miscdev);
	struct vxd_link *link;
	int ret;

	dev_dbg(miscdev->this_device, "%s: PID: %d, vxd: %p\n",
		__func__, current->pid, vxd);

	link = devm_kzalloc(miscdev->this_device, sizeof(struct vxd_link),
		GFP_KERNEL);
	if (!link) {
		dev_err(miscdev->this_device, "%s: failed to allocate link!\n",
			__func__);
		return -ENOMEM;
	}
	link->vxd = vxd;

	ret = img_mem_create_proc_ctx(&link->mem_ctx);
	if (ret) {
		dev_err(miscdev->this_device, "%s: failed to create context!\n",
			__func__);
		devm_kfree(miscdev->this_device, link);
		return ret;
	}

	INIT_LIST_HEAD(&link->items_done);
	INIT_LIST_HEAD(&link->streams);
	init_waitqueue_head(&link->queue);

	file->private_data = link;

	ret = vxd_add_link(vxd, link);
	if (ret) {
		dev_err(miscdev->this_device, "%s: failed to add link!\n",
				__func__);
		img_mem_destroy_proc_ctx(link->mem_ctx);
		devm_kfree(miscdev->this_device, link);
		return ret;
	}

	return 0;
}

static long vxd_ioctl_str_create(struct vxd_link *link, void __user *buf)
{
	struct vxd_create_stream_data data = { 0 };
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;
	uint32_t str_id;
	int ret;

	dev_dbg(miscdev->this_device, "%s: link %p\n", __func__, link);

	if (copy_from_user(&data, buf, sizeof(struct vxd_create_stream_data)))
		return -EFAULT;

	ret = vxd_create_stream(vxd, link, &str_id, data.stream_type);
	if (ret) {
		dev_err(miscdev->this_device, "%s: failed to create stream!\n",
			__func__);
		return ret;
	}

	data.stream_id = str_id;
	ret = copy_to_user(buf, &data, sizeof(struct vxd_create_stream_data));
	if (ret) {
		dev_err(miscdev->this_device, "%s: copy to user failed!\n",
			__func__);
		ret = -EFAULT;
		goto out_destroy;
	}

	return 0;

out_destroy:
	if (vxd_destroy_stream(vxd, link, str_id)) {
		/*
		 * Failed to destroy stream, but we'll keep it on link->streams
		 * list, so it can be removed when link is being destroyed
		 */
		dev_err(miscdev->this_device, "%s: failed to destroy stream!\n",
			__func__);
	}
	return ret;
}

static long vxd_ioctl_str_destroy(struct vxd_link *link, void __user *buf)
{
	struct vxd_destroy_stream_data data = { 0 };
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;
	int ret;

	dev_dbg(miscdev->this_device, "%s: link %p\n", __func__, link);

	if (copy_from_user(&data, buf, sizeof(struct vxd_destroy_stream_data)))
		return -EFAULT;

	ret = vxd_destroy_stream(vxd, link, data.stream_id);
	if (ret) {
		/*
		 * Failed to destroy stream, but we'll keep it on link->streams
		 * list, so it can be removed when link is being destroyed
		 */
		dev_err(miscdev->this_device, "%s: failed to destroy stream!\n",
			__func__);
	}

	return ret;
}

static long vxd_ioctl_get_props(struct vxd_link *link, void __user *buf)
{
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;

	dev_dbg(miscdev->this_device, "%s: link %p\n", __func__, link);

	if (copy_to_user(buf, &vxd->props, sizeof(struct vxd_core_props))) {
		dev_err(miscdev->this_device, "%s: copy to user failed!\n",
			__func__);
		return -EFAULT;
	}

	return 0;
}

static long vxd_ioctl_alloc(struct vxd_link *link, void __user *buf)
{
	struct vxd_alloc_data data;
	int ret;

	if (copy_from_user(&data, buf, sizeof(struct vxd_alloc_data)))
		return -EFAULT;

	ret = img_mem_alloc(link->vxd->dev, link->mem_ctx, data.heap_id,
			    data.size, data.attributes, &data.buf_id);
	if (ret)
		return ret;

	if (copy_to_user(buf, &data, sizeof(struct vxd_alloc_data))) {
		img_mem_free(link->mem_ctx, data.buf_id);
		return -EFAULT;
	}

	return 0;
}

static long vxd_ioctl_import(struct vxd_link *link, void __user *buf)
{
	struct vxd_import_data data;
	int ret;

	if (copy_from_user(&data, buf, sizeof(struct vxd_import_data)))
		return -EFAULT;

	ret = img_mem_import(link->vxd->dev, link->mem_ctx, data.heap_id,
			     data.size, data.attributes, data.buf_fd,
			     &data.buf_id);
	if (ret)
		return ret;

	if (copy_to_user(buf, &data, sizeof(struct vxd_import_data))) {
		img_mem_free(link->mem_ctx, data.buf_id);
		return -EFAULT;
	}

	return 0;
}

static void vxd_ioctl_free(struct vxd_link *link, void __user *buf)
{
	struct vxd_free_data data;
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;

	if (copy_from_user(&data, buf, sizeof(struct vxd_free_data))) {
		dev_err(miscdev->this_device,
			"%s: copy_from_user error\n", __func__);
		return;
	}

	img_mem_free(link->mem_ctx, data.buf_id);
}

static long vxd_ioctl_map(struct vxd_link *link, void __user *buf)
{
	struct vxd_map_data data;
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;

	if (copy_from_user(&data, buf, sizeof(struct vxd_map_data))) {
		dev_err(miscdev->this_device,
			"%s: copy_from_user error\n", __func__);
		return -EFAULT;
	}

	return vxd_map_buffer(vxd, link, data.stream_id, data.buf_id,
			data.virt_addr, data.flags);
}

static long vxd_ioctl_unmap(struct vxd_link *link, void __user *buf)
{
	struct vxd_unmap_data data;
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;

	if (copy_from_user(&data, buf, sizeof(struct vxd_unmap_data))) {
		dev_err(miscdev->this_device,
			"%s: copy_from_user error\n", __func__);
		return -EFAULT;
	}

	return vxd_unmap_buffer(vxd, link, data.stream_id, data.buf_id);
}

static long vxd_ioctl(struct file *file, unsigned int code,
		unsigned long value)
{
	struct vxd_link *link = (struct vxd_link *)file->private_data;
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;

	dev_dbg(miscdev->this_device, "%s: code: 0x%x, value: 0x%lx\n",
		__func__, code, value);

	switch (code) {
	case VXD_IOCTL_STREAM_CREATE:
		return vxd_ioctl_str_create(link, (void __user *)value);
	case VXD_IOCTL_STREAM_DESTROY:
		return vxd_ioctl_str_destroy(link, (void __user *)value);
	case VXD_IOCTL_PROPS:
		return vxd_ioctl_get_props(link, (void __user *)value);
	case VXD_IOCTL_ALLOC:
		return vxd_ioctl_alloc(link, (void __user *)value);
	case VXD_IOCTL_FREE:
		vxd_ioctl_free(link, (void __user *)value);
		return 0;
	case VXD_IOCTL_VXD_MAP:
		return vxd_ioctl_map(link, (void __user *)value);
	case VXD_IOCTL_VXD_UNMAP:
		return vxd_ioctl_unmap(link, (void __user *)value);
	case VXD_IOCTL_IMPORT:
		return vxd_ioctl_import(link, (void __user *)value);
	default:
		dev_err(miscdev->this_device, "%s: code %#x unknown\n",
			__func__, code);
		return -EINVAL;
	}
}

static int vxd_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct vxd_link *link = (struct vxd_link *)file->private_data;
	struct vxd_dev *vxd = link->vxd;
	struct miscdevice *miscdev = &vxd->miscdev;
	int ret = 0;

	dev_dbg(miscdev->this_device,
		"%s: PID: %d start %#lx end %#lx\n",
		__func__, current->pid,
		vma->vm_start, vma->vm_end);
	dev_dbg(miscdev->this_device, "%s: PID: %d pgoff %#lx\n",
		__func__, current->pid, vma->vm_pgoff);

	/* pgoff beyond IMG_MEM_MAN_MAX_BUFFER is treated as IO map request!*/
	if (vma->vm_pgoff > IMG_MEM_MAN_MAX_BUFFER) {
		/* Limit IO region offset to 16 pages only */
		unsigned long offset = ((vma->vm_pgoff-1)&0xF) << PAGE_SHIFT;
		struct page *io_page = vmalloc_to_page((void __force *)vxd->reg_base);
		unsigned long phy_addr = page_to_phys(io_page) + offset;

		/* Only one page mapping allowed at time for IO */
		if (vma->vm_end - vma->vm_start > PAGE_SIZE) {
			dev_err(miscdev->this_device,
					"%s: PID: %d Can't mmap more than one page for IO!\n",
					__func__, current->pid);
			return -EINVAL;
		}
		dev_dbg(miscdev->this_device,
			"%s: PID: %d IO virt: %p phys: 0x%lx\n",
			__func__,
			current->pid, (void __force *)(vxd->reg_base + offset), phy_addr);

		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		ret = io_remap_pfn_range(vma, vma->vm_start,
				phy_addr >> PAGE_SHIFT,
				vma->vm_end - vma->vm_start, vma->vm_page_prot);
		vma->vm_flags |= VM_IO;
	} else {
		/* pgoff is treated as buffer id, that we allocated before */
		int buff_id = vma->vm_pgoff;
		dev_dbg(miscdev->this_device, "%s: PID: %d buff_id %d\n",
		__func__, current->pid, buff_id);
		ret = img_mem_map_um(link->mem_ctx, buff_id, vma);
	}

	return ret;
}

static const struct file_operations vxd_fops = {
	.owner = THIS_MODULE,
	.read = vxd_read,
	.write = vxd_write,
	.release = vxd_release,
	.open = vxd_open,
	.mmap = vxd_mmap,
	.unlocked_ioctl = vxd_ioctl,
	.compat_ioctl = vxd_ioctl,
};

#define VXD_MAX_NODE_NAME 16

int vxd_api_add_dev(struct device *dev, unsigned int id,
		struct vxd_dev *vxd)
{
	int ret;
	char *dev_name = NULL;

	if (!dev || !vxd) {
		pr_err("%s: invalid params!\n", __func__);
		return -EINVAL;
	}
	dev_name = devm_kzalloc(dev, VXD_MAX_NODE_NAME, GFP_KERNEL);
	if (!dev_name) {
		dev_err(dev, "%s: miscdev name allocation failed!\n",
			__func__);
		return -ENOMEM;
	}

	snprintf(dev_name, VXD_MAX_NODE_NAME, "vxd%d", id);

	dev_dbg(dev, "%s: trying to register misc dev %s...\n",
		__func__, dev_name);

	vxd->miscdev.minor = MISC_DYNAMIC_MINOR;
	vxd->miscdev.fops = &vxd_fops;
	vxd->miscdev.name = dev_name;

	ret = misc_register(&vxd->miscdev);
	if (ret) {
		dev_err(dev, "%s: failed to register VXD misc device\n",
			__func__);
		goto out_register;
	}

	dev_dbg(dev, "%s: misc dev registered successfuly\n", __func__);

	if (vxd_dbgfs_populate(vxd, dev_name) < 0)
		dev_warn(dev, "%s: failed to populate debugfs !\n", __func__);

	return 0;

out_register:
	devm_kfree(dev, dev_name);

	return ret;
}

int vxd_api_rm_dev(struct device *dev, struct vxd_dev *vxd)
{
	int ret = 0;

	dev_dbg(dev, "%s: trying to deregister VXD misc device\n", __func__);

	if (!dev || !vxd) {
		pr_err("%s: invalid params!\n", __func__);
		return -EINVAL;
	}

	/* note: since linux v4.3, misc_deregister does not return errors */
	misc_deregister(&vxd->miscdev);

	devm_kfree(dev, (void *)vxd->miscdev.name);

	dev_dbg(dev, "%s: VXD misc dev deregistered: %d\n", __func__, ret);

	vxd_dbgfs_cleanup(vxd);

	return ret;
}

static int __init vxd_api_init(void)
{
	int ret;

	pr_debug("loading VXD module.\n");

	vxd_core_early_init();

	ret = vxd_plat_init();
	if (ret)
		pr_err("failed initialize VXD driver\n");

	return ret;
}

static void __exit vxd_api_exit(void)
{
	int ret;

	pr_debug("unloading VXD module.\n");

	ret = vxd_plat_deinit();
	if (ret)
		pr_err("failed to deinitialise VXD driver\n");
}

module_init(vxd_api_init);
module_exit(vxd_api_exit);

MODULE_LICENSE("GPL");


/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
