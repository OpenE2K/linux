/*
 * Copyright (c) 2011 by MCST.
 */
 
#include <linux/module.h>
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/mm.h>

//for mknod
#include <linux/err.h>
#include <linux/namei.h>
#include <linux/audit.h>

#define _KERNEL
#include <linux/mcst/wrnvram.h>
#include <linux//mcst/wrnvram_io.h>


MODULE_LICENSE	  ("GPL");
MODULE_AUTHOR     ("Alexey Mukhin");
MODULE_DESCRIPTION("MCST write/read nvram pseudo-driver");

unsigned int	step  = 0; // step for attach/detach
unsigned int	major = 0;
unsigned int	wrnvram_nr_devs;
wrnvram_dev_t	*wrnvram_devices[MAX_WRNVRAM];


static int wrnvram_detach( wrnvram_dev_t *wrnvram );

int mk_mknod(char *filename, int mode, dev_t dev);
int mk_mkdir(char *pathname, int mode);
int mk_rm_dir(char *dir);
int mk_unlink(char *filename);



int
write_in_nvram(u_int off, u_char *addr, int sz)
{
	int i;

	for(i = 0; i < sz; i++)
	  writeb_asi(addr[i], ASI_NVRAM_BASE + off + i, ASI_NVRAM);

	return i;
  
}


int
read_from_nvram(u_int off, u_char *addr, int sz)
{
	int i;

	for(i = 0; i < sz; i++)
	  addr[i] = readb_asi(ASI_NVRAM_BASE + off + i, ASI_NVRAM);

	return i;
  
}


/*
 * return length of read/write
 */
int
mcst_mfgid(int mode, u_long *val)
{
	u_long 	mfgid[1];
	int		len;
	
	if (mode) {
	  mfgid[0] = *val;
	  len = write_in_nvram(OFF_MFGID, (u_char *)&mfgid, sizeof(u_long));
	}
	else {
	  len = read_from_nvram(OFF_MFGID, (u_char *)&mfgid, sizeof(u_long));
	  *val = mfgid[0];
	}
  
	return len;
}


static void
__exit wrnvram_exit(void)
{
	int inst;
	char nod[128];

	for(inst = 0; inst < wrnvram_nr_devs; inst++) {
		wrnvram_detach( wrnvram_devices[inst] );
		sprintf(nod,"/dev/%s", MODULE_NAME);
		mk_unlink(nod);
	}

	//mk_rm_dir("/dev/wrnvram");
}


static int
wrnvram_open(struct inode *inode, struct file *filp)
{
	wrnvram_dev_t *wrnvram;
	int minor = MINOR(inode->i_rdev);

	wrnvram = (wrnvram_dev_t *)filp->private_data;
	if (!wrnvram) {
		if ( minor >= wrnvram_nr_devs )
			return -ENODEV;
		wrnvram = wrnvram_devices[minor];
		filp->private_data = wrnvram;
	}

	if ( wrnvram->open == 1) {
		printk(KERN_WARNING "wrnvram open: cannot re-open device.\n");
		return -EBUSY;
	}
	  
	wrnvram->open = 1;

	return 0;
}


static int
wrnvram_close(struct inode *inode, struct file *filp)
{

	wrnvram_dev_t *wrnvram;
	int minor = MINOR(inode->i_rdev);

	if ( minor >= wrnvram_nr_devs )
		return -ENODEV;

	wrnvram = wrnvram_devices[minor];

	wrnvram->open = 0;
	filp->private_data = NULL; // needed ?

	return(0);
}


static loff_t
wrnvram_llseek(struct file *filp, loff_t offset, int whence)
{
  
	loff_t newpos;
	
	switch(whence) {
	case 0: /* SEEK_SET */
	  newpos = offset;
	  break;
	case 1: /* SEEK_CUR */
	  newpos = filp->f_pos + offset;
	  break;
	case 2: /* SEEK_END */
	  newpos = SIZE_NVRAM + offset;
	  break;
	}
  
	if ( newpos < 0 ) {
	  printk(KERN_WARNING "wrnvram llseek: offset less than nvram size.\n");
	  return -EINVAL;
	}
	
	//needed ?
	if ( newpos >= SIZE_NVRAM ) {
	  printk(KERN_WARNING "wrnvram llseek: offset more than nvram size.\n");
	  return -EINVAL;
	}
	
	filp->f_pos = newpos;
  
	return newpos;
}


static ssize_t
wrnvram_write(struct file *filp, const char *buf, size_t size, loff_t *f_pos)
{
	int	res = 0;
	u_char 	*msg;
	int	off = (u_int)*f_pos;
	
	if ( (off + size) > SIZE_NVRAM ) {
	  printk(KERN_WARNING "wrnvram write: off | size INCORRECT. "
		 "(off =%x +size =%x) =%x, SIZE_NVRAM =%x.\n",
		 off, size, off+size, SIZE_NVRAM);
	  return -EFAULT;
	}
	
	msg = (u_char*)kmalloc(size, GFP_KERNEL);
	
	res = copy_from_user((caddr_t)msg, (caddr_t)buf, size);
	if (res) {
	  printk(KERN_WARNING "wrnvram write: error - copy_from_user(0x%x, 0x%x, 0x%x).\n",
		 buf, msg, size);
	  kfree((void*)msg);
	  return -EFAULT;
	}
	
	res = write_in_nvram(off, msg, (u_int)size);
	
	*f_pos += res;

	kfree((void*)msg);
	return res;
}


static ssize_t
wrnvram_read(struct file *filp, char *buf, size_t size, loff_t *f_pos)
{
	int	 res = 0, len = 0;
	u_char *msg;
	int	 off = (u_int)*f_pos;

	if ( (off + size) > SIZE_NVRAM ) {
	  printk(KERN_WARNING "wrnvram read: off | size INCORRECT. "
		 "(off =%x +size =%x) =%x, SIZE_NVRAM =%x.\n",
		 off, size, off+size, SIZE_NVRAM);
	  return -EFAULT;
	}
	  
	msg = (u_char*)kmalloc(size, GFP_KERNEL);
	
	len = read_from_nvram(off, msg, (u_int)size);
	
	res = copy_to_user((caddr_t)buf, (caddr_t)msg, size);
	if (res) {
	  printk(KERN_WARNING "wrnvram read: error - copy_to_user(0x%x, 0x%x, 0x%x).\n",
		 msg, buf, size);
	  kfree((void*)msg);
	  return -EFAULT;
	}
	
	*f_pos += len;
	
	kfree((void*)msg);
	return len;
}


static int
wrnvram_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
	int     retval = 0, err = 0;
	
	if (_IOC_TYPE(cmd) != WRNVRAM_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > WRNVRAM_IOC_MAXNR) return -ENOTTY;
	if (_IOC_DIR(cmd) & _IOC_READ)
	  err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
	  err =  !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (err) return -EFAULT;

	
        switch (cmd) {

	case WRNVRAM_GET_MFGID:
	  {
	    u_long mfgid;
	    mcst_mfgid(0, &mfgid);
	    
	    if ( copy_to_user((u_long __user *)arg,
			      &mfgid,
			      sizeof(u_long)) )
	      {
		printk(KERN_WARNING "wrnvram ioctl: error WRNVRAM_GET_MFGID on copy to user.\n");
		retval = -EFAULT;
		break;
	      }
	  } 
	  break;

	case WRNVRAM_SET_MFGID:
	  {
	    u_long mfgid;
	    if ( copy_from_user(&mfgid,
				(u_long __user *)arg,
				sizeof(u_long)) )
	      {
		printk(KERN_WARNING "wrnvram ioctl: error WRNVRAM_SET_MFGID on copy from user.\n");
		retval = -EFAULT;
		break;
	      }
	    
	    mcst_mfgid(1, &mfgid);
	  }
	  break;

        default :
	  printk(KERN_WARNING "wrnvram ioctl: unknown cmd = 0x%x.\n", cmd);
	  retval = -EINVAL;
	  break;
        }

        return retval;
}


static struct file_operations wrnvram_fops = {
	.owner	= THIS_MODULE,
	.open	= wrnvram_open,
	.release = wrnvram_close,
	.read	= wrnvram_read,
	.write	= wrnvram_write,    
	.llseek	= wrnvram_llseek,
	.ioctl	= wrnvram_ioctl
};


static int wrnvram_detach( wrnvram_dev_t *wrnvram )
{

	switch (step) {
	case 3:
	  cdev_del(&wrnvram->cdev);
	case 2:
	  kfree(wrnvram);
	case 1:
	  unregister_chrdev_region(MKDEV(major, 0), MAX_WRNVRAM);
	case 0:
	  break;
	}
  
	return (0);
}


static int __init wrnvram_init(void)
{
	wrnvram_dev_t* wrnvram;
	dev_t	dev_mn;
	int	result, devno;

	printk(KERN_NOTICE "%s %s: wrnvram init.\n", MODULE_NAME, __DATE__);

	result = alloc_chrdev_region(&dev_mn, 0, MAX_WRNVRAM, "wrnvram");
	if (result < 0) {
		printk(KERN_WARNING "wrnvram init: can't get major %d.\n", major);
		return result;
	}

	step = 1;
	
	if (!major) {
		major = MAJOR(dev_mn);
		printk(KERN_NOTICE "wrnvram init: got dynamic major %d.\n", major);
	}

	/* module defaults initialisation */
	wrnvram_nr_devs = 0;
	if ( (wrnvram = kmalloc(sizeof(wrnvram_dev_t), GFP_KERNEL)) < 0 ) {
		printk(KERN_WARNING "wrnvram init: cannot allocate memory for wrnvram_dev_t.\n");
		result = -ENOMEM;
		goto failed;
	}

	step = 2;
	
	memset(wrnvram, 0, sizeof(wrnvram_dev_t));
	wrnvram->dev = dev_mn;
	wrnvram->open = 0;

	devno = MKDEV(major, wrnvram_nr_devs);
	cdev_init(&wrnvram->cdev, &wrnvram_fops);
	wrnvram->cdev.owner = THIS_MODULE;
	wrnvram->cdev.ops = &wrnvram_fops;
	
	result = cdev_add (&wrnvram->cdev, devno, 1);
	if ( result != 0 ) {
	  printk(KERN_WARNING "wrnvram init: cannot add device to the system.\n");
	  goto failed;
	}

	step = 3;
	
	wrnvram_devices[wrnvram_nr_devs] = wrnvram;

	/* increment device number, for what ? */
	wrnvram_nr_devs++;

	if ( wrnvram_nr_devs > 0 ) {
		if ( major == 0 )
			major = result;
	}
	else {
		printk(KERN_WARNING "wrnvram init: error: cannot add module.\n");
		result = -ENODEV;
		goto failed;
	}


// Create nodes
{
	int mode, i = 0;
	dev_t	devt;
	char nod[128];

	mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	//mk_mkdir("/dev/wrnvram", mode);
    
	//for (i = 0; i < wrnvram_nr_devs; i++) {

		//sprintf(nod,"/dev/%s/%s%d", MODULE_NAME, MODULE_NAME, i);
		sprintf(nod,"/dev/%s", MODULE_NAME);
	
		mode |= S_IFCHR;
		devt = (major << 8) | i;

		if (mk_mknod(nod, mode, devt)  == -EEXIST) {
			printk("mknod: node %s exist, removing then creating again\n", nod);
			mk_unlink(nod);
			if (mk_mknod(nod, mode, devt) != 0)  {
				printk("mk_create_minor: creating node %s failed\n", nod);
				return -1;
			}
		}
    	//}
}

	return (0);

failed:
	(void) wrnvram_detach(wrnvram);
	return (result);	
}



/****************************** !!!!!!!!!!! *******************/

int mk_unlink(char *filename)
{	
	int error = 0;
	char *name;
	struct dentry *dentry;
	struct nameidata nd;
	struct inode *inode = NULL;


	name = __getname();
	audit_getname(name);
	if (!name){
		name = ERR_PTR(-ENOMEM);
		error = PTR_ERR(name);
	}
	if(IS_ERR(name))
		return PTR_ERR(name);

	sprintf(name, "%s", filename);
	error = path_lookup(name, LOOKUP_PARENT, &nd);
	if (error) {
		printk("mk_unlink: path_lookup() ret error %s %d\n", name, error);
		goto exit;
	}
	error = -EISDIR;
	if (nd.last_type != LAST_NORM)
		goto exit1;
	down(&nd.dentry->d_inode->i_sem);
	dentry = lookup_hash(&nd.last, nd.dentry);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		/* Why not before? Because we want correct error value */
		if (nd.last.name[nd.last.len])
			goto slashes;
		inode = dentry->d_inode;
		if (inode)
			atomic_inc(&inode->i_count);
		error = vfs_unlink(nd.dentry->d_inode, dentry);
	exit2:
		dput(dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
exit1:
	path_release(&nd);
exit:
	putname(name);

	if (inode)
		iput(inode);	/* truncate the inode here */
	return error;

slashes:
	error = !dentry->d_inode ? -ENOENT :
		S_ISDIR(dentry->d_inode->i_mode) ? -EISDIR : -ENOTDIR;
	goto exit2;
}


int mk_rm_dir(char *dir)
{
	int error = 0;
	char * name;
	struct dentry *dentry;
	struct nameidata nd;
	
	if (dir == NULL) {
		printk("mk_rm_dir: dir == NULL\n");
		return -EFAULT;
	}

	name = __getname();
	audit_getname(name);
	if (!name){
		name = ERR_PTR(-ENOMEM);
		error = PTR_ERR(name);
	}

	if(IS_ERR(name))
		return PTR_ERR(name);

	sprintf(name, "%s", dir);

	error = path_lookup(name, LOOKUP_PARENT, &nd);
	if (error) {
		printk("mk_rm_dir: path_lookup() ret error %s %d\n", name, error);
		goto exit;
	}
	
	switch(nd.last_type) {
		case LAST_DOTDOT:
			error = -ENOTEMPTY;
			goto exit1;
		case LAST_DOT:
			error = -EINVAL;
			goto exit1;
		case LAST_ROOT:
			error = -EBUSY;
			goto exit1;
	}

	down(&nd.dentry->d_inode->i_sem);

	dentry = lookup_hash(&nd.last, nd.dentry);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		error = vfs_rmdir(nd.dentry->d_inode, dentry);
		dput(dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
exit1:	
	path_release(&nd);
exit:
	putname(name);
	return error;
}

int mk_mkdir(char *pathname, int mode)
{
	int 			error = 0;
	char 			*tmp;
	struct dentry 		*dentry;
	struct nameidata 	nd;

	if (pathname == NULL) {
		printk("mk_mkdir: pathname == NULL ret -EFAULT\n");
		return -EFAULT;
	}

	tmp = __getname();
	audit_getname(tmp);
	if (!tmp) {
		tmp = ERR_PTR(-ENOMEM);
		error = PTR_ERR(tmp);
	}
	if (!IS_ERR(tmp)) {
		sprintf(tmp, "%s", pathname);
		error = path_lookup(tmp, LOOKUP_PARENT, &nd);
		if (error) {
			printk("mk_mkdir: path_lookup() ret error %d\n", error);
			goto out;
		}
		dentry = lookup_create(&nd, 1);
		error = PTR_ERR(dentry);
		if (!IS_ERR(dentry)) {
			if (!IS_POSIXACL(nd.dentry->d_inode))
				mode &= ~current->fs->umask;
			error = vfs_mkdir(nd.dentry->d_inode, dentry, mode);
			dput(dentry);
		}
		up(&nd.dentry->d_inode->i_sem);
		path_release(&nd);
out:
		putname(tmp);
	}
		return error;
}


extern asmlinkage long sys_mknod(const char * filename, int mode, dev_t dev);
int mk_mknod(char *filename, int mode, dev_t dev)
{
	int error = 0;
	char *tmp;
	struct dentry * dentry;
	struct nameidata nd;
	
	if (filename == NULL) {
		printk("mk_mknod: filename == NULL\n"); 
		return -EINVAL;
	}
	if (S_ISDIR(mode)) {
		printk("mk_mknod: S_ISDIR\n"); 
		return -EPERM;
	}

	tmp = __getname();
	audit_getname(tmp);
	if (!tmp){
		tmp = ERR_PTR(-ENOMEM);
		error = PTR_ERR(tmp);
	}
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	sprintf(tmp, "%s", filename);
	error = path_lookup(tmp, LOOKUP_PARENT, &nd);
	if (error){	
		printk("mk_mknod: path_lookup() ret error %s %d\n", tmp, error);
		goto out;
	}
	dentry = lookup_create(&nd, 0);
	error = PTR_ERR(dentry);
	if (!IS_POSIXACL(nd.dentry->d_inode))
		mode &= ~current->fs->umask;
	if (!IS_ERR(dentry)) {
		switch (mode & S_IFMT) {
		case 0: case S_IFREG:
				error = vfs_create(nd.dentry->d_inode,dentry,mode,&nd);
				break;
		case S_IFCHR: case S_IFBLK: 
				error = vfs_mknod(nd.dentry->d_inode,dentry,mode,new_decode_dev(dev));
				break;
		case S_IFIFO: case S_IFSOCK:
				error = vfs_mknod(nd.dentry->d_inode,dentry,mode,0);
				break;
		case S_IFDIR:
				error = -EPERM;
				break;
		default:
				error = -EINVAL;
		}
		dput(dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
	path_release(&nd);
out:
	putname(tmp);

	return error;
}

/****************************** !!!!!!!!!!! *******************/

module_init(wrnvram_init);
module_exit(wrnvram_exit);

