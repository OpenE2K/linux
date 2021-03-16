/*
 * Copyright (c) 2010 by MCST.
 */
#ifndef MCST_WRNVRAM_H
#define MCST_WRNVRAM_H

#define MODULE_NAME "wrnvram"

/* offset in NVRAM for mem of mcst */

#define	OFF_SUF		0x1fa0
#define	OFF_MFGID	0x1fe8
#define	SIZE_NVRAM	0x2000
#define ASI_NVRAM_BASE	0xf1200000
#define ASI_NVRAM	0x2f


#define bzero(d, n) memset((d), 0, (n))

#if (WRNVRAMDEBUG > 0)
/* static int wrnvram_debug = WRNVRAMDEBUG; */	/* set internally */
int wrnvram_debug =WRNVRAMDEBUG; 	/* if set externally */
#define	DEBUGF(level, args)	{ if (wrnvram_debug >= (level)) \
					{drv_usecwait(100000); cmn_err args;} }
#else
#define	DEBUGF(level, args)	/* nothing */
int wrnvram_debug = 0;
#endif /* WRNVRAMDEBUG */

#ifdef _KERNEL

#define	MAX_WRNVRAM 16

/* Private data of each instance of driver */

typedef struct wrnvram_dev {
	dev_t			dev;
	int			attach_level;
	//spinlock_t		*mutex;
	int 			instance;
	struct cdev		cdev;
	
	u_int			debug;
	u_char			open;

} wrnvram_dev_t;

#endif /*_KERNEL*/

/*
 *		Debug flags
 */
#define	WRNVRAM_DEBUG_WAITING		0x001
#define	WRNVRAM_DBG_START_TRANSFER		0x002
#define	WRNVRAM_DBG_ERR_RETURNS		0x004
#define	WRNVRAM_DBG_INTR			0x008
#define	WRNVRAM_DBG_IOCTL			0x010
#define	WRNVRAM_DBG_RESET			0x020
#define	WRNVRAM_DBG_SEND_CMD		0x040
#define	WRNVRAM_REG_WR			0x080
#define	WRNVRAM_ATTACH			0x100



/*------------------ For USER ------------------*/



#ifndef _KERNEL

int wrnvram_read(int fd,char* all_bufs, int buf_num)
{
/*	wrnvram_buf_t	buf_rd;
	int res = ioctl(fd, WRNVRAM_IOC_RD_BUF, buf_num);
	if (res) {
		print_msg_error("WRNVRAM_IOC_RD_BUF :err =%d",res);
		return	-1;
		}
	ioctl(fd, WRNVRAM_IOC_FREE_BUF, buf_num);*/
	return 0;
}

int wrnvram_write(int fd,char* all_bufs, int buf_num)
{
	/*res = ioctl(fd, WRNVRAM_IOC_WR_BUF, buf_num);
	return res;*/
	return 0;
	
}

#endif /*_KERNEL*/
#endif /*MCST_WRNVRAM_H*/
