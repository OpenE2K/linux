/*
 * Copyright (c) 2005 by MCST.
 * 
 * Written by Alexey V. Sitnikov, MCST 2005 
 */

#define	DBG_MODE 0
#define DBG_READ_MODE 0
#define DBG_WRITE_MODE 0
#define DBG_MEM_MODE	0
#define DBGPDCDETAIL_MODE 0
#define	DBGDMA_MODE 0

#define	dbgpdc	if (DBG_MODE) printk
#define	dbgpdc_rd	if (DBG_READ_MODE) printk
#define	dbgpdc_wr	if (DBG_WRITE_MODE) printk
#define	dbgpdc_mem	if (DBG_MEM_MODE) printk
#define dbgpdcdetail if (DBGPDCDETAIL_MODE) printk
#define	dbgdma	if (DBGDMA_MODE) printk

#include <linux/miscdevice.h>

#include <linux/mm.h>
#include <linux/namei.h>

#include <linux/mcst/ddi.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <linux/compiler.h>
#include <linux/termios.h>

#include "user_intf.h"

#define	drv_name	"pidc"
#define board_name	"MCST,pidc"	/* should be same as FCODE.name */

#define DEV_DEVN(d)	(getminor(d))		/* dev_t -> minor (dev_num) */
#define DEV_inst(m)	(m >> 3)		/* minor -> instance */
#define DEV_MINOR(i)	((i << 3))	        /* instance -> minor*/
#define DEV_INST(d)	DEV_inst(DEV_DEVN(d))	/* dev_t -> instance */


#define CH_DMA_H_ALLOCD   1 	/* chan res alloc stat bit masks */
#define CH_DMA_MH_ALLOCD  2

struct dma_mem {
        uchar_t allocs;	 		 /* chan res alloc statbit stack */

	unsigned long	 dma;   /* Адрес со стороны процессора */
	dma_addr_t	 prim_dev_mem; /* Адрес со стороны устройства */

	caddr_t		 buf_addr;
//	unsigned int	 real_size;
	size_t		 real_size;

};

typedef struct dma_mem dma_mem_t;

#define MAX_TIMER 15000000	/*   не более xxx сек	      */

/*
 *	Slot entity globals
 */
#define SL_CONF_ALLOCD   1 	/* slot res alloc stat bit masks */
#define SL_MEMH_ALLOCD   2
#define SL_COOKIE_BIND 	 4

typedef struct pdc_state {
	dev_info_t		*dip;
        uchar_t 		allocs;	 	/* resourse allocations status */
	int			opened;
	int			open_flags;
	
	int			clear_on_slave;		/* включить очистку */
	int			clear_on_master;	/* включить очистку */
	int			stat; 		/* Состояние устройства */
	unsigned int		evs;		/* Информация о полученных прерываниях */	
	clock_t			timer;  	/* таймер мксек операции I/O     */ 
						/* ==0 - опрос, >0 - блокировака */
						/*      до завершения операции   */
	kcondvar_t		cv_master;
	kcondvar_t		cv_slave;
	kcondvar_t		cv_rmi_master;	
	kcondvar_t		cv_rmi_slave;

	raw_spinlock_t		lock;

	caddr_t			regbase;   	/* slot regs mapped base addr */
        int  			mask_set;
        int  			instance;
	dma_mem_t		memd;
	struct termios		termios;	
} pdc_state_t;

int	pdc_instances;

static int 	pdc_attach(dev_info_t	*dip);
static int 	pdc_detach(dev_info_t	*dip);


static ssize_t	pdc_read(struct file *filp, char *buf, size_t size, loff_t *off);
static ssize_t	pdc_write(struct file *filp, const char  *buf, size_t size, loff_t *off);
static int 	pdc_open(struct inode *inode, struct file *file);
static int 	pdc_close(struct inode *inode, struct file *file);
static uint_t 	pdc_chpoll(struct file *file, struct poll_table_struct *wait);
static int 	pdc_ioctl(struct inode *inode, struct file *filp,
           			unsigned int cmd, unsigned long arg);
static int 	pdc_mmap(struct file *file, struct vm_area_struct *vma);

int		pdc_iocrw(dev_t dev,  pdc_ioc_parm_t * parm, int kop);
irqreturn_t	pdc_intr(int irq, void *arg, struct pt_regs *regs);
void 		free_mem(dev_info_t *dip, dma_mem_t * memd); 
size_t 		init_mem(dev_info_t *dip, dma_mem_t * memd, size_t reqlen);
int 		make_dev(dev_info_t *dip); 
int 		rmv_dev(dev_info_t *dip); 
void 		Resetting(struct pdc_state	*xsp);
void		pdc_interrupt(void *arg);
/*
 * file_operations
 */
static struct file_operations pdc_fops = {
	owner:   THIS_MODULE,
	read:	 pdc_read,
	write:	 pdc_write,
	open:	 pdc_open,
	release: pdc_close,
	poll:    pdc_chpoll,
	ioctl:   pdc_ioctl,
	mmap:	 pdc_mmap,
};

int identify(int reg)
{
	switch (reg){
		case CONTROL_REGISTER :
		return 0;
		case STATUS_REGISTER :
		return 0;
		case MASTER_CONTROL_REGISTER :
		return 0;
		case MASTER_ADDRESS_REGISTER :
		return 0;
		case SLAVE_CONTROL_REGISTER :
		return 0;
		case SLAVE_DATA_REGISTER :
		return 0;
		case SRBC_REGISTER :
		return 0;
		case STBC_REGISTER :
		return 0;
		case MRBC_REGISTER :
		return 0;
		case MTBC_REGISTER :
		return 0;
		default :
		return -1;
	}
}

int
WRR(caddr_t a,unsigned int reg, unsigned int val)
{
	unsigned int *p;
	dbgpdcdetail("**** WRR reg=%x val=%u ****\n",reg,val);
	if(identify(reg)) {
		printk("WRR[] reg=%x unknown. SORRY!\n", reg);
		return -EINVAL;
	}
	p = ((unsigned int *)a + reg);	
	dbgpdcdetail("WRR: Reg addr = 0x%lx\n", (unsigned long)p);

	*p = val;
	return 0;	
}

int
RDR(caddr_t a,unsigned int reg)
{
	unsigned int val;
	unsigned int * p;
	dbgpdcdetail("**** RDR reg=%x ****\n",reg);
	if(identify(reg)) {
		printk("RDR[] reg=%x unknown. SORRY!\n", reg);
		return -EINVAL;
	}
	p = ((unsigned int *)a + reg);
	val = *p;
	dbgpdcdetail("**** RDR reg=%x val=%u ****\n",reg,val);
	return val;
}

/* Проверяет есть ли данные в набортном Slave Recieve Buffer.
   После каждого чтения регистра SData значение счетчика SRBC уменьшается на 1 (4 байта)
   После каждого получения данных в набортный буфер (порциями по 4 байта) значение  SRBC
   увеличивается на единицу. Т.о. если  значение  SRBC > 0 то данные в SRB буфере имеются */
static int IN_SRB(pdc_state_t *xsp) 
{
	return RDR(xsp->regbase, SRBC_REGISTER);	
}

/* Сброс задачи Slave */
static void clear_slave_task (pdc_state_t *xsp)
{
	Slave_Control_Reg_t S_Cntrl_Reg;
	if (xsp->stat & PDC_SB_TRANSMIT || xsp->stat & PDC_SB_RECIEVE){
		AS_WORD(S_Cntrl_Reg) = RDR(xsp->regbase, SLAVE_CONTROL_REGISTER);
		AS_STRUCT(S_Cntrl_Reg).SV = 0;
		WRR(xsp->regbase, SLAVE_CONTROL_REGISTER, AS_WORD(S_Cntrl_Reg));
	}
}

/* Сброс задачи Slave */
static void clear_slave_task_mu (pdc_state_t *xsp)
{
	Slave_Control_Reg_t S_Cntrl_Reg;
	spin_mutex_enter(&xsp->lock);
	if ((xsp->stat & PDC_SB_TRANSMIT || xsp->stat & PDC_SB_RECIEVE) && 
		((AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Err) != 1 && 
				(AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) != 1)){
		xsp->clear_on_slave = 1;
		AS_WORD(S_Cntrl_Reg) = RDR(xsp->regbase, SLAVE_CONTROL_REGISTER);
		AS_STRUCT(S_Cntrl_Reg).SV = 0;
		WRR(xsp->regbase, SLAVE_CONTROL_REGISTER, AS_WORD(S_Cntrl_Reg));
	}
	spin_mutex_exit(&xsp->lock);
}

/* Сброс задачи Master */
static void clear_master_task (pdc_state_t *xsp)
{
	Master_Control_Reg_t M_Cntrl_Reg;
	if (xsp->stat & PDC_MB_TRANSMIT || xsp->stat & PDC_MB_RECIEVE){
		AS_WORD(M_Cntrl_Reg) = RDR(xsp->regbase, MASTER_CONTROL_REGISTER);
		AS_STRUCT(M_Cntrl_Reg).MV = 0;
		WRR(xsp->regbase, MASTER_CONTROL_REGISTER, AS_WORD(M_Cntrl_Reg));
	}
}

/* Сброс задачи Master */
static void clear_master_task_mu (pdc_state_t *xsp)
{
	Master_Control_Reg_t M_Cntrl_Reg;
	spin_mutex_enter(&xsp->lock);
	if ((xsp->stat & PDC_MB_TRANSMIT || xsp->stat & PDC_MB_RECIEVE) && 
		((AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Err) != 1 && 
				(AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) != 1)){
		xsp->clear_on_master = 1;
		AS_WORD(M_Cntrl_Reg) = RDR(xsp->regbase, MASTER_CONTROL_REGISTER);
		AS_STRUCT(M_Cntrl_Reg).MV = 0;
		WRR(xsp->regbase, MASTER_CONTROL_REGISTER, AS_WORD(M_Cntrl_Reg));
		cv_signal(&xsp->cv_master);
	}
	spin_mutex_exit(&xsp->lock);
}

void Resetting(struct pdc_state	*xsp)
{
	Control_Reg_t Control_Reg;

	clear_master_task_mu(xsp);
	clear_slave_task_mu(xsp);

again:
	spin_mutex_enter(&xsp->lock);
	if (xsp -> stat != 0){
		spin_mutex_exit(&xsp->lock);
		goto again;
	}
	spin_mutex_exit(&xsp->lock);
	AS_WORD(Control_Reg) = RDR(xsp->regbase, CONTROL_REGISTER);
	AS_STRUCT(Control_Reg).Rst = 1;
	WRR(xsp->regbase, CONTROL_REGISTER, AS_WORD(Control_Reg));
	xsp->evs = 0;
}

/* Вычисление переданного/полученного размера DW (4 байта) для Master */
size_t mb_calculate_size(pdc_state_t *xsp, size_t Msize_trans)
{
	Master_Control_Reg_t M_Cntrl_Reg;
	AS_WORD(M_Cntrl_Reg) = RDR(xsp->regbase, MASTER_CONTROL_REGISTER);
	dbgpdc("mb_calculate_size : %lx bytes transmitted\n", 
			(u_long)(Msize_trans - AS_STRUCT(M_Cntrl_Reg).MSize)*4);
	return (Msize_trans - AS_STRUCT(M_Cntrl_Reg).MSize)*4;
}

/* Вычисление переданного/полученного размера DW (4 байта) для Slave */
size_t sb_calculate_size(pdc_state_t *xsp, size_t Slave_count)
{
	Slave_Control_Reg_t S_Cntrl_Reg;
	AS_WORD(S_Cntrl_Reg) = RDR(xsp->regbase, SLAVE_CONTROL_REGISTER);
	return (Slave_count - AS_STRUCT(S_Cntrl_Reg).SSize)*4;
}

static void clear_master_transmit_buffer(pdc_state_t *xsp)
{
	Master_Control_Reg_t M_Cntrl_Reg;
	AS_WORD(M_Cntrl_Reg) = 0;
	AS_STRUCT(M_Cntrl_Reg).C_MTB = 1;
	WRR(xsp->regbase, MASTER_CONTROL_REGISTER, AS_WORD(M_Cntrl_Reg));
}

static void clear_master_recieve_buffer(pdc_state_t *xsp)
{
	Master_Control_Reg_t M_Cntrl_Reg;
	AS_WORD(M_Cntrl_Reg) = 0;
	AS_STRUCT(M_Cntrl_Reg).C_MRB = 1;
	WRR(xsp->regbase, MASTER_CONTROL_REGISTER, AS_WORD(M_Cntrl_Reg));
}

static void clear_slave_transmit_buffer(pdc_state_t *xsp)
{
	Slave_Control_Reg_t S_Cntrl_Reg;
	AS_WORD(S_Cntrl_Reg) = 0;
	AS_STRUCT(S_Cntrl_Reg).C_STB = 1;
	WRR(xsp->regbase, SLAVE_CONTROL_REGISTER, AS_WORD(S_Cntrl_Reg));
}

static void clear_slave_recieve_buffer(pdc_state_t *xsp)
{
	Slave_Control_Reg_t S_Cntrl_Reg;
	AS_WORD(S_Cntrl_Reg) = 0;
	AS_STRUCT(S_Cntrl_Reg).C_SRB = 1;
	WRR(xsp->regbase, SLAVE_CONTROL_REGISTER, AS_WORD(S_Cntrl_Reg));
}

#if PDC_INT_TRACE
static void prt_evs(int inst, unsigned int evs) {

  	printk("***** evs[%u]: %x *****\n", inst, evs);
  	if (AS_STRUCT(((Status_Reg_t)evs)).Err) {
  		printk("***** evs[%u] Err (Не устранимая ошибка) *****\n", inst); 
  	}

	if (AS_STRUCT(((Status_Reg_t)evs)).PI) {
  		printk("***** evs[%u] PI *****\n", inst); 
  	}

	if (AS_STRUCT(((Status_Reg_t)evs)).PI_Src_MV) {
  		printk("***** evs[%u] PI_Src_MV *****\n", inst); 
  	}

	if (AS_STRUCT(((Status_Reg_t)evs)).PI_Src_SV) {
  		printk("***** evs[%u] PI_Src_SV *****\n", inst); 
  	}	

	if (AS_STRUCT(((Status_Reg_t)evs)).PI_Src_Err) {
  		printk("***** evs[%u] PI_Src_Err *****\n", inst); 
  	}

	if (AS_STRUCT(((Status_Reg_t)evs)).PI_Src_Rm) {
  		printk("***** evs[%u] PI_Src_Rm *****\n", inst); 
  	}

	if (AS_STRUCT(((Status_Reg_t)evs)).NMI) {
  		printk("***** evs[%u] PI *****\n", inst); 
  	}

	if (AS_STRUCT(((Status_Reg_t)evs)).NMI_Src_MV) {
  		printk("***** evs[%u] PI_Src_MV *****\n", inst); 
  	}

	if (AS_STRUCT(((Status_Reg_t)evs)).NMI_Src_SV) {
  		printk("***** evs[%u] PI_Src_SV *****\n", inst); 
  	}	

	if (AS_STRUCT(((Status_Reg_t)evs)).NMI_Src_Err) {
  		printk("***** evs[%u] PI_Src_Err *****\n", inst); 
  	}

	if (AS_STRUCT(((Status_Reg_t)evs)).NMI_Src_Rm) {
  		printk("***** evs[%u] PI_Src_Rm *****\n", inst); 
  	}
}
#endif /* PDC_INT_TRACE */

static int 
pdc_attach(dev_info_t *dip) 
{
	pdc_state_t	*xsp;
	int		rval, inst;
	Control_Reg_t		Cntrl_Reg;

	dbgpdc("***** pdc_attach START *****\n");
	dbgpdc("pdc_attach addr = 0x%lx\n", (u_long)pdc_attach);
	if (dip == NULL) return -EFAULT;
	xsp = (pdc_state_t *)dip->soft_state;
	inst = dip->instance;	

	spin_mutex_init(&xsp->lock);
	cv_init(&xsp->cv_master);
	cv_init(&xsp->cv_slave);
	cv_init(&xsp->cv_rmi_master);
	cv_init(&xsp->cv_rmi_slave);


	spin_mutex_init(&xsp->lock);
	xsp->dip = dip;		

	xsp->instance = inst;
	xsp->opened = 0;
	xsp->timer = MAX_TIMER;	

	/* slot DVMA registers mapping */
	if (ddi_ioremap(dip) != DDI_SUCCESS) {
		printk("~%s~%d_attach: failed to map regs\n", board_name, inst);
		goto failed;
	}
	xsp->regbase = (caddr_t )dip->base_addr[0];
	xsp->mask_set = 0;

	rval = ddi_add_irq(dip, &pdc_intr, SA_SHIRQ);
	if (rval) {
		printk("request_irq fail\n");
		goto failed;
	}
	if (make_dev(dip) == -1)
		goto failed;				

	/* Сброс устройства */
	Resetting(xsp);
	/* Дефолтная настройка устройства */
	AS_WORD(Cntrl_Reg) = 0;
	AS_STRUCT(Cntrl_Reg).MV_NMI_en = 1;
        AS_STRUCT(Cntrl_Reg).SV_NMI_en = 1;
	AS_STRUCT(Cntrl_Reg).MV_PI_en = 1;
	AS_STRUCT(Cntrl_Reg).SV_PI_en = 1;
	AS_STRUCT(Cntrl_Reg).Err_PI_en = 1;
	WRR(xsp->regbase, CONTROL_REGISTER, AS_WORD(Cntrl_Reg));
	memset(&xsp->termios, 0, sizeof(struct termios)); 

	dbgpdc("pdc_attach: DONE \n");
#if 0
	printk("Readning 8 bytes from 0x10014000 in dma mode ...");
{
	Master_Address_Reg_t MAddress;
	Master_Control_Reg_t M_Cntrl_Reg;

	AS_STRUCT(MAddress).MAddress =  0x10014000;
        AS_STRUCT(M_Cntrl_Reg).MSize = 2;
        AS_STRUCT(M_Cntrl_Reg).MCmd = 0x6; /* Чтение */
        AS_STRUCT(M_Cntrl_Reg).MV = 1;
	
	WRR(xsp->regbase, MASTER_ADDRESS_REGISTER, AS_WORD(MAddress));
	WRR(xsp->regbase, MASTER_CONTROL_REGISTER, AS_WORD(M_Cntrl_Reg));
	Resetting(xsp);
	printk("DONE");
}
#endif
	return (DDI_SUCCESS);

failed:
	ddi_unrgstr_dev(dip);
	dbgpdc("pdc_attach: FAILED\n");
	return (DDI_FAILURE);
}

static int 
pdc_detach(dev_info_t *dip) 
{
	struct pdc_state *xsp;
	int error = 0;
	
	if (dip == NULL) return -EFAULT;
	xsp = (pdc_state_t *)dip->soft_state;	
	if (xsp == NULL) return -EFAULT;
	if (xsp->opened)
		return -EBUSY;
	Resetting(xsp);
	free_mem(dip, &xsp->memd);
	error = (int)rmv_dev(dip);
	ddi_unrgstr_dev(dip);
	return error;
	
}


void free_mem(dev_info_t *dip, dma_mem_t *memd) 
{
	struct pdc_state *xsp;
	dbgpdc("%s.free_mem START, allocs=%x:\n", 
		drv_name, memd->allocs);

	if (dip == NULL) return;
	xsp = (pdc_state_t *)dip->soft_state;	
	if (xsp == NULL) return;		

	if (memd->allocs & CH_DMA_MH_ALLOCD) 
	{
		dbgpdc("free_mem.ddi_dma_mem_free\n"); 
		clear_master_task_mu(xsp);
again:
		spin_mutex_enter(&xsp->lock);
		if (xsp->stat & PDC_MB_TRANSMIT || xsp->stat & PDC_MB_RECIEVE){
			spin_mutex_exit(&xsp->lock);
			goto again;
		}
		spin_mutex_exit(&xsp->lock);
		dbgpdc("free_mem memd->real_size = %lu, memd->prim_dev_mem = 0x%lx, "
		       "memd->dma = 0x%lx\n",
			(u_long)memd->real_size, (unsigned long)memd->prim_dev_mem, 
						(unsigned long)memd->dma);		
		ddi_dma_mem_free(dip, 	memd->real_size,
					memd->prim_dev_mem,
					memd->dma);
		memd->allocs &=~ CH_DMA_MH_ALLOCD;
	}
	dbgpdc("%s.free_mem FINISH \n", drv_name);
}

int make_dev(dev_info_t *dip) 
{
	int	inst  = dip->instance;
	int     minor = DEV_MINOR(inst);
	char	name[64];

	dbgpdc("make_dev addr = 0x%lx\n", (u_long)make_dev);
	sprintf(name, "%s_%d", drv_name, inst);
	if (ddi_create_minor(dip, name, S_IFCHR, minor)) {
		printk("%s_attach: ddi_create_minor_node failed\n", 
			board_name);
		return -1;
	}
	dbgpdc("%s_attach,make_dev: minor_node = %s\n", board_name, name);	

	return 0;
}

int rmv_dev(dev_info_t *dip) 
{
	int	inst  = ddi_get_instance(dip);
	char	name[64];
	int 	error = 0;

	sprintf(name, "%s_%d", drv_name, inst);
	error = ddi_unlink(dip, name);
	if (error){
		printk("rmv_dev: ddi_unlink failed, error = %d\n", error);
		return error;
	}
	dbgpdc("%s_detach.rmv_dev: minor = %u !~~!\n",
		board_name, DEV_MINOR(inst));	
	return error;
}


size_t init_mem(dev_info_t *dip, dma_mem_t * memd, size_t reqlen) 
{
	char * err_msg;

	dbgpdc("**** init_mem START ****\n");

	if (memd->allocs & CH_DMA_MH_ALLOCD)
		return 0;

	memd->allocs = CH_DMA_H_ALLOCD;
	  
	if (ddi_dma_mem_alloc(dip, reqlen, 
				&memd->prim_dev_mem,
				&memd->real_size,
				&memd->dma) != DDI_SUCCESS) {
	   	err_msg = "ddi_dma_mem_alloc"; 
	   	goto failed;
	}	
  	if (memd->prim_dev_mem == 0) {
    		printk ("init_mem: channel have not get free memory\n");
    		return -1;
  	}
 	memd->allocs = memd->allocs | CH_DMA_MH_ALLOCD;
	memd->buf_addr = (caddr_t)memd->dma;

	dbgpdc_mem("init_mem: reql=%ld-0x%lx, real_s=%ld-0x%lx\n",
		(u_long)reqlen,(u_long)reqlen, 
		(u_long)memd->real_size, (u_long)memd->real_size);
	dbgpdc_mem("\t\t: prim_dev_mem=0x%lx buf_addr=0x%lx\n",
		(long)memd->prim_dev_mem, (long)memd->buf_addr);
	dbgpdc_mem("\t\t:[%d] prim_dev_mem=0x%lx buf_addr=0x%lx\n",dip->instance,
		(long)memd->prim_dev_mem, (long)memd->buf_addr);

	memset (memd->buf_addr, 0, memd->real_size);
 	
	dbgpdc("**** init_mem: DONE ****\n");
	return memd->real_size;

	
failed:
	free_mem(dip, memd);
	printk("**** %s: init_mem: %s FAILED ****\n",
		board_name, err_msg);
	return (-1);
}

static void rw_init_device(pdc_ioc_parm_t *parm, size_t size)
{
	parm->rwmode = 0;
	parm->size = size;
} 

static ssize_t pdc_write(struct file *filp, const char *buf, size_t size, loff_t *off)
{
	dev_info_t 		*dip;
	struct	pdc_state	*xsp;
	dev_t			dev;
	int			dev_num;
	int			instance;
	size_t			size_bytes = 0;
	size_t			i_size_bytes = 0;
	size_t			size_bytes_from_user = 0;
	size_t			size_words = 0;	
	size_t			i_size_words = 0;
	size_t			i = 0;
	ssize_t			res = 0;
	ssize_t			result = 0;
	pdc_ioc_parm_t  	parm;

	dbgpdc("\n***** PDC_WRITE START *****\n");
	dev = ddi_file_dev(filp);
	dip = ddi_file_dip(filp);
	if (!dip || !dev) return (-ENXIO);
	dev_num = DEV_DEVN(dev);
	instance = DEV_inst(dev_num);

	dbgpdc("pdc_write dev[inst] = %u[%u]\n", dev_num,instance);

	xsp = dip->soft_state;
	if (xsp == NULL) {
     		printk("~%s~_write: unattached instance %d\n", board_name, instance);
	        return (-ENXIO);
	}
	if (size <= 0){
		printk("~%s~_write: size parametr shold be > 0\n", board_name);
		return (-EINVAL);
	}
	i = size / (((1 << 16) - 1 - 1023) * 4); /* size / 64512 * 4 bytes */
	if (i){
		i_size_bytes = (((1 << 16) - 1 - 1023) * 4);
		res = init_mem(dip, &xsp->memd, i_size_bytes);
		if (res == -1)
			return (-ENOMEM);
	}
	size_bytes_from_user = size % (((1 << 16) - 1 - 1023) * 4); 
	/* Выровним size_bytes до 1024 байт */
	size_bytes = (((size_bytes_from_user + 1023)/1024) * 1024); 

	size_words = (size_bytes / 4);
	i_size_words = (i_size_bytes / 4);

	dbgpdc_wr("pdc_write: i_size_bytes = 0x%lx, i = %ld\n", (u_long)i_size_bytes, (u_long)i);
	dbgpdc_wr("pdc_write: size_bytes = 0x%lx\n", (u_long)size_bytes);
	dbgpdc_wr("pdc_write: size_bytes_from_user = 0x%lx\n", (u_long)size_bytes_from_user);
	dbgpdc_wr("pdc_write: size = 0x%lx\n", (u_long)size);
	dbgpdc_wr("pdc_write: timer = 0x%lx\n", drv_usectohz(xsp->timer));

	while (i) {
		rw_init_device(&parm, i_size_bytes);	

		if (ddi_copyin((void *)buf, (void *)xsp->memd.dma, i_size_bytes) == -1) {
			printk("pdc_write: ddi_copyout failed\n"); 
			free_mem(dip,&xsp->memd);
			return (-EINVAL);
		}
		res = pdc_iocrw(dev, &parm, PDC_MB_TRANSMIT);
		if (res < 0)
			return res;
		if (parm.err_no){
			printk("WRITE: pdc_iocrw when buffer queue FAILED, "
			       "err_no = %s\n", 
				msg_by_code(parm.err_no, iocerrs, 17));
			free_mem(dip,&xsp->memd);
			result = result + parm.size;
			printk("WRITE: result = 0x%lx\n", (long)result);
			return result;
		}
		(char *)buf = (char *)buf + i_size_bytes;
		result = result + i_size_bytes;
		i--;
	}
	if (i_size_bytes)
		free_mem(dip,&xsp->memd);
	if (size_bytes) {
		res = init_mem(dip, &xsp->memd, size_bytes);
		if (res == -1)
			return (-ENOMEM);
		rw_init_device(&parm, size_bytes);

		if (ddi_copyin((void *)buf, (void *)xsp->memd.dma, size_bytes_from_user) == -1) {
			printk("pdc_write: ddi_copyout failed\n"); 
			free_mem(dip,&xsp->memd);
			return (-EINVAL);
		}
		res = pdc_iocrw(dev, &parm, PDC_MB_TRANSMIT);
		if (res < 0)
			return res;
		if (parm.err_no){
			printk("WRITE: pdc_iocrw FAILED, err_no = %s\n", 
				msg_by_code(parm.err_no, iocerrs, 17));
			free_mem(dip,&xsp->memd);
			if (parm.size > size_bytes_from_user){
				result = result + size_bytes_from_user;
			}else{
				result = result + parm.size;
			}
			printk("WRITE: result = 0x%lx\n",(long)result);
			return result;
		}
		result = result + size_bytes_from_user;
	}
	free_mem(dip,&xsp->memd);
	dbgpdc("***** PDC_WRITE SUCCESSFULLY FINISH *****\n");
	return result;
}

static ssize_t pdc_read(struct file *filp, char *buf, size_t size, loff_t *off)
{
	dev_info_t 		*dip;
	struct	pdc_state	*xsp;
	dev_t			dev;
	int			dev_num;
	int			instance;
	size_t			size_bytes = 0;
	size_t			i_size_bytes = 0;
	size_t			size_bytes_to_user = 0;
	size_t			size_words = 0;	
	size_t			i_size_words = 0;
	size_t			i = 0;
	ssize_t			res = 0;
	ssize_t			result = 0;
	pdc_ioc_parm_t  	parm;

	dbgpdc("\n***** PDC_READ START *****\n");
	dev = ddi_file_dev(filp);
	dip = ddi_file_dip(filp);
	if (!dip || !dev) return (ENXIO);
	dev_num = DEV_DEVN(dev);
	instance = DEV_inst(dev_num);

	dbgpdc("pdc_read dev[inst] = %u[%u]\n", dev_num,instance);

	xsp = dip->soft_state;
	if (xsp == NULL) {
     		printk("~%s~_read: unattached instance %d\n", board_name, instance);
	        return (-ENXIO);
	}
	if (size <= 0){
		printk("~%s~_read: size parametr shold be > 0\n", board_name);
		return (-EINVAL);
	}
	i = size / (((1 << 16) - 1 - 1023) * 4); /* size / 64512 * 4 bytes */
	if (i){
		i_size_bytes = (((1 << 16) - 1 - 1023) * 4);
		res = init_mem(dip, &xsp->memd, i_size_bytes);
		if (res == -1)
			return (-ENOMEM);
	}
	size_bytes_to_user = size % (((1 << 16) - 1 - 1023) * 4); 
	/* Выровним size_bytes до 1024 байт */
	size_bytes = (((size_bytes_to_user + 1023)/1024) * 1024); 

	size_words = (size_bytes / 4);
	i_size_words = (i_size_bytes / 4);

	dbgpdc_rd("pdc_read: i_size_bytes = 0x%lx, i = %ld\n", 	(u_long)i_size_bytes, (u_long)i);
	dbgpdc_rd("pdc_read: size_bytes = 0x%lx\n", 		(u_long)size_bytes);
	dbgpdc_rd("pdc_read: size_bytes_to_user = 0x%lx\n", 	(u_long)size_bytes_to_user);
	dbgpdc_rd("pdc_read: size = 0x%lx\n", 			(u_long)size);
	dbgpdc_rd("pdc_read: timer = 0x%lx\n", 			drv_usectohz(xsp->timer));	

	while (i) {
		rw_init_device(&parm, i_size_bytes);

		res = pdc_iocrw(dev, &parm, PDC_MB_RECIEVE);
		if (res < 0)
			return res;
		if (parm.err_no){
			printk("READ: pdc_iocrw when buffer queue FAILED, "
			       "err_no = %s\n", 
				msg_by_code(parm.err_no, iocerrs, 17));
			free_mem(dip,&xsp->memd);
			result = result + parm.size;
			printk("READ: result = 0x%lx\n", (long)result);
			return result;
		}
		if (ddi_copyout((void *)xsp->memd.dma, (void *)buf, i_size_bytes) == -1) {
			printk("pdc_read: ddi_copyin failed\n"); 
			free_mem(dip,&xsp->memd);
			return (-EINVAL);
		}
		(char *)buf = (char *)buf + i_size_bytes;
		result = result + i_size_bytes;
		i--;
	}
	if (i_size_bytes)
		free_mem(dip,&xsp->memd);
	if (size_bytes) {
		res = init_mem(dip, &xsp->memd, size_bytes);
		if (res == -1)
			return (-ENOMEM);
		rw_init_device(&parm, size_bytes);

		res = pdc_iocrw(dev, &parm, PDC_MB_RECIEVE);
		if (res < 0)
			return res;
		if (parm.err_no){
			printk("READ: pdc_iocrw FAILED, err_no = %s\n", 
				msg_by_code(parm.err_no, iocerrs, 17));
			free_mem(dip,&xsp->memd);
			if (parm.size < size_bytes_to_user){
				result = result + parm.size;
			}else{
				result = result + size_bytes_to_user;
			}
			printk("READ: result = 0x%lx\n", (long)result);
			return result;
		}
		if (ddi_copyout((void *)xsp->memd.dma, (void *)buf, size_bytes_to_user) == -1) {
			printk("pdc_read: ddi_copyin failed\n"); 
			free_mem(dip,&xsp->memd);
			return (-EINVAL);
		}
		result = result + size_bytes_to_user;
	}
	free_mem(dip,&xsp->memd);
	dbgpdc("***** PDC_READ SUCCESSFULLY FINISH *****\n");
	return result;
}

/* Device access */

static int 
pdc_open(struct inode *inode, struct file *file) 
{
	dev_info_t 		*dip;
	struct	pdc_state	*xsp;
	dev_t			dev;
	int			dev_num;
	int			instance;
#if ONCE_OPENING
	int			firstopen = 0;
#endif 
	int			rval = 0;

	dbgpdc("\n***** pdc_open START *****\n");	

	rval = ddi_open(inode, file);
	if (rval < 0) return rval;
	dev = ddi_inode_dev(inode);
	dip = ddi_inode_dip(inode);
	if (!dip || !dev) return (-ENXIO);
	dev_num = DEV_DEVN(dev);
	instance = DEV_inst(dev_num);

	dbgpdc("pdc_open dev[inst] = %u[%u]\n", dev_num,instance);

	xsp = dip->soft_state;
	if (xsp == NULL) {
     		printk("~%s~_open: unattached instance %d\n", board_name, instance);
	        return (-ENXIO);
	}
    
	spin_mutex_enter(&xsp->lock);
#if ONCE_OPENING     
     
	firstopen = (xsp->opened == 0);	
	/*
	* Check for exclusive open - exclusivity affects the whole board,
	* not just the device being opened.
	*/
	if (firstopen == 0) {
		printk("~=%s=~%d_open: exclusive open of "
			board_name, "already opened device\n", instance);
		spin_mutex_exit(&xsp->lock);
		
		return (-EBUSY);
	}

	/*
	* Remember we're opened, if we get a detach request
	*/

	xsp -> opened = 1;
#else
	xsp->opened++;
#endif
	dbgpdc("pdc_open: opened = %u\n", xsp -> opened);
	spin_mutex_exit(&xsp->lock);

	dbgpdc("***** pdc_open NORMALLY FINISH *****\n");
	return  (0);
}

static int 
pdc_close(struct inode *inode, struct file *file) 
{
	dev_info_t 		*dip;
	dev_t			dev;
	struct pdc_state	*xsp = NULL;
	int			dev_num;
	int			instance;

	dev = ddi_inode_dev(inode);
	dip = ddi_inode_dip(inode);
	if (!dip || !dev) return (-ENXIO);
	xsp = (pdc_state_t *)dip->soft_state;
	if (xsp == NULL) return (-ENXIO);
	dev_num = DEV_DEVN(dev);
	instance = DEV_inst(dev_num);

	spin_mutex_enter(&xsp->lock);

#if ONCE_OPENING	
	xsp->opened = 0;	
#else
	xsp->opened--;
#endif /* ONCE_OPENING */

	dbgpdc("pdc_close for instance = %u, opened = %u\n", instance, xsp->opened);
	spin_mutex_exit(&xsp->lock);
	ddi_close(inode, file);

	return (0);
}

#ifdef STATE_DEBUG
void PRINT_STATE(pdc_state_t *xsp)
{
	Control_Reg_t Cntrl_Reg;
	AS_WORD(Cntrl_Reg) = RDR(xsp->regbase, CONTROL_REGISTER);

	if (AS_STRUCT(Cntrl_Reg).MV_NMI_en)
		printk("Control_Reg State: MV_NMI_en Установлен. (Выставление NMI прерывания при сбросе бита MV разрешено)\n");
	}
	if (AS_STRUCT(Cntrl_Reg).SV_NMI_en)
		printk("Control_Reg State: SV_NMI_en Установлен. (Выставление NMI прерывания при сбросе бита SV разрешено)\n");
	}
	if (AS_STRUCT(Cntrl_Reg).Err_NMI_en)
		printk("Control_Reg State: Err_NMI_en Установлен. (Выставление NMI прерывания при неустр. ошибке разрешено)\n");
	}
	if (AS_STRUCT(Cntrl_Reg).MV_PI_en)
		printk("Control_Reg State: MV_PI_en Установлен. (Выставление PCI прерывания при сбросе бита MV разрешено)\n");
	}
	if (AS_STRUCT(Cntrl_Reg).SV_PI_en)
		printk("Control_Reg State: SV_PI_en Установлен. (Выставление PCI прерывания при сбросе бита SV разрешено)\n");
	}
	if (AS_STRUCT(Cntrl_Reg).Err_PI_en)
		printk("Control_Reg State: Err_PI_en Установлен. (Выставление PCI прерывания при неустр. ошибке разрешено)\n");
	}
	if (AS_STRUCT(Cntrl_Reg).Rmode){
		printk("Control_Reg State: Режим контр. по приему перекрестный: PCI MASTER<-PCI SLAVE, PCI SLAVE<-PCI MASTER\n");
	}else {
		printk("Control_Reg State: Режим контр. по приему прямой: PCI MASTER<-PCI MASTER, PCI SLAVE<-PCI SLAVE\n");
	}
	
	if (AS_STRUCT(Cntrl_Reg).Hmode){
		printk("Control_Reg State: Hide режим включен\n");
	}
}
#endif /* STATE_DEBUG */

static 
int pdc_ioctl(struct inode *inode, struct file *filp,
                 unsigned int cmd, unsigned long arg) {
	
	dev_info_t 		*dip;
	dev_t			dev;
	int			dev_num;
	int			instance;
	pdc_ioc_parm_t 		parm;
	Status_Reg_t		Status_Reg;
	Control_Reg_t		Cntrl_Reg;
	int 			res = 0;
	struct pdc_state	*xsp = NULL;

	size_t			size_bytes = 0;
	size_t			i_size_bytes = 0;
	size_t			size_bytes_from_user = 0;
	size_t			i = 0;
	ssize_t			result = 0;
	dma_addr_t		save_dma_addr = 0;

	dbgpdc("\n***** pdc_ioctl: START *****\n");
	dev = ddi_inode_dev(inode);
	dip = ddi_inode_dip(inode);
	if (!dip || !dev) return (-ENXIO);
	xsp = (pdc_state_t *)dip->soft_state;
	if (xsp == NULL) return (-ENXIO);
	dev_num = DEV_DEVN(dev);
	instance = DEV_inst(dev_num);

	dbgpdc("***** %u: pdc_ioctl: cmd=%x *****\n", 
		instance, (uint) cmd);

	if (cmd == TCGETS){
		if (ddi_copyout((caddr_t)&xsp->termios, (caddr_t)arg,
			sizeof (struct termios)) == -1) {
			printk("pdc_ioctl: ddi_copyout failed\n"); 
			return (-EINVAL);
		}
		return 0;
	}

	if (cmd == TCSETS){
		if (ddi_copyin((caddr_t)arg, (caddr_t)&xsp->termios,
			sizeof (struct termios)) == -1) {
			printk("pdc_ioctl: ddi_copyin failed\n"); 
			return (-EINVAL);
		}
		return 0;
	}

	if (ddi_copyin((void *)arg, (void *)&parm,
		sizeof (pdc_ioc_parm_t)) == -1) {
		printk("pdc_ioctl: ddi_copyin failed, sizeof (pdc_ioc_parm_t) = %lx\n", 
			(u_long)sizeof (pdc_ioc_parm_t)); 
		return (-EINVAL);
	}
	
	parm.err_no = res = 0;
	switch (cmd) {

	case PDC_INIT :
		dbgpdc("***** pdc_ioctl: cmd = PDC_INIT *****\n");
		AS_WORD(Cntrl_Reg) = 0;
		AS_STRUCT(Cntrl_Reg).MV_PI_en = 1;
		AS_STRUCT(Cntrl_Reg).SV_PI_en = 1;
		AS_STRUCT(Cntrl_Reg).Err_PI_en = 1;
		WRR(xsp->regbase, CONTROL_REGISTER, AS_WORD(Cntrl_Reg));
		break;
	case PDC_SET_TIMER :
		dbgpdc("***** pdc_ioctl: cmd = PDC_SET_TIMER *****\n");
		parm.size = xsp->timer;
		xsp->timer = parm.data;
		break;
	case PDC_IOC_ALLOCB :
		dbgpdc("***** pdc_ioctl: cmd = PDC_IOC_ALLOCB, reqlen = 0x%lx\n", 
									(u_long)parm.size);
		if (parm.size <= 0){
			res = -EINVAL;
			parm.data = -1;
			parm.err_no = PDC_E_SIZE;
		}
		parm.data = init_mem(dip, &xsp->memd, parm.size);
		if (parm.data == -1) {
			res = -ENOMEM;
			parm.err_no = PDC_E_NOBUF;
			break;	
		}
		break;
	case PDC_IOC_FREEB:
		dbgpdc("***** pdc_ioctl: cmd = PDC_IOC_FREEB\n");
		free_mem(dip, &xsp->memd);
		break;

	case PDC_WRR:
		dbgpdc("***** pdc_ioctl: cmd = PDC_WRR\n");
		res = WRR(xsp->regbase, parm.size, parm.data);
		parm.err_no = res;
		break;
	case PDC_RDR:
		dbgpdc("***** pdc_ioctl: cmd = PDC_RDR\n");
		res = RDR(xsp->regbase, parm.size);
		parm.data = res;
		break;
	case PDC_IOC_ALLOCB_ALIGNED :
		dbgpdc("***** pdc_ioctl: cmd = PDC_IOC_ALLOCB_ALIGNED, reqlen = 0x%lx\n", 
									(u_long)parm.size);
		if (parm.size <= 0){
			res = -EINVAL;
			parm.data = -1;
			parm.err_no = PDC_E_SIZE;
			break;
		}

		i = parm.size / (((1 << 16) - 1 - 1023) * 4); /* size / 64512 * 4 bytes */
		if (i){
			i_size_bytes = (((1 << 16) - 1 - 1023) * 4);
		}

		size_bytes_from_user = parm.size % (((1 << 16) - 1 - 1023) * 4); 
		/* Выровним size_bytes до 1024 байт */
		size_bytes = (((size_bytes_from_user + 1023)/1024) * 1024);
		
		parm.size = ((i_size_bytes * i) + size_bytes);
		parm.data = init_mem(dip, &xsp->memd, parm.size);
		if (parm.data == -1) {
			res = -ENOMEM;
			parm.err_no = PDC_E_NOBUF;
			break;	
		}
		break;
	case PDC_WRITE_MORE_THAN_16BITS_SIZE:
		dbgpdc("\n***** PDC_WRITE_MORE_THAN_16BITS_SIZE START *****\n");

		dbgpdc("PDC_WRITE_MORE_THAN_16BITS_SIZE dev[inst] = %u[%u]\n", dev_num,instance);
		
		xsp = dip->soft_state;
		if (xsp == NULL) {
	     		printk("~%s~_write: unattached instance %d\n", board_name, instance);
		        return (-ENXIO);
		}
		if (parm.size <= 0){
			printk("~%s~_write: size parametr shold be > 0\n", board_name);
			return (-EINVAL);
		}
		save_dma_addr = xsp->memd.prim_dev_mem;
		dbgpdc("WRITE addr = 0x%lx\n", save_dma_addr);
		i = parm.size / (((1 << 16) - 1 - 1023) * 4); /* size / 64512 * 4 bytes */
		if (i){
			i_size_bytes = (((1 << 16) - 1 - 1023) * 4);
		}

		size_bytes_from_user = parm.size % (((1 << 16) - 1 - 1023) * 4); 
		/* Выровним size_bytes до 1024 байт */
		size_bytes = (((size_bytes_from_user + 1023)/1024) * 1024); 

		dbgpdc_wr("pdc_write: i_size_bytes = 0x%lx, i = %ld\n", (u_long)i_size_bytes, (u_long)i);
		dbgpdc_wr("pdc_write: size_bytes = 0x%lx\n", (u_long)size_bytes);
		dbgpdc_wr("pdc_write: size_bytes_from_user = 0x%lx\n", (u_long)size_bytes_from_user);
		dbgpdc_wr("pdc_write: size = 0x%lx\n", (u_long)parm.size);
		dbgpdc_wr("pdc_write: timer = 0x%lx\n", drv_usectohz(xsp->timer));

		while (i) {
			rw_init_device(&parm, i_size_bytes);	

			res = pdc_iocrw(dev, &parm, PDC_MB_TRANSMIT);
			if (res < 0){
				xsp->memd.prim_dev_mem = save_dma_addr;
				break;
			}
			if (parm.err_no){
				printk("WRITE: pdc_iocrw when buffer queue FAILED, "
				       "err_no = %s\n", 
					msg_by_code(parm.err_no, iocerrs, 17));
				result = result + parm.size;
				printk("WRITE: result = 0x%lx\n", (long)result);
				parm.size = result;
				xsp->memd.prim_dev_mem = save_dma_addr;
				break;
			}
			xsp->memd.prim_dev_mem = xsp->memd.prim_dev_mem + i_size_bytes;
			result = result + i_size_bytes;
			i--;
		}
		if (size_bytes) {
			rw_init_device(&parm, size_bytes);

			res = pdc_iocrw(dev, &parm, PDC_MB_TRANSMIT);
			if (res < 0){
				xsp->memd.prim_dev_mem = save_dma_addr;
				break;
			}
			if (parm.err_no){
				printk("WRITE: pdc_iocrw FAILED, err_no = %s\n", 
					msg_by_code(parm.err_no, iocerrs, 17));
				if (parm.size > size_bytes_from_user){
					result = result + size_bytes_from_user;
				}else{
					result = result + parm.size;
				}
				printk("WRITE: result = 0x%lx\n", (long)result);
				parm.size = result;
				xsp->memd.prim_dev_mem = save_dma_addr;
				break;
			}
			result = result + size_bytes_from_user;
		}
		parm.size = result;
		xsp->memd.prim_dev_mem = save_dma_addr;
		dbgpdc("***** PDC_WRITE_MORE_THAN_16BITS_SIZE SUCCESSFULLY FINISH *****\n");
		break;
	case PDC_READ_MORE_THAN_16BITS_SIZE:
		dbgpdc("\n***** PDC_READ_MORE_THAN_16BITS_SIZE START *****\n");

		dbgpdc("PDC_READ_MORE_THAN_16BITS_SIZE dev[inst] = %u[%u]\n", dev_num,instance);
		
		xsp = dip->soft_state;
		if (xsp == NULL) {
	     		printk("~%s~_read: unattached instance %d\n", board_name, instance);
		        return (-ENXIO);
		}
		if (parm.size <= 0){
			printk("~%s~_read: size parametr shold be > 0\n", board_name);
			return (-EINVAL);
		}
		save_dma_addr = xsp->memd.prim_dev_mem;
		dbgpdc("READ addr = 0x%lx\n", save_dma_addr);
		i = parm.size / (((1 << 16) - 1 - 1023) * 4); /* size / 64512 * 4 bytes */
		if (i){
			i_size_bytes = (((1 << 16) - 1 - 1023) * 4);
		}

		size_bytes_from_user = parm.size % (((1 << 16) - 1 - 1023) * 4); 
		/* Выровним size_bytes до 1024 байт */
		size_bytes = (((size_bytes_from_user + 1023)/1024) * 1024); 

		dbgpdc_rd("pdc_read: i_size_bytes = 0x%lx, i = %ld\n", (u_long)i_size_bytes, (u_long)i);
		dbgpdc_rd("pdc_read: size_bytes = 0x%lx\n", (u_long)size_bytes);
		dbgpdc_rd("pdc_read: size_bytes_from_user = 0x%lx\n", (u_long)size_bytes_from_user);
		dbgpdc_rd("pdc_read: size = 0x%lx\n", (u_long)parm.size);
		dbgpdc_rd("pdc_read: timer = 0x%lx\n", drv_usectohz(xsp->timer));

		while (i) {
			rw_init_device(&parm, i_size_bytes);	

			res = pdc_iocrw(dev, &parm, PDC_MB_RECIEVE);
			if (res < 0){
				xsp->memd.prim_dev_mem = save_dma_addr;
				break;
			}
			if (parm.err_no){
				printk("READ: pdc_iocrw when buffer queue FAILED, "
				       "err_no = %s\n", 
					msg_by_code(parm.err_no, iocerrs, 17));
				result = result + parm.size;
				printk("READ: result = 0x%lx\n", (long)result);
				parm.size = result;
				xsp->memd.prim_dev_mem = save_dma_addr;
				break;
			}
			xsp->memd.prim_dev_mem = xsp->memd.prim_dev_mem + i_size_bytes;
			result = result + i_size_bytes;
			i--;
		}
		if (size_bytes) {
			rw_init_device(&parm, size_bytes);

			res = pdc_iocrw(dev, &parm, PDC_MB_RECIEVE);
			if (res < 0){
				xsp->memd.prim_dev_mem = save_dma_addr;
				break;
			}
			if (parm.err_no){
				printk("READ: pdc_iocrw FAILED, err_no = %s\n", 
					msg_by_code(parm.err_no, iocerrs, 17));
				if (parm.size > size_bytes_from_user){
					result = result + size_bytes_from_user;
				}else{
					result = result + parm.size;
				}
				printk("READ: result = 0x%lx\n", (long)result);
				parm.size = result;
				xsp->memd.prim_dev_mem = save_dma_addr;
				break;
			}
			result = result + size_bytes_from_user;
		}
		parm.size = result;
		xsp->memd.prim_dev_mem = save_dma_addr;
		dbgpdc("***** PDC_READ_MORE_THAN_16BITS_SIZE SUCCESSFULLY FINISH *****\n");
		break;
	case PDC_MB_RECIEVE: /* Recieve data to the Master Buffer */
		dbgpdc("***** pdc_ioctl: cmd = PDC_MB_RECIEVE, reqlen = %lx\n", 
								(u_long)parm.size);
		res = pdc_iocrw(dev, &parm, PDC_MB_RECIEVE);
		break;
	case PDC_MB_TRANSMIT: /* Transmit the Master Buffer */
		dbgpdc("***** pdc_ioctl: cmd = PDC_MB_TRANSMIT, reqlen = %lx\n", 
								(u_long)parm.size);
		res = pdc_iocrw(dev, &parm, PDC_MB_TRANSMIT);
		break;
	case PDC_SB_RECIEVE: /* Recieve data to the Slave Buffer */
		dbgpdc("***** pdc_ioctl: cmd = PDC_SB_RECIEVE, reqlen = %lx\n", 
								(u_long)parm.size);
		res = pdc_iocrw(dev, &parm, PDC_SB_RECIEVE);
		break;
	case PDC_SB_TRANSMIT: /* Transmit the Slave Buffer */
		dbgpdc("***** pdc_ioctl: cmd = PDC_SB_TRANSMIT reqlen = %lx\n", 
								(u_long)parm.size);
		res = pdc_iocrw(dev, &parm, PDC_SB_TRANSMIT);
		break;

	case PDC_WAITING_RMI_MASTER:	/* Remove Interrupt waiting */
		dbgpdc("***** pdc_ioctl: cmd = PDC_WAITING_RMI_MASTER\n");
		res = pdc_iocrw(dev, &parm, PDC_WAITING_RMI_MASTER);
		break;
	case PDC_WAITING_RMI_SLAVE:	/* Remove Interrupt waiting */
		dbgpdc("***** pdc_ioctl: cmd = PDC_WAITING_RMI_SLAVE\n");
		res = pdc_iocrw(dev, &parm, PDC_WAITING_RMI_SLAVE);
		break;

	case PDC_SEND_PI:	/* Remove Interrupt (PI) Send */
		AS_WORD(Status_Reg) = 0;
		AS_STRUCT(Status_Reg).PI = 1;
		WRR(xsp->regbase, STATUS_REGISTER, AS_WORD(Status_Reg));
		break;
	case PDC_SEND_NMI:	/* Remove Interrupt (NMI) Send */
		AS_WORD(Status_Reg) = 0;
		AS_STRUCT(Status_Reg).NMI = 1;
		WRR(xsp->regbase, STATUS_REGISTER, AS_WORD(Status_Reg));
		break;

	case PDC_RESET:		/* Resetting PDC */
		Resetting(xsp);
		break;	

	case PDC_CLEAR_MASTER_TASK: /* Stopping Master task */
		clear_master_task_mu(xsp);
		break;
	case PDC_CLEAR_SLAVE_TASK: 
		clear_slave_task_mu(xsp); /* Stopping Slave task */
		break;

	case PDC_CLEAR_MTB:
		if (xsp -> stat & PDC_MB_TRANSMIT){
			parm.err_no = PDC_E_PENDING;
			break;
		}
		clear_master_transmit_buffer(xsp);
		break;
	case PDC_CLEAR_MRB:
		if (xsp -> stat & PDC_MB_RECIEVE){
			parm.err_no = PDC_E_PENDING;
			break;
		}
		clear_master_recieve_buffer(xsp);
		break;
	case PDC_CLEAR_STB:
		if (xsp -> stat & PDC_SB_TRANSMIT){
			parm.err_no = PDC_E_PENDING;
			break;
		}
		clear_slave_transmit_buffer(xsp);
		break;
	case PDC_CLEAR_SRB:
		if (xsp -> stat & PDC_SB_RECIEVE){
			parm.err_no = PDC_E_PENDING;
			break;
		}
		clear_slave_recieve_buffer(xsp);
		break;

	case PDC_CLEAR_LAST_INT: /* Clear last interrupt */
		if (xsp -> stat != 0){
			parm.err_no = PDC_E_PENDING;
			break;
		}
		xsp -> evs = 0;
	case PDC_SHOW_LAST_INT: /* Show last interrupt */
		if (xsp -> stat != 0){
			parm.err_no = PDC_E_PENDING;
			break;
		}
		parm.rwmode = xsp -> evs;
		break;

	default :	
		printk("default operation NOT EXPECTED\n");
		res = -EINVAL;
		parm.err_no = PDC_E_INVAL;
	}
	if (ddi_copyout((caddr_t)&parm, (caddr_t)arg,
		sizeof (pdc_ioc_parm_t)) == -1) {
		printk("pdc_ioctl: ddi_copyout failed\n"); 
		return (-EINVAL);
	}	
	if (res == 0) {
		dbgpdc("***** %u: pdc_ioctl: NORMAL_END: size=%lx *****\n\n", 
				instance, (u_long)parm.size);
		return 0;
	}
		dbgpdc("***** %u: pdc_ioctl: ERR_END: size=%lx err[%d]=%s *****\n\n", 
			instance, (u_long)parm.size, parm.err_no,
			msg_by_code(parm.err_no, &iocerrs[0], 
				     sizeof(iocerrs) / sizeof(code_msg_t)
				)
		);
			
	return res; 	
}

static	uint_t
pdc_chpoll(struct file *file, struct poll_table_struct *wait)
{
	dev_info_t 		*dip;
	dev_t			dev;
	struct pdc_state	*xsp;
	int			dev_num;
	int			instance;

	dev = ddi_file_dev(file);
	dip = ddi_file_dip(file);
	if (!dip || !dev) return (-ENXIO);
	xsp = (pdc_state_t *)dip->soft_state;
	if (xsp == NULL) return (-ENXIO);
	dev_num = DEV_DEVN(dev);
	instance = DEV_inst(dev_num);
	
	printk("pdc_chpoll isn't emplemented\n");
	return (0);
}


/* Interrupt handler  */

irqreturn_t
pdc_intr(int irq, void *arg, struct pt_regs *regs) 
{
	register	dev_info_t     	*dip;
	register struct pdc_state 	*xsp;
	register unsigned int 		evs = 0;
	Status_Reg_t			Status_Reg;
#if PDC_INT_TRACE
	int             		instance;
#endif
	dbgpdcdetail("\n***** pdc_intr START *****\n");

	if (arg == NULL) {
		printk("pdc_intr: arg == NULL\n");
		return IRQ_NONE;
	}

	AS_WORD(Status_Reg) = 0;
	dip = (dev_info_t *)arg;
	xsp = (pdc_state_t *)dip->soft_state;

	spin_lock(&xsp->lock);

	evs = RDR(xsp->regbase, STATUS_REGISTER) ; /* read ints */
	if (evs == 0){
		spin_unlock(&xsp->lock); 
		return IRQ_NONE;
	}

	WRR(xsp->regbase, STATUS_REGISTER, AS_WORD(Status_Reg)); /* clear ints */
	
	xsp -> evs = evs;
	
#if PDC_INT_TRACE
	instance = xsp->instance;
	printk("***** pdc_intr[ins=%u]: REG_INTRS=0x%x *****\n",
		instance, evs);
	prt_evs(instance, evs);
#endif
	
	if ((AS_STRUCT(((Status_Reg_t)evs)).PI_Src_Err) != 0 || (AS_STRUCT(((Status_Reg_t)evs)).PI_Src_Rm) != 0) {
		if (xsp->stat & PDC_MB_TRANSMIT || xsp->stat & PDC_MB_RECIEVE){
			clear_master_task(xsp);
			cv_signal(&xsp->cv_master);
		}
		if (xsp->stat & PDC_SB_TRANSMIT || xsp->stat & PDC_SB_RECIEVE){
			clear_slave_task(xsp);
		}
		if (xsp->stat & PDC_WAITING_RMI_MASTER) 
			cv_signal(&xsp->cv_rmi_master);
		if (xsp->stat & PDC_WAITING_RMI_SLAVE) 
			cv_signal(&xsp->cv_rmi_slave);
	}else{ 
		if ((AS_STRUCT(((Status_Reg_t)evs)).PI_Src_MV) != 0){
			cv_signal(&xsp->cv_master);
		}
	}/* endif PI_Src_Err, PI_Src_Rm */

#if PDC_INT_TRACE
	if ((AS_STRUCT(((Status_Reg_t)evs)).NMI_Src_MV) != 0){
                        printk("***** pdc_intr: NMI Recieved *****\n");
	}
	printk("***** pdc_intr: FINISH, evs = 0x%x *****\n\n", evs);
#endif /* PDC_INT_TRACE */	

	spin_unlock(&xsp->lock);
	return IRQ_HANDLED;;  /* forces INT_PDC cycle */
/**********************/
}

static 
int pdc_mmap(struct file *file, struct vm_area_struct *vma) {
	int			rval;
	dev_info_t 		*dip;
	dev_t			dev;
	struct pdc_state	*xsp;
	dma_mem_t * 		memd;

	dbgpdc("***** pdc_mmap START *****\n");
	
	dev = ddi_file_dev(file);
	dip = ddi_file_dip(file);
	if (!dip || !dev) return (-ENXIO);
	xsp = (pdc_state_t *)dip->soft_state;
	if (xsp == NULL) return (-ENXIO);

	memd = &xsp->memd;
	spin_mutex_enter(&xsp->lock);
	vma->vm_flags |= (VM_IO | VM_SHM | VM_LOCKED | VM_READ | VM_WRITE );
	rval = ddi_remap_page(memd->buf_addr, memd->real_size, vma);
	spin_mutex_exit(&xsp->lock);
	if (rval) {
		dbgpdc(" ***** pdc_mmap WRONGLY finish *****\n");
		return -EAGAIN;
	}
	dbgpdc("***** pdc_mmap NORMALY finish *****\n");
	return (0);

}

int 
pdc_iocrw(dev_t dev,  pdc_ioc_parm_t * parm, int kop) 
{
	pdc_state_t	*xsp = NULL;
	int		dev_num  = DEV_DEVN(dev);
	int		instance = DEV_inst(dev_num);
	clock_t		tick;
	ulong		cur_clock;	
	dma_addr_t	addr_dma;
	size_t 		Ssize_trans = 0;
	size_t		Msize_trans = 0;
	dma_mem_t 	*memd;
	dev_info_t	*dip;

	int res = 0;
	int rwmode = parm->rwmode;
	void *user_buffer = NULL;
	int *i		= NULL;	

 	Control_Reg_t Cntrl_Reg;
	Master_Control_Reg_t M_Cntrl_Reg;
	Master_Address_Reg_t MAddress;
	Slave_Control_Reg_t S_Cntrl_Reg;
	Slave_Data_Reg_t SData;

	dbgpdc("**** pdc_iocrw START. kop = %d ****\n", kop);
	dip = (dev_info_t *)ddi_dev_dip(dev);
	xsp = (pdc_state_t *)dip->soft_state;
	if (xsp == NULL){
		printk("%s: bad instance %d\n",
			 board_name, instance);
		return (-ENXIO);
	}

	memd = &xsp->memd;

	addr_dma = memd->prim_dev_mem; /* Здесь prim_dev_mem - адресс со стороны устройства */

	switch (kop) {

	case PDC_MB_TRANSMIT:
		dbgpdc("**** pdc_iocrw: kop = PDC_MB_TRANSMIT\n");	

		spin_mutex_enter(&xsp->lock);

		parm->err_no = 0;
		parm->data   = 0;
		/* идет обмен */
		if (xsp->stat & PDC_MB_TRANSMIT || xsp->stat & PDC_MB_RECIEVE) { 			
			if (rwmode == PDC_CHECK) {
				parm->err_no = PDC_BUSY;
				parm->rwmode = xsp->stat;
				parm->size   = 0;		
				goto mux_exit;
			}
			
			parm->err_no = PDC_E_PENDING;
			parm->rwmode = xsp->stat;
			parm->size   = 0;
			goto mux_exit;
		}

		/* Проверка канала */
		if (rwmode == PDC_CHECK) {
			parm->err_no = PDC_NOTRUN;
			parm->rwmode = 0;
			parm->size   = 0;
			goto mux_exit;
		}

		if (parm->size < 0){
			dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, EINVAL\n");
			parm->err_no = PDC_E_SIZE;
			parm->rwmode = PDC_MB_TRANSMIT;
			res = (-EINVAL);
			goto mux_exit;	
		}
		Msize_trans = parm->size; /* bytes */
	
		Msize_trans = Msize_trans/4; /* words, 4 bytes */
	
		if ((parm->size)%4)
			Msize_trans += 1; /* Align */
	
		if ((Msize_trans * 4) > memd->real_size){
			Msize_trans = memd->real_size;
			Msize_trans = Msize_trans/4;
		}
		dbgpdc_wr("pdc_iocrw[%d]: PDC_MB_TRANSMIT, Msize_trans = %ld, "
			  "addr_dma = 0x%lx, (u32)Msize_trans = %d\n", 
			instance, (u_long)Msize_trans, addr_dma, (u32)Msize_trans);
		if (!addr_dma) {
			dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, ENOMEM\n");
			parm->err_no = PDC_E_INIT_MEM;
			parm->rwmode = PDC_MB_TRANSMIT;
			parm->size   = 0;
			res = (-ENOMEM);
			goto mux_exit;	
		}

		xsp->stat |= PDC_MB_TRANSMIT;

		AS_STRUCT(MAddress).MAddress = 	addr_dma;
		AS_STRUCT(M_Cntrl_Reg).MSize = (u32)Msize_trans;
		AS_STRUCT(M_Cntrl_Reg).MCmd = 0x6; /* Чтение */
		AS_STRUCT(M_Cntrl_Reg).MV = 1;

		WRR(xsp->regbase, MASTER_ADDRESS_REGISTER, AS_WORD(MAddress));

		if (AS_STRUCT(((Status_Reg_t)(xsp->evs))).Err) {
			dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, в системе"
			       "	   зарегистрировано прерывание Err\n");
			parm->err_no = PDC_E_ERTRANS;
			parm->rwmode = xsp->evs;
			parm->size = mb_calculate_size(xsp,Msize_trans);
			xsp->stat &=~ PDC_MB_TRANSMIT;
			goto mux_exit;
		}
		if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
			dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, в системе"
			       "	   зарегистрировано удаленное прерывание Rm\n");
			parm->err_no = PDC_RMI;
			parm->rwmode = xsp->evs;
			parm->size = mb_calculate_size(xsp,Msize_trans);
			xsp->stat &=~ PDC_MB_TRANSMIT;
			goto mux_exit;
		}
		/* Запуск Мастер */
		WRR(xsp->regbase, MASTER_CONTROL_REGISTER, AS_WORD(M_Cntrl_Reg)); 
		AS_WORD(Cntrl_Reg) = RDR(xsp->regbase, CONTROL_REGISTER);

		if (AS_STRUCT(Cntrl_Reg).MV_PI_en) { /* Interrupt enable */
		/* Waiting */
			drv_getparm(LBOLT, &cur_clock);
			dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT drv_usectohz(xsp->timer) = 0x%lx, timer = 0x%lx\n", 
					drv_usectohz(xsp->timer), xsp->timer);
			tick = (clock_t)cur_clock + drv_usectohz(xsp->timer);
			if (cv_spin_timedwait(&xsp->cv_master, &xsp->lock, tick) < 0) {
				dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, выход по таймеру или сигналу\n");
				clear_master_task(xsp);	
				ddi_dma_sync(dip, addr_dma, (Msize_trans*4), PCI_DMA_TODEVICE);
				parm->err_no = PDC_E_TIMER;
				if (signal_pending(current)) {
			                parm->err_no = PDC_SIGNAL;
			        }
				parm->rwmode = PDC_MB_TRANSMIT;
				parm->size = mb_calculate_size(xsp,Msize_trans); 
				xsp->stat &=~ PDC_MB_TRANSMIT;
				goto mux_exit;
			}
			ddi_dma_sync(dip, addr_dma, (Msize_trans*4), PCI_DMA_TODEVICE);
			parm->rwmode = xsp->evs;
			parm->size = mb_calculate_size(xsp,Msize_trans);
			xsp->stat &=~ PDC_MB_TRANSMIT;

			if(xsp->clear_on_master){
				dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, в системе"
				       "	   зарегистрировано clear_master_task_mu()\n");
				goto mux_exit;
			}

			if (AS_STRUCT(((Status_Reg_t)parm->rwmode)).PI_Src_Err) {
				dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, выход по Err\n");
				parm->err_no = PDC_E_ERTRANS;
				goto mux_exit;
			}
			if (AS_STRUCT(((Status_Reg_t)parm->rwmode)).PI_Src_Rm) {
				dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, выход по Rm\n");
				parm->err_no = PDC_RMI;
				goto mux_exit;
			}
			dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, получено PI_Src_MV\n");
	
		}else {
			while ((parm->size = mb_calculate_size(xsp,Msize_trans)) != Msize_trans){

				if (cv_spin_wait(&xsp->cv_master, &xsp->lock) == -1) {
					dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, выход по сигналу\n");
					clear_master_task(xsp);
					parm->err_no = PDC_SIGNAL;
					parm->rwmode = PDC_MB_TRANSMIT;
					parm->size = mb_calculate_size(xsp,Msize_trans); 
					xsp->stat &=~ PDC_MB_TRANSMIT;
					goto mux_exit;
				}

				if (xsp->clear_on_master) {
					dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, в системе"
					       "	   зарегистрировано clear_master_task_mu()\n");
					parm->rwmode = xsp->evs;
					xsp->stat &=~ PDC_MB_TRANSMIT;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Err) {
					dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, выход по Err\n");
					parm->rwmode = xsp->evs;
					parm->err_no = PDC_E_ERTRANS;
					xsp->stat &=~ PDC_MB_TRANSMIT;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
					dbgpdc("pdc_iocrw: PDC_MB_TRANSMIT, выход по Rm\n");
					parm->rwmode = xsp->evs;
					parm->err_no = PDC_RMI;
					xsp->stat &=~ PDC_MB_TRANSMIT;
					goto mux_exit;
				}
			}
			xsp->stat &=~ PDC_MB_TRANSMIT;
		}
		
		res = 0;
		break;	
	
	case PDC_MB_RECIEVE:
		dbgpdc("**** pdc_iocrw: kop = PDC_MB_RECIEVE\n");	

		spin_mutex_enter(&xsp->lock);

		parm->err_no = 0;
		parm->data   = 0;
		/* идет обмен */
		if (xsp->stat & PDC_MB_TRANSMIT || xsp->stat & PDC_MB_RECIEVE) { 			
			if (rwmode == PDC_CHECK) {
				parm->err_no = PDC_BUSY;
				parm->rwmode = xsp->stat;
				parm->size   = 0;		
				goto mux_exit;
			}
			
			parm->err_no = PDC_E_PENDING;
			parm->rwmode = xsp->stat;
			parm->size   = 0;
			goto mux_exit;
		}

		/* Проверка канала */
		if (rwmode == PDC_CHECK) {
			parm->err_no = PDC_NOTRUN;
			parm->rwmode = 0;
			parm->size   = 0;
			goto mux_exit;
		}

		if (parm->size < 0){
			dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, EINVAL\n");
			parm->err_no = PDC_E_SIZE;
			parm->rwmode = PDC_MB_RECIEVE;
			res = (-EINVAL);
			goto mux_exit;	
		}

		Msize_trans = parm->size; /* bytes */
	
		Msize_trans = Msize_trans/4; /* words, 4 bytes */
	
		if ((parm->size)%4)
			Msize_trans += 1; /* Align */
	
		if ((Msize_trans * 4) > memd->real_size){
			Msize_trans = memd->real_size;
			Msize_trans = Msize_trans/4;
		}
		dbgpdc_rd("pdc_iocrw[%d]: PDC_MB_RECIEVE, Msize_trans = %ld, "
			  "addr_dma = 0x%lx, (u32)Msize_trans = %d\n", 
				instance, (u_long)Msize_trans, addr_dma, (u32)Msize_trans);
		if (!addr_dma) {
			dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, ENOMEM\n");
			parm->err_no = PDC_E_INIT_MEM;
			parm->rwmode = PDC_MB_RECIEVE;
			parm->size   = 0;
			res = (-ENOMEM);
			goto mux_exit;	
		}

		xsp->stat |= PDC_MB_RECIEVE;

		AS_STRUCT(MAddress).MAddress = 	addr_dma;
		AS_STRUCT(M_Cntrl_Reg).MSize = (u32)Msize_trans;
		AS_STRUCT(M_Cntrl_Reg).MCmd = 0x7; /* запись */
		AS_STRUCT(M_Cntrl_Reg).MV = 1;

		WRR(xsp->regbase, MASTER_ADDRESS_REGISTER, AS_WORD(MAddress));

		if (AS_STRUCT(((Status_Reg_t)xsp->evs)).Err) {
			dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, в системе"
			       "	   зарегистрировано прерывание Err\n");
			parm->err_no = PDC_E_ERTRANS;
			parm->rwmode = xsp->evs;
			parm->size = mb_calculate_size(xsp,Msize_trans);
			xsp->stat &=~ PDC_MB_RECIEVE;
			goto mux_exit;
		}
		if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
			dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, в системе"
			       "	   зарегистрировано удаленное прерывание Rm\n");
			parm->err_no = PDC_RMI;
			parm->rwmode = xsp->evs;
			parm->size = mb_calculate_size(xsp,Msize_trans);
			xsp->stat &=~ PDC_MB_RECIEVE;
			goto mux_exit;
		}
		/* Запуск Мастер */
		WRR(xsp->regbase, MASTER_CONTROL_REGISTER, AS_WORD(M_Cntrl_Reg)); 
		AS_WORD(Cntrl_Reg) = RDR(xsp->regbase, CONTROL_REGISTER);

		if (AS_STRUCT(Cntrl_Reg).MV_PI_en) { /* Interrupt enable */
		/* Waiting */
		drv_getparm(LBOLT, &cur_clock);
			dbgpdc("pdc_iocrw: PDC_MB_RECIEVE drv_usectohz(xsp->timer) = 0x%lx, timer = 0x%lx\n", 
					drv_usectohz(xsp->timer), xsp->timer);
			tick = (clock_t)cur_clock + drv_usectohz(xsp->timer);
			if (cv_spin_timedwait(&xsp->cv_master, &xsp->lock, tick) < 0) {
				dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, выход по таймеру или сигналу\n");
				clear_master_task(xsp);
				ddi_dma_sync(dip, addr_dma, (Msize_trans*4), PCI_DMA_TODEVICE);
				parm->err_no = PDC_E_TIMER;
				if (signal_pending(current)) {
			                parm->err_no = PDC_SIGNAL;
			        }
				parm->rwmode = PDC_MB_RECIEVE;
				parm->size = mb_calculate_size(xsp,Msize_trans); 
				xsp->stat &=~ PDC_MB_RECIEVE;
				goto mux_exit;
			}
			ddi_dma_sync(dip, addr_dma, (Msize_trans*4), PCI_DMA_TODEVICE);
			parm->rwmode = xsp->evs;
			parm->size = mb_calculate_size(xsp,Msize_trans);
			xsp->stat &=~ PDC_MB_RECIEVE;			

			if(xsp->clear_on_master){
				dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, в системе"
				       "	   зарегистрировано clear_master_task_mu()\n");
				goto mux_exit;
			}

			if (AS_STRUCT(((Status_Reg_t)parm->rwmode)).PI_Src_Err) {
				dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, выход по Err\n");
				parm->err_no = PDC_E_ERTRANS;
				goto mux_exit;
			}
			if (AS_STRUCT(((Status_Reg_t)parm->rwmode)).PI_Src_Rm) {
				dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, выход по Rm\n");
				parm->err_no = PDC_RMI;
				goto mux_exit;
			}
			dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, получено PI_Src_MV\n");
	
		}else{
			while ((parm->size = mb_calculate_size(xsp,Msize_trans)) != Msize_trans){

				if (cv_spin_wait(&xsp->cv_master, &xsp->lock) == -1) {
					dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, выход по сигналу\n");
					clear_master_task(xsp);
					parm->err_no = PDC_SIGNAL;
					parm->rwmode = PDC_MB_RECIEVE;
					parm->size = mb_calculate_size(xsp,Msize_trans); 
					xsp->stat &=~ PDC_MB_RECIEVE;
					goto mux_exit;
				}

				if (xsp->clear_on_master) {
					dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, в системе"
					       "	   зарегистрировано clear_master_task_mu()\n");
					parm->rwmode = xsp->evs;
					xsp->stat &=~ PDC_MB_RECIEVE;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Err) {
					dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, выход по Err\n");
					parm->rwmode = xsp->evs;	
					parm->err_no = PDC_E_ERTRANS;
					xsp->stat &=~ PDC_MB_RECIEVE;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
					dbgpdc("pdc_iocrw: PDC_MB_RECIEVE, выход по Rm\n");
					parm->rwmode = xsp->evs;
					parm->err_no = PDC_RMI;
					xsp->stat &=~ PDC_MB_RECIEVE;
					goto mux_exit;
				}
			}
			xsp->stat &=~ PDC_MB_RECIEVE;
		}
		
		res = 0;
		break;

	case PDC_WAITING_RMI_MASTER:		/* Ожидание прерывания RMI */
		dbgpdc("**** pdc_iocrw: kop = PDC_WAITING_RMI_MASTER\n");
		spin_mutex_enter(&xsp->lock);

		parm->err_no = 0;
		parm->size   = 0;
		parm->data   = 0;
		
		if (xsp->stat & PDC_WAITING_RMI_MASTER){
			parm->err_no = PDC_E_ALREADY_WAIT;
			parm->rwmode = PDC_WAITING_RMI_MASTER;
			goto mux_exit;
		}
		xsp->stat |= PDC_WAITING_RMI_MASTER;

		if (AS_STRUCT(((Status_Reg_t)xsp->evs)).Err) {
			dbgpdc("pdc_iocrw: PDC_WAITING_RMI_MASTER, выход по Err\n");
			parm->err_no = PDC_E_ERWAIT;
			parm->rwmode = xsp->evs;
			xsp->stat &=~ PDC_WAITING_RMI_MASTER;
			goto mux_exit;
		}
		if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
			parm->rwmode = xsp->evs;
			xsp->stat &=~ PDC_WAITING_RMI_MASTER;
			goto mux_exit;
		}
		/* Waiting */
		drv_getparm(LBOLT, &cur_clock);
		tick = (clock_t)cur_clock + drv_usectohz(xsp->timer);
		if (cv_spin_timedwait(&xsp->cv_rmi_master, &xsp->lock, tick) < 0) {
			dbgpdc("pdc_iocrw: PDC_WAITING_RMI_MASTER, выход по таймеру или сигналу\n");
			parm->err_no = PDC_E_TIMER;
			xsp->stat &=~ PDC_WAITING_RMI_MASTER;
			if (signal_pending(current)) {
				parm->err_no = PDC_SIGNAL;
			}
			parm->rwmode = PDC_WAITING_RMI_MASTER;
			goto mux_exit;
		}

		parm->rwmode = xsp->evs;
		xsp->stat &=~ PDC_WAITING_RMI_MASTER;

		if (AS_STRUCT(((Status_Reg_t)parm->rwmode)).Err) {
			dbgpdc("pdc_iocrw: PDC_WAITING_RMI_MASTER, выход по Err\n");
			parm->err_no = PDC_E_ERWAIT;
			goto mux_exit;
		}
		break;

	case PDC_WAITING_RMI_SLAVE:		/* Ожидание прерывания RMI */
		dbgpdc("**** pdc_iocrw: kop = PDC_WAITING_RMI_SLAVE\n");
		spin_mutex_enter(&xsp->lock);

		parm->err_no = 0;
		parm->size   = 0;
		parm->data   = 0;
		
		if (xsp->stat & PDC_WAITING_RMI_SLAVE){
			parm->err_no = PDC_E_ALREADY_WAIT;
			parm->rwmode = PDC_WAITING_RMI_SLAVE;
			goto mux_exit;
		}
		xsp->stat |= PDC_WAITING_RMI_SLAVE;

		if (AS_STRUCT(((Status_Reg_t)xsp->evs)).Err) {
			dbgpdc("pdc_iocrw: PDC_WAITING_RMI_SLAVE, выход по Err\n");
			parm->err_no = PDC_E_ERWAIT;
			parm->rwmode = xsp->evs;
			xsp->stat &=~ PDC_WAITING_RMI_SLAVE;
			goto mux_exit;
		}
		if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
			parm->rwmode = xsp->evs;
			xsp->stat &=~ PDC_WAITING_RMI_SLAVE;
			goto mux_exit;
		}
		/* Waiting */
		drv_getparm(LBOLT, &cur_clock);
		tick = (clock_t)cur_clock + drv_usectohz(xsp->timer);
		if (cv_spin_timedwait(&xsp->cv_rmi_slave, &xsp->lock, tick) < 0) {
			dbgpdc("pdc_iocrw: PDC_WAITING_RMI_SLAVE, выход по таймеру или сигналу\n");
			parm->err_no = PDC_E_TIMER;
			xsp->stat &=~ PDC_WAITING_RMI_SLAVE;
			if (signal_pending(current)) {
				parm->err_no = PDC_SIGNAL;
			}
			parm->rwmode = PDC_WAITING_RMI_SLAVE;
			goto mux_exit;
		}

		parm->rwmode = xsp->evs;
		xsp->stat &=~ PDC_WAITING_RMI_SLAVE;

		if (AS_STRUCT(((Status_Reg_t)parm->rwmode)).Err) {
			dbgpdc("pdc_iocrw: PDC_WAITING_RMI_SLAVE, выход по Err\n");
			parm->err_no = PDC_E_ERWAIT;
			goto mux_exit;
		}
		break;

	case PDC_SB_TRANSMIT:   /* Передача данных  */
		dbgpdc("**** pdc_iocrw: kop = PDC_SB_TRANSMIT\n");	

		spin_mutex_enter(&xsp->lock);

		parm->err_no = 0;

		/* идет обмен */
		if (xsp->stat & PDC_SB_TRANSMIT || xsp->stat & PDC_SB_RECIEVE) { 			
			if (rwmode == PDC_CHECK) {
				parm->err_no = PDC_BUSY;
				parm->rwmode = xsp->stat;
				parm->data   = 0;
				parm->size   = 0;		
				goto mux_exit;
			}
			
			parm->err_no = PDC_E_PENDING;
			parm->rwmode = xsp->stat;
			parm->data   = 0;
			parm->size   = 0;
			goto mux_exit;
		}

		/* Проверка канала */
		if (rwmode == PDC_CHECK) {
			parm->err_no = PDC_NOTRUN;
			parm->rwmode = 0;
			parm->data   = 0;
			parm->size   = 0;
			goto mux_exit;
		}
/* Передача буфера пользователя */
		if (rwmode == PDC_USER_BUFFER) {
			if (parm->size <= 0) {
				dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, EINVAL\n");
				parm->err_no = PDC_E_SIZE;
				parm->rwmode = PDC_SB_TRANSMIT;
				res = (-EINVAL);
				goto mux_exit;
			}
			Ssize_trans = parm->size; /* bytes */
			Ssize_trans = Ssize_trans/4; /* words, 4 bytes */
			if ((parm->size)%4)
				Ssize_trans += 1; /* Align */
			user_buffer = kmalloc((Ssize_trans*4), GFP_KERNEL);
			if (!user_buffer) {
				dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, ENOMEM\n");
				parm->err_no = PDC_E_MEMORY_ALLOC;
				parm->rwmode = PDC_SB_TRANSMIT;
				parm->size   = 0;
				res = (-ENOMEM);
				goto mux_exit;	
			}
			if ((res = ddi_copyin((void *)parm->data, user_buffer, parm->size)) != 0){
				dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, copy_from_user error\n");
				parm->err_no = PDC_E_DDI_COPYIN;
				parm->rwmode = PDC_SB_TRANSMIT;
				parm->size   = 0;
				goto mux_exit;
			}

			AS_STRUCT(S_Cntrl_Reg).SSize = Ssize_trans;
			AS_STRUCT(S_Cntrl_Reg).SDir = 0x0; /* Передача */
			AS_STRUCT(S_Cntrl_Reg).SV = 1;
			
			xsp -> stat |= PDC_SB_TRANSMIT;
			/* Активизация Slave */
			WRR(xsp->regbase, SLAVE_CONTROL_REGISTER, AS_WORD(S_Cntrl_Reg));

			for (i = user_buffer; i != (int *)user_buffer + Ssize_trans; i++){
				AS_WORD(SData) = *i;
			
				if (xsp->clear_on_slave) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, в системе"
					       "	   зарегистрировано clear_slave_task_mu()\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}

				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).Err) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, в системе"
					       "	   зарегистрировано прерывание Err\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					parm->err_no = PDC_E_ERTRANS;
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, в системе"
					       "	   зарегистрировано удаленное прерывание Rm\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					parm->err_no = PDC_RMI;
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
				/* Запуск Slave */
				WRR(xsp->regbase, SLAVE_DATA_REGISTER, AS_WORD(SData));
				if (cv_spin_wait(&xsp->cv_slave, &xsp->lock) == -1) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, выход по сигналу\n");
					clear_slave_task(xsp);
					parm->err_no = PDC_SIGNAL;
					parm->rwmode = PDC_SB_TRANSMIT;
					parm->size = sb_calculate_size(xsp,Ssize_trans); 
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
			}
			
			while (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_SV != 1 || 
					sb_calculate_size(xsp,Ssize_trans) != Ssize_trans) {
				
				if (xsp->clear_on_slave) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, в системе"
					       "	   зарегистрировано clear_slave_task_mu()\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).Err) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, выход по Err\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					parm->err_no = PDC_E_ERTRANS;
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, выход по Rm\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					parm->err_no = PDC_RMI;
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
				
				if (cv_spin_wait(&xsp->cv_slave, &xsp->lock) == -1) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_BUFFER, выход по сигналу\n");
					clear_slave_task(xsp);
					parm->err_no = PDC_SIGNAL;
					parm->rwmode = PDC_SB_TRANSMIT;
					parm->size = sb_calculate_size(xsp,Ssize_trans); 
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
			}
			parm->size = sb_calculate_size(xsp,Ssize_trans);
		}
/* передача 32 бит данных */
		if (rwmode == PDC_USER_DATA) {
			AS_STRUCT(S_Cntrl_Reg).SSize = 1;
			AS_STRUCT(S_Cntrl_Reg).SDir = 0x0; /* Передача */
			AS_STRUCT(S_Cntrl_Reg).SV = 1;
			
			xsp -> stat |= PDC_SB_TRANSMIT;
			/* Активизация Slave */
			WRR(xsp->regbase, SLAVE_CONTROL_REGISTER, AS_WORD(S_Cntrl_Reg));

			AS_WORD(SData) = parm -> data;
			
			if (AS_STRUCT(((Status_Reg_t)xsp->evs)).Err) {
				dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_DATA, В системе зарегистрировано"
				       " 	   прерывание Err\n");
				parm->err_no = PDC_E_ERTRANS;
				parm->rwmode = xsp->evs;
				parm->size = sb_calculate_size(xsp,1);
				xsp->stat &=~ PDC_SB_TRANSMIT;
				goto mux_exit;
			}
			if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
				dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_DATA, В системе зарегистрировано"
				       "	   удаленное прерывание Rm\n");
				parm->err_no = PDC_RMI;
				parm->rwmode = xsp->evs;
				parm->size = sb_calculate_size(xsp,1);
				xsp->stat &=~ PDC_SB_TRANSMIT;
				goto mux_exit;
			}
			
			/* Запуск Slave */
			WRR(xsp->regbase, SLAVE_DATA_REGISTER, AS_WORD(SData));
			while (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_SV != 1 || 
					sb_calculate_size(xsp,1) != 1) {
				if (xsp->clear_on_slave) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_DATA, в системе"
					       "	   зарегистрировано clear_slave_task_mu()\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,1);
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)parm->rwmode)).Err) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_DATA, выход по Err\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,1);
					parm->err_no = PDC_E_ERTRANS;
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)parm->rwmode)).PI_Src_Rm) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_DATA, выход по Rm\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,1);
					parm->err_no = PDC_RMI;
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
				if (cv_spin_wait(&xsp->cv_slave, &xsp->lock) == -1) {
					dbgpdc("pdc_iocrw: PDC_SB_TRANSMIT, rwmode = PDC_USER_DATA, выход по сигналу\n");
					clear_slave_task(xsp);
					parm->err_no = PDC_SIGNAL;
					parm->rwmode = PDC_SB_TRANSMIT;
					parm->size = sb_calculate_size(xsp,1); 
					xsp->stat &=~ PDC_SB_TRANSMIT;
					goto mux_exit;
				}
			}
			parm->size = sb_calculate_size(xsp,1);
		}

		parm->rwmode = xsp->evs;
		clear_slave_transmit_buffer(xsp); /* Очистка буфера */
		xsp->stat &=~ PDC_SB_TRANSMIT;

		res = 0;
		break;

	case PDC_SB_RECIEVE:
		dbgpdc("**** pdc_iocrw: kop = PDC_SB_RECIEVE\n");	

		spin_mutex_enter(&xsp->lock);

		parm->err_no = 0;

		/* идет обмен */
		if (xsp->stat & PDC_SB_TRANSMIT || xsp->stat & PDC_SB_RECIEVE) { 			
			if (rwmode == PDC_CHECK) {
				parm->err_no = PDC_BUSY;
				parm->rwmode = xsp->stat;
				parm->data   = 0;
				parm->size   = 0;		
				goto mux_exit;
			}
			
			parm->err_no = PDC_E_PENDING;
			parm->rwmode = xsp->stat;
			parm->data   = 0;
			parm->size   = 0;
			goto mux_exit;
		}

		/* Проверка канала */
		if (rwmode == PDC_CHECK) {
			parm->err_no = PDC_NOTRUN;
			parm->rwmode = 0;
			parm->data   = 0;
			parm->size   = 0;
			goto mux_exit;
		}
/* Прием в буфер пользователя */
		if (rwmode == PDC_USER_BUFFER) {
			if (parm->size <= 0) {
				dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER, EINVAL\n");
				parm->err_no = PDC_E_SIZE;
				parm->rwmode = PDC_SB_RECIEVE;
				res = (-EINVAL);
				goto mux_exit;
			}
			Ssize_trans = parm->size; /* bytes */
			Ssize_trans = Ssize_trans/4; /* words, 4 bytes */
			if ((parm->size)%4)
				Ssize_trans += 1; /* Align */
			user_buffer = kmalloc((Ssize_trans*4), GFP_KERNEL);
			if (!user_buffer) {
				dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER, ENOMEM\n");
				parm->err_no = PDC_E_MEMORY_ALLOC;
				parm->rwmode = PDC_SB_RECIEVE;
				parm->size   = 0;
				res = (-ENOMEM);
				goto mux_exit;	
			}

			AS_STRUCT(S_Cntrl_Reg).SSize = Ssize_trans;
			AS_STRUCT(S_Cntrl_Reg).SDir = 0x1; /* Прием */
			AS_STRUCT(S_Cntrl_Reg).SV = 1;
			
			xsp -> stat |= PDC_SB_RECIEVE;
			/* Активизация Slave */
			WRR(xsp->regbase, SLAVE_CONTROL_REGISTER, AS_WORD(S_Cntrl_Reg));

			for (i = user_buffer; i != (int *)user_buffer + Ssize_trans; i++){
again:
				if (xsp->clear_on_slave) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER, в системе"
					       "	   зарегистрировано clear_slave_task()\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					if ((res = ddi_copyout(user_buffer, (caddr_t)parm->data, parm->size)) != 0){
						dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER,"
						       "           copy_to_user error\n");
						parm->err_no |= PDC_E_DDI_COPYOUT;
					}
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).Err) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER, в системе"
					       "	   зарегистрировано прерывание Err\n");
					parm->err_no = PDC_E_ERTRANS;
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					if ((res = ddi_copyout(user_buffer, (caddr_t)parm->data, parm->size)) != 0){
						dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER,"
						       "	   copy_to_user error\n");
						parm->err_no |= PDC_E_DDI_COPYOUT;
					}
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER, в системе"
					       "	   зарегистрировано удаленное прерывание Rm\n");
					parm->err_no = PDC_RMI;
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					if ((res = ddi_copyout(user_buffer, (caddr_t)parm->data, parm->size)) != 0){
						dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER,"
						       "           copy_to_user error\n");
						parm->err_no |= PDC_E_DDI_COPYOUT;
					}
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				if (cv_spin_wait(&xsp->cv_slave, &xsp->lock) == -1) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER, выход по сигналу\n");
					clear_slave_task(xsp);
					parm->err_no = PDC_SIGNAL;
					parm->rwmode = PDC_SB_RECIEVE;
					parm->size = sb_calculate_size(xsp,Ssize_trans); 
					if ((res = ddi_copyout(user_buffer, (caddr_t)parm->data, parm->size)) != 0){
						dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER,"
						       "           copy_to_user error\n");
						parm->err_no |= PDC_E_DDI_COPYOUT;
					}
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				if (!IN_SRB(xsp)){
					goto again;
				}
				/* Запуск Slave */
				*i = RDR(xsp->regbase, SLAVE_DATA_REGISTER);
			}

			while (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_SV != 1 || 
				sb_calculate_size(xsp,Ssize_trans) != Ssize_trans) {
				
				if (xsp->clear_on_slave) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER, в системе"
					       "	   зарегистрировано clear_slave_task_mu()\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					if ((res = ddi_copyout(user_buffer, (caddr_t)parm->data, parm->size)) != 0){
						dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER,"
						       "           copy_to_user error\n");
						parm->err_no |= PDC_E_DDI_COPYOUT;
					}
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).Err) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER, выход по Err\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					parm->err_no = PDC_E_ERTRANS;
					if ((res = ddi_copyout(user_buffer, (caddr_t)parm->data, parm->size)) != 0){
						dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER,"
						       "           copy_to_user error\n");
						parm->err_no |= PDC_E_DDI_COPYOUT;
					}
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER, выход по Rm\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,Ssize_trans);
					parm->err_no = PDC_RMI;
					if ((res = ddi_copyout(user_buffer, (caddr_t)parm->data, parm->size)) != 0){
						dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER,"
						       "           copy_to_user error\n");
						parm->err_no |= PDC_E_DDI_COPYOUT;
					}
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				
				if (cv_spin_wait(&xsp->cv_slave, &xsp->lock) == -1) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER, выход по сигналу\n");
					clear_slave_task(xsp);
					parm->err_no = PDC_SIGNAL;
					parm->rwmode = PDC_SB_RECIEVE;
					parm->size = sb_calculate_size(xsp,Ssize_trans); 
					if ((res = ddi_copyout(user_buffer, (caddr_t)parm->data, parm->size)) != 0){
						dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_BUFFER,"
						       "           copy_to_user error\n");
						parm->err_no |= PDC_E_DDI_COPYOUT;
					}
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
			}
			parm->size = sb_calculate_size(xsp,Ssize_trans);	
		}
/* Прием 32 бит данных */
		if (rwmode == PDC_USER_DATA) {
			AS_STRUCT(S_Cntrl_Reg).SSize = 1;
			AS_STRUCT(S_Cntrl_Reg).SDir = 0x1; /* Прием */
			AS_STRUCT(S_Cntrl_Reg).SV = 1;
			
			xsp -> stat |= PDC_SB_RECIEVE;
			/* Активизация Slave */
			WRR(xsp->regbase, SLAVE_CONTROL_REGISTER, AS_WORD(S_Cntrl_Reg));
			
			if (AS_STRUCT(((Status_Reg_t)xsp->evs)).Err) {
				dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_DATA, В системе зарегистрировано"
				       " 	   прерывание Err\n");
				parm->err_no = PDC_E_ERTRANS;
				parm->rwmode = xsp->evs;
				parm->size = sb_calculate_size(xsp,1);
				xsp->stat &=~ PDC_SB_RECIEVE;
				goto mux_exit;
			}
			if (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_Rm) {
				dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_DATA, В системе зарегистрировано"
				       "	   удаленное прерывание Rm\n");
				parm->err_no = PDC_RMI;
				parm->rwmode = xsp->evs;
				parm->size = sb_calculate_size(xsp,1);
				xsp->stat &=~ PDC_SB_RECIEVE;
				goto mux_exit;
			}

			while (AS_STRUCT(((Status_Reg_t)xsp->evs)).PI_Src_SV != 1 || 
					sb_calculate_size(xsp,1) != 1) {
				if (xsp->clear_on_slave) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_DATA, в системе"
					       "	   зарегистрировано clear_slave_task_mu()\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,1);
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)parm->rwmode)).Err) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_DATA, выход по Err\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,1);
					parm->err_no = PDC_E_ERTRANS;
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				if (AS_STRUCT(((Status_Reg_t)parm->rwmode)).PI_Src_Rm) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_DATA, выход по Rm\n");
					parm->rwmode = xsp->evs;
					parm->size = sb_calculate_size(xsp,1);
					parm->err_no = PDC_RMI;
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				if (cv_spin_wait(&xsp->cv_slave, &xsp->lock) == -1) {
					dbgpdc("pdc_iocrw: PDC_SB_RECIEVE, rwmode = PDC_USER_DATA, выход по сигналу\n");
					clear_slave_task(xsp);
					parm->err_no = PDC_SIGNAL;
					parm->rwmode = PDC_SB_RECIEVE;
					parm->size = sb_calculate_size(xsp,1); 
					xsp->stat &=~ PDC_SB_RECIEVE;
					goto mux_exit;
				}
				/* запуск Slave */
				parm -> data = RDR(xsp->regbase, SLAVE_DATA_REGISTER);
			}
			parm->size = sb_calculate_size(xsp,1);
		}

		parm->rwmode = xsp->evs;
		clear_slave_recieve_buffer(xsp); /* Очистка буфера */
		xsp->stat &=~ PDC_SB_RECIEVE;

		res = 0;
		break;

	default :
		printk("**** pdc_iocrw: kop = default, should never happen, FAILED\n");	
		return -1;
	}
mux_exit:
	kfree(user_buffer);
	xsp->clear_on_master = 0;
	xsp->clear_on_slave = 0;
	spin_mutex_exit(&xsp->lock);
	dbgpdc("**** pdc_iocrw FINISH, res=%d ****\n", res);
	return res;
}
 	
/*
 * For Linux add pdc_init() & pdc_exit()
 * to call pdc_attach & pdc_detach for each instance
 */
 
static int
__init pdc_init(void)
{
	int 		rval;
	dev_info_t	*dip;

	dbgpdc("***** pdc_init: START  *****\n");
	rval = ddi_rgstr_dev(board_name, DDI_PCI_SPARC, &pdc_fops);
	if (!rval) {
		printk("pdc_init: ENODEV\n");
		return(-ENODEV);
	}

   	pdc_instances = 0;
   	for (;;) {
   		dip = ddi_inst_dip(board_name, pdc_instances);
   		if (!dip) break;
   		rval = ddi_init_soft(dip, sizeof(pdc_state_t));
   		if (rval) return rval;
   		rval = pdc_attach(dip);
   		if (pdc_attach < 0) {
   			printk("pdc_init: pdc_attach < 0\n");
   			return -EFAULT;
   		}
   		pdc_instances++;   		
   	}
	if (pdc_instances == 0) {
		printk("pdc_init: Device not found\n");
		return -ENODEV;
	}
	dbgpdc("***** pdc_init: FINISH inst %d *****\n", pdc_instances);
	return 0;
}

static void  
__exit pdc_exit(void)
{
	int		i;
	dev_info_t	*dip = NULL;
	int error = 0;

	dbgpdc("***** pdc_exit: START *****\n");
 	for ( i = 0; i < pdc_instances; i++ ) {
 		dip = ddi_inst_dip(board_name, i);
 		error = pdc_detach(dip);
 	} 
	if (!error){
		error = ddi_rm_dir(dip); 
		if (error)
			printk("pdc_exit: ddi_rm_dir failed, error = %d\n", error);
	}
	dbgpdc("***** pdc_exit: FINISH *****\n");
}

/*
 * For Linux add these lines
 */

module_init(pdc_init);
module_exit(pdc_exit);
MODULE_LICENSE("Copyright by MCST 2005");
MODULE_DESCRIPTION("PCI Device Card driver");


