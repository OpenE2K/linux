/*
 * Copyright (c) 2002 by MCST.
 *
 * Ported in linux by Alexey V. Sitnikov, MCST, 2004 
 *
 */

#define NEW_MBKP	1

#define MBKP1   	0

#define MBKP_DBG 	0

#define MBKP_IO_TRACE 	0

#define MBKP_TIME_TRACE 0

#define DESK_DBG	0

#define MBKP_INT_TRACE	0

#define MBKP_REG_TRACE  0
	
#define MBKP_DBG_ATT 	0

#define MBKP_MMAP_TRACE 0

#define INTERRUPT_REG_DEBUG 0

#define	DBG_MODE 0
#define DBGMBKPDETAIL_MODE 0

#define	dbgmbkp	if (DBG_MODE) printk
#define dbgmbkpdetail if (DBGMBKPDETAIL_MODE) printk

#ifndef MBKP_DBG
#define MBKP_DBG 	0
#endif /* MBKP_DBG */

#ifndef MBKP_IO_TRACE
#define MBKP_IO_TRACE 	0
#endif /* MBKP_IO_TRACE */

#ifndef DESK_DBG
#define DESK_DBG	0
#endif /* DESK_DBG */

#ifndef MBKP_INT_TRACE
#define MBKP_INT_TRACE	0
#endif /* MBKP_INT_TRACE */

#ifndef MBKP_REG_TRACE
#define MBKP_REG_TRACE  0
#endif /* MBKP_REG_TRACE */

#ifndef MBKP_DBG_ATT	
#define MBKP_DBG_ATT 	0
#endif /* MBKP_DBG_ATT */

#ifndef INTERRUPT_REG_DEBUG
#define INTERRUPT_REG_DEBUG 0
#endif /* INTERRUPT_REG_DEBUG */

#define mbkp_dbg	if(MBKP_DBG) printk

#include <linux/miscdevice.h>

#include <linux/mm.h>
#include <linux/interrupt.h>

#include <linux/mcst/ddi.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/dma.h>

#include <linux/mcst/mbkp1_reg.h>
#include <linux/mcst/user_intf.h>

static caddr_t e1rega;
static caddr_t e2rega;

#if NEW_MBKP

/* Количество блоков + неполный блок */
static int cnt_tr (int n) {
        int ns = n % 8;
        int nb = (n / 8);
        if (ns>0)
                nb++;
        return ( (nb<<4) + ns);
}

#endif /* NEW_MBKP */

#define  STATE_DEBUG 0

#define IO_TIMEOUT 10000000 /* n000000: n sec i/o timeout */

#define	mcst_node_type	"mcst_node_type"

#if MBKP1
#define	mod_name	"mbkp1"
#define board_name	"MCST,mbkp1"	/* should be same as FCODE.name */
#else
#define	mod_name	"mbkp2"
#define board_name	"MCST,mbkp2"	/* should be same as FCODE.name */
#endif

#define DEV_DEVN(d)	(getminor(d))		/* dev_t -> minor (dev_num) */
#define DEV_inst(m)	(m >> 3)		/* minor -> instance */
#define DEV_chan(m)	(m & 0x7)		/* minor -> channel */
#define DEV_MINOR(i, c)	((i << 3) | (c))	/* instance + channel -> minor*/
#define DEV_INST(d)	DEV_inst(DEV_DEVN(d))	/* dev_t -> instance */
#define DEV_CHAN(d)	DEV_chan(DEV_DEVN(d)) 	/* dev_t -> channel */


#define CH_DMA_H_ALLOCD   1 	/* chan res alloc stat bit masks */
#define CH_DMA_MH_ALLOCD  2
#define CH_COOKIE_BIND 	  4

#if INTERRUPT_REG_DEBUG
#define INTERRUPT_REG_BASE   0xf1410000
#define INTERRUPT_MASK_REG   0x4
#define INTERRUPT_MASK_CLEAR 0x8
#define INTERRUPT_MASK_SET   0xc


#define mcst_read(__reg) \
({	u32 __ret; \
	__asm__ __volatile__("lda [%1] %2, %0" \
			     : "=r" (__ret) \
			     : "r" (__reg), "i" (0x2f)  \
			     : "memory"); \
	__ret; \
})

#define mcst_write(__reg, __val) \
({	__asm__ __volatile__("sta %0, [%1] %2" \
			     : 		\
			     : "r" (__val), "r" (__reg), "i" (0x2f) \
			     : "memory"); })
#endif /* INTERRUPT_REG_DEBUG */

unsigned long	mcst_rg = 0;
unsigned long	mcst_rg_mask = 0;

struct dma_chan {
   	uchar_t channel;	 	 /*      channel index in slot 	 */
        uchar_t allocs;	 		 /* chan res alloc statbit stack */

//	ddi_dma_handle_t dma_handle; 	 /* <= ddi_dma_alloc_handle 	*/
//	ddi_acc_handle_t dma_mem_handle; /* <= ddi_dma_mem_alloc	*/

	dma_addr_t	 dma_busa;

	unsigned long	 prim_buf_addr;
	size_t		 real_size;

//	ddi_dma_cookie_t dma_cookie; 	 /* <= ddi_dma_addr_bind_handle */	
};

typedef struct dma_chan dma_chan_t;

/*
	статус трактов приема-передача (МБКР1) прием1-приема2 (МБКР2)
*/
struct rw_state {
	raw_spinlock_t	lock;
	kcondvar_t	cv;

	uchar_t		stat;   /* состояние обмена в тракте   */
	uchar_t		int_ac; /* прерывание для канала принято */
	uint_t		evs;    /* шкала прерываний в тракте   */
	uchar_t		descen;   /* разрешен прием дескриптора */

	
	dma_chan_t     *chd_p; /* при stat !=0 обслуживаемый канал */
	
				/* смещения регистров слота:   */
			
	int		orcnt;  /*   начальный счетчик	       */ 

	clock_t		timer;  /* таймер мксек операции I/O     */ 
				/* ==0 - опрос, >0 - блокировака */
				/*      до завершения операции   */
						
	uint_t		last_desk;	  /* last ch1 accepted descriptor */
	uint_t		last_desk2;	  /* last ch2 accepted descriptor */
				
		/* статистика */
	uint_t		not_my_intr;
};

#define MAX_TIMER 15000000	/*   не более xxx сек	      */

				/* биты rw_state.stat 0 - свободен  */
#define RW_STAT_RUNNING 1	/* !=0 идет обмен IOCRW_xxx	    */

typedef struct rw_state rw_state_t; 

typedef rw_state_t * rw_state_p;

#define READ_TR_PTR(xsp, p) (p == &xsp->rw_states[0])


/*
 *	Slot entity globals
 */
#define SL_CONF_ALLOCD   1 	/* slot res alloc stat bit masks */
#define SL_MEMH_ALLOCD   2
#define SL_COOKIE_BIND 	 4


typedef struct mbkp_state {
	dev_info_t		*dip;
        uchar_t 		allocs;	 /* resourse allocations status */
	int			opened;
	int			open_flags;
	uchar_t			busy;

	raw_spinlock_t		lock;
	kcondvar_t		cv;
	kcondvar_t		cv_busy;

#ifdef MBKP_MODEL  
	kmutex_t		mu_model;
#endif	/* MBKP_MODEL */

	//ddi_iblock_cookie_t	iblock_cookie;
	//ddi_idevice_cookie_t	idevice_cookie;
	
	//ddi_acc_handle_t	reghnd;	   /* handler and  */
	caddr_t			regbase;   /* slot regs mapped base addr */
	
	//ddi_acc_handle_t	codehnd;   /* handler and  */
	caddr_t			codebase;  /* slot fcode mapped base addr */
        int  			mask_set;
        int  			instance;
		
	uint_t 			hzip;

	dma_chan_t dma_chans[MAX_CHANNEL];	/* DMA channels vector */
	rw_state_t rw_states[2];
	uint_t tzip;

} mbkp_state_t;

static 	void *statep;
int	mbkp_instances;

static int mbkp_attach(dev_info_t	*dip);
static int mbkp_detach(dev_info_t	*dip);


static int mbkp_open(struct inode *inode, struct file *file);
static int mbkp_close(struct inode *inode, struct file *file);

static int mbkp_iocrw(dev_t dev,  mbkp_ioc_parm_t * parm, int kop); 

static int mbkp_ioctl(struct inode *inode, struct file *filp,
           			unsigned int cmd, unsigned long arg);
static int mbkp_mmap(struct file *file, struct vm_area_struct *vma);
static uint_t mbkp_chpoll(struct file *file, struct poll_table_struct *wait);

void free_chan(dev_info_t *dip, dma_chan_t * chd); 
ssize_t init_chan(dev_info_t *dip, dma_chan_t * chd, uchar_t channel, size_t reqlen);
dma_chan_t * make_dev(dev_info_t *dip, dma_chan_t * chd, uchar_t channel); 
int	rmv_dev(dev_info_t *dip, dma_chan_t * chd, uchar_t channel); 

static irqreturn_t mbkp_intr(int irq, void *arg, struct pt_regs *regs);

#if MBKP_INT_TRACE
static void prt_evs(int inst, int evs) {

#if MBKP1
  	printk("prt_evs[%u]: %x\n", inst, evs);

  	if (evs&BUF_TR) {
  		printk("MBKP1_BUF_TR[%u]\n", inst); 
  		evs ^= BUF_TR;
  	}
  	if (evs&BUF_RCV1) {
  		printk("MBKP1_BUF_RCV1[%u]\n", inst);  
  		evs ^= BUF_RCV1;
  	}
  	if (evs&PAR_RCV1)  {
  		printk("MBKP1_PAR_RCV1[%u]\n", inst);  
  		evs ^= PAR_RCV1;
  	}
  	if (evs&PAR_SBUS) {
  		printk("MBKP1_PAR_SBUS[%u]\n", inst);  
  		evs ^= PAR_SBUS;
  	}

  	if (evs&ERR_SBUS) {
  		printk("MBKP1_ERR_SBUS[%u]\n", inst);  
  		evs ^= ERR_SBUS;
  	}
  	if (evs&DESC_RCV1) {
  		printk("MBKP1_DESC_RCV1[%u]\n", inst); 
  		evs ^= DESC_RCV1;
  	}

  	if (evs != 0) 
  		printk("M1_UNKNOWN INTERRUPTS[%u]: %x\n", inst,	evs);
#else
  	printk("M2prt_evs[%u]: %x\n", inst, evs);
  	if (evs&M2MAS_RCV1) {
  		printk("MBKP2_M2MAS_RCV1[%u]\n", inst); 
  		evs ^= M2MAS_RCV1;
  	}
  	if (evs&M2PAR_RCV1) {
  		printk("MBKP2_M2PAR_RCV1[%u]\n", inst); 
  		evs ^= M2PAR_RCV1;
  	}
  	if (evs&M2SBUS_PAR) {
  		printk("MBKP2_M2SBUS_PAR[%u]\n", inst); 
  		evs ^= M2SBUS_PAR;
  	}
 
  	if (evs&M2SBUS_LATERR) {
  		printk("MBKP2_M2SBUS_LATERR[%u]\n", inst);
  		evs^=M2SBUS_LATERR;
  	}
  	if (evs&M2DESC_RCV1) {
  		printk("MBKP2_M2DESC_RCV1[%u]\n", inst); 
  		evs ^= M2DESC_RCV1;
  	}
  	if (evs&M2MAS_RCV2) {
  		printk("MBKP2_M2MAS_RCV2[%u]\n", inst); 
  		evs ^= M2MAS_RCV2;
  	}
  	if (evs&M2PAR_RCV2) {
  		printk("MBKP2_M2PAR_RCV2[%u]\n", inst); 
  		evs ^= M2PAR_RCV2;
  	}
  	if (evs&M2DESC_RCV2) {
  		printk("MBKP2_M2DESC_RCV2[%u]\n", inst); 
  		evs ^= M2DESC_RCV2;
  	}
  	if (evs != 0) 
  		printk("MBKP2_UNKNOWN INTERRUPTS[%u]: %x\n", inst, evs);
#endif /* MBKP1 */
}
#endif /* MBKP_INT_TRACE */

/*
 * file_operations
 */
static struct file_operations mbkp_fops = {
	owner:   THIS_MODULE,
	open:	 mbkp_open,
	release: mbkp_close,
	poll:    mbkp_chpoll,
	ioctl:   mbkp_ioctl,
	mmap:	 mbkp_mmap,
};

void
WRR(caddr_t a,unsigned int reg, unsigned int val)
{
	unsigned int *p;
#if MBKP_REG_TRACE
	int inst = (a == e1rega) ? 0 : 1;
#if MBKP1
	printk("**** WRR[inst=%u] reg=%x val=%u ****\n",inst,reg,val);
#else
	printk("**** WRR2[inst=%u] reg=%x val=%u ****\n",inst,reg,val);
#endif	/* MBKP1 */
#endif	/* MBKP_REG_TRACE */
	reg = (reg & 0xfff) % 0x90;
	p = (unsigned int *)(a + reg);	
#if MBKP_REG_TRACE
	printk("WRR: Reg addr = 0x%lx\n", (unsigned long)p);
#endif	/* MBKP_REG_TRACE */
	if ((reg & 3) != 0) {
 		printk("WRR[] reg=%x unaligned!\n", reg);
		return;
 	}
	*p = val;	
}

unsigned int
RDR(caddr_t a,unsigned int reg)
{
	unsigned int val;
	unsigned int * p;
#if MBKP_REG_TRACE
	int inst = (a == e1rega) ? 0 : 1;
#endif	/* MBKP_REG_TRACE */
	reg = (reg & 0xfff) % 0x90;
	p = (unsigned int *)(a + reg);
#if MBKP_REG_TRACE
	printk("RDR: Reg addr = 0x%lx\n", (unsigned long)p);
#endif	/* MBKP_REG_TRACE */
	if ((reg & 3) != 0) {
 		printk("RDR[] reg=%x unaligned!\n", reg);
		return 0;
 	}
	val = *p;
#if MBKP_REG_TRACE
#if MBKP1
	printk("**** RDR[inst=%u] reg=%x val=%u ****\n",inst,reg,val);
#else
	printk("**** RDR2[inst=%u] reg=%x val=%u ****\n",inst,reg,val);
#endif /* MBKP1 */
#endif /* MBKP_REG_TRACE */
	return val;
}

#if NEW_MBKP

#define OK_RCV_CNT 0x0

int calc_len_tr (unsigned int beg, unsigned int end) {

        if ( (end>>4) == OK_RCV_CNT)
                return beg;

        end = ((end >> 1) & 0xfffffff0) + (end & 0x7);
                      /*      12345678    */

        return beg - end;
}

#else

int calc_len (unsigned int beg, unsigned int end)
{
	if ( (end & SGCNT_MASK) > MAX_CNT) 
		end = 0;
	
	return (beg - end);
}

#endif /* NEW_MBKP */
 

		/* Device Configuration */
static void  
rw_state_init(struct mbkp_state *xsp)
{
	rw_state_p p; int i;
	for (i=0; i<2;i++) {
		p = &xsp->rw_states[i];
		spin_mutex_init(&p->lock);
		cv_init(&p->cv);
		p->stat = 0;
		p->timer = MAX_TIMER;
		p->not_my_intr = 0;
#if MBKP_DBG
		printk("%u: rw_state_init: timer=%u\n", i, p->timer);
#endif /* MBKP_DBG */
	}
}


static int 
mbkp_attach(dev_info_t *dip) 
{
	mbkp_state_t	*xsp;
	int		rval, inst;
	int		channel;
	int		irq;

#if INTERRUPT_REG_DEBUG	
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
#endif /* INTERRUPT_REG_DEBUG */
	dbgmbkp("***** mbkp_attach START mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx *****\n", 
			mcst_rg, mcst_rg_mask);
	if (dip == NULL) return -EFAULT;
	statep = (mbkp_state_t *)dip->soft_state;
	xsp = (mbkp_state_t *)dip->soft_state;
	inst = dip->instance;	
	spin_mutex_init(&xsp->lock);
	cv_init(&xsp->cv_busy);
	cv_init(&xsp->cv);

#ifdef MBKP_MODEL  
	mutex_init(&xsp->mu_model);
#endif	/* MBKP_MODEL */		
	xsp->dip = dip;		
	
	xsp->instance = inst;
	xsp->opened = 0;
		
	rw_state_init(xsp);

	/* slot DVMA registers mapping */
	if (ddi_ioremap(dip) != DDI_SUCCESS) {
		printk("~%s~%d_attach: failed to map regs\n",
							board_name, inst);
		goto failed;
	}
	xsp->regbase = (caddr_t )dip->base_addr[0];
	xsp->codebase = (caddr_t )dip->base_addr[1];
		
	if (inst == 0) 
		e1rega = xsp->regbase;
	else
		e2rega = xsp->regbase;
	
	xsp->mask_set = 0;
//	RDR(xsp->regbase,SW_TRBA_RCV1);    /* запретить ТРБА в канале */
		
#if MBKP_DBG
	printk("mbkp_attach: regsva=0x%x\n", (int)xsp->regbase);
	printk("mbkp_attach: codeva=0x%x\n", (int)xsp->codebase);
#endif /* MBKP_DBG */	
	irq = ddi_prop_int(dip, "interrupts");
	dbgmbkpdetail(KERN_ALERT "mbkp_attach: IRQ = %d\n", irq);
#if INTERRUPT_REG_DEBUG
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
	dbgmbkp("mbkp_attach: mcst_rg_mask before ddi_add_irq = 0x%lx\n", mcst_rg_mask);
#endif /* INTERRUPT_REG_DEBUG */
	rval = ddi_add_irq(dip, &mbkp_intr, SA_SHIRQ);
	if (rval) {
		printk("request_irq fail\n");
		goto failed;
	}
#if INTERRUPT_REG_DEBUG
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
	dbgmbkp("mbkp_attach: mcst_rg_mask after ddi_add_irq = 0x%lx\n", mcst_rg_mask);
	mcst_rg_mask = 0x3F80 ; /* Clear Sbus bits */
	mcst_write((INTERRUPT_REG_BASE + INTERRUPT_MASK_CLEAR), mcst_rg_mask);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
	dbgmbkp("mbkp_attach: mcst_rg_mask after Sbus clear mask = 0x%lx\n", mcst_rg_mask);
#endif /* INTERRUPT_REG_DEBUG */	
	for (channel=0; channel < MAX_CHANNEL; channel++) {
		if (make_dev(dip, &xsp->dma_chans[channel], channel) == NULL)
			goto failed;				
	}

#if MBKP_DBG
#if INTERRUPT_REG_DEBUG
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
#endif /* INTERRUPT_REG_DEBUG */
	printk("mbkp_attach: DONE mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx\n", mcst_rg, mcst_rg_mask);
#endif /* MBKP_DBG */
	return (DDI_SUCCESS);

failed:
	ddi_unrgstr_dev(dip);
	printk("mbkp_attach: FAILED\n");
	return (DDI_FAILURE);
}

static int 
mbkp_detach(dev_info_t *dip) 
{
	struct mbkp_state *xsp;
	int channel;
	int error = 0;
	
	if (dip == NULL) return -EFAULT;
	xsp = (mbkp_state_t *)dip->soft_state;	
	if (xsp == NULL) return -EFAULT;
	for (channel=0; channel < MAX_CHANNEL; channel++) {
		free_chan(dip, &xsp->dma_chans[channel]);
		error = rmv_dev(dip, &xsp->dma_chans[channel], channel);
	}
	ddi_unrgstr_dev(dip);
	return error;
	
}


void free_chan(dev_info_t *dip, dma_chan_t *chd) 
{
#if MBKP_DBG
	printk("%s.free_chan.%u, allocs=%x:\n", 
		mod_name, chd->channel, chd->allocs);		
#endif /* MBKP_DBG */	
	if (chd->allocs & CH_DMA_MH_ALLOCD) 
	{
#if MBKP_DBG
		printk("free_chan.ddi_dma_mem_free\n"); 
#endif /* MBKP_DBG */
		ddi_dma_mem_free(dip, 	chd->real_size,
					chd->dma_busa,
					chd->prim_buf_addr);
	}
}

dma_chan_t *make_dev(dev_info_t *dip, dma_chan_t * chd, uchar_t channel) 
{
	int	inst  = dip->instance;
	int     minor = DEV_MINOR(inst, channel);
	char	name[64];

	sprintf(name, "%s_%d_:%d", mod_name,	inst, channel);
	if (ddi_create_minor(dip, name, S_IFCHR, minor)) {
		printk("%s%d_attach: ddi_create_minor_node failed\n", 
			board_name, channel);
		return NULL;
	}
#if MBKP_DBG
	printk("%s%d_attach,make_dev: minor_node = %s\n",
		board_name, channel, name);	
#endif /* MBKP_DBG */

	return chd;
}

int rmv_dev(dev_info_t *dip, dma_chan_t * chd, uchar_t channel) 
{
	int	inst  = ddi_get_instance(dip);
	char	name[64];
	int error = 0;
#if MBKP_DBG
	int     minor = DEV_MINOR(inst, channel);
#endif /* MBKP_DBG */
	sprintf(name, "%s_%d_:%d", mod_name,	inst, channel);
	error = ddi_unlink(dip, name);
	if (error){
		printk("rmv_dev: ddi_unlink failed, error = %d\n", error);
		return error;
	}
#if MBKP_DBG
	printk("%s%d_detach.rmv_dev: minor = %u !~~!\n",
		board_name, channel, minor);	
#endif /* MBKP_DBG */
	return error;
}


ssize_t init_chan(dev_info_t *dip, dma_chan_t * chd, uchar_t channel, size_t reqlen) 
{
	char * err_msg;

#if MBKP_DBG
#if INTERRUPT_REG_DEBUG
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
#endif /* INTERRUPT_REG_DEBUG */
	printk("**** init_chan START mcst_rg = 0x%lx,  mcst_rg_mask = 0x%lx ****\n", 
			mcst_rg, mcst_rg_mask);
#endif /* MBKP_DBG */

 	chd->allocs = CH_DMA_H_ALLOCD;
	  
	if (ddi_dma_mem_alloc(dip, reqlen, 
				&chd->dma_busa,
				&chd->real_size,
				&chd->prim_buf_addr) != DDI_SUCCESS) {
	   	err_msg = "ddi_dma_mem_alloc"; 
	   	goto failed;
	}	
  	if (chd->prim_buf_addr == 0) {
    		printk ("init_chan[%u]: channel have not get free memory\n", channel);
    		return -1;
  	}
 	chd->allocs = chd->allocs | CH_DMA_MH_ALLOCD;

#if MBKP_DBG 
	printk("init_chan[%u]: reql=%ld-0x%lx, real_s=%ld-0x%lx\n",
		channel, reqlen,reqlen, 
		chd->real_size, chd->real_size);
	printk("\t\t: prim_addr=0x%lx dma_busa=0x%x\n",
		chd->prim_buf_addr, chd->dma_busa);
#endif	/* MBKP_DBG */

	memset ((void *)chd->prim_buf_addr, 0, chd->real_size);
 	
#if INTERRUPT_REG_DEBUG
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
#endif /* INTERRUPT_REG_DEBUG */
#if MBKP_DBG
	printk("**** init_chan: DONE mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx ****\n", 
			mcst_rg, mcst_rg_mask);
#endif
	return chd->real_size;

	
failed:
	free_chan(dip, chd);
	printk("**** %s_%d: init_chan: %s FAILED ****\n",
		board_name, channel, err_msg);
	return (-1);
}

/* Device access */

static int 
mbkp_open(struct inode *inode, struct file *file) 
{
	dev_info_t 		*dip;
	struct	mbkp_state	*xsp;
	dev_t			dev;
	int			dev_num;
	int			instance;
	int			channel;

	int		firstopen = 0;
	int		rval = 0;
     /*
      * Is the instance attached?
      */
#if MBKP_DBG
#if INTERRUPT_REG_DEBUG
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
#endif /* INTERRUPT_REG_DEBUG */
	printk("\n***** mbkp_open START mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx\n", 
			mcst_rg, mcst_rg_mask);	
#endif /* MBKP_DBG */	
	rval = ddi_open(inode, file);
	if (rval < 0) return rval;
	dev = ddi_inode_dev(inode);
	dip = ddi_inode_dip(inode);
	if (!dip || !dev) return (ENXIO);
	dev_num = DEV_DEVN(dev);
	instance = DEV_inst(dev_num);
	channel = DEV_chan(dev_num);
#if MBKP_DBG
	printk("mbkp_open dev[inst] = %u[%u], channel = %d\n", dev_num,instance, channel);
#endif /* MBKP_DBG */

     xsp = dip->soft_state;
     if (xsp == NULL) {
     	printk("~%s~_open: unattached instance %d\n", board_name, instance);
        return (ENXIO);
     };

     /*
      * Verify otyp is appropriate
      */

     /*
      *  Verify the open flag
      */

     spin_mutex_enter(&xsp->lock);


     
#if 1     
     
     firstopen = (((1 << channel) & (xsp->opened )) == 0);	
     /*
      * Check for exclusive open - exclusivity affects the whole board,
      * not just the device being opened.
      */
      if (firstopen == 0) {
		printk("~=%s=~%d_open: exclusive open of "
			board_name, "already opened device\n", instance);
		spin_mutex_exit(&xsp->lock);
		
		return (EBUSY);
      }

     /*
      * Remember we're opened, if we get a detach request
      */

//	xsp -> open_flags |= flag;
	xsp -> opened |= (1 << channel);
#endif

//	xsp->opened++;
#if MBKP_DBG
	printk("mbkp_open: opened_flg=%u\n", xsp -> opened);
#endif /* MBKP_DBG */
	spin_mutex_exit(&xsp->lock);
//  	MOD_INC_USE_COUNT;
#if MBKP_DBG
#if INTERRUPT_REG_DEBUG
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
#endif /* INTERRUPT_REG_DEBUG */
	printk("***** mbkp_open NORMALLY FINISH mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx *****\n\n", 
			mcst_rg, mcst_rg_mask);
#endif /* MBKP_DBG */
	return  (0);
}

static int 
mbkp_close(struct inode *inode, struct file *file) 
{
	dev_info_t 		*dip;
	dev_t			dev;
	struct mbkp_state	*xsp = NULL;
	int			dev_num;
	int			instance;
	int			channel;

	dev = ddi_inode_dev(inode);
	dip = ddi_inode_dip(inode);
	if (!dip || !dev) return (ENXIO);
	xsp = (mbkp_state_t *)dip->soft_state;
	if (xsp == NULL) return (ENXIO);
	dev_num = DEV_DEVN(dev);
	instance = DEV_inst(dev_num);
	channel = DEV_chan(dev_num);

	spin_mutex_enter(&xsp->lock);
	xsp->open_flags = 0;
	
	xsp->opened = (xsp->opened &~ (1 << channel));	

//	xsp->opened--;
#if MBKP_DBG
	printk("mbkp_close for instance = %u, open_flg=%u\n", 
		instance, xsp->opened);
#endif /* MBKP_DBG */
	spin_mutex_exit(&xsp->lock);
	ddi_close(inode, file);
//  	MOD_DEC_USE_COUNT;	

	return (0);

}

#if STATE_DEBUG
void PRINT_STATE(mbkp_state_t *xsp)
{
	if (RDR(xsp->regbase, INTR_M_WD)&WRDESC_BUSY) {
		printk("mbkp_ioctl: WRDESC_BUSY \n");
	}else{
		printk("mbkp_ioctl: WRDESC_FREE \n");
	}
	if (RDR(xsp->regbase, INTR_M_WD)&0x2) {
		printk("mbkp_ioctl: Маска програмных прерываний установлена \n");
	}
	if (RDR(xsp->regbase, INTR_M_WD)&0x4) {
		printk("mbkp_ioctl: Маска контроля четности установлена \n");
	}
	if (RDR(xsp->regbase, INTR_M_WD)&0x8) {
		printk("mbkp_ioctl: Признак наличия контроля по SBUS шине \n");
	}
	if (RDR(xsp->regbase, INTR_M_WD)&0x10) {
		printk("mbkp_ioctl: Режим приема дескриптора установлен \n");
	}else{
		printk("mbkp_ioctl: Режим приема дескриптора сброшен \n");
	}	
}
#endif /* STATE_DEBUG */

static 
int mbkp_ioctl(struct inode *inode, struct file *filp,
                 unsigned int cmd, unsigned long arg) {
	
	dev_info_t 		*dip;
	dev_t			dev;
	struct mbkp_state	*xsp = NULL;
	int			dev_num;
	int			instance;
	int			channel;
	int 			res = 0;
	mbkp_ioc_parm_t 	parm;

#if MBKP_DBG
	printk("\n***** mbkp_ioctl: START *****\n");
#endif /* MBKP_DBG */
	dev = ddi_inode_dev(inode);
	dip = ddi_inode_dip(inode);
	if (!dip || !dev) return (ENXIO);
	xsp = (mbkp_state_t *)dip->soft_state;
	if (xsp == NULL) return (ENXIO);
	dev_num = DEV_DEVN(dev);
	instance = DEV_inst(dev_num);
	channel = DEV_chan(dev_num);

#if MBKP_DBG
	printk("***** %u,%u: mbkp_ioctl: cmd=%x *****\n", 
		instance, channel, (uint) cmd);
		
#endif /* MBKP_DBG */
	if (xsp == NULL){
		return (ENXIO);
	}
	if (ddi_copyin((caddr_t)arg, (caddr_t)&parm,
		sizeof (mbkp_ioc_parm_t)) == -1) {
		printk("mbkb_ioctl: ddi_copyin failed, sizeof (mbkp_ioc_parm_t) = 0x%lx\n", 
			(u_long)sizeof (mbkp_ioc_parm_t)); 
		return (EINVAL);
	}
	
	parm.err_no = res = 0;
	switch (cmd) {

	case MBKP_TIMER_FOR_READ :
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_TIMER_FOR_READ, reqlen (mksec) = 0x%x\n", 
			min((uint_t)MAX_TIMER, (uint_t)parm.reqlen));
		
	        parm.acclen = (&xsp->rw_states[0])->timer;
	        (&xsp->rw_states[0])->timer = min((uint_t)MAX_TIMER, (uint_t)parm.reqlen);
		break;

	case MBKP_TIMER_FOR_WRITE:
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_TIMER_FOR_WRITE, reqlen (mksec) = 0x%x\n",
			min((uint_t)MAX_TIMER, (uint_t)parm.reqlen));
	        parm.acclen = (&xsp->rw_states[1])->timer;
	        (&xsp->rw_states[1])->timer = min((uint_t)MAX_TIMER, (uint_t)parm.reqlen);
		break;

	case MBKP_IOC_ALLOCB :
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_IOC_ALLOCB, reqlen = 0x%lx\n", 
									(u_long)parm.reqlen);
		parm.acclen = init_chan(dip, &xsp->dma_chans[channel], 
			channel, parm.reqlen);
		if (parm.acclen == -1) {
			res = -1; parm.err_no = MBKP_E_NOBUF;
			break;	
		}
#if INTERRUPT_REG_DEBUG
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
	dbgmbkp("*** mbkp_ioctl MBKP_IOC_ALLOCB before memcpy mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx\n", 
			mcst_rg, mcst_rg_mask);
#endif /* INTERRUPT_REG_DEBUG */
		memcpy((void *)(&xsp->dma_chans[channel])->prim_buf_addr, xsp->codebase,
 			 0x40);
#if INTERRUPT_REG_DEBUG
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
	dbgmbkp("*** mbkp_ioctl MBKP_IOC_ALLOCB after memcpy mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx\n", 
			mcst_rg, mcst_rg_mask);
#endif /* INTERRUPT_REG_DEBUG */
		break;

	case MBKP_IOC_WRR:
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_IOC_WRR\n");
		res = 0;
/*
		printk("START MBKP_IOC_WRR: reg=0x%lx: val=0x%lx\n", 
			parm.reqlen, parm.acclen);
*/
		WRR(xsp->regbase, (uint_t)parm.reqlen, (uint_t)parm.acclen);
		break;

	case MBKP_IOC_RDR:
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_IOC_RDR\n");
		res = 0;
		parm.acclen = RDR(xsp->regbase, (uint_t)parm.reqlen);
		break;
		
	case MBKP_IOC_READ:
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_IOC_READ, reqlen = 0x%lx\n", 
									(u_long)parm.reqlen);
		parm.acclen = 0;		
		res = mbkp_iocrw(dev, &parm, MBKP_IOC_READ);
		break;
#if MBKP1
	case MBKP_IOC_WRITE:
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_IOC_WRITE, reqlen = 0x%lx\n", 
									(u_long)parm.reqlen);
		parm.acclen = 0;		
		res = mbkp_iocrw(dev, &parm, MBKP_IOC_WRITE);
		break;
#else 
	case MBKP_IOC_RDALT:
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_IOC_RDALT\n");
		parm.acclen = 0;		
		res = mbkp_iocrw(dev, &parm, MBKP_IOC_RDALT);
		break;
#endif /* MBKP1 */

	case MBKP_IOC_DR:
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_IOC_DR\n");
		parm.acclen = 0;		
		res = mbkp_iocrw(dev, &parm, MBKP_IOC_DR);
		break;

		
#if MBKP1
	case MBKP_IOC_DW:
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_IOC_DW\n");
		parm.acclen = 0;		
		res = mbkp_iocrw(dev, &parm, MBKP_IOC_DW);
		break;
#else 
	case MBKP_IOC_RDESCALT:
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_IOC_RDESCALT\n");
		parm.acclen = 0;		
		res = mbkp_iocrw(dev, &parm, MBKP_IOC_RDESCALT);
		break;
#endif /* MBKP1 */

	case MBKP_IOC_DE:
		mbkp_dbg("***** mbkp_ioctl: cmd = MBKP_IOC_DE\n");
		parm.acclen = 0;		
		res = mbkp_iocrw(dev, &parm, MBKP_IOC_DE);
		break;
	
	default :	
		printk("default operation NOT EXPECTED\n");
		res = -1;
		parm.err_no = MBKP_E_INVOP;
	}
	if (ddi_copyout((caddr_t)&parm, (caddr_t)arg,
		sizeof (mbkp_ioc_parm_t)) == -1) {
		printk("mbkb_ioctl: ddi_copyout failed\n"); 
		return (EINVAL);
	}	
	if (res == 0) {
#if MBKP_DBG
		printk("***** %u,%u: mbkp_ioctl: NORMAL_END: acclen=0x%lx *****\n\n", 
				instance, channel, parm.acclen);
#endif /* MBKP_DBG */
		return 0;
	}
#if MBKP_DBG
		printk("***** %u,%u: mbkp_ioctl: ERR_END: acclen=0x%lx err[%d]=%s *****\n\n", 
			instance, channel, parm.acclen, parm.err_no,
			msg_by_code(parm.err_no, &iocerrs[0], 
				     sizeof(iocerrs) / sizeof(code_msg_t)
				   )
			
			);
#endif /* MBKP_DBG */
	return -EINVAL; 	/* !? return l>0 == return -1 !?*/
}

/* int poll(struct pollfd *fds, unsigned long nfds, int timeout); */

/* user: man poll.2
 int poll(struct pollfd *fds, unsigned long nfds, int timeout); 
driver: man chpoll

ReadyWR - if no write run
ReadyRD - if no read run
 
 */
static	uint_t
mbkp_chpoll(struct file *file, struct poll_table_struct *wait)
{
	dev_info_t 		*dip;
	dev_t			dev;
	struct mbkp_state	*xsp;
	int			dev_num = DEV_DEVN(dev);
	int			instance = DEV_inst(dev_num);

	dev = ddi_file_dev(file);
	dip = ddi_file_dip(file);
	if (!dip || !dev) return (ENXIO);
	xsp = (mbkp_state_t *)dip->soft_state;
	if (xsp == NULL) return (ENXIO);
	dev_num = DEV_DEVN(dev);
	instance = DEV_inst(dev_num);
	
	printk("mbkp_chpoll isn't emplemented\n");
	return (0);
}


#if MBKP1

		/* Interrupt handler  */
irqreturn_t 
mbkp_intr(int irq, void *arg, struct pt_regs *regs) 
{
	dev_info_t 		*dip;
	struct mbkp_state 	*xsp;
//	uchar_t			channel;
	int 			io_length;
	unsigned int 		evs;
 	rw_state_p 		p = NULL;
 	int 			instance;

#if MBKP_INT_TRACE
	printk("\n***** mbkp_intr START *****\n");
#endif /* MBKP_INT_TRACE */
	if (arg == NULL) {
		printk("mbkp_intr: arg == NULL\n");
		return IRQ_NONE;
	}

	dip = (dev_info_t *)arg;
	xsp = (mbkp_state_t *)dip->soft_state;
	instance = xsp->instance;
	
	evs = RDR(xsp->regbase, INTR_EV_WD) ; /* read & clear ints */


#if MBKP_INT_TRACE
	printk("***** mbkp_intr[ins=%u]: REG_INTRS=0x%x *****\n",
		instance, evs);
#endif /* MBKP_INT_TRACE */
	evs = evs & ALL_INT;
	if (evs == 0)
		return IRQ_NONE;
#if MBKP_INT_TRACE 
	prt_evs(instance, evs);
	printk("mbkp_intr: evs after prt_evs = 0x%x\n", evs);
#endif /* MBKP_INT_TRACE */
	if ((evs & CH0_INT) != 0) {
		p 	= &xsp->rw_states[0];	
		spin_lock(&p->lock);
		p->evs  = evs & CH0_INT; 
		evs 	= evs & (~CH0_INT);
#if MBKP_INT_TRACE
		printk("mbkp_intr[ins=%u]: CH0_INT: %x\n",
			instance, p->evs);
#endif /* MBKP_INT_TRACE */
		if (p->stat == 0) {
#if MBKP_INT_TRACE
			printk("mbkp_intr[ins=%u]: CH0_INT NOT EXPECTED!\n",
				instance);
#endif /* MBKP_INT_TRACE */
			if (p->evs & DESC_RCV1) {
				p->last_desk = RDR(xsp->regbase, RD_DESC_RCV1);
				p->stat = MBKP_E_URGENT;
#if MBKP_INT_TRACE
				printk("mbkp_intr[ins=%u]: DESC=%x\n",
					instance, p->last_desk); 
				p->evs = p->evs ^ DESC_RCV1;
#endif /* MBKP_INT_TRACE */
			}
			p->int_ac = 1;
			cv_signal(&p->cv); 
			spin_unlock(&p->lock);
		}
		else {	/* p->stat != 0 - waiting ints in chanel 0 */
			io_length = RDR(xsp->regbase, CNT_RCV1) & SGCNT_MASK;
#if MBKP_INT_TRACE
			printk("mbkp_intr[ins=%u]: CH0_INT EXPECTED!\n",
				instance	
			       );
#endif /* MBKP_INT_TRACE */
			p->int_ac = 1;
			cv_signal(&p->cv); 
			spin_unlock(&p->lock);			
		}

	} /* endif CH0_INT */
	if ((evs & CH1_INT) != 0) {
		p 	= &xsp->rw_states[1];	
		spin_lock(&p->lock);
		p->evs  = evs & CH1_INT; 
		evs 	= evs & (~CH1_INT);
#if MBKP_INT_TRACE
		printk("mbkp_intr[ins=%u]: CH1_INT=%x\n",
			instance, p->evs);
#endif /* MBKP_INT_TRACE */
		if (p->stat == 0) {
#if MBKP_INT_TRACE
			printk("mbkp_intr[ins=%u]: CH1_INT NOT EXPECTED!\n",
				instance);
#endif /* MBKP_INT_TRACE */
			p->int_ac = 1;
			cv_signal(&p->cv); 
			spin_unlock(&p->lock);
		}
		else {
			io_length = RDR(xsp->regbase,CNT_RCV1) & SGCNT_MASK;
#if MBKP_INT_TRACE
			printk("mbkp_intr[ins=%u]: CH1_INT EXPECTED!\n",
				instance	
			       );
#endif /* MBKP_INT_TRACE */
			p->int_ac = 1;
			cv_signal(&p->cv); 
			spin_unlock(&p->lock);
		}
		
	} /* endif CH1_INT */
	if (evs != 0) {
#if MBKP_INT_TRACE
		printk("mbkp_intr[ins=%u]: NON_MBKP INTERUPTS = %x:\n", 
			instance, evs);
		return IRQ_NONE;
#endif /* MBKP_INT_TRACE */
//		p->not_my_intr++;
	}
#if MBKP_INT_TRACE
	printk("***** mbkp_intr: FINISH, evs = 0x%x *****\n\n", evs);
#endif /* MBKP_INT_TRACE */	
	return IRQ_HANDLED;  /* forces INT_ACK cycle */	
}

#else 

irqreturn_t
mbkp_intr(int irq, void *arg, struct pt_regs *regs) 
{
	dev_info_t 		*dip;
	struct mbkp_state 	*xsp;
//	uchar_t			channel;
#if MBKP_INT_TRACE
	int 			io_length;
#endif /* MBKP_INT_TRACE */
	unsigned int 		evs;
	unsigned int 		aevs;
 	rw_state_p 		p = NULL;
 	int 			instance;
	
	if (arg == NULL) {
		printk("mbkp_intr: arg == NULL\n");
		return IRQ_NONE;
	}

	dip = (dev_info_t *)arg;
	xsp = (mbkp_state_t *)dip->soft_state;
	instance = xsp->instance;
	
	evs = RDR(xsp->regbase, INTR_EV_WD) ; /* read & clear ints */
#if MBKP_INT_TRACE
	printk("mbkp2_intr[ins=%u]: REG_INTRS=0x%x i0=0x%x i1=0x%x\n",
		instance, evs, CH0_INT, CH1_INT);
#endif /* MBKP_INT_TRACE */
	evs = evs & ALL_INT;
	if (evs == 0)
		return IRQ_NONE;
#if MBKP_INT_TRACE 
	prt_evs(instance, evs);
#endif /* MBKP_INT_TRACE */
	if ((evs & CH0_INT) != 0) {
		p 	= &xsp->rw_states[0];	
		spin_lock(&p->lock);
		p->evs  = evs & CH0_INT; 
		evs 	= evs & (~CH0_INT);
#if MBKP_INT_TRACE
		printk("mbkp2_intr[ins=%u]: CH0_INT: %x\n",
			instance, p->evs);
#endif /* MBKP_INT_TRACE */
		if (p->stat == 0) {
#if MBKP_INT_TRACE
			printk("mbkp2_intr[ins=%u]: CH0_INT NOT EXPECTED!\n",
				instance
			       );
#endif /* MBKP_INT_TRACE */
			if (p->evs & M2DESC_RCV1) {
				p->last_desk = RDR(xsp->regbase, RD_DESC_RCV1);
				p->stat = MBKP_E_URGENT;
#if MBKP_INT_TRACE
				printk("mbkp2_intr[ins=%u]: DESC=%x\n",
					instance, p->last_desk
				       ); 
				p->evs = p->evs ^ M2DESC_RCV1;
#endif /* MBKP_INT_TRACE */
			}
			p->int_ac = 1;
			cv_signal(&p->cv); 
			spin_unlock(&p->lock);
		}
		else {	/* p->stat != 0 - waiting ints in chanel 0 */
#if MBKP_INT_TRACE
			printk("mbkp2_intr[ins=%u]: CH0_INT EXPECTED!\n",
				instance	
			       );
#endif /* MBKP_INT_TRACE */
			p->int_ac = 1;
			cv_signal(&p->cv); 
			spin_unlock(&p->lock);			
		}

	} /* endif CH0_INT */
	
	if ((evs & CH1_INT) != 0) {
		p 	= &xsp->rw_states[1];	
		spin_lock(&p->lock);
		p->evs  = (evs & CH1_INT); 
		aevs    = (evs & CH1_INT);
		evs 	= evs & (~CH1_INT);
#if MBKP_INT_TRACE
		printk("mbkp2_intr[ins=%u]: CH1_INT=%x\n",
			instance, p->evs);
#endif /* MBKP_INT_TRACE */
		if (p->stat == 0) {
#if MBKP_INT_TRACE
			printk("mbkp2_intr[ins=%u]: "
				"CH1_INT NOT EXPECTED! p->evs=%x\n",
				instance, p->evs
			       );
#endif /* MBKP_INT_TRACE */
			if (p->evs & M2DESC_RCV2) {
				p->last_desk2 = RDR(xsp->regbase, RD_DESC_RCV2);
				p->stat = MBKP_E_URGENT;
#if MBKP_INT_TRACE
				printk("mbkp2_intr[ins=%u]: DESC=%x\n",
					instance, p->last_desk2
				       ); 
				p->evs = p->evs ^ M2DESC_RCV2;
#endif /* MBKP_INT_TRACE */
			}
			p->int_ac = 1;
			cv_signal(&p->cv); 
			spin_unlock(&p->lock);
		}
		else {
#if MBKP_INT_TRACE
			io_length = RDR(xsp->regbase,CNT_RCV1) & SGCNT_MASK;
			printk("mbkp2_intr[ins=%u]: CH1_INT EXPECTED!\n",
				instance	
			       );
#endif /* MBKP_INT_TRACE */
			p->int_ac = 1;
			cv_signal(&p->cv); 
			spin_unlock(&p->lock);
		}
		
	} /* endif CH1_INT */
	if (evs != 0) {
#if MBKP_INT_TRACE
		printk("mbkp2_intr[ins=%u]: NON_MBKP2 INTERUPTS = %x:\n", 
			instance, evs
		       );
		return IRQ_NONE;
#endif /* MBKP_INT_TRACE */
//		       p->not_my_intr++;
	}
#if MBKP_INT_TRACE
	printk("***** mbkp2_intr: FINISH *****\n");
#endif /* MBKP_INT_TRACE */
	return IRQ_HANDLED;  /* forces INT_ACK cycle */	
}

#endif /* MBKP1 */


static 
int mbkp_mmap(struct file *file, struct vm_area_struct *vma) {
	int			rval;
	dev_info_t 		*dip;
	dev_t			dev;
	int			dev_num;
	int			channel;
	struct mbkp_state	*xsp;
	dma_chan_t * 		chd;

#if INTERRUPT_REG_DEBUG
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
#endif /* INTERRUPT_REG_DEBUG */
	dbgmbkp("***** mbkp_mmap START mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx *****\n", mcst_rg, mcst_rg_mask);

	dev = ddi_file_dev(file);
	dip = ddi_file_dip(file);
	if (!dip || !dev) return (ENXIO);
	xsp = (mbkp_state_t *)dip->soft_state;
	if (xsp == NULL) return (ENXIO);

	dev_num = DEV_DEVN(dev);
	dbgmbkpdetail(" ***** mbkp_mmap: dev_num = %d\n", dev_num);
	channel = DEV_chan(dev_num);
	dbgmbkpdetail(" ***** mbkp_mmap: channel = %d\n", channel);

	chd = &xsp->dma_chans[channel];
	rval = ddi_remap_page((void *)chd->prim_buf_addr, chd->real_size, vma);
	if (rval) {
		dbgmbkp(" ***** mbkp_mmap WRONGLY finish *****\n");
		return -EAGAIN;
	}
#if INTERRUPT_REG_DEBUG
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
#endif /* INTERRUPT_REG_DEBUG */
	dbgmbkp("***** mbkp_mmap NORMALY finish mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx *****\n", 
			mcst_rg, mcst_rg_mask);
	return (0);

}

static int 
mbkp_iocrw(dev_t dev,  mbkp_ioc_parm_t * parm, int kop) 
{
	mbkp_state_t	*xsp = NULL;
	int		dev_num  = DEV_DEVN(dev);
	int		instance = DEV_inst(dev_num);
	int		channel	 = DEV_chan(dev_num);
	clock_t		tick;
	ulong		cur_clock;	
	size_t		size_trans, /*size_trans_ost,*/ len;
	dma_addr_t	addr_dma;
	dma_chan_t 	*chd;
	dev_info_t	*dip;

	dbgmbkp("**** mbkp_iocrw START. kop = %d ****\n", kop);
	dip = (dev_info_t *)ddi_dev_dip(dev);
	xsp = (mbkp_state_t *)dip->soft_state;
	if (xsp == NULL){
		printk("%s: bad instance %d\n",
			 board_name, instance);
		return (ENXIO);
	}

	chd = &xsp->dma_chans[channel];

#ifndef MBKP_MODEL

/* chd->dma_handle: chd->dma_cookie - IOMMU <= slot
		    chd->buf_addr   - MMU   <= driver   */

{
 	rw_state_p p;
 	int res = -1;
	int rwmode = parm->rwmode;
 	
 	size_trans = ((min(parm->reqlen, chd->real_size) 
			+ BYTE_IN_TRWD - 1)  / BYTE_IN_TRWD);

#if MBKP_DBG
	printk("size_trans = 0x%lx\n", size_trans);
#endif /* MBKP_DBG */

	addr_dma = chd->dma_busa;

#ifdef IO_MASK	
	if (xsp->mask_set == 0) {
		WRR(xsp->regbase,INTR_M_WD, 
		       	0 | INTR_M1 | INTR_M2 | INTR_M3);
		xsp->mask_set = 1; 
		printk("Начальная маска установлена: <%x>\n",
			 0 | INTR_M1 | INTR_M2 | INTR_M3);
	 };
#endif /* IO_MASK */
#if MBKP_DBG
	printk("RW_MODE = %x: %s\n",rwmode,
			msg_by_code(rwmode, &rwmods[0], 
			sizeof(rwmods)/sizeof(code_msg_t))
		);    	
#endif /* MBKP_DBG */
	switch (kop) {

	case MBKP_IOC_READ:
		dbgmbkp("**** mbkp_iocrw: kop = MBKP_IOC_READ\n");	
		p 	= &xsp->rw_states[0];
		spin_mutex_enter(&p->lock); 
		parm->err_no = 0;
		/* все операции чтения должны вернуть доставленный деск	*/
		if (p->stat == MBKP_E_URGENT) {
			parm->err_no 	= MBKP_E_URGENT;
			parm->acclen 	= p->last_desk;
			printk("ALL_READ: desc=%x\n",p->last_desk); 
			p->stat 	= 0;
#if MBKP_IO_TRACE
			printk("MBKP_IOC_READ[%u,%u]: MBKP_E_URGENT\n",
				instance, channel);
#endif /* MBKP_IO_TRACE */
			goto mux_exit;
		}
#if MBKP_IO_TRACE
		printk("MBKP_IOC_READ[%u,%u]: BEGIN stat=%s - 0x%x\n",
			instance, channel,
			msg_by_code(p->stat, &ioctls[0], 
			     	      sizeof(ioctls) / sizeof(code_msg_t) 
			           ), p->stat 
			);
#endif /* MBKP_IO_TRACE */
		
		if (p->stat != 0) { 			/* идет обмен */
			if (rwmode == MBKP_IOC_CHECK) {
				if (p->chd_p != chd) {
					parm->err_no = MBKP_IOC_DIFCH;
					parm->rwmode = chd->channel;
					goto mux_exit;
				}
				goto WAIT_READ;
			}
			if (rwmode == MBKP_IOC_POLL) { 
				parm->err_no = MBKP_E_PENDING;
				parm->rwmode = p->stat;
				goto mux_exit;
			}
			
			/* MBKP_IOC_WAIT, MBKP_IOC_NOWAIT - недопустимы */
			parm->err_no = MBKP_E_PENDING;
			parm->rwmode = p->stat;
			goto mux_exit;
		}
		
		/* канал чтения свободен */
		if (rwmode == MBKP_IOC_CHECK) {
			parm->err_no = MBKP_IOC_NOTRUN;
			parm->rwmode = 0;
			goto mux_exit;
		}
		if (rwmode == MBKP_IOC_POLL) { 
#if MBKP_IO_TRACE
			printk("MBKP_IOC_READ[%u,%u]: MBKP_IOC_POLL\n",
				instance, channel);
#endif /* MBKP_IO_TRACE */
			parm->err_no = parm->rwmode = 0;
			goto mux_exit;
		}

	/*	START_READ:*/	/* rwmode = {MBKP_IOC_WAIT, MBKP_IOC_NOWAIT} */
		p->int_ac = 0;
#if MBKP_IO_TRACE
#if NEW_MBKP
		printk("MBKP_IOC_READ[%u,%u]: START_READ, worl=0x%lx, cnt_tr = 0x%x\n",
			instance, channel, size_trans, cnt_tr((uint_t)size_trans));
#else 
		printk("MBKP_IOC_READ[%u,%u]: START_READ, worl=0x%lx, cnt_tr = 0x%lx\n",
			instance, channel, size_trans, size_trans);
#endif /* NEW_MBKP */
#endif /* MBKP_IO_TRACE */
		p->chd_p = chd; 
		p->orcnt = (uint_t)size_trans;
		p->stat = MBKP_IOC_READ; 
//		RDR(xsp->regbase, SW_TRBA_RCV1); /* уст реж 'прием массива' */
		WRR(xsp->regbase, VA_RCV1, addr_dma);
		
#if NEW_MBKP
                WRR(xsp->regbase, CNT_RCV1, cnt_tr((uint_t)size_trans) );
#else
                WRR(xsp->regbase, CNT_RCV1, (uint_t)size_trans); /* старт READ */
#endif

		if (rwmode == MBKP_IOC_NOWAIT) { /* начата read - окончания не 
						    ждать */
			parm->err_no = 0;
			parm->rwmode = MBKP_IOC_NOWAIT;
			
			goto mux_exit;
		}		

		WAIT_READ: /* rwmode = {MBKP_IOC_WAIT, MBKP_IOC_CHECK} */
#if MBKP_IO_TRACE
			printk("MBKP_IOC_READ[%u,%u]: WAIT_READ, int_ac=%x\n",
			instance, channel, p->int_ac);
#endif /* MBKP_IO_TRACE */
#if INTERRUPT_REG_DEBUG
		mcst_rg = mcst_read(INTERRUPT_REG_BASE);
		mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
		dbgmbkp("mbkp_ioctl WAIT_READ before cv_timedwait mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx\n", 
				mcst_rg, mcst_rg_mask);
#endif /* INTERRUPT_REG_DEBUG */
		parm->err_no = 0;
		if (p->int_ac) {
				
			goto SYNC_READ;
		}
		
		drv_getparm(LBOLT, &cur_clock);
		tick = (clock_t)cur_clock + drv_usectohz(p->timer);
		if (cv_spin_timedwait(&p->cv, &p->lock, tick) == -1) {
			parm->err_no = MBKP_E_TIMER;
			ddi_dma_sync(dip, (dma_addr_t)addr_dma,
				size_trans, PCI_DMA_FROMDEVICE);
#if NEW_MBKP
                        parm->acclen =
                           calc_len_tr(p->orcnt,
                                RDR(xsp->regbase,CNT_RCV1) & SGCNT_MASK
                           ) * BYTE_IN_TRWD;
#else
                        parm->acclen =
                           calc_len(p->orcnt,
                                RDR(xsp->regbase,CNT_RCV1) & SGCNT_MASK
                           ) * BYTE_IN_TRWD;
#endif /* NEW_MBKP */
#if MBKP_IO_TRACE
			printk("MBKP_IOC_READ[%u,%u]: TIMER wfinl=%x\n",
				  instance, channel, 
				  RDR(xsp->regbase,CNT_RCV1) & SGCNT_MASK
				);
#endif /* MBKP_IO_TRACE */
  			p->stat = 0;
#if INTERRUPT_REG_DEBUG
			mcst_rg = mcst_read(INTERRUPT_REG_BASE);
			mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
			dbgmbkp("mbkp_ioctl WAIT_READ after cv_timedwait mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx\n", 
					mcst_rg, mcst_rg_mask);
#endif /* INTERRUPT_REG_DEBUG */
			goto mux_exit;
		}
#if INTERRUPT_REG_DEBUG
		mcst_rg = mcst_read(INTERRUPT_REG_BASE);
		mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
		dbgmbkp("mbkp_ioctl WAIT_READ after cv_timedwait mcst_rg = 0x%lx, mcst_rg_mask = 0%lx\n", 
				mcst_rg, mcst_rg_mask);
#endif /* INTERRUPT_REG_DEBUG */
		SYNC_READ:
#if MBKP_IO_TRACE
			printk("MBKP_IOC_READ[%u,%u]: SYNC_READ\n",
			instance, channel);
#endif /* MBKP_IO_TRACE */
	        /*ddi_dma_sync(chd->dma_handle, 0, chd->real_size,
			DDI_DMA_SYNC_FORCPU);*/
		ddi_dma_sync(dip, (dma_addr_t)addr_dma,
				size_trans, PCI_DMA_FROMDEVICE);
#if NEW_MBKP
                parm->acclen =  calc_len_tr(p->orcnt,
                                         RDR(xsp->regbase,CNT_RCV1) & SGCNT_MASK
                                        ) * BYTE_IN_TRWD;
#else
                parm->acclen =  calc_len(p->orcnt,
                                         RDR(xsp->regbase,CNT_RCV1) & SGCNT_MASK
                                        ) * BYTE_IN_TRWD;
#endif /* NEW_MBKP */
#if MBKP_IO_TRACE
		printk("MBKP_IOC_READ[%u,%u]: FINISH READ: len=%lu, wfinl=%x\n",
			instance, channel, parm->acclen,
			RDR(xsp->regbase,CNT_RCV1) & SGCNT_MASK
			); 
#endif /* MBKP_IO_TRACE */
		p->stat = 0;
	/*	if (p->descen == 1) 
			WRR(xsp->regbase,SW_TRBA_RCV1,0);*/ /* уст реж 'прием деск' */
		res = 0;
#if MBKP1
		if ( (p->evs ^ BUF_RCV1) != 0) {
#if MBKP_IO_TRACE
		printk("MBKP_IOC_READ: p->evs ^ BUF_RCV1, p->evs = 0x%x\n", p->evs);
#endif
#else
		if ( (p->evs ^ M2MAS_RCV1) != 0) {
#if MBKP_IO_TRACE
		printk("MBKP_IOC_READ: p->evs ^ M2MAS_RCV1, p->evs = 0x%x\n", p->evs);
#endif
#endif /* MBKP1 */
			parm->err_no = MBKP_ERREAD;
			parm->rwmode = p->evs;
			goto mux_exit;
		}
		break;
#if MBKP1

	case MBKP_IOC_WRITE:
		dbgmbkp("**** mbkp_iocrw: kop = MBKP_IOC_WRITE\n");		
		p = &xsp->rw_states[1];
		parm->err_no = 0;
		spin_mutex_enter(&p->lock); 
#if MBKP_IO_TRACE
		printk("MBKP_IOC_WRITE[%u,%u]: BEGIN stat=%s - 0x%x\n",
			instance, channel,
			msg_by_code(p->stat, &ioctls[0], 
			     	      sizeof(ioctls) / sizeof(code_msg_t) 
			           ),p->stat   
			);
#endif /* MBKP_IO_TRACE */
		if (p->stat != 0) { 			/* идет обмен */
			if (rwmode == MBKP_IOC_CHECK) {
				if (p->chd_p != chd) {
					parm->err_no = MBKP_IOC_DIFCH;
					parm->rwmode = chd->channel;
					goto mux_exit;
				}
				goto WAIT_WRITE;
			}
			if (rwmode == MBKP_IOC_POLL) { 
				parm->err_no = MBKP_E_PENDING;
				parm->rwmode = p->stat;
				goto mux_exit;
			}
			
			/* MBKP_IOC_WAIT, MBKP_IOC_NOWAIT - недопустимы */
			parm->err_no = MBKP_E_PENDING;
			parm->rwmode = p->stat;
			goto mux_exit;
		}

		
		/* канал записи свободен */
		if (rwmode == MBKP_IOC_CHECK) {
			parm->err_no = MBKP_IOC_NOTRUN;
			parm->rwmode = 0;
			goto mux_exit;
		}
		if (rwmode == MBKP_IOC_POLL) { 
#if MBKP_IO_TRACE
			printk("MBKP_IOC_WRITE[%u,%u]: MBKP_IOC_POLL\n",
				instance, channel);
#endif /* MBKP_IO_TRACE */
			parm->err_no = parm->rwmode = 0;
			goto mux_exit;
		}
		
	/*	START_WRITE:*/	/* rwmode = {MBKP_IOC_WAIT, MBKP_IOC_NOWAIT} */
		p->int_ac = 0;
#if MBKP_IO_TRACE
#if NEW_MBKP
			printk("MBKP_IOC_WRITE[%u,%u]: START_WRITE, worl=0x%lx, cnt_tr = 0x%x\n",
				  instance, channel, size_trans, cnt_tr((uint_t)size_trans));
#else
			printk("MBKP_IOC_WRITE[%u,%u]: START_WRITE, worl=0x%lx, cnt_tr = 0x%lx\n",
				  instance, channel, size_trans, size_trans);
#endif /* NEW_MBKP */ 
#endif /* MBKP_IO_TRACE */
		p->chd_p = chd; 
		p->orcnt = (uint_t)size_trans;
		p->stat = MBKP_IOC_WRITE; 
		WRR(xsp->regbase,VA_TR, addr_dma);
		
#if NEW_MBKP
                WRR(xsp->regbase, CNT_TR, cnt_tr((uint_t)size_trans) );
#else
                WRR(xsp->regbase, CNT_TR, (uint_t)size_trans); /* старт WRITE */
#endif
		if (rwmode == MBKP_IOC_NOWAIT) { /* начата write - окончания не ждать */
			parm->err_no = 0;
			parm->rwmode = MBKP_IOC_NOWAIT;
			
			goto mux_exit;
		}

		WAIT_WRITE: /* rwmode = {MBKP_IOC_WAIT, MBKP_IOC_CHECK} */
#if MBKP_IO_TRACE
			printk("MBKP_IOC_WRITE[%u,%u]: WAIT_WRITE, int_ac=%x\n",
			instance, channel, p->int_ac);
#endif /* MBKP_IO_TRACE */
#if INTERRUPT_REG_DEBUG
		mcst_rg = mcst_read(INTERRUPT_REG_BASE);
		mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
		dbgmbkp("mbkp_ioctl WAIT_WRITE before cv_timedwait mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx\n", 
				mcst_rg, mcst_rg_mask);
#endif /* INTERRUPT_REG_DEBUG */
		parm->err_no = 0;
		if (p->int_ac) {
			
			goto SYNC_WRITE;
		}
			
		drv_getparm(LBOLT, &cur_clock);
		tick = (clock_t)cur_clock + drv_usectohz(p->timer);
		if (cv_spin_timedwait(&p->cv, &p->lock, tick) == -1) {		
			parm->err_no = MBKP_E_TIMER;
	        	/*ddi_dma_sync(chd->dma_handle, 0, chd->real_size,
				DDI_DMA_SYNC_FORDEV);*/
			ddi_dma_sync(dip, (dma_addr_t)addr_dma,
				size_trans, PCI_DMA_TODEVICE);
#if NEW_MBKP
                        parm->acclen =
                            calc_len_tr(p->orcnt,
                                 RDR(xsp->regbase,CNT_TR) & SGCNT_MASK
                        ) * BYTE_IN_TRWD;
#else
                        parm->acclen =
                            calc_len(p->orcnt,
                                 RDR(xsp->regbase,CNT_TR) & SGCNT_MASK
                        ) * BYTE_IN_TRWD;
#endif /* NEW_MBKP */
#if MBKP_IO_TRACE
			printk("MBKP_IOC_WRITE[%u,%u]: TIMER wfinl=%x\n",
				  instance, channel, 
				  RDR(xsp->regbase,CNT_TR) & SGCNT_MASK
				);
#endif /* MBKP_IO_TRACE */
			p->stat = 0;
#if INTERRUPT_REG_DEBUG
			mcst_rg = mcst_read(INTERRUPT_REG_BASE);
			mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
			dbgmbkp("mbkp_ioctl WAIT_WRITE after cv_timedwait mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx\n", 
					mcst_rg, mcst_rg_mask);
#endif /* INTERRUPT_REG_DEBUG */
			goto mux_exit;
		}
#if INTERRUPT_REG_DEBUG
		mcst_rg = mcst_read(INTERRUPT_REG_BASE);
		mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
		dbgmbkp("mbkp_ioctl WAIT_WRITE after cv_timedwait mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx\n", 
				mcst_rg, mcst_rg_mask);
#endif /* INTERRUPT_REG_DEBUG */
		SYNC_WRITE:
#if MBKP_IO_TRACE
			printk("MBKP_IOC_WRITE[%u,%u]: SYNC_WRITE\n",
			instance, channel);
#endif /* MBKP_IO_TRACE */
		ddi_dma_sync(dip, (dma_addr_t)addr_dma,
				size_trans, PCI_DMA_TODEVICE);
#if NEW_MBKP
                parm->acclen =
                        calc_len_tr(p->orcnt,
                                 RDR(xsp->regbase,CNT_TR) & SGCNT_MASK
                                ) * BYTE_IN_TRWD;
#else
                parm->acclen =
                        calc_len(p->orcnt,
                                 RDR(xsp->regbase,CNT_TR) & SGCNT_MASK
                                ) * BYTE_IN_TRWD;
#endif  /* NEW_MBKP */
#if MBKP_IO_TRACE
		printk("MBKP_IOC_WRITE[%u,%u]: FINISH WRITE: len=%u, wfinl=%x\n",
			instance, channel, parm->acclen,
			RDR(xsp->regbase,CNT_TR) & SGCNT_MASK
				
			); 
#endif /* MBKP_IO_TRACE */
		p->stat = 0;
		res = 0;
		if ( (p->evs ^ BUF_TR) != 0) {
			parm->err_no = MBKP_ERWRITE;
			parm->rwmode = p->evs;
			goto mux_exit;
		}
		break;
#else

//#include "read_a.c"		
	case MBKP_IOC_RDALT:
		dbgmbkp("**** mbkp_iocrw, kop = MBKP_IOC_RDALT\n");
		p = &xsp->rw_states[1];
		parm->err_no = 0;
		spin_mutex_enter(&p->lock); 
#if MBKP_IO_TRACE
		printk("MBKP_IOC_RDALT[%u,%u]: BEGIN stat=%s - 0x%x\n",
			instance, channel,
			msg_by_code(p->stat, &ioctls[0], 
			     	      sizeof(ioctls) / sizeof(code_msg_t) 
			           ),p->stat   
			);
#endif /* MBKP_IO_TRACE */
		if (p->stat != 0) { 			/* идет обмен */
			if (rwmode == MBKP_IOC_CHECK) {
				if (p->chd_p != chd) {
					parm->err_no = MBKP_IOC_DIFCH;
					parm->rwmode = chd->channel;
					goto mux_exit;
				}
				goto WAIT_RDALT;
			}
			if (rwmode == MBKP_IOC_POLL) { 
				parm->err_no = MBKP_E_PENDING;
				parm->rwmode = p->stat;
				goto mux_exit;
			}
			
			/* MBKP_IOC_WAIT, MBKP_IOC_NOWAIT - недопустимы */
			parm->err_no = MBKP_E_PENDING;
			parm->rwmode = p->stat;
			goto mux_exit;
		}

		
		/* канал свободен */
		if (rwmode == MBKP_IOC_CHECK) {
			parm->err_no = MBKP_IOC_NOTRUN;
			parm->rwmode = 0;
			goto mux_exit;
		}
		if (rwmode == MBKP_IOC_POLL) { 
#if MBKP_IO_TRACE
			printk("MBKP_IOC_RDALT[%u,%u]: MBKP_IOC_POLL\n",
				instance, channel);
#endif /* MBKP_IO_TRACE */
			parm->err_no = parm->rwmode = 0;
			goto mux_exit;
		}
		
	/*	START_RDALT:*/	/* rwmode = {MBKP_IOC_WAIT, MBKP_IOC_NOWAIT} */
		p->int_ac = 0;
#if MBKP_IO_TRACE
#if NEW_MBKP
			printk("MBKP_IOC_RDALT[%u,%u]: START_RDALT, worl=0x%lx, cnt_tr = 0x%x\n",
					instance, channel, size_trans, cnt_tr((uint_t)size_trans));
#else
			printk("MBKP_IOC_RDALT[%u,%u]: START_RDALT, worl=0x%lx, cnt_tr = 0x%lx\n",
					instance, channel, size_trans, size_trans);
#endif /* NEW_MBKP */
#endif /* MBKP_IO_TRACE */
		p->chd_p = chd; 
		p->orcnt = (uint_t)size_trans;
		p->stat = MBKP_IOC_RDALT; 
		WRR(xsp->regbase,VA_RCV2, addr_dma);
		
#if NEW_MBKP
                WRR(xsp->regbase, CNT_RCV2, cnt_tr((uint_t)size_trans) );
#else
                WRR(xsp->regbase, CNT_RCV2, (uint_t)size_trans); /* старт READ CH#2 */
#endif
		if (rwmode == MBKP_IOC_NOWAIT) { /* начата оп - окончания не 
						    ждать */
			parm->err_no = 0;
			parm->rwmode = MBKP_IOC_NOWAIT;
			
			goto mux_exit;
		}

		WAIT_RDALT: /* rwmode = {MBKP_IOC_WAIT, MBKP_IOC_CHECK} */
#if MBKP_IO_TRACE
			printk("MBKP_IOC_RDALT[%u,%u]: WAIT_RDALT, int_ac=%x\n",
					instance, channel, p->int_ac);
#endif /* MBKP_IO_TRACE */
		parm->err_no = 0;
		if (p->int_ac) {
			
			goto SYNC_RDALT;
		}
			
		drv_getparm(LBOLT, &cur_clock);
		tick = (clock_t)cur_clock + drv_usectohz(p->timer);
		if (cv_spin_timedwait(&p->cv, &p->lock, tick) == -1) {
			parm->err_no = MBKP_E_TIMER;
	        	/*ddi_dma_sync(chd->dma_handle, 0, chd->real_size,
				DDI_DMA_SYNC_FORDEV);*/
			ddi_dma_sync(dip, (dma_addr_t)addr_dma,
				size_trans, PCI_DMA_TODEVICE);
#if NEW_MBKP
                        parm->acclen =
                            calc_len_tr(p->orcnt,
                                        RDR(xsp->regbase,CNT_RCV2) & SGCNT_MASK
                                    ) * BYTE_IN_TRWD;
#else
                        parm->acclen =
                            calc_len(p->orcnt,
                                        RDR(xsp->regbase,CNT_RCV2) & SGCNT_MASK
                                    ) * BYTE_IN_TRWD;
#endif /* NEW_MBKP */
#if MBKP_IO_TRACE
			printk("MBKP_IOC_WRITE[%u,%u]: TIMER wfinl=%x\n",
				  instance, channel, 
				  RDR(xsp->regbase,CNT_RCV2) & SGCNT_MASK);
#endif /* MBKP_IO_TRACE */
			p->stat = 0;
			goto mux_exit;
		}
		
		SYNC_RDALT:
#if MBKP_IO_TRACE
			printk("MBKP_IOC_RDALT[%u,%u]: SYNC_RDALT wfinl=%x\n",
				 instance, channel,
				 RDR(xsp->regbase,CNT_RCV2) & SGCNT_MASK);
#endif /* MBKP_IO_TRACE */
	        /*ddi_dma_sync(chd->dma_handle, 0, chd->real_size,
			DDI_DMA_SYNC_FORDEV);*/
		ddi_dma_sync(dip, (dma_addr_t)addr_dma,
				size_trans, PCI_DMA_TODEVICE);
#if NEW_MBKP
                parm->acclen =
                        calc_len_tr(p->orcnt,
                                 RDR(xsp->regbase,CNT_RCV2) & SGCNT_MASK
                                ) * BYTE_IN_TRWD;
#else
                parm->acclen =
                        calc_len(p->orcnt,
                                 RDR(xsp->regbase,CNT_RCV2) & SGCNT_MASK
                                ) * BYTE_IN_TRWD;
#endif /* NEW_MBKP */
#if MBKP_IO_TRACE
		printk("MBKP_IOC_RDALT[%u,%u]: FINISH RDALT: len=%lu\n",
			instance, channel, parm->acclen); 
#endif /* MBKP_IO_TRACE */
		p->stat = 0;
		res = 0;
		if ( (p->evs ^ M2MAS_RCV2) != 0) {
			parm->err_no = MBKP_ERREAD1;
			parm->rwmode = p->evs;
			goto mux_exit;
		}
		break;

#endif /* MBKP1 */

	case MBKP_IOC_DR:			/* desc read */
#if MBKP_IO_TRACE
		printk("**** mbkp_iocrw: kop = MBKP_IOC_RD\n");
#endif /* MBKP_IO_TRACE */
		p = &xsp->rw_states[0];
		parm->err_no = 0;
		spin_mutex_enter(&p->lock);
		if (p->stat != 0) {
			if (p->stat == MBKP_E_URGENT) {
#if MBKP_IO_TRACE
				printk("MBKP_IOC_DR[%u,%u]: MBKP_E_URGENT\n",
					instance, channel);
#endif /* MBKP_IO_TRACE */
				goto GET_DESK;
			}
			parm->err_no = MBKP_E_PENDING;
			goto mux_exit;
		}
		p->chd_p = chd; 
		p->descen = (uchar_t)parm->reqlen;
#if MBKP_IO_TRACE
			printk("MBKP_IOC_DR[%u,%u]: WAIT_DESC, int_ac=%x\n",
			instance, channel, p->int_ac);
#endif /* MBKP_IO_TRACE */
		parm->err_no = 0;
#if STATE_DEBUG
		printk("\nmbkp_ioctl DR: Установка регистра режима приема дескриптора\n");
#endif /* STATE_DEBUG */
		
		WRR(xsp->regbase,SW_TRBA_RCV1, 0x10); /* on TRBA rcv+tr */
#if STATE_DEBUG
		printk("\n ***** mbkp_ioctl DR: Регистр состояния после установки Режима приема дескриптора:\n");
		PRINT_STATE(xsp);
#endif /* STATE_DEBUG */
		drv_getparm(LBOLT, &cur_clock);
		tick = (clock_t)cur_clock + drv_usectohz(p->timer);
		if (cv_spin_timedwait(&p->cv, &p->lock, tick) == -1) {
		/*	if (p->descen == 0) 
				RDR(xsp->regbase,SW_TRBA_RCV1); */
				/* восстановить запрет 'прием деск' */
			parm->err_no = MBKP_E_TIMER;
			parm->acclen = 0;	
			p->stat = 0;
			goto mux_exit;
		}
/*		if (p->descen == 0) 
			RDR(xsp->regbase,SW_TRBA_RCV1); */
			/* восстановить запрет 'прием деск' */

		GET_DESK:
		p->stat = 0;
		parm->err_no = 0;
		parm->acclen = p->last_desk;
		res = 0;
		break;

#if MBKP1

	case MBKP_IOC_DW:			/* desc write */
		p = &xsp->rw_states[1];
#if MBKP_IO_TRACE
		printk("**** mbkp_iocrw: kop = MBKP_IOC_DW, DESC=0x%lx\n", parm->reqlen);
#endif /* MBKP_IO_TRACE */
		spin_mutex_enter(&p->lock);
		if (p->stat != 0) {
			parm->err_no = MBKP_E_PENDING;
#if MBKP_IO_TRACE
		printk("**** mbkp_iocrw: MBKP_E_PENDING\n");
#endif /* MBKP_IO_TRACE */			
			goto mux_exit;
		}
		/* chanel free of write array - try to POOL_DESC_WR_FREE */
		if (RDR(xsp->regbase, INTR_M_WD)&WRDESC_BUSY) {
			parm->err_no = MBKP_DESC_DISABLED;
#if MBKP_IO_TRACE
			printk("**** mbkp_iocrw: MBKP_DESC_DISABLED\n");
#endif /* MBKP_IO_TRACE */
			goto mux_exit;
		}		
		p->chd_p = chd;

#if STATE_DEBUG
/*		printk("mbkp_ioctl: Установка регистра режима приема дескриптора в 1,
			Значение читается в регистре состояния\n");
		WRR(xsp->regbase, SW_TRBA_RCV1, 1);*/
		printk("\n ***** mbkp_ioctl DW: Регистр состояния до записи дескриптора: \n");
		PRINT_STATE(xsp);

		printk("\nmbkp_ioctl DW: Запись дескриптора в регистр дескриптора передатчика \n");

#endif /* STATE_DEBUG */
		WRR(xsp->regbase, WRCMD_RCV1, (uint_t)parm->reqlen);

#if STATE_DEBUG
		printk("\n ***** mbkp_ioctl DW: Регистр состояния после записи дескриптора: \n");
		PRINT_STATE(xsp);
#endif /* STATE_DEBUG */

		parm->acclen = 1; 
#if (MBKP_IO_TRACE | DESK_DBG )
		printk("**** mbkp_iocrw: DESC POSTED: 0x%lx\n", parm->reqlen); 
#endif /* (MBKP_IO_TRACE | DESK_DBG ) */
		p->stat = 0;
		res = 0;
		break;
#else 
	case MBKP_IOC_RDESCALT:		/* desc read from al chanel */
		p = &xsp->rw_states[1];
#if MBKP_IO_TRACE
		printk("**** mbkp_iocrw: kop = MBKP_IOC_RDESCALT\n");
#endif /* MBKP_IO_TRACE */
		parm->err_no = 0;
		spin_mutex_enter(&p->lock); 
		if (p->stat != 0) {
			if (p->stat == MBKP_E_URGENT) {
#if MBKP_IO_TRACE
				printk("MBKP_IOC_RDESCALT[%u,%u]: MBKP_E_URGENT\n",
					instance, channel);
#endif /* MBKP_IO_TRACE */
				goto GET_DESK_ALT;
			}
			parm->err_no = MBKP_E_PENDING;
			goto mux_exit;
		}
		p->chd_p = chd; 
		p->descen = (uchar_t)parm->reqlen;
#if MBKP_IO_TRACE
			printk("MBKP_IOC_RDESCALT[%u,%u]: WAIT_DESC, int_ac=%x\n",
			instance, channel, p->int_ac);
#endif /* MBKP_IO_TRACE */
		parm->err_no = 0;
		
		WRR(xsp->regbase,SW_TRBA_RCV2, 0); /* on TRBA rcv+tr */
		drv_getparm(LBOLT, &cur_clock);
		tick = (clock_t)cur_clock + drv_usectohz(p->timer);
		if (cv_spin_timedwait(&p->cv, &p->lock, tick) == -1) {
		/*	if (p->descen == 0) 
				RDR(xsp->regbase,SW_TRBA_RCV2); */
				/* восстановить запрет 'прием деск' */
			parm->err_no = MBKP_E_TIMER;
			parm->acclen = 0;	
			p->stat = 0;
			goto mux_exit;
		}
/*		if (p->descen == 0) 
			RDR(xsp->regbase,SW_TRBA_RCV2); */
			/* восстановить запрет 'прием деск' */

		GET_DESK_ALT:
		p->stat = 0;
		parm->err_no = 0;
		parm->acclen = p->last_desk2;
		res = 0;
		break;

#endif /* MBKP1 */

	case MBKP_IOC_DE:			/* desc read */
		p = &xsp->rw_states[0];
		parm->err_no = 0;
#if MBKP_IO_TRACE
	 	printk("**** mbkp_iocrw, kop = MBKP_IOC_DE\n");
#endif /* MBKP_IO_TRACE */
		spin_mutex_enter(&p->lock); 
		if (p->stat != 0) {
			parm->err_no = MBKP_E_PENDING;
			goto mux_exit;
		}
		p->chd_p = chd; 
		p->descen = (uchar_t)parm->reqlen;
		if (p->descen)
			WRR(xsp->regbase,SW_TRBA_RCV1, 0); /* on TRBA rcv+tr */
		else
			RDR(xsp->regbase,SW_TRBA_RCV1); /* off TRBA rcv+tr */
		p->stat = 0;
		res = 0;
		break;

		
	default :
		printk("**** mbkp_iocrw: kop = default, should never happen, FAILED\n");	
		return -1;
	}

mux_exit:
	spin_mutex_exit(&p->lock);
	dbgmbkp("**** mbkp_iocrw FINISH, res=%d ****\n", res);
	return res;
}
	

#else 

//#include "rw_model.c"
	
#endif /* MBKP_MODEL */
	dbgmbkp("**** mbkp_iocrw FINISH, len=%ld ****\n", (unsigned long)len);
	return len;
}

/*
 * For Linux add mbkp_init() & mbkp_exit()
 * to call mbkp_attach & mbkp_detach for each instance
 */
 
static int
__init mbkp_init(void)
{
	int 		rval;
	dev_info_t	*dip;

#if INTERRUPT_REG_DEBUG	
	mcst_rg = mcst_read(INTERRUPT_REG_BASE);
	mcst_rg_mask = mcst_read(INTERRUPT_REG_BASE + INTERRUPT_MASK_REG);
#endif /* INTERRUPT_REG_DEBUG */
	
	dbgmbkp("***** mbkp_init: START mcst_rg = 0x%lx, mcst_rg_mask = 0x%lx *****\n", 
				mcst_rg, mcst_rg_mask);
	rval = ddi_rgstr_dev(board_name, DDI_SBUS_SPARC, &mbkp_fops);
	if (!rval) {
		printk("mvp_init: ENODEV\n");
		return(-ENODEV);
	}

   	mbkp_instances = 0;
   	for (;;) {
   		dip = ddi_inst_dip(board_name, mbkp_instances);
   		if (!dip) break;
   		rval = ddi_init_soft(dip, sizeof(mbkp_state_t));
   		if (rval) return rval;
   		rval = mbkp_attach(dip);
   		if (mbkp_attach < 0) {
   			printk("mbkp_init: mbkp_attach < 0\n");
   			return -EFAULT;
   		}
   		mbkp_instances++;   		
   	}
	if (mbkp_instances == 0) {
		printk("mbkp_init: Device not found\n");
		return -ENODEV;
	}
	dbgmbkp("***** mbkp_init: FINISH inst %d *****\n", mbkp_instances);
	return 0;
}

static void  
__exit mbkp_exit(void)
{
	int		i;
	dev_info_t	*dip = NULL;
	int error = 0;

	dbgmbkp("***** mbkp_exit: START *****\n");
 	for ( i = 0; i < mbkp_instances; i++ ) {
 		dip = ddi_inst_dip(board_name, i);
 		error = mbkp_detach(dip);
 	} 
	if (!error){
		error = ddi_rm_dir(dip); 
		if (error)
			printk("mbkp_exit: ddi_rm_dir failed, error = %d\n", error);
	}
	dbgmbkp("***** mbkp_exit: FINISH *****\n");
}

/*
 * For Linux add these lines
 */

module_init(mbkp_init);
module_exit(mbkp_exit);
MODULE_LICENSE("Copyright by MCST 2002");
MODULE_DESCRIPTION("MBKP driver");


