/*
 * Copyright (c) 1997 by MCST.
*/

/*             ---------  MOP.C  LINUX  ---------     */

//
// 2005.6.14 (vt 14 ijunja 2005 g)  wait_finish_com
// 2005.5.23(mn 2 мая 2005 г.) прод убирать закоментир-е ре части драйвера
// 2005.5.20(20 мая 2005 г.) убираю закоментированные ранее части драйвера
// 2005.2.4 15.10 2005.2.14 15.15__________________
// 2005.2.4 2005.2.4 15.10 2005.2.14 15.15__________________
// 2004.7.6-emv-edit-mop_open-INTR_IN
//                  -mop_open-mask -> intr_mask
// 2004.8.4-emv-edit-    DBGMOP_MODE    1
//                  -   (n_ir != 3)
//                  -   self_test return(0)
// 2004.8.17-emv-edit-  mop_chpoll ins debug
//                   -  mop_chpoll ins debug
//                   -  mop_open -  add
// 2004.8.18-emv-edit-  mop_intr_handler+MOP_SEND_INTR
//			+mop_chpoll+
// 2004.8.23-emv-edit-  mop_attach regs_mapped
// 2004.10.29
// 2004.11.01   doing mmap  2004.11.10
// 2004.11.22   ending mmap  also no debugging  
// 2004.11.29   ending intr_handler - translating, no debugging 
// 2004.12.01 tester  2004.12.07  2004.12.09
// 2004.12.22 new MOPIO_GET_REG 2005.1.14
// 2005.01.28 MOP_START_MP, me90_io.h 

#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/mm.h>

#include <linux/timex.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>

#include <linux/delay.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/dma.h>

#include <linux/mcst/ddi.h>

#include <linux/mcst/mop.h>
#include "mopvar.h"
#include <linux/mcst/mcst_selftest.h>

/*TODO: move p2s_info_t definition somewhere else */
#include <../drivers/pci2sbus/internal.h>

#ifdef	__e2k__
#if IS_ENABLED(CONFIG_PCI2SBUS)
#include <linux/mcst/p2ssbus.h>
#include <linux/of_platform.h>
#endif
#elif defined(__sparc__)
#include <linux/of_platform.h>
#include <asm/sbus.h>
#endif

// /proc/sys/debug/mop_debug trigger
int mop_debug = 0;
int mop_debug_more = 0;

#define DBGMOP_MODE
#undef DBGMOP_MODE

#define DBGMOPDETAIL_MODE
#undef DBGMOPDETAIL_MODE

#if defined(DBGMOP_MODE)
#define dbgmop                  printk
#else
#define dbgmop                  if ( mop_debug ) printk
#endif

#if defined(DBGMOPDETAIL_MODE)
#define dbgmopdetail            printk
#else
#define dbgmopdetail            if ( mop_debug_more ) printk
#endif

#define CHP             printk(KERN_ERR "%s:%s():%d\n", __FILE__, __func__, __LINE__);
#undef CHP

#define OPEN_EXCL			1
static int mop_instances;
static int mop_major;

#define MOP_NAME	"MCST,mop"
#define MOP_DIR		"mop"

#define MAX_MOP_INSTANCES	16
static mop_state_t	*mop_states[MAX_MOP_INSTANCES];

#define VERSION "  ver SP-drv 221 LINUX  20.06.2005 monday cv_init-one par"
#ifdef KKKK
	ver 210 of 04.02.2004 вер для LINUX
	ver 203 of 19.11.2003 вер для передачи инф-и чере3
	ver 202 of 03.11.2003 вер для контроля работоспособности ЦВ
	ver 201 of 29.10.2003 вер для контроля работоспособности ЦВ
	ver 200 of 27.10.2003 вер для контроля работоспособности ЦВ
	ver 197 of 23.10.2003 вер для контроля работоспособности ЦВ
	ver 196 of 31.10.2000 версия для имитатора
	ver 195 of 14.7.2000  GET_REG_MOP attach
	ver 194 of 28.6.2000  if(PRN) в IOCTL
	ver 193 of 29.5.2000  вер для контроля состояния SPARCa (Семенихина ver 2)
	ver 192 of 17.4.2000  вер для контроля состояния SPARCa (отлажена,  ver 1)
	ver 191 of 10.4.2000  
	ver 190 of 30.3.2000  ioctl RST_BOZU + intr + WAIT
	ver 189 of 23.3.2000  для зап в Бозу ioctl WRITE_RST_ + intr
	ver 188 of 23.3.2000  для зап в Бозу ioctl WRITE_RST_
         2. ioctl для зап зн в  в БОЗУ  (WR1)
         1. Чистка 
	ver 187 of 21.2.2000  intr_errno       
       	ver 183 of 10.2.2000  open-close mop_contrPT                 	  
      	ver 178 of 10.2.2000  create GET_STATE для mop_contrPT                 
        ver 177 of 09.2.2000  корр SET_POLAR,SET_MASK для mop_contrPT          
      	ver 170 of 28.1.2000  анализ работы mopv_control,не призн OUT - комент 
      	ver 163 of 24.1.2000  пр-ка SP др-ра на тст mopv_control MOPIO_SET_FZMC
      	ver 162 of 19.1.2000  проверка SP драйвера на тестах mopv_tests   + 	  
      	ver 158 of 19.1.2000  проверка SP драйвера на тестах mop_exemples +    
      	ver 157 of 17.1.2000  intr=*+intr_handler                              
      	ver 155 of 14.1.2000 отладка функций "обработки прерываний"            
      	ver 153 of 12.1.2000 в mop_intr печатать отн-ое .время прер.           
      	ver 152 of 12.1.2000                                                   
      	ver 144 of 5.1.2000  исключил зап и чт РОБов, вых после 1-го map да да 
	не пишет в регистры ( писать только через putl и читать через getl)  
#endif /* KKKK */

int me90_sbus_clock_freg=0;
int me90_sbus_nsec_cycle=0;
int me90_mp_clock_freg  =0;
int me90_mp_nsec_cycle  =0;

unsigned long mopio_write_bozu_0;
unsigned long mopio_write_bozu_1;
unsigned long mopio_write_bozu_2;
unsigned long mopio_write_bozu_3;
EXPORT_SYMBOL(mopio_write_bozu_0);
EXPORT_SYMBOL(mopio_write_bozu_1);
EXPORT_SYMBOL(mopio_write_bozu_2);
EXPORT_SYMBOL(mopio_write_bozu_3);

/*
 * Prototypes for this module
 */
static	int	mop_probe(struct of_device *op, const struct of_device_id *match);
static	int	mop_open(struct inode *inode, struct file *file);
static	int	mop_close(struct inode *inode, struct file *file);
static	long	mop_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static	int	mop_mmap (struct file *file, struct vm_area_struct *vma);
static	uint_t	mop_chpoll(struct file *file, struct poll_table_struct *wait);

/*
 * Local routines.
 */
static int mop_self_test(mop_state_t *s);
static irqreturn_t mop_intr_handler(int irq, void *arg);
static void	mop_init_info(mop_state_t *s);

/*
 * file_operations of mop
 */
static struct file_operations mop_fops = {
	owner:   THIS_MODULE,
	poll:    mop_chpoll,
	unlocked_ioctl:   mop_ioctl,
	mmap:    mop_mmap,
	open:	 mop_open,
	release: mop_close,
};

typedef struct bmem_trans_desk
{
	caddr_t		mem_address;		/* SPARC memory address */
	caddr_t		mp_bmem_address;	/* MP base memory address */
	size_t		byte_size;		/* byte size of loaded code */
	caddr_t		mp_drv_init_info;	/* pointer of MP driver init info */
	size_t		mp_drv_init_info_size;	/* size of MP driver init info */
	caddr_t		mp_drv_init_info_addr;	/* MP driver init info base memory */
                                       /* address */
} bmem_trans_desk_t;

static	hrtime_t	time_s = 0;
static	hrtime_t	time_p = 0;

#define PRN (state->deb > 0) ? (--state->deb, 1) : 0

#define F_T "%lld,%03lld.%03llds."
#define P_T(tmks) \
	(tmks)/1000000, ((tmks)-((tmks)/1000000)*1000000)/1000, (tmks)%1000

#if defined(CONFIG_SYSCTL)
#include <linux/sysctl.h>

static ctl_table mop_table[] = {
	{
		.procname	= "mop_debug",
		.data		= &mop_debug, 
		.maxlen		= sizeof(mop_debug),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "mop_debug_more",
		.data		= &mop_debug_more, 
		.maxlen		= sizeof(mop_debug_more),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static ctl_table mop_root_table[] = {
	{
		.procname	= "debug",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= mop_table,
	},
	{ }
};

static struct ctl_table_header *mop_sysctl_header;

static void __init mop_sysctl_register(void)
{
	mop_sysctl_header = register_sysctl_table(mop_root_table);
}

static void mop_sysctl_unregister(void)
{
	if ( mop_sysctl_header )
		unregister_sysctl_table(mop_sysctl_header);
}

#else /* CONFIG_SYSCTL */

static void __init mop_sysctl_register(void)
{
}

static void mop_sysctl_unregister(void)
{
}
#endif

/*
 * Driver attach (init) entry point
 */
static int
mop_probe(struct of_device *op, const struct of_device_id *match)
{
	mop_state_t	*state;
	int		intr;
	int		minor;
	int		len, n_reg;
	int		rval;
	char	name[64];
	int		pzu_mapped  = 0;
	int		regs_mapped = 0;
	int		bozu_mapped = 0;
	int		intr_added = 0;
	int		base_faza;
	int		irq_flags = 0;

	/*
	 * Some sanity checking.
	 */
	dbgmop("%s(): start\n", __func__);

	if ( op->num_irqs != 1 ) {
		dbgmop("%s() : #interrupts = %x\n", __func__, op->num_irqs);
		return DDI_FAILURE;
	}

	of_get_property(op->node, "reg", &len);
	n_reg = len/sizeof(struct linux_prom_registers);

	if ( n_reg != 3 ) {
		dbgmop("%s() : #regs = %x\n", __func__, n_reg);
		return DDI_FAILURE;
	}

	mop_major = register_chrdev(0, MOP_NAME, &mop_fops);
	if ( mop_major < 0 ) {
		return mop_major;
	}

	if ( op->resource[0].end - op->resource[0].start < MOP_REG_SIZE ) {
		printk(KERN_ERR "%s() : off < MOP_REG_SIZE off = %ux\n", __func__, op->resource[0].end - op->resource[0].start);
		return DDI_FAILURE;
	}

	/*
	 * Get the soft state for this instance
	 */
	state = ddi_malloc(sizeof(mop_state_t));
	if ( state == NULL )
		return -EFAULT;

	init_waitqueue_head(&(state->pollhead));
	
	/*
	 * Initialize the soft state for this instance
	 */
	state->op = op;
	state->irq = op->irqs[0];
	state->inst	= mop_instances++;
	state->major = mop_major;
	state->open_in = 0;
	state->open_out = 0;
	state->open_rst = 0;
	state->open_mpr = 0;
	state->open_exch = 0;
	state->open_cntl = 0;
	state->open_imt = 0;
	state->open_tst = 0;
	state->open_excl = 0;
	state->intr_mask = 0;
	state->mp_drv_loaded = 0;
	state->deb = 0;

	mop_states[state->inst] = state;

	mop_init_info(state);

	/*
	 * Map in operating registers
	 */
	state->pzu_base = (void *)of_ioremap(&op->resource[0], 0,
					op->resource[0].end - op->resource[0].start + 1,
					MOP_NAME);

	if ( state->pzu_base == NULL ) {
		printk(KERN_ERR "INST %d. of_ioremap() завершена с ошибкой для набора регистров pzu_base\n", state->inst);
		goto err_remap0;
	}

	dbgmopdetail("%s(): regs_mapped pzu_base %p\n", __func__, state->pzu_base );

	state->regs_base = (void *)of_ioremap(&op->resource[1], 0,
					op->resource[1].end - op->resource[1].start + 1,
					MOP_NAME);

	if ( state->regs_base == NULL ) {
		printk(KERN_ERR "INST %d. of_ioremap() завершена с ошибкой для набора регистров regs_base\n", state->inst);
		goto err_remap1;
	}

	dbgmopdetail("%s(): regs_mapped regs_base %p\n", __func__, state->regs_base);

	state->bozu_base = (void *)of_ioremap(&op->resource[2], 0,
					op->resource[2].end - op->resource[2].start + 1,
					MOP_NAME);

	if ( state->bozu_base == NULL ) {
		printk(KERN_ERR "INST %d. of_ioremap() завершена с ошибкой для набора регистров bozu_base\n", state->inst);
		goto err_remap2;
	}

	dbgmopdetail("%s(): regs_mapped bozu_base %p\n", __func__, state->bozu_base);

	mopio_write_bozu_0 = (unsigned long)(state->bozu_base + (MOP_BOZU_RST_COUNTER + 0));
	mopio_write_bozu_1 = (unsigned long)(state->bozu_base + (MOP_BOZU_RST_COUNTER + 4));
	mopio_write_bozu_2 = (unsigned long)(state->bozu_base + (MOP_BOZU_RST_COUNTER + 8));
	mopio_write_bozu_3 = (unsigned long)(state->bozu_base + (MOP_BOZU_RST_COUNTER + 12));

	pzu_mapped  = 1;
	regs_mapped = 1;
	bozu_mapped = 1;

	PUT_MOP_REG(state, tli, close_intr_bit);
	PUT_MOP_REG(state, trm, 1);   /* halt MP */

	if ( GET_MOP_REG(state,0) & 0x0e000 ) {
		PUT_MOP_REG(state, rerr, 0);
		dbgmop( "%s():-7-1 mapped regs= 0x%lx, robs=0x%x ", __func__, 
		(u_long) state->regs_base, GET_MOP_REG(state,0));
	}

	{
		const void *p = of_get_property(op->node, "mop-faza", NULL);;

		( p == NULL ) ? ( base_faza = 0 ) : ( base_faza = *(int *)p );
	}

	state->base_faza = MOP_NS2IN(base_faza);   // ????
	state->faza = state->base_faza;

	/*
	 * mop-state property can be added if required.
	 */
	spin_mutex_init(&(state->intr_lock));
	
#ifdef CONFIG_MCST_RT
	irq_flags |=  IRQF_DISABLED;
#endif
	irq_flags |= IRQF_SHARED;

	if ( (rval = request_threaded_irq(state->irq, &mop_intr_handler, NULL,
		irq_flags, MOP_NAME, (void *)state)) ) {
			printk(KERN_ERR "INST %d. %s(): request_threaded_irq(irq %d) failed\n", state->inst, __func__, state->irq);
			goto err_req_irq;
	}

	dbgmopdetail("%s(): intr_added\n", __func__);

	intr_added = 1;
	cv_init(&state->intrs[0].cv);
	cv_init(&state->intrs[1].cv);
	cv_init(&state->intrs[2].cv);
	cv_init(&state->intrs[3].cv);

	/*
	 * Some hardware control.
	 */
	if ( mop_self_test(state) != 0 ) {
		dbgmop("Driver %s inst %d fail for mop_self_test\n",
		MOP_NAME, state->inst);
		goto err_mop_self_test;
	}

	/*
	 * Create minor nodes for this instance
	 */
	for ( intr = 0; intr < MOP_N_IN_INTER; intr++ ) {
		minor = MOP_MINOR(state->inst, MOP_IO_IN, intr);
		dbgmopdetail("%s(): getting minor for MOP_IO_IN %d\n", __func__, minor);
		(void) sprintf(name, "mop_%d_in:%d", state->inst, intr);

		if ( ddi_create_minor(MOP_DIR, name, S_IFCHR, new_encode_dev(MKDEV(state->major, minor))) ) {
			dbgmop("%s(): ddi_create_minor IN failed %d\n", __func__, rval);
			goto err_failure;
		}
	}

	for ( intr = 0; intr < MOP_N_OUT_INTER; intr++ ) {
		minor = MOP_MINOR(state->inst, MOP_IO_OUT, intr);
		dbgmopdetail("%s(): getting minor for MOP_IO_OUT %d\n", __func__, minor);
		(void) sprintf(name, "mop_%d_out:%d", state->inst, intr);

		if ( ddi_create_minor(MOP_DIR, name, S_IFCHR, new_encode_dev(MKDEV(state->major, minor))) ) {
			dbgmop("%s(): ddi_create_minor OUT failed\n", __func__);
			goto err_failure;
		}
	}

	for ( intr = 0; intr < MOP_N_RST_INTER; intr++ ) {
		minor = MOP_MINOR(state->inst, MOP_IO_RST, intr);
		dbgmopdetail("%s(): getting minor for MOP_IO_RST %d\n", __func__, minor);
		(void) sprintf(name, "mop_%d_rst:%d", state->inst, intr);

		if ( ddi_create_minor(MOP_DIR, name, S_IFCHR, new_encode_dev(MKDEV(state->major, minor))) ) {
			dbgmop("%s(): ddi_create_minor RST failed\n", __func__);
			goto err_failure;
		}
	}

	for ( intr = 0; intr < MOP_N_MPR_INTER; intr++ ) {
		minor = MOP_MINOR(state->inst, MOP_IO_MPR, intr);
		dbgmopdetail("%s(): getting minor for MOP_IO_MPR %d\n", __func__, minor);
		(void) sprintf(name, "mop_%d_mpr:%d", state->inst, intr);

		if ( ddi_create_minor(MOP_DIR, name, S_IFCHR, new_encode_dev(MKDEV(state->major, minor))) ) {
			dbgmop("%s(): ddi_create_minor MPR failed\n", __func__);
			goto err_failure;
		}
	}

	for ( intr = 0; intr < MOP_N_IMT_INTER; intr++ ) {
		minor = MOP_MINOR(state->inst, MOP_IO_IMT, intr);
		dbgmopdetail("%s(): getting minor for MOP_IO_IMT %d\n", __func__, minor);
		(void) sprintf(name, "mop_%d_imt:%d", state->inst, intr);

		if ( ddi_create_minor(MOP_DIR, name, S_IFCHR, new_encode_dev(MKDEV(state->major, minor))) ) {
			dbgmop("%s(): ddi_create_minor IMT failed\n", __func__);
			goto err_failure;
		}
	}

	for ( intr = 0; intr < MOP_N_TST_INTER; intr++ ) {
		minor = MOP_MINOR(state->inst, MOP_IO_TST, intr);
		dbgmopdetail("%s(): getting minor for MOP_IO_TST %d\n", __func__, minor);
		(void) sprintf(name, "mop_%d_tst:%d", state->inst, intr);

		if ( ddi_create_minor(MOP_DIR, name, S_IFCHR, new_encode_dev(MKDEV(state->major, minor))) ) {
			dbgmop("%s(): ddi_create_minor TST failed\n", __func__);
			goto err_failure;
		}
	}

	mutex_init(&(state->mux));

	dev_set_drvdata(&op->dev, state);

	dbgmop("%s() is finished for Driver %s inst %d\n", __func__, 
			MOP_NAME, state->inst);

	return 0;

err_failure:
err_mop_self_test:
	free_irq(state->irq, state);
err_req_irq:
	of_iounmap(&op->resource[2], state->bozu_base, op->resource[2].end - op->resource[2].start + 1);
err_remap2:
	of_iounmap(&op->resource[1], state->regs_base, op->resource[1].end - op->resource[1].start + 1);
err_remap1:
	of_iounmap(&op->resource[0], state->pzu_base, op->resource[0].end - op->resource[0].start + 1);
err_remap0:
	unregister_chrdev(mop_major, MOP_NAME);

	printk(KERN_ERR "INST %d. "
		"%s(): Driver loading Failed.\n", state->inst, __func__);

	kfree(state);

	return -EFAULT;
}

/*
 * Driver detach entry point
 */

static int
mop_remove(struct of_device *op)
{
	mop_state_t	*state = (mop_state_t *)dev_get_drvdata(&op->dev);
	int		error = 0;
	int		intr;
	char	name[64];
	int		instance;

	dbgmop("%s(): start\n", __func__);

	if ( state == NULL )
		return -EFAULT;

	instance = state->inst;

	for ( intr = 0; intr < MOP_N_IN_INTER; intr++ ) {
		(void) sprintf(name, "mop_%d_in:%d", instance, intr);
		dbgmopdetail("%s(): device: %s\n", __func__, name);

		error = ddi_unlink(MOP_DIR, name);
		if ( error ) {
			dbgmop("%s(): in ddi_unlink failed, error = %d\n", __func__, error);
		}
	}

	for ( intr = 0; intr < MOP_N_OUT_INTER; intr++ ) {
		(void) sprintf(name, "mop_%d_out:%d", instance, intr);
		dbgmopdetail("%s(): %s\n", __func__, name);

		error = ddi_unlink(MOP_DIR, name);
		if ( error ) {
			dbgmop("%s(): out ddi_unlink failed, error = %d\n", __func__, error);
		}
	}

	for ( intr = 0; intr < MOP_N_RST_INTER; intr++ ) {
		(void) sprintf(name, "mop_%d_rst:%d", instance, intr);
		dbgmopdetail("%s(): %s\n", __func__, name);

		error = ddi_unlink(MOP_DIR, name);
		if ( error ) {
			dbgmop("%s(): rst ddi_unlink failed, error = %d\n", __func__, error);
		}
	}

	for ( intr = 0; intr < MOP_N_MPR_INTER; intr++ ) {
		(void) sprintf(name, "mop_%d_mpr:%d", instance, intr);
		dbgmopdetail("%s(): %s\n", __func__, name);

		error = ddi_unlink(MOP_DIR, name);
		if ( error ) {
			dbgmop("%s(): mpr ddi_unlink failed, error = %d\n", __func__, error);
		}
	}

	for ( intr = 0; intr < MOP_N_IMT_INTER; intr++ ) {
		(void) sprintf(name, "mop_%d_imt:%d", instance, intr);
		dbgmopdetail("%s(): %s\n", __func__, name);

		error = ddi_unlink(MOP_DIR, name);
		if ( error ) {
			dbgmop("%s(): imt ddi_unlink failed, error = %d\n", __func__, error);
		}
	}

	for ( intr = 0; intr < MOP_N_TST_INTER; intr++ ) {
		(void) sprintf(name, "mop_%d_tst:%d", instance, intr);
		dbgmopdetail("%s(): %s\n", __func__, name);

		error = ddi_unlink(MOP_DIR, name);
		if ( error ) {
			dbgmop("%s(): tst ddi_unlink failed, error = %d\n", __func__, error);
		}
	}

	dev_set_drvdata(&op->dev, NULL);

	free_irq(state->irq, state);

	of_iounmap(&op->resource[2], state->bozu_base, op->resource[2].end - op->resource[2].start + 1);

	of_iounmap(&op->resource[1], state->regs_base, op->resource[1].end - op->resource[1].start + 1);

	of_iounmap(&op->resource[0], state->pzu_base, op->resource[0].end - op->resource[0].start + 1);

	kfree(state);

	unregister_chrdev(state->major, MOP_NAME);

	dbgmop("%s() finish\n", __func__);

	return error;
}

/*
 * Driver open entry point
 */
static int
mop_open(struct inode *inode, struct file *file)
{
	dev_t	dev = inode->i_rdev;
	int		intr;
	int		intr_mask = 0;
	mop_state_t	*state;
	int		firstopen = 1;
	int		instance = MOP_INST(dev);

	dbgmopdetail("%s(): start\n", __func__);
	
	if ( !dev ) {
		dbgmop("%s(): !dev\n", __func__);
		return -EFAULT;
	}

	state = mop_states[instance];

	intr = MOP_INTR(dev);
	dbgmopdetail("%s(): intr %x\n", __func__, intr);

	mutex_enter(&state->mux);

	firstopen = (state->open_in == 0 )  \
		&& (state->open_out == 0 )  \
		&& (state->open_rst == 0 )  \
		&& (state->open_mpr == 0 )  \
		&& (state->open_imt == 0 )  \
		&& (state->open_tst == 0 )  \
		&& (state->open_exch == 0 )  \
		&& (state->open_cntl == 0 )  \
	;

	if ( MOP_IN(dev) ) {
		intr_mask = 1 << intr;
		state->open_in |= intr_mask;
		state->mask |= intr_mask;
		state->faza = (state->faza & ~ intr_mask) | //clear faza
		(state->base_faza  &   intr_mask);   //allot base_faza

	dbgmopdetail("%s(): mask %x\n", __func__, intr_mask);
	PUT_MOP_REG(state, MOP_FZMC,
			((state->faza <<16) & 0xff000000)|
			((state->faza << 8) & 0x0000ff00)|
			((state->mask << 8) & 0x00ff0000)|
			((state->mask) & 0x000000ff));

	PUT_MOP_REG(state, tli, open_intr_bit);
	} else if ( MOP_OUT(dev) ) {
		intr_mask = 1 << intr;  
		state->open_out |= intr_mask;
		dbgmopdetail("%s(): MOP_OUT intr_mask %x open_out %x\n",
			__func__, intr_mask, state->open_out);
	} else if ( MOP_RST(dev) ) {
		state->open_rst |= intr_mask;
		intr_mask = 1 << intr ;
		dbgmopdetail("%s(): RST intr_mask %x \n", __func__, intr_mask);
	} else if ( MOP_MPR(dev) ) {
		state->open_mpr |= intr_mask;
		intr_mask = 1 << intr ;
		dbgmopdetail("%s(): MPR intr_mask %x \n", __func__, intr_mask);
	} else if ( MOP_IMT(dev) ) {
		state->open_imt |= intr_mask;
		intr_mask = 1 << intr ;
		dbgmopdetail("%s(): IMT intr_mask %x \n", __func__, intr_mask);
	} else if ( MOP_TST(dev) ) {
		state->open_tst |= intr_mask;
		intr_mask = 1 << intr ;
		dbgmopdetail("%s(): TST intr_mask %x \n", __func__, intr_mask);
	}

	dbgmopdetail("%s(): open_in  = %x,"
					" open_out = %x,"
					" open_rst = %x,\n"	
					" open_mpr = %x,"
					" open_imt = %x,"
					" open_tst = %x,"
					" OPEN_EXCL = %x,"
					" firstopen = %x;\n", __func__,
					state->open_in, 
					state->open_out,
					state->open_rst,
					state->open_mpr,
					state->open_imt,
					state->open_tst,
					OPEN_EXCL,
					firstopen
				);

	mutex_exit(&state->mux);

	state->dev = dev;
	file->private_data = (void *)state;

	return 0;
}

/*
 * Driver close entry point
 */
static int
mop_close(struct inode *inode, struct file *file)
{
	dev_t	dev = inode->i_rdev;
	int		instance;
	mop_state_t	*state;
	int		intr;
	int		intr_mask;
	
	if ( !dev )
		return -ENXIO;

	instance = MOP_INST(dev);
	state = mop_states[instance];

	if ( state == NULL )
		return -ENXIO;
	
	intr = MOP_INTR(dev);
	mutex_enter(&state->mux);

	if ( MOP_IN(dev) ) {
		intr_mask = 1 << intr ;
		state->open_in  &= intr_mask;
		state->mask     &= intr_mask;
		state->faza   = (state->faza & ~ intr_mask); //clear faza
		dbgmopdetail("%s(): mask %x\n", __func__, intr_mask);
		PUT_MOP_REG(state, MOP_FZMC,
			((state->faza <<16) & 0xff000000)|
			((state->faza << 8) & 0x0000ff00)|
			((state->mask << 8) & 0x00ff0000)|
			((state->mask ) & 0x000000ff));

		if ( !state->open_in ) {
			PUT_MOP_REG(state, tli , close_intr_bit);
			PUT_MOP_REG(state, MOP_FZMC , 0);
		}
	} else if ( MOP_OUT(dev) ) {
		intr_mask = 1 << intr ;
		state->open_out &= ~intr_mask;
	} else if ( MOP_RST(dev) ) {
		intr_mask = 1 << intr ;
		state->open_rst &= ~intr_mask;
	} else if ( MOP_MPR(dev) ) {
		intr_mask = 1 << intr ;
		state->open_mpr &= ~intr_mask;
	} else if ( MOP_IMT(dev) ) {
		intr_mask = 1 << intr ;
		state->open_imt &= ~intr_mask;
	} else if ( MOP_TST(dev) ) {
		intr_mask = 1 << intr ;
		state->open_tst &= ~intr_mask;
	} else {
		dbgmop("%s(): ERROR\n", __func__);
	}

	dbgmopdetail("%s(): open_in  = %x,  open_out = %x,   open_rst = %x,\n"
			"open_mpr = %x,  open_imt = %x,   open_tst = %x;\n", 
			__func__, state->open_in , state->open_out, state->open_rst,
			state->open_mpr, state->open_imt, state->open_tst);

	mutex_exit(&state->mux);

	return 0;
}

/*
 * Copy data from a MP base memory to a source kernel address. Source addresss
 * and base memory address must have the same alignment into word
 */
/*ARGSUSED*/
int mop_read_base_memory(
	mop_state_t	*state,
	caddr_t address_from,
	caddr_t address_to,
	size_t byte_size,
	int char_data)
{
	dbgmopdetail("CE_NOTE: mop_read_base_memory :unimplemented now\n");

	return -EINVAL;
}

/*
 * Rotate bytes of the word (big and litle endian compatibility)
 */
/*ARGSUSED*/
u_int
mop_rotate_word_bytes(u_int source_word)
{
	u_int new_word = 0;
	u_char *new_word_p = (u_char *)&new_word;
	u_char *source_word_p = (u_char *)&source_word;
	int cur_byte = 0;

	for ( cur_byte = 0; cur_byte < sizeof(u_int); cur_byte ++ ) {
		new_word_p[(sizeof(u_int)-1) - cur_byte] = source_word_p[cur_byte];
	}

	return new_word;
}

/*
 * Copy data from a source kernel address to a MP base memory. Source addresss
 * and base memory address must have the same alignment into word
 */
/*ARGSUSED*/
int
mop_write_base_memory(mop_state_t *state,
				caddr_t	address_from, 
				caddr_t	address_to,
				size_t	byte_size,
				int	char_data)
{
	u_int *      kmem_area_from = NULL;
	u_int *      bmem_area_to = NULL;
	size_t       begin_rem = 0;
	size_t       cur_byte_size = 0;
	size_t       word_size = 0;
	size_t       rem = 0;
	int          cur_word = 0;

	if ( ((u_long) address_from & (sizeof(u_int)-1)) !=
		((u_long) address_to   & (sizeof(u_int)-1)) ) {
		dbgmopdetail("CE_WARN: mop_write_base_memory :kernel and BMEM addresses have different alignment into word\n");

		return EINVAL;
	}

	begin_rem = ((u_long) address_from & (sizeof(u_int)-1));
	kmem_area_from = (u_int *) ((u_long) address_from - begin_rem);
	bmem_area_to = (u_int *) & state->bozu_base[(u_long) address_to - begin_rem];

	cur_byte_size = byte_size;
	if ( begin_rem != 0 ) {
		u_int   first_bmem_word = bmem_area_to[0];
		u_char * first_bmem_word_p = (u_char *) & first_bmem_word;
		u_char * first_kernel_word = (u_char *) & kmem_area_from[0];
		int      begin_size = sizeof(u_int) - begin_rem;
		int      cur_byte = 0;

		dbgmop("Rem is found\n");
		if (char_data)
		first_bmem_word = mop_rotate_word_bytes(first_bmem_word);
		begin_size = (begin_size > cur_byte_size) ? cur_byte_size : begin_size;

		for ( cur_byte = begin_rem; cur_byte < begin_rem + begin_size; cur_byte++ ) {
			first_bmem_word_p[cur_byte] = first_kernel_word[cur_byte];
        }

		if ( char_data )
			first_bmem_word = mop_rotate_word_bytes(first_bmem_word);

		bmem_area_to[0] = first_bmem_word;
		cur_byte_size -= begin_size;
		((long) kmem_area_from) ++;
		((long) bmem_area_to) ++;
	}

	word_size = cur_byte_size / sizeof(u_int);
	rem = byte_size % sizeof(u_int);
	for ( cur_word = 0; cur_word < word_size; cur_word ++ ) {
		if ( char_data )
			bmem_area_to[cur_word] = mop_rotate_word_bytes(kmem_area_from[cur_word]);
		else
			bmem_area_to[cur_word] = kmem_area_from[cur_word];
	}

	if ( rem != 0 ) {
		u_int last_bmem_word = bmem_area_to[word_size];
		u_char *last_bmem_word_p = (u_char *) & last_bmem_word;
		u_char *last_kernel_word = (u_char *) & kmem_area_from[word_size];
		int cur_byte = 0;

		dbgmop("Rem2 is found\n");
		if ( char_data )
			last_bmem_word = mop_rotate_word_bytes(last_bmem_word);

		for ( cur_byte = 0; cur_byte < rem; cur_byte ++ ) {
			last_bmem_word_p[cur_byte] = last_kernel_word[cur_byte];
		}

		if ( char_data )
			last_bmem_word = mop_rotate_word_bytes(last_bmem_word);

		bmem_area_to[word_size] = last_bmem_word;
	}

	if ( PRN )
		dbgmopdetail("CE_NOTE: mop_write_base_memory :succeeded to copy data from addr 0x%08lx to BMEM addr 0x%08lx size 0x%lx\n",
			(u_long)address_from, (u_long)address_to, (ulong_t)byte_size);

	return 0;
}

/*
 * Data transfer operations from/to base memory of MP and
 * general memory of SPARC  (mutex_enter must be done by caller)
 */
/*ARGSUSED*/

int
mop_bmem_data_transfer(
	mop_state_t	*state,
	bmem_trans_desk_t	*transfer_desk,
	int		write_op,
	int		mode,
	int		char_data,
	caddr_t		kmem_buf,
	caddr_t		*kmem_area_p)
{
	caddr_t       kmem_area = NULL;
	int           rval = 0;
	int           kmem_size = 0;
	int           word_rem = 0;

	word_rem = ((long) transfer_desk -> mp_bmem_address & (sizeof(u_int)-1));
	kmem_size = transfer_desk -> byte_size + word_rem;

	if ( kmem_buf == NULL )
		kmem_area = (caddr_t)kmalloc(kmem_size,GFP_KERNEL);
	else
		kmem_area = kmem_buf;

	if ( kmem_area == NULL ) {
       dbgmopdetail("CE_WARN: mop_bmem_data_transfer :kmem_alloc no memory is available\n");
       return -EINVAL;
	}

	if ( write_op ) {
		if ( ddi_copyin(transfer_desk -> mem_address,
				&kmem_area[word_rem],
				transfer_desk -> byte_size) ) {
		if ( kmem_buf == NULL )
			kfree(kmem_area);

		dbgmopdetail("CE_WARN: mop_bmem_data_transfer ddi_copyin failed\n");
		return -EFAULT;
		}
	}

	if ( write_op )
		rval = mop_write_base_memory(state,
					&kmem_area[word_rem],
					transfer_desk->mp_bmem_address,
					transfer_desk->byte_size,
					char_data);
	else
		rval = mop_read_base_memory(state,
					&kmem_area[word_rem],
					transfer_desk->mp_bmem_address,
					transfer_desk->byte_size,
					char_data);

	if ( rval != 0 ) {
		if ( kmem_buf == NULL )
			kfree(kmem_area);

		dbgmopdetail("CE_WARN: mop_bmem_data_transfer read/write base memory failed\n");
        return rval;
	}

	if ( !write_op ) {
		if ( ddi_copyout(&kmem_area[word_rem],
                        transfer_desk->mem_address,
                        transfer_desk->byte_size) ) {
			if ( kmem_buf == NULL )
				kfree(kmem_area);

			dbgmopdetail("CE_WARN: mop_bmem_data_transfer :ddi_copyout failed\n");
			return EFAULT;
		}
	}

	if ( kmem_buf == NULL )
		kfree(kmem_area);
	else if ( kmem_area_p != NULL )
		*kmem_area_p = &kmem_area[word_rem];

	if ( PRN )
		dbgmopdetail("CE_NOTE: mop_bmem_data_transfer succeeded !\n");

	return 0;
}

/*ARGSUSED*/
int
wait_finish_com(mop_state_t *state,  hrtime_t time_wait_)
{
	hrtime_t	time_begin_wait = ddi_gethrtime();
	hrtime_t	time_wait = 0; /* в мили-секундах */
	u_int		word_bmem;
	int 		rval = 0;

	dbgmop("wait_finish_com-1 : wait end cом MP!\n");

	for ( ; ; ) { /* ========= Ждем когда MP driver отработает пред. команду */
		word_bmem = GET_MOP_BOZU(state, bozu_buso);
		dbgmop("wait_finish_com: word_bmem = 0x%x\n", word_bmem);
		if ( (word_bmem & 0x0ff) == 0 ) break;
		else {
			time_wait = ((ddi_gethrtime() - time_begin_wait)/1000000);

			if ( time_wait >= time_wait_ ) {
				dbgmop("wait_finish_com-2 : MP long work !"
					"T.wait = %lld милисек. bozu_buso =%0x\n",
					time_wait, word_bmem);

				rval = -1;
				break;
			}
		}
	}

	dbgmop("wait_finish_com-3 : end cом MP! rval=%d\n",rval);
	return rval;
}

/*
 * Driver ioctl entry point
 */
long
mop_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	dev_t	dev = filp->f_path.dentry->d_inode->i_rdev;
	mop_state_t	*state = (mop_state_t *)filp->private_data;

	int		intr = MOP_INTR(dev);
	int		instance = MOP_INST(dev);

	int		rval = 0;
	mop_info_t	info;
	mop_op_t	op;
	int		mask = 0;
	int		mode = 0;
	hrtime_t	time_ioctl = ddi_gethrtime();
	ulong		cur_time_in_tiks=0;
	u_int		interrupts;
	mop_intrw_t	intr_krnl;
	u_int		buff_for_com[15];   /* < Буфер для команд МР > */

	if ( state == NULL ) {
		dbgmop("%s(): state == NULL\n", __func__);
		return -ENXIO;
	}

	lock_kernel();

	drv_getparm(LBOLT, &cur_time_in_tiks);
	switch ( cmd ) {
		case MCST_SELFTEST_MAGIC:
		{
			selftest_t st;
#if defined(CONFIG_SBUS)
			selftest_sbus_t *st_sbus = &st.info.sbus;
			char *tmp, *sl_n;
			int slot_num, addr;
			struct device_node *dn = state->op->node;
			size_t rval;

			st.bus_type = BUS_SBUS;
			st_sbus->bus = 0;
			strcpy(st_sbus->name, MOP_NAME);

			st_sbus->major = MAJOR(dev);
			st_sbus->minor = MINOR(dev);

			printk("full_name [%s]\n", dn->full_name);
			tmp = strrchr(dn->full_name, '@');
			if ( tmp ) {
				// Уберём символ "@" из строки
				tmp = &tmp[1];
				//printk("STRRCHR: [%s]\n", tmp);

				sl_n = strrchr(tmp, ',');

				if ( sl_n ) {
					sscanf(tmp, "%d", &slot_num);
					sscanf(&sl_n[1], "%x", &addr);
					printk("STRRCHR: slot_number [%d], [%s], [%d]\n", slot_num, sl_n, addr);

					if ( (addr >> 28) != 0 ) { // Присутствует расширитель
						st_sbus->br_slot = slot_num;
						st_sbus->slot = addr >> 28;
					} else {
						st_sbus->br_slot = -1;
						st_sbus->slot = slot_num;
					}

					st_sbus->address = addr & 0x0FFFFFFF;
				}
			} else {
				st.error = 1;
			}

//printk("%s:\n\tName [%s]\n\tMAJOR [%d], MINOR [%d].\n\tBUS [%d], BRIDGE_SLOT [%d], SLOT [%d], ADDRESS [%#x].\n", __func__, st_sbus->name, st_sbus->major, st_sbus->minor, st_sbus->bus, st_sbus->br_slot, st_sbus->slot, st_sbus->address);
#elif IS_ENABLED(CONFIG_PCI2SBUS)
			selftest_pci_t *st_pci = &st.info.pci;
			int irq = state->irq;
			p2s_info_t* p2s_info = get_p2s_info(irq >> 8);

			if ( !p2s_info ) {
				printk("%s: MCST_SELFTEST_MAGIC: Cannot get p2s_info struct corresponded to IRQ=%d\n", __func__, irq);
				return -EFAULT;
			}

			struct pci_dev *pdev = p2s_info->pdev;
			int rval;
			st_pci->vendor = pdev->vendor;
			st_pci->device = pdev->device;

			st.bus_type = BUS_PCI;

			strcpy(st_pci->name, MOP_NAME);
			st_pci->bus = pdev->bus->number;
			st_pci->slot = PCI_SLOT(pdev->devfn);
			st_pci->func = PCI_FUNC(pdev->devfn);
			st_pci->class = pdev->class;

			st_pci->major = MAJOR(dev);
			st_pci->minor = MINOR(dev);
#else
			printk("%s: MCST_SELFTEST_MAGIC: neither CONFIG_SBUS nor CONFIG_PCI2SBUS(CONFIG_PCI2SBUS_MODULE) is defined!! Strange...\n");
			return -EFAULT;
#endif
			rval = copy_to_user((void *)arg, (void *)&st, sizeof(selftest_t));
			if ( rval != 0 ) {
				printk( "%s: MCST_SELFTEST_MAGIC: copy_to_user() failed\n", __func__);
				return -EFAULT;
			}
		}

			return 0;
		case MOPIO_START_MP :
		{
			dbgmop("MOPIO_START_MP-1 arg= %ld\n",arg);
			spin_mutex_enter(&state->intr_lock);
			PUT_MOP_REG(state, rerr, 0);
			PUT_MOP_REG(state, trm, 1);
			PUT_MOP_REG(state, tlrm, 1);
			PUT_MOP_BOZU(state, bozu_buso, 1);
			PUT_MOP_REG(state, trm, 0);

			spin_mutex_exit(&state->intr_lock);
			dbgmop("MOPIO_START_MP-2 arg= %ld\n",arg);

			if ( wait_finish_com(state, 1000) != 0 ) {
		  		dbgmop("MOPIO_START_MP-3 : endless_finish_com !\n");
		  		rval = -EINVAL;
		  		break;
			} else if ( PRN ) {
		  		u_int word_bmem = GET_MOP_BOZU(state, 0x603 *4);
		  		dbgmop("MOPIO_START_MP-4 :МП ЗАПУЩЕН ! "
			 	"Версия =0x%x\n", word_bmem   );
			}

			break;
		}

		case MOPIO_STOP_MP :
			if ( PRN )
				dbgmopdetail("MOPIO_STOP_MP arg= %lx\n",arg);

			spin_mutex_enter(&state->intr_lock);
			PUT_MOP_REG(state, rerr, 0);
			PUT_MOP_REG(state, trm, 1);
			PUT_MOP_REG(state, tlrm, 1);
			spin_mutex_exit(&state->intr_lock);
			break;

		case MOPIO_RESET_MP :
			dbgmopdetail("CE_NOTE: MOPIO_RESET_MP arg= %lx\n",arg);
			break;

		case MOPIO_LOAD_MP_DRV_CODE :
		/// =========== Загрузка микропроцессорного ДРАЙВЕРА =======
		{
			bmem_trans_desk_t mp_driver_code;
			if ( ddi_copyin((caddr_t)arg, (caddr_t)&mp_driver_code,
			sizeof (bmem_trans_desk_t)) ) {
				dbgmop( "CE_WARN: MOPIO_LOAD_MP_DRV_CODE : ddi_copyin failed\n");
				rval = -EFAULT;
				goto out;
			}

			if ( PRN )
				dbgmopdetail("CE_NOTE: MOPIO_LOAD_MP_DRV_CODE state->deb = %x\n", state->deb);
			if ( PRN )
				dbgmopdetail("CE_NOTE: MOPIO_LOAD_MP_DRV_CODE from 0x%08lx to 0x%08lx "
				"of BMEM size 0x%lx bytes\n",
				(u_long)mp_driver_code.mem_address,
				(u_long)mp_driver_code.mp_bmem_address,
				(u_long)mp_driver_code.byte_size);

			spin_mutex_enter(&state->intr_lock);
			rval = mop_bmem_data_transfer(state, &mp_driver_code, 1, mode, 0, NULL, NULL);
			if ( rval != 0 ) {
				spin_mutex_exit(&state->intr_lock);
				dbgmopdetail("CE_WARN: MOPIO_LOAD_MP_DRV_CODE : BMEM load failed\n");
				break;
			}

			state->mp_drv_loaded = 1;
			spin_mutex_exit(&state->intr_lock);
			if ( PRN )
				dbgmopdetail("CE_NOTE: MOPIO_LOAD_MP_DRV_CODE succeeded !\n");
			break;
		}

		case MOPIO_WRITE_BOZU_0 :
		case MOPIO_WRITE_BOZU_1 :
		case MOPIO_WRITE_BOZU_2 :
		case MOPIO_WRITE_BOZU_3 :
		{
			int	num_kan =  cmd & 3 ;
			if ( PRN )
				dbgmop("CE_NOTE:  MOPIO_WRITE_BOZU_%x arg= %lx",num_kan ,arg);
			spin_mutex_enter(&state->intr_lock);
			PUT_MOP_BOZU(state,(MOP_BOZU_RST_COUNTER)+(num_kan*4),arg);
			spin_mutex_exit(&state->intr_lock);
			break;
		}

		case MOPIO_WRITE_COM :
			dbgmop("MOPIO_WRITE_COM-1 arg= %lx\n",arg);
			spin_mutex_enter(&state->intr_lock);

			ddi_copyin((caddr_t)arg,(caddr_t)buff_for_com,sizeof(mop_buso_t));

			if ( wait_finish_com(state, 100) == 0 ) {
				int   i;
				u_int *bozu = (u_int *)(state->bozu_base+bozu_buso);
				for ( i = (sizeof(mop_buso_t) +3)/4; i >= 0; i-- )
	    			bozu[i] = buff_for_com[i];

				dbgmop("MOPIO_WRITE_COM-2 : end wait finish_com\n");
			} else
				dbgmop("MOPIO_WRITE_COM-3 : long wait finish_com\n");

			spin_mutex_exit(&state->intr_lock);
			break;

		case MOPIO_SET_TIME_OF_PANIC:
		{
			u_int cmd[3];

			cmd[0] = 17;
			cmd[1] = arg;
			cmd[2] = arg;
			time_p = time_ioctl;

			dbgmop("CE_NOTE, MOPIO_SET_TIME_OF_PANIC arg= %lx",arg);

			spin_mutex_enter(&state->intr_lock);

			if (wait_finish_com(state, 100) == 0) {
				int i;
				u_int *bozu = (u_int *)(state->bozu_base+bozu_buso);

				for ( i = (sizeof(mop_buso_t) +3)/4; i >= 0; i-- )
					bozu[i] = cmd[i];
			} else
				dbgmop("CE_NOTE, MOPIO_SET_TIME_OF_PANIC : long wait finish_com");

			spin_mutex_exit(&state->intr_lock);
			break;
		}

		case MOPIO_WRITE_INTR:
			if ( PRN )
				dbgmop("CE_NOTE, MOPIO_WRITE_INTR arg= %lx",arg);

			spin_mutex_enter(&state->intr_lock);

			ddi_copyin((caddr_t)arg, (caddr_t)buff_for_com, sizeof(mop_buso_intr_t));

			if ( wait_finish_com(state, 100) == 0 ) {
				int i;
				u_int *bozu = (u_int *)(state->bozu_base+bozu_buso);

				for (i = (sizeof(mop_buso_intr_t) +3)/4; i >= 0; i--)
				bozu[i] = buff_for_com[i];
			} else
				dbgmop("CE_NOTE, MOPIO_WRITE_INTR : long wait finish_com");

			spin_mutex_exit(&state->intr_lock);
			break;

		case MOPIO_WRITE_SIG:
			if ( PRN )dbgmop("CE_NOTE, MOPIO_WRITE_SIG arg= %lx",arg);

			spin_mutex_enter(&state->intr_lock);
		
			ddi_copyin((caddr_t)arg, (caddr_t)buff_for_com, 
				sizeof(mop_buso_sig_t));

			if ( wait_finish_com(state, 100) == 0 ) {
				int i;
				u_int *bozu = (u_int *)(state->bozu_base+bozu_buso);

				for ( i = (sizeof(mop_buso_sig_t) +3)/4; i >= 0; i-- )
					bozu[i] = buff_for_com[i];
			} else
				dbgmop("CE_NOTE, MOPIO_WRITE_SIG : long wait finish_com");

			spin_mutex_exit(&state->intr_lock);
			break;

		case MOPIO_CLOSE_RST:
			if ( PRN )
				dbgmop("CE_NOTE, MOPIO_CLOSE_RST arg= %lx",arg);

			spin_mutex_enter(&state->intr_lock);
			if ( ddi_copyin( (caddr_t) arg,
				(caddr_t)(state->bozu_base+bozu_buso),        sizeof(mop_buso_t)) != 0 ) {
				dbgmop("CE_WARN, mop_ioctl_WRITE_BUF failed, cmd=%x\n", cmd);
				rval = -EINVAL;
				spin_mutex_exit(&state->intr_lock);
				break;
			}

			spin_mutex_exit(&state->intr_lock);
			break;
		
		case MOPIO_DEBUG_ON:
			if ( PRN )
				dbgmop("CE_NOTE, MOPIO_DEBUG_ON arg= %lx\n",arg);
			time_s = time_ioctl; 
			spin_mutex_enter(&state->intr_lock);
			state->deb = arg;
			spin_mutex_exit(&state->intr_lock);
			break;

		case MOPIO_DEBUG_OFF:
			if ( PRN )
				dbgmop("CE_NOTE, mop_ioctl_DEBUG_OFF arg= %lx\n",arg);

			spin_mutex_enter(&state->intr_lock);
			state->deb = 0;
			spin_mutex_exit(&state->intr_lock);
			break;

		case MOPIO_RESET_INTR:
			if ( PRN )
				dbgmop("CE_NOTE, mop_ioctl_RESET_INTR arg= %lx\n",arg);
			break;

		case MOPIO_WAIT_INTR0 :
		case MOPIO_WAIT_INTR1 :
		case MOPIO_WAIT_INTR2 :
		case MOPIO_WAIT_INTR3 :
		case MOPIO_WAIT_RST0  :
		case MOPIO_WAIT_RST1  :
		case MOPIO_WAIT_RST2  :
		case MOPIO_WAIT_RST3  :
	 	{
			int		num_intr =  cmd & 3;
			int		c_kan;
			mop_intr_t	*intr = &state->intrs[num_intr];
			hrtime_t	time_begin_of_wait_intr = 0;
			int		what_mode = /* 0 - WAIT_RST, 1 - WAIT_INTR */
			THAT_IS_WAIT_INTR(cmd);
			char	*msg_cmd = (what_mode) ? "INTR" : "RST";
		
			c_kan = (THAT_IS_WAIT_INTR(cmd))
					? c_mpr_0 << num_intr
					: (0x000f0000 << (num_intr*4)) | (0x1110 << num_intr);

			dbgmop("1 MOPIO_WAIT_%s%d inst=%x, arg=%lx, cmd=%x\n",
		                msg_cmd, num_intr, instance, arg, cmd);

			spin_mutex_enter(&state->intr_lock); 
			intr_krnl.intr_errno = 0;

			dbgmop("2 MOPIO_WAIT_%s%d inst=%x, arg=%lx, cmd=%x\n",
		                msg_cmd, num_intr, instance, arg, cmd);

			if ( ddi_copyin((caddr_t)arg, (caddr_t)&intr_krnl,
					sizeof (mop_intrw_t)) != 0 ) {
				dbgmop("3 MOPIO_WAIT_ ddi_copyin() failed,inst= %x, cmd= %x\n", instance,cmd);
				rval = -EINVAL;
				spin_mutex_exit(&state->intr_lock); 
				break;
			}

			dbgmop("4 MOPIO_WAIT_%s%d :cnt =%d,"
				" cur_time_in_tiks =%ld, timewait =%ld\n",
				msg_cmd, num_intr, intr->cnt, cur_time_in_tiks,
				cur_time_in_tiks + drv_usectohz(intr_krnl.intr_time) + 1);

			if ( intr->cnt == 0 || THAT_IS_WAIT_INTR(cmd)) {
				time_begin_of_wait_intr = ddi_gethrtime();

				dbgmop("5 MOPIO_WAIT_%s%d :cnt =%d,"
					" cur_time_in_tiks =%ld, timewait =%ld\n",
					msg_cmd, num_intr, intr->cnt, cur_time_in_tiks,
					cur_time_in_tiks + drv_usectohz(intr_krnl.intr_time) + 1 );

				if ( cv_spin_timedwait(&intr->cv, &state->intr_lock, cur_time_in_tiks + drv_usectohz(intr_krnl.intr_time) + 1) == -1   ) { /*  Too long waiting ( не дождались ) */
				dbgmop("6 MOPIO_WAIT cv_timedwait(%d) failed  wait "
					"не дождались,cur_time_in_tiks = %lx, intr_time= %x\n",
					num_intr,cur_time_in_tiks,
					intr_krnl.intr_time);

				intr_krnl.intr_errno =
				rval = -ETIME;
				spin_mutex_exit(&state->intr_lock);

				dbgmop("7 MOPIO_WAIT cv_timedwait(%d) = ETIME "
						"cur_time_in_tiks = %lx, intr_time = %x\n",
						num_intr,cur_time_in_tiks,
						intr_krnl.intr_time );
				break;
				}

			dbgmop("8 MOPIO_WAIT end failed no wait rval = %d (ETIME) ;\n", rval );
			}

			intr_krnl.intr_time = (( intr->cnt > 1 )
			/* время опоздания ПОЛЬЗ с ВЫХОДОМ в ож. прер */
			? time_begin_of_wait_intr - intr->time_cnt1
			: ddi_gethrtime() - ( (intr->cnt == 0) ? time_ioctl /* ETIME ! время ожидания в ож. прер. */ : intr->time /* полное время на реакции на прер */ )) / 1000;

			intr_krnl.intr_delay  = intr->delay;
			intr_krnl.intr_cnt  = intr->cnt;
			intr->cnt = 0;
			interrupts = state->intr_val ;
			intr_krnl.intr_val = interrupts & c_kan;
			state->intr_val = ( interrupts | c_kan ) ^ c_kan ;

			dbgmop("8 MOPIO_WAIT_INTR%d : intr_time =%d, "
				"state->intr_val =%X, intr_krnl.intr_val =%X\n",
				num_intr, intr_krnl.intr_time,
				state->intr_val, intr_krnl.intr_val);

			if ( ddi_copyout( (caddr_t)&intr_krnl, (caddr_t)arg,
				   sizeof (mop_intrw_t) ) != 0 ) {
				dbgmop("9 MOPIO_WAIT ddi_copyout() failed, inst= %x, cmd= %x\n", instance, cmd);
				rval = EINVAL;
				spin_mutex_exit(&state->intr_lock);
				break;
			}

			spin_mutex_exit(&state->intr_lock); //alex

			dbgmop("10 MOPIO_WAIT COMPLITED SUCCESSFULY, inst= %x, cmd= %x\n",
		          instance, cmd  );
			break;
		}

		case MOPIO_SEND_INTR :
			dbgmopdetail("MOP_IOCTL: MOPIO_SEND_INTR\n");

			if ( !MOP_OUT(dev) ) {
				rval = -EINVAL;
				goto out;
			}

			mask = 1 << intr;
			spin_mutex_enter(&state->intr_lock);
			PUT_MOP_REG(state, MOP_OIR, mask);
			PUT_MOP_REG(state, MOP_OIR, 0);
			spin_mutex_exit(&state->intr_lock);
			break;

		case MOPIO_SET_STATE :
			dbgmopdetail("MOP_IOCTL: MOPIO_SET_STATE\n");

			if ( !MOP_OUT(dev) ) {
				dbgmop("MOP_IOCTL: return !MOP_OUT(dev)\n");
				rval = -EINVAL;
				goto out;
			}

			mask = 1 << intr ;
			spin_mutex_enter(&state->intr_lock);

			if ( (ulong_t)arg == 0 ) {
				state->mask &= ~mask; // ????
			} else {
				state->mask |=  mask; // ????
			}

			PUT_MOP_REG(state, MOP_OIR, state->mask);
			spin_mutex_exit(&state->intr_lock);
			break;

		case MOPIO_GET_REG :
			dbgmopdetail("MOP_IOCTL: MOPIO_GET_REG, sizeof(mop_op_t) = 0x%lx\n", (u_long)sizeof(mop_op_t));

			if ( ddi_copyin((caddr_t)arg, (caddr_t)&op, sizeof(mop_op_t)) !=  0 ) {
				dbgmop("EBADE= %d\n",EBADE);
				rval = -EBADE;
				goto out;
			}

			spin_mutex_enter(&state->intr_lock);
		
			/*
		 	* Check reg number is valid
		 	*/
			if ( (op.reg < 0) || (op.reg >= MOP_REG_SIZE) ||
		    	((op.reg & 3) != 0) ) {
				spin_mutex_exit(&state->intr_lock);

				dbgmop("EINVAL= %d\n", EINVAL);
				rval = -EINVAL;
				goto out;
			}

			op.val = GET_MOP_REG(state, op.reg);
			spin_mutex_exit(&state->intr_lock);

			if ( ddi_copyout((caddr_t)&op, (caddr_t)arg, sizeof(mop_op_t)) ) {
				dbgmop("EFAULT= %d\n", EFAULT);
				rval = -EFAULT;
				goto out;
			}

			break;

		case MOPIO_SET_REG :
			dbgmopdetail("MOP_IOCTL: MOPIO_SET_REG\n");

			if ( ddi_copyin((void *)&op, (void *)arg, sizeof(mop_op_t) ) != 0) {
				dbgmop("EBADE= %d\n",EBADE);
				rval = -EBADE;
				goto out;
			}
		
			spin_mutex_enter(&state->intr_lock);
			/*
		 	* Check reg number is valid
		 	*/
			if ( (op.reg < 0) || (op.reg >= MOP_REG_SIZE) ||
		    	((op.reg & 3) != 0) ) {
				spin_mutex_exit(&state->intr_lock);
				dbgmop("EINVAL= %d\n",EINVAL);
				rval = -EINVAL;
				goto out;
			}

			PUT_MOP_REG(state, op.reg, op.val);
			spin_mutex_exit(&state->intr_lock);

			if ( ddi_copyout((caddr_t)&op, (caddr_t)arg,
				sizeof (mop_op_t)) ) {
				dbgmop("EFAULT= %d\n",EFAULT);
				rval = -EFAULT;
				goto out;
			}

			break;

		case MOPIO_INFO :
			dbgmopdetail("MOP_IOCTL: MOPIO_INFO\n");

			info.intr_claimed = state->intr_claimed;
			info.intr_unclaimed = state->intr_unclaimed;
			info.first_lbolt = state->first_lbolt;
			info.last_lbolt = state->last_lbolt;
			info.tick = HZ;

			dbgmopdetail("info.intr_unclaimed = %d\n", info.intr_unclaimed);
			dbgmopdetail("info.intr_claimed = %d\n", info.intr_claimed);

			copy_to_user((void *)arg, (void *)&info, sizeof(mop_info_t));
			break;

		case MOPIO_CLEAR_INFO :
			dbgmopdetail("MOP_IOCTL: MOPIO_CLEAR_INFO\n");

			mop_init_info(state);
			break;

		default:
			dbgmopdetail("MOP_IOCTL: default\n");

			rval = -ENOTTY;
			break;
	}

out:
	unlock_kernel();
	return rval;
}

/*
 * Driver mmap entry point   from mop
 */
/*ARGSUSED*/
static int
mop_mmap(struct file *file, struct vm_area_struct *vma)
{
	mop_state_t	*state = (mop_state_t *)file->private_data;
	dev_t	dev = state->dev;

	int			dev_num;
	int			instance;
	int			channel;
	int			space_num = 1;
	caddr_t		mapped_reg_set_p = NULL;
	off_t		reg_set_offset;
	size_t		space_size = 0;
	unsigned long off = (long)(vma->vm_pgoff << PAGE_SHIFT);

	dbgmop("***** %s(): START *****\n", __func__);

	if ( !dev )
		return -ENXIO;

	dev_num = getminor(dev); // instanse

	instance = (dev_num >> 4);
	channel  = (dev_num & 0xf);  // intr

	dbgmop("%s(): dev_num- %x, instance- %x, channel- %x\n", __func__, dev_num, instance, channel);

	if ( state == NULL ) {
		dbgmop("%s(): unattached instance %x\n", __func__, instance);
		return (ENXIO);
	}

	if ( off >= MOP_PZU_OFFSET && off < MOP_PZU_OFFSET + MOP_PZU_SIZE ) {
		mapped_reg_set_p =  (caddr_t) state -> pzu_base;
		reg_set_offset = off - MOP_PZU_OFFSET;
		space_num = 0;
		space_size = MOP_PZU_SIZE;

		dbgmop("%s(): register set is EPROM\n", __func__);
	} else if (off >= MOP_REG_OFFSET && off < MOP_REG_OFFSET + MOP_REG_SIZE) {
		mapped_reg_set_p = (caddr_t) state -> regs_base;
		reg_set_offset = off - MOP_REG_OFFSET;
		space_num = 1;
		space_size = MOP_REG_SIZE;

		dbgmop("%s(): register set is REGS\n", __func__);
	} else if ( off >= MOP_BOZU_OFFSET && off < MOP_BOZU_OFFSET + MOP_BOZU_SIZE ) {
		mapped_reg_set_p = (caddr_t) state -> bozu_base;
		reg_set_offset = off - MOP_BOZU_OFFSET;
		space_num = 2;
		space_size = MOP_BOZU_SIZE;

		dbgmop("%s(): register set is BOZU\n", __func__);
		} else {
            	dbgmop("%s(): invalid register set off 0x%x\n", __func__, (unsigned int)off);
				return -1;
		}

	off += state->op->resource[space_num].start & PAGE_MASK;

	vma->vm_pgoff = off >> PAGE_SHIFT;

	vma->vm_flags |= (VM_IO | VM_LOCKED | VM_RESERVED | VM_READ | VM_WRITE );

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if ( io_remap_pfn_range(vma, vma->vm_start, MK_IOSPACE_PFN(0xe, (off >> PAGE_SHIFT)), vma->vm_end - vma->vm_start, vma->vm_page_prot) ) {

	return -EAGAIN;
	}

	dbgmop("***** %s() NORMALY finish *****\n", __func__);

	return 0;
}


/*
 * Driver poll entry point
 */
static uint_t
mop_chpoll(struct file *file, struct poll_table_struct *wait)
{
	mop_state_t	*state = (mop_state_t *)file->private_data;
	dev_t	dev = state->dev;

	int		intr;
	int		mask;

	if ( state == NULL )
		return -ENXIO;

	intr = MOP_INTR(dev);

	if ( !MOP_IN(dev) ) {
		return -EINVAL;
	}

	mask = 1 << intr;

	ddi_poll_wait(file, &(state->pollhead),  wait);

	dbgmopdetail("mop_chpoll begin  4  state->intr_mask = %x\n",state->intr_mask);
	spin_mutex_enter(&state->intr_lock);

	if ( (state->intr_mask & mask) != 0 ) {
		state->intr_mask &= ~mask;
		spin_mutex_exit(&state->intr_lock);
		dbgmopdetail("mop_chpoll success  5  -----------------------------\n");
		return POLLIN;
	} else {
		dbgmopdetail("mop_chpoll wait  6  -----------------------------\n");
		spin_mutex_exit(&state->intr_lock);
		return 0;
	}
}

static irqreturn_t
mop_intr_handler(int irq, void *arg)
{
#define tisb_c   0x10
#define tli_c	 0x20
	mop_state_t	*state = (mop_state_t *)arg;
	u_int	eir;
	u_int	interrupts;
	int		two_intr = 0;
	int		instance = 0;
	unsigned long flag;
	hrtime_t timeout = ddi_gethrtime();

	dbgmop("%s(): START----------------------\n", __func__);
	if ( arg == NULL ) {
		dbgmop("%s(): arg == NULL\n", __func__);
		return IRQ_NONE;
	}

	raw_spin_lock_irqsave(&state->intr_lock, flag);

	interrupts = GET_MOP_REG(state, 0);

	dbgmop("mop_intr_handler --interrupts= %x;\n",interrupts);

	if ( (  interrupts & tisb_c ) == 0 ) { /* trig intr sys bus from MP */
		/*====== external interrupts begin ======================  */
		if ( (  interrupts & tli_c ) == 0 ) { /* trig blok intr */
			dbgmop( "(rob.tisb == 0) && ( rob.tli == 0) -- unclaimed\n");
			raw_spin_unlock_irqrestore(&state->intr_lock, flag);
			return IRQ_NONE;
		}

		eir = GET_MOP_REG(state, MOP_EIR);
		dbgmopdetail("mop_intr_handler eir = %x \n", eir);
		if ( eir == 0 ) {
			state->intr_unclaimed++;
			raw_spin_unlock_irqrestore(&state->intr_lock, flag);
			return IRQ_NONE;
		}

		dbgmopdetail("mop_intr_handler state->intr_unclaimed = %d\n", state->intr_unclaimed);

		eir = GET_MOP_REG(state, MOP_EIR0);
		state->intr_claimed++;

		dbgmop("mop_intr_handler state->intr_claimed = %d\n", state->intr_claimed);

		if ( state->intr_mask & eir )
			two_intr = 1;

		state->intr_mask |= eir;

		dbgmopdetail("mop_intr_handler Waking up\n");

		raw_spin_unlock_irqrestore(&state->intr_lock, flag);
		wake_up_interruptible(&state->pollhead);

		return IRQ_HANDLED;
	} else { /* ===========external interrupts end =========== */
		/* ======== come my interrupts  RESTART or MPRER ========  */	  
		mop_intr_t *intr;
		int num_intr;
		int c_rst_cm;

		dbgmop("== mop_intr from MP ==\n");

		PUT_MOP_REG(state, tisb, 0);	   /* zero to ROB.tisb  */
		interrupts = GET_MOP_BOZU(state, bozu_dr);	/* get 680 */

		dbgmop("== mop_intr from MP interrupts(680)=%x\n",interrupts);

		PUT_MOP_BOZU(state, bozu_dr, 0); /* zero to 680   */            
		if ( interrupts == 0x12345678 ) {
			dbgmop("mop_intr_handler: mop_intr: = 0x12345678 \n"); 

			raw_spin_unlock_irqrestore(&state->intr_lock, flag);
			return IRQ_HANDLED;
		}

		eir = interrupts;      /* for printing */
		{
			hrtime_t  time;
			if ( time_s == 0 )
				time_s = timeout;

			time = ((timeout - time_s)/1000);
#if 0
			dbgmop( F_T " mop_intr: "
				"inst=0x%x, intr_val=0x%x, interrupts=0x%x\n",
				P_T(time), state->inst, state->intr_val, interrupts);
#endif
		}

		if ( !(eir & 15) ) { /* no modeling interrupts */
			eir = eir >> 4;

			if ( !(eir & 15) )
				eir = eir >> 8;
		}

		dbgmop("== mop_intr from MP--- before END  eir = %x\n", eir);
		switch ( eir & 15 ) {
			case 1 : num_intr = 0; c_rst_cm =c_rst_cm_0; break;
			case 2 : num_intr = 1; c_rst_cm =c_rst_cm_1; break;
			case 4 : num_intr = 2; c_rst_cm =c_rst_cm_2; break;
			case 8 : num_intr = 3; c_rst_cm =c_rst_cm_3; break;
			default :
				dbgmop("mop_intr_UNCLAIMED-case INST=0x%x, INTR=0x%x\n",
				instance,interrupts);

				raw_spin_unlock_irqrestore(&state->intr_lock, flag);
				return IRQ_NONE ;
		} /* теперь правильно  */

		state->intr_val = (state->intr_val & c_rst_cm) | interrupts;
		intr = &state->intrs[num_intr];
		intr->cnt++;

		dbgmop("intr->cnt = 0x%x, inst = 0x%x, num_intr = 0x%x\n", 
		intr->cnt, state->inst, num_intr);

		if ( intr->cnt == 1 ) /* для первого ОПОЗДАНИЯ пользователя */
			intr->time_cnt1 = timeout;

		intr->delay = ((timeout - intr->time) / 1000);
		intr->time = timeout ;

		dbgmop("== mop_intr from MP---- before cv_broadcast; for chan 0x%x\n",num_intr );

		raw_spin_unlock_irqrestore(&state->intr_lock, flag);
		ddi_cv_broadcast(&intr->cv);
	}

	dbgmop("== mop_intr from MP----------------  END=\n");
	return IRQ_HANDLED;
}


static int
mop_self_test(mop_state_t *s)
{
	int	r = 0;
	uint	val;

	/*
	 * Start test MOP_FZMC.
	 */
	val = GET_MOP_REG(s, MOP_FZMC);
	if ( val != 0 ) {
		r++;

		dbgmop("After power on "
			"MOP_FZMC = 0x%x expected 0x%x\n", val, 0);
	}

	PUT_MOP_REG(s, MOP_FZMC, MOP_IN_MASK);
	val = GET_MOP_REG(s, MOP_FZMC);

	if ( val != MOP_IN_MASK ) {
		r++;

		dbgmop("Write to  MOP_FZMC = 0x%x\n"
			"Read from MOP_FZMC = 0x%x\n",
			MOP_IN_MASK, val);
	}

	PUT_MOP_REG(s, MOP_FZMC, 0);
	val = GET_MOP_REG(s, MOP_FZMC);
	if ( val != 0 ) {
		r++;

		dbgmop("Write to  MOP_FZMC = 0x%x\n"
			"Read from MOP_FZMC = 0x%x\n",
			0, val);
	}

	/*
	 * Start test MOP_OIR.
	 */
	val = GET_MOP_REG(s, MOP_OIR);
	if ( val != 0 ) {
		r++;

		dbgmop("After power on "
		    "MOP_OIR = 0x%x expected 0x%x\n", val, 0);
	}

	PUT_MOP_REG(s, MOP_OIR, 0);
	val = GET_MOP_REG(s, MOP_OIR);
	if ( val != 0 ) {
		r++;

		dbgmop("Write to  MOP_OIR = 0x%x\n"
			"Read from MOP_OIR = 0x%x\n",
			0, val);
	}

	if ( r != 0 ) {
		dbgmop("MOP hardware works unproperly!\n");

		return 0;
	}

	return 0;
}

static void
mop_init_info(
	mop_state_t	*s)
{
	s->intr_claimed = 0;
	s->intr_unclaimed = 0;
	s->n_iter = 0;
}

static const struct of_device_id mop_match[] = {
	{
#if IS_ENABLED(CONFIG_PCI2SBUS) || defined(CONFIG_E90_FASTBOOT)
		.name = "mop",
#else
		.name = MOP_NAME,
#endif
        },
	{},
};

MODULE_DEVICE_TABLE(of, mop_match);

static struct of_platform_driver mop_driver = {
	.name			= MOP_NAME,
	.match_table	= mop_match,
	.probe			= mop_probe,
	.remove			= mop_remove,
};

static int
__init mop_init(void)
{
	int 	ret;
	
	mop_instances = 0;

	mop_sysctl_register();

	dbgmop(KERN_ALERT "********* MOP_INIT: START for %s *********\n", MOP_NAME);

	ret = of_register_driver(&mop_driver, &of_platform_bus_type);

	dbgmop(KERN_ALERT "********* MOP_INIT: FINISH. Found %d MOP instances *********\n", mop_instances);

	return ret;
}

static void
__exit mop_exit(void)
{
	dbgmop(KERN_ALERT "********* MOP_EXIT: START *********\n");

	of_unregister_driver(&mop_driver);

	dbgmop(KERN_ALERT "********* MOP_EXIT: FINISH *********\n");

	mop_sysctl_unregister();
}

module_init(mop_init);
module_exit(mop_exit);
MODULE_LICENSE("Copyright by MCST 2002");
MODULE_DESCRIPTION("MOP driver");
