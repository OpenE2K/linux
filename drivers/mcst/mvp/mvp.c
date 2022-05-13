
/*
 * Copyright (c) 2006 by MCST.
 */


#include <linux/irq.h>
#include <linux/of_platform.h>
#include <linux/mcst/ddi.h>
#include <linux/mcst/mvp_def.h>
#include <linux/mcst/p2ssbus.h>
#include <linux/mcst/mcst_selftest.h>

//#include <asm/of_device.h>

// /proc/sys/debug/mvp_debug trigger
int mvp_debug = 0;
int mvp_debug_more = 0;

#define MVP_NO_IRQDELAY

#define	DBGMVP_MODE
#undef DBGMVP_MODE

#define DBGMVPDETAIL_MODE
#undef DBGMVPDETAIL_MODE

#if defined(DBGMVP_MODE)
#define	dbgmvp			printk
#else
#define	dbgmvp			if ( mvp_debug ) printk
#endif

#if defined(DBGMVPDETAIL_MODE)
#define	dbgmvpdetail		printk
#else
#define dbgmvpdetail		if ( mvp_debug_more ) printk
#endif

#define OPEN_EXCL	0

#define MVP_NAME	"MCST,mvp"

/*
 * Definition of relationship between dev_t and interrupt numbers
 * instance, #intr, in/out  <=> minor
 */
#define MVP_IO_IN               1
#define MVP_IO_OUT              2
#define MVP_IO_OS               3

#define MVPTYPE_OLD             1
#define MVPTYPE_NEW             0

#define MAX_MVP_INSTANCES	16	
#define MVP_MINOR(i, io, n)     ((i) << 7 | (io) << 5 | (n))
#define MVP_INTR(d)             (getminor(d) & 0x1f)
#define MVP_INST(d)             (getminor(d) >> 7)
#define MVP_INOUT(d)            (getminor(d) >> 5 & 3)
#define MVP_IN(d)               (MVP_INOUT(d) == MVP_IO_IN)
#define MVP_OUT(d)              (MVP_INOUT(d) == MVP_IO_OUT)
#define MVP_OS(d)               (MVP_INOUT(d) == MVP_IO_OS)

#define MVP_N2OUT(n)            (n < 8) ? 1 << (n + 8) : 1 << (n + 16)
#define MVP_N2IN(n)             (n < 10) ? 1 << (n + 6) : 1 << (n + 12)
#define MVP_NS2IN(m)            (((m << 6) & 0xffc0) | ((m << 12) & 0xffc00000))
#define MVP_IN2NS(m)            (((m >> 6) & 0x3ff) | ((m >> 12) & 0xffc00))


/*
 * MVP chip definitions.
 */

#define MVP_REG_SIZE    0x044   /* size to be mapped                    */

/*
 * MVP_PARITY
 */
#define MVP_PARITY_ENABLE       0x400

/*
 * driver state per instance
 */


/*
 * driver state per instance
 */
typedef struct mvp_state {
        struct of_device	*op;
	int			minor;
        struct mutex            mux;           /* open/close mutex     */
        int                     open_in;
        int                     open_out;
        int                     open_st;
        int                     open_excl;
        caddr_t                 regs_base;
        int                     parity;
        int                     base_polar;
        int                     polar;
        int                     current_st;
        off_t                   mvp_regs_sz;
        raw_spinlock_t          intr_lock;      /* interrupt mutex      */
        u_int                   intr_mask;      /* pending mask         */
        wait_queue_head_t       pollhead;
                                                /* info & measurement   */
        ulong_t                 intr_claimed;
        ulong_t                 intr_unclaimed;
        ulong_t                 n_iter;         /* to send interrupt    */
        ulong_t                 first_lbolt;    /* interrupt send       */
        ulong_t                 last_lbolt;     /* interrupt recieved   */
        u_int                   mvp_type;       /* type of mvp */
	int 			irq_registered;
} mvp_state_t;


struct mvp_file_private {
	int		count;
	mvp_state_t	*state;
	dev_t		dev;
};
/*
 * Macros for register access
 */
#define MVP_REG_ADDR(s, reg)    ((ulong_t *)(s->regs_base + reg))

#define GET_MVP_REG(s, reg)     ddi_getl(DDI_SBUS_SPARC, MVP_REG_ADDR(s, reg))
#define PUT_MVP_REG(s, reg, v)  ddi_putl(DDI_SBUS_SPARC, MVP_REG_ADDR(s, reg), (long)v)

#define mvp_request_threaded_irq request_threaded_irq

static struct class *mvp_class;

static uint_t mvp_chpoll(struct file *file, struct poll_table_struct *wait);
long mvp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static int mvp_open(struct inode *inode, struct file *file);
static int mvp_close(struct inode *inode, struct file *file);

/*
 * file_operations of mvp
 */
const static struct file_operations mvp_fops = {
	.owner		= THIS_MODULE,
	.poll		= mvp_chpoll,
	.unlocked_ioctl	= mvp_ioctl,
	.open		= mvp_open,
	.release	= mvp_close,
};

/*
 * Local routines.
 */

static int	mvp_self_test(mvp_state_t *s);
static irqreturn_t	mvp_intr_handler(int irq, void *arg);


static  mvp_state_t	*mvp_states[MAX_MVP_INSTANCES];
static int mvp_major = 0;


#if defined(CONFIG_SYSCTL)
#include <linux/sysctl.h>

static ctl_table mvp_table[] = {
	{
		.procname	= "mvp_debug",
		.data		= &mvp_debug, 
		.maxlen		= sizeof(mvp_debug),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "mvp_debug_more",
		.data		= &mvp_debug_more, 
		.maxlen		= sizeof(mvp_debug_more),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static ctl_table mvp_root_table[] = {
	{
		.procname	= "debug",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= mvp_table,
	},
	{ }
};

static struct ctl_table_header *mvp_sysctl_header;

static void __init mvp_sysctl_register(void)
{
	mvp_sysctl_header = register_sysctl_table(mvp_root_table);
}

static void mvp_sysctl_unregister(void)
{
	if ( mvp_sysctl_header )
		unregister_sysctl_table(mvp_sysctl_header);
}

#else /* CONFIG_SYSCTL */

static void __init mvp_sysctl_register(void)
{
}

static void mvp_sysctl_unregister(void)
{
}
#endif

static void mvp_init_info(mvp_state_t *s)
{
	s->intr_claimed = 0;
	s->intr_unclaimed = 0;
	s->n_iter = 0;
}


/*
 * Driver detach entry point
 */
static int mvp_detach(struct of_device *op)
{
	mvp_state_t	*state = dev_get_drvdata(&op->dev);
	int error = 0;
	int minor, intr;
	int		instance;

	dbgmvp("mvp_detach start\n");
	if (!state) {
		return 0;
	}
	dev_set_drvdata(&op->dev, NULL);
	instance = state->minor;
	if (state->irq_registered) {
#if defined(CONFIG_SBUS)
                 free_irq(op->irqs[0], state);
#elif IS_ENABLED(CONFIG_PCI2SBUS)
                 sbus_free_irq(op->irqs[0], state);
#else
                 printk("Really crazy behavoir ...\n");
#endif
	}
	if (state->regs_base) {
		 of_iounmap(&state->op->resource[0], state->regs_base, MVP_REG_SIZE);
	} 

	for (intr = 0; intr < MVP_N_IN_INTER; intr++) {
		minor = MVP_MINOR(instance, MVP_IO_IN, intr);
		device_destroy(mvp_class, MKDEV(mvp_major, minor));
	}
	for (intr = 0; intr < MVP_N_OUT_INTER; intr++) {
		minor = MVP_MINOR(instance, MVP_IO_OUT, intr);
		device_destroy(mvp_class, MKDEV(mvp_major, minor));
	}
	for (intr = 0; intr < MVP_N_OUT_INTER; intr++) {
		minor = MVP_MINOR(instance, MVP_IO_OS, intr);
		device_destroy(mvp_class, MKDEV(mvp_major, minor));
	}
	mvp_states[instance] = NULL;
	kfree(state);
        if (!instance && !error)
		class_destroy(mvp_class);
	dbgmvp("mvp_detach finish\n");
	return error;
}




static int mvp_attach(struct of_device *op, const struct of_device_id *match)
{
        mvp_state_t     *state;
	int instance = 0;
	int flags = 0;
	int intr;
        int minor = 0;
	char name[64];

printk("%s:%d\n", __func__, __LINE__);
	mvp_major = register_chrdev(0, MVP_NAME, &mvp_fops);

	for (instance = 0; instance < MAX_MVP_INSTANCES; instance++) {
		if (mvp_states[instance] == NULL) {
			break;
		}
	}

        printk("mvp_attach: start for MVP-%d\n", instance);
	if (instance >= MAX_MVP_INSTANCES) {
		printk("mvp_attach: too many mvps in system (max = %d)\n", MAX_MVP_INSTANCES);
		return -EINVAL;
	}
	state = ddi_malloc(sizeof (mvp_state_t));
	memset(state, 0, sizeof (*state));		
        init_waitqueue_head(&(state->pollhead));
	state->minor = instance;
        state->op = op;
        state->open_in = 0;
        state->open_out = 0;
        state->open_st = 0;
        state->open_excl = 0;
        state->intr_mask = 0;
        mvp_init_info(state);
        spin_mutex_init(&state->intr_lock);
        mutex_init(&state->mux);

        dev_set_drvdata(&op->dev, state);
        /*
	 * Map in operating registers
	 */

        dbgmvpdetail("mvp_attach: resource[0] for MVP-%d is equal to 0x%x\n", instance, 
                              op->resource[0].start);
        state->regs_base = of_ioremap(&op->resource[0], 0,
                               MVP_REG_SIZE, MVP_NAME);
	if (!state->regs_base) {
		printk("mvp_attach: MVP-%d: Could not map regs\n", instance);
		return -EINVAL;
	}


        state->parity = of_getintprop_default(op->node, "mvp-parity", 0);
        state->parity &= 1;
        state->base_polar = MVP_NS2IN(of_getintprop_default(op->node, "mvp-polar", 0));
        state->polar = state->base_polar;

        /*
         * mvp-state property can be added if required.
         */
        state->current_st = 0;
        PUT_MVP_REG(state, MVP_OSR, state->current_st); //+++++++
        PUT_MVP_REG(state, MVP_PARITY, state->parity << 22);

#ifndef MVP_BODY_FOR_PCI
        flags = IRQF_SHARED;
#endif
#ifdef CONFIG_MCST_RT
        flags |=  IRQF_DISABLED;
#endif

	/* sprintf(name,"mvp%d", instance); */
#if defined(CONFIG_SBUS)
        if (mvp_request_threaded_irq(op->irqs[0], &mvp_intr_handler, NULL,
				flags, MVP_NAME, (void *)state)) {
                printk(KERN_ERR "MVP-%d: Can't get irq %d\n", instance, op->irqs[0]);
                return -EAGAIN;
        }
#elif IS_ENABLED(CONFIG_PCI2SBUS)
        if (sbus_request_irq(op->irqs[0], &mvp_intr_handler, NULL, 
				flags, MVP_NAME, (void *)state)) {
                printk(KERN_ERR "MVP-%d: Can't get irq %d\n", instance, op->irqs[0]);
                return -EAGAIN; 
        }
#else
        printk("MVP driver may be loaded only under SBUS || PCI2SBUS || PCI2SBUS_MODULE configs\n");
        return -EAGAIN;
#endif   
        dbgmvpdetail("mvp_attach: request_irq is ok for MVP-%d\n", instance);
        state->irq_registered = 1;


        /*
         * Some hardware control.
         */
        if (mvp_self_test(state) != 0) {
                printk("mvp_attach: MVP-%d fail for mvp_self_test\n", instance);
                goto failure;
        }
        
        printk("mvp_attach: self testing is ok for MVP-%d\n", instance);

        {
//		u_int	init_st = ddi_prop_int(dip, "mvp-init_st"); 

		u_int   init_st = 0x00008000;
		init_st &= 0XFF00FF00;
		if (init_st > 0 && instance == 0) {
			printk("%d mvp_attach: set state = 0x%x.\n"
				"See file mvp.conf\n",
				instance, init_st);
			state->current_st = init_st;
			PUT_MVP_REG(state, MVP_OSR, state->current_st);
		}
	} //+++++++

	mvp_class = class_create(THIS_MODULE, "mvp");
	if (IS_ERR(mvp_class)) {
		pr_err("Error creating class: /sys/class/mvp.\n");
	}

        for (intr = 0; intr < MVP_N_IN_INTER; intr++) {
		(void) sprintf(name, "mvp_%d_in:%d", instance, intr);
		minor = MVP_MINOR(instance, MVP_IO_IN, intr);
		if (!IS_ERR(mvp_class)) {
			/* pr_info("make node /sys/class/mvp/%s\n", name); */
			if (device_create(mvp_class, NULL,
				MKDEV(mvp_major, minor), NULL, name) == NULL)
				pr_err("create a node %s failed\n", name);
		}

        }
        for (intr = 0; intr < MVP_N_OUT_INTER; intr++) {
		(void) sprintf(name, "mvp_%d_out:%d", instance, intr);
                minor = MVP_MINOR(instance, MVP_IO_OUT, intr);
		if (!IS_ERR(mvp_class)) {
			/* pr_info("make node /sys/class/mvp/%s\n", name); */
			if (device_create(mvp_class, NULL,
				MKDEV(mvp_major, minor), NULL, name) == NULL)
				pr_err("create a node %s failed\n", name);
		}

        }
        for (intr = 0; intr < MVP_N_OUT_INTER; intr++) {
                (void) sprintf(name, "mvp_%d_st:%d", instance, intr);
		minor = MVP_MINOR(instance, MVP_IO_OS, intr);
		if (!IS_ERR(mvp_class)) {
			/* pr_info("make node /sys/class/mvp/%s\n", name); */
			if (device_create(mvp_class, NULL,
				MKDEV(mvp_major, minor), NULL, name) == NULL)
				pr_err("create a node %s failed\n", name);
		}
        }
	mvp_states[instance] = state;
        printk("mvp_attach: successfully finished for MVP-%d\n", instance);
        return (0);

failure:
        printk("mvp_attach: some failures happen when attaching MVP-%d\n", instance);
        mvp_detach(op);
        return (-EFAULT);
}



/*
 * Driver open entry point
 */

static int
mvp_open(struct inode *inode, struct file *file)
{
	dev_t		dev = MKDEV(mvp_major, iminor(inode));
	mvp_state_t	*state = mvp_states[MVP_INST(dev)];
	int		intr;
	int		intr_mask;
	int		firstopen = 1;
	struct mvp_file_private *pdata;

        dbgmvpdetail("mvp_open: start\n");
	if (state == NULL) {
		return -EINVAL;
	}	
	intr = MVP_INTR(dev);
	dbgmvpdetail("mvp_open: intr %d, dev = 0x%x, i_rdev = 0x%x\n", intr, dev, inode->i_rdev); 
		
	mutex_enter(&state->mux);
	if (MVP_IN(dev)) {		
		intr_mask = MVP_N2IN(intr); 
		firstopen = ((state->open_in & intr_mask) == 0);
	} else if (MVP_OUT(dev)) {
		intr_mask = MVP_N2OUT(intr);
		firstopen = ((state->open_out & intr_mask) == 0);
	}else {
		intr_mask = MVP_N2OUT(intr);
		firstopen = ((state->open_st & intr_mask) == 0);
	}
	dbgmvpdetail("OPEN: open_in = 0x%x, open_out = 0x%x, open_st = 0x%x\n",
		(unsigned int)state->open_in, (unsigned int)state->open_out, 
                (unsigned int)state->open_st);

        if (OPEN_EXCL) {
		printk("mvp: OPEN_EXCL: %d\n", OPEN_EXCL);
                /* Some node can be opened only once */
	        if (!firstopen) {
		        mutex_exit(&state->mux);
		        printk("mvp: already opened\n");
		        return (-EBUSY);
                }
                state->open_excl = 1;
	} else {
		if (state->open_excl) {
			mutex_exit(&state->mux);
			printk("mvp:already opened exclusively, %d\n", state->open_excl);
			return (-EBUSY);
		}
	}
	 

        /* Common case ... that allows many openings */
        pdata = (struct mvp_file_private *)file->private_data;
	if (pdata) {
		if (pdata->state != state) {
			mutex_exit(&state->mux);
			printk("Dismatch state of file and inode\n");
			return -EINVAL;
		}
		pdata->count++;
	} else {
		pdata = ddi_malloc(sizeof (*pdata));
		pdata->count = 1;
		pdata->state = state;
		pdata->dev = dev;
		file->private_data = pdata;
	}

	if (MVP_IN(dev)) {
		intr_mask = MVP_N2IN(intr);
		state->open_in |= intr_mask;
		state->polar = (state->polar & ~intr_mask) |
		    (state->base_polar & intr_mask);
		dbgmvpdetail("mvp_open: MVP_IN intr_mask 0x%x open_in 0x%x polar 0x%x\n",
			(unsigned int)intr_mask, 
                        (unsigned int)state->open_in, (unsigned int)state->polar); 
		PUT_MVP_REG(state, MVP_EIPR, state->polar);
		PUT_MVP_REG(state, MVP_EIMR, state->open_in);
	} else if (MVP_OUT(dev)) {
		intr_mask = MVP_N2OUT(intr);
		state->open_out |= intr_mask;
		dbgmvpdetail("mvp_open: MVP_OUT intr_mask 0x%x open_out 0x%x\n",
			(unsigned int)intr_mask, (unsigned int)state->open_out); 
	} else {
		intr_mask = MVP_N2OUT(intr);
		state->open_st |= intr_mask;
		dbgmvpdetail("mvp_open: MVP_N2OUT intr_mask 0x%x open_st 0x%x\n",
			(unsigned int)intr_mask, (unsigned int)state->open_st); 
	}
	mutex_exit(&state->mux);
	return (0);
}

/*
 * Driver close entry point
 */

static int
mvp_close(struct inode *inode, struct file *file)
{
	dev_t		dev = MKDEV(mvp_major, iminor(inode));
	mvp_state_t	*state = mvp_states[MVP_INST(dev)];
	int		intr;
	int		intr_mask;
        struct mvp_file_private *pdata;

	if (state == NULL) {
		return (ENXIO);
	}
	intr = MVP_INTR(dev);
	
	mutex_enter(&state->mux);

	pdata = file->private_data;
	if (pdata) {
		if (--pdata->count == 0) {
			file->private_data = NULL;
			kfree(pdata);
		}
	} else {
		dbgmvpdetail(KERN_ERR "%s: file private data == NULL\n", __FUNCTION__);
                mutex_exit(&state->mux);
                return EINVAL;
	}
	if (MVP_IN(dev)) {
		intr_mask = MVP_N2IN(intr);
		state->open_in &= ~intr_mask;
		PUT_MVP_REG(state, MVP_EIMR, state->open_in);
	} else if (MVP_OUT(dev)) {
		intr_mask = MVP_N2OUT(intr);
		state->open_out &= ~intr_mask;
	} else {
		intr_mask = MVP_N2OUT(intr);
		state->open_st &= ~intr_mask;
	}
	dbgmvpdetail("CLOSE: open_in = 0x%x, open_out = 0x%x, open_st = 0x%x\n", 
			(unsigned int)state->open_in, (unsigned int)state->open_out, (unsigned int)state->open_st);
	
	if (state->open_excl) {
		state->open_excl = 0;
		/* restore mvp registers */
		PUT_MVP_REG(state, MVP_EIMR, 0);
		PUT_MVP_REG(state, MVP_EIR, 0);
		PUT_MVP_REG(state, MVP_OIR, 0);
	}
	mutex_exit(&state->mux);

	return (0);
}


/*
 * Driver ioctl entry point
 */
long
mvp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	dev_t		dev = MKDEV(mvp_major, iminor(inode));
	mvp_state_t	*state = mvp_states[MVP_INST(dev)];
	int		rval = 0;
	mvp_op_t	op;
	mvp_info_t	info;
	int		intr;
	int		mask;

	dbgmvpdetail("MVP_IOCTL: cmd - %d, major - %d, minor - %d, dev - 0x%x, i_rdev - 0x%x\n", 
			cmd, MAJOR( inode->i_rdev ), MINOR( inode->i_rdev ), dev, inode->i_rdev);
	if (state == NULL) {
		printk("MVP_IOCTL: return NULL (mvp_state_t *)\n");
		return -ENXIO;
	}
	
	intr = MVP_INTR(dev);
	dbgmvpdetail("MVP_IOCTL: Before switch, MVPIO_SET_STATE: %d\n", MVPIO_SET_STATE);
	switch (cmd) {
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
			strcpy(st_sbus->name, MVP_NAME);

			st_sbus->major = MAJOR(dev);
			st_sbus->minor = MINOR(dev);

//			printk("full_name [%s]\n", dn->full_name);
			tmp = strrchr(dn->full_name, '@');
			if ( tmp ) {
				/* removed symbol "@" from string */
				tmp = &tmp[1];
				//printk("STRRCHR: [%s]\n", tmp);

				sl_n = strrchr(tmp, ',');

				if ( sl_n ) {
					sscanf(tmp, "%d", &slot_num);
					sscanf(&sl_n[1], "%x", &addr);
//					printk("STRRCHR: slot_number [%d], [%s], [%d]\n", slot_num, sl_n, addr);

					if ((addr >> 28) != 0) {
						/* expand present */
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
			int irq = state->irq_registered;
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

			strcpy(st_pci->name, MVP_NAME);
			st_pci->bus = pdev->bus->number;
			st_pci->slot = PCI_SLOT(pdev->devfn);
			st_pci->func = PCI_FUNC(pdev->devfn);
			st_pci->class = pdev->class;

			st_pci->major = MAJOR(dev);
			st_pci->minor = MINOR(dev);

			//printk("%s: tty->index = %d, major = %d, minor = %d\n", __func__, tty->index, st_pci->major, st_pci->minor);

//printk("%s: name [%s]. vendor = %#x, device = %#x. major = %d, minor = %d. bus = %d, slot = %d, func = %d, class = %#x\n", __func__, st_pci->name, st_pci->vendor, st_pci->device, st_pci->major, st_pci->minor, st_pci->bus, st_pci->slot, st_pci->func, st_pci->class);
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
	case MVP_PARITY :
		dbgmvpdetail("MVP_IOCTL: MVP_PARITY\n");
		break;

	case MVPIO_SEND_INTR :
		dbgmvpdetail("MVP_IOCTL: MVPIO_SEND_INTR\n");
		if (!MVP_OUT(dev)) {
                        printk("MVP_IOCTL: is not OUT\n");
			return (-EINVAL);
		}
		mask = MVP_N2OUT(intr);
		spin_mutex_enter(&state->intr_lock);
		PUT_MVP_REG(state, MVP_OIR, mask);
		PUT_MVP_REG(state, MVP_OIR, 0);
		spin_mutex_exit(&state->intr_lock);
		break;
	case MVPIO_SET_POLAR :
		dbgmvpdetail("MVP_IOCTL: MVPIO_SET_POLAR\n");
		if (!MVP_IN(dev)) {
			return (EINVAL);
		}
		mask = MVP_N2IN(intr);
		spin_mutex_enter(&state->intr_lock);
		if ((ulong_t)arg == 0) {
			state->polar &= ~mask;
		} else {
			state->polar |= mask;
		}
		PUT_MVP_REG(state, MVP_EIPR, state->polar);
		spin_mutex_exit(&state->intr_lock);
		break;

	case MVPIO_SET_STATE :
		dbgmvpdetail("MVP_IOCTL: MVPIO_SET_STATE\n");
		if (!MVP_OS(dev)) {
			printk("MVP_IOCTL: return !MVP_OS(dev)\n");
			return (-EINVAL);
		}
		mask = MVP_N2OUT(intr);
		spin_mutex_enter(&state->intr_lock);
		if ((ulong_t)arg == 0) {
			state->current_st &= ~mask;
		} else {
			state->current_st |= mask;
		}
		PUT_MVP_REG(state, MVP_OSR, state->current_st);
		spin_mutex_exit(&state->intr_lock);
		break;

/*!!!*/	case MVPIO_GET_INTR :
		dbgmvpdetail("MVP_IOCTL: MVPIO_GET_INTR\n");
	case MVPIO_GET_INTR_ALL :
		dbgmvpdetail("MVP_IOCTL: MVPIO_GET_INTR_ALL\n");
		{
        	u_int	eir0 = 0;	/* pending mask	*/		
        	u_int	v_r_intr_mask;	/* external interrupt mask	*/
        	u_int	v_r_intr_polr;	/* external interrupt polar	*/
        	u_int	res;
        	u_int	intr;
        	u_int	i;

		spin_mutex_enter(&state->intr_lock);

		v_r_intr_mask = GET_MVP_REG(state, MVP_EIMR);
		v_r_intr_polr = GET_MVP_REG(state, MVP_EIPR);

		if (state->mvp_type == MVPTYPE_OLD) {
			PUT_MVP_REG(state, MVP_EIPR, NULL);
			PUT_MVP_REG(state, MVP_EIPR, MVP_IN_MASK);
			PUT_MVP_REG(state, MVP_EIMR, NULL);
			PUT_MVP_REG(state, MVP_EIMR, MVP_IN_MASK);
		} else {
			PUT_MVP_REG(state, MVP_EIMR, NULL);
			PUT_MVP_REG(state, MVP_EIPR, NULL);
			PUT_MVP_REG(state, MVP_EIMR, MVP_IN_MASK);
		}

		for (i = 0; i < 10; i++) {
			eir0 = GET_MVP_REG(state, MVP_EIR0);
			if (eir0)
				break;
		}

		if (state->mvp_type == MVPTYPE_OLD)
			eir0 ^= MVP_IN_MASK;

		if (cmd == MVPIO_GET_INTR)
			intr = v_r_intr_mask & eir0;
		else
			intr = eir0;

		PUT_MVP_REG(state, MVP_EIPR, v_r_intr_polr);
		PUT_MVP_REG(state, MVP_EIMR, v_r_intr_mask);
		spin_mutex_exit(&state->intr_lock);

		res = ((intr >> 12) & 0xffc00) | ((intr >> 6) & 0x3ff);
    		copy_to_user ((void *)arg, (void *)&res, sizeof(u_int));
		break;
	}

	case MVPIO_GET_REG :
		dbgmvpdetail("MVP_IOCTL: MVPIO_GET_REG, sizeof(mvp_op_t) = 0x%lx\n", 
						(u_long)sizeof(mvp_op_t));
		if (ddi_copyin((caddr_t)arg, (caddr_t)&op,
  						sizeof(mvp_op_t)) != 0)
     			 return -EBADE;
    		
    		spin_mutex_enter(&state->intr_lock);
		/* 
		 * Temporary put under comment.
		if (state->open_excl == 0) {
			mutex_exit(&state->intr_mutex);
			return (EINVAL);
		}
		 */

		/*
		 * Check reg number is valid
		 */
		if ((op.reg < 0) || (op.reg >= MVP_REG_SIZE) ||
		    ((op.reg & 3) != 0)) {
			spin_mutex_exit(&state->intr_lock);
			return (-EINVAL);
		}
		op.val = GET_MVP_REG(state, op.reg);
		spin_mutex_exit(&state->intr_lock);
		if (ddi_copyout((caddr_t)&op, (caddr_t)arg,
			sizeof (mvp_op_t))) {
			return (-EFAULT);
		}

		break;

	case MVPIO_SET_REG :
		dbgmvpdetail("MVP_IOCTL: MVPIO_SET_REG\n");
		if (ddi_copyin((caddr_t)arg, (caddr_t)&op,
  						sizeof(mvp_op_t)) != 0)
     			 return -EBADE;
		spin_mutex_enter(&state->intr_lock);
		if (state->open_excl == 0) {
			spin_mutex_exit(&state->intr_lock);
			return (EINVAL);
		}
		/*
		 * Check reg number is valid
		 */
		if ((op.reg < 0) || (op.reg >= MVP_REG_SIZE) ||
		    ((op.reg & 3) != 0)) {
			spin_mutex_exit(&state->intr_lock);
			return (EINVAL);
		}
		PUT_MVP_REG(state, op.reg, op.val);
		spin_mutex_exit(&state->intr_lock);
		if (ddi_copyout((caddr_t)&op, (caddr_t)arg,
			sizeof (mvp_op_t))) {
			return (EFAULT);
		}
		break;

	case MVPIO_AUTO_INTR :
		dbgmvpdetail("MVP_IOCTL: MVPIO_AUTO_INTR\n");
		if (!MVP_IN(dev)) {
			return (EINVAL);
		}
		mask = MVP_N2IN(intr);
		spin_mutex_enter(&state->intr_lock);
		if (state->open_excl == 0) {
			spin_mutex_exit(&state->intr_lock);
			return (EINVAL);
		}
		state->n_iter = (ulong_t)arg;
		drv_getparm(LBOLT, &state->first_lbolt);
		state->last_lbolt = state->first_lbolt;
		PUT_MVP_REG(state, MVP_EIR, mask);
		spin_mutex_exit(&state->intr_lock);
		break;

	case MVPIO_INFO :
		dbgmvpdetail("MVP_IOCTL: MVPIO_INFO\n");
		info.intr_claimed = state->intr_claimed;
		info.intr_unclaimed = state->intr_unclaimed;
		info.first_lbolt = state->first_lbolt;
		info.last_lbolt = state->last_lbolt;
		// info.tick =  drv_hztousec((clock_t)1);
    		info.tick = HZ;
		dbgmvpdetail("info.intr_unclaimed = %ld\n", info.intr_unclaimed);
		dbgmvpdetail("info.intr_claimed = %ld\n", info.intr_claimed);
    		copy_to_user((void *)arg, (void *)&info, sizeof(mvp_info_t));
		break;
	case MVPIO_CLEAR_INFO :
		dbgmvpdetail("MVP_IOCTL: MVPIO_CLEAR_INFO\n");
		mvp_init_info(state);
		break;

	default:
		dbgmvpdetail("MVP_IOCTL: default\n");
		rval = ENOTTY;
		break;
	}

	return (rval);
}

/*
 * Driver poll entry point
 */
static uint_t
mvp_chpoll(struct file *file, struct poll_table_struct *wait)
{
	struct mvp_file_private *pdata = file->private_data;
	mvp_state_t	*state;
	int		intr;
	int		mask;
	dev_t		dev;

	if (pdata == NULL) {
		return -ENXIO;
	}
	state = pdata->state;
	dev = pdata->dev;
	if (state == NULL) {
		return (ENXIO);
	}
	intr = MVP_INTR(dev);
	
	if (!MVP_IN(dev)) {
		return (EINVAL);
	}
	mask = MVP_N2IN(intr);

	ddi_poll_wait(file, &(state->pollhead),  wait);

	spin_mutex_enter(&state->intr_lock);
	if ((state->intr_mask & mask) != 0) {
		state->intr_mask &= ~mask;
		spin_mutex_exit(&state->intr_lock);
    		return (POLLIN);
	} else {
		spin_mutex_exit(&state->intr_lock);
		return (0);
	}
}



static irqreturn_t
mvp_intr_handler(int irq, void *arg)
{
	mvp_state_t	*state = arg;
	u_int		eir;
	int		two_intr = 0;
	
	dbgmvpdetail("mvp_intr_handler START\n");
	if (arg == NULL) {
		printk("mvp_intr_handler: arg == NULL\n");
		return IRQ_NONE;
	}

	raw_spin_lock_irq(&state->intr_lock);
	eir = GET_MVP_REG(state, MVP_EIR);
	if (eir == 0) {
		state->intr_unclaimed++;
		raw_spin_unlock_irq(&state->intr_lock);
		return IRQ_NONE;
	}
	dbgmvpdetail("mvp_intr_handler state->intr_unclaimed = %ld\n", state->intr_unclaimed);
	eir = GET_MVP_REG(state, MVP_EIR0);
	state->intr_claimed++;
	dbgmvp("mvp_intr_handler state->intr_claimed = %ld\n", state->intr_claimed);
	if ((state->open_excl == 0) || (state->n_iter == 0)) {
		if (state->intr_mask & eir)
			two_intr = 1;
		state->intr_mask |= eir;
		dbgmvpdetail("mvp_intr_handler Waking up\n");
		raw_spin_unlock_irq(&state->intr_lock);
                wake_up_interruptible(&state->pollhead);
		return IRQ_HANDLED;
	}

	/* measurement	*/
	if ((state->n_iter--) <=1 ) {
		//drv_getparm(LBOLT, &state->last_lbolt); last_lbolt ??
		drv_getparm(LBOLT, &state->first_lbolt);
	}
	PUT_MVP_REG(state, MVP_EIR, eir);
	raw_spin_unlock_irq(&state->intr_lock);
	return IRQ_NONE;
}

static int
mvp_self_test(mvp_state_t *s)
{
	int	r = 0;
	uint	val;
	uint	saved;


	/*
	 * Start test MVP_EIMR.
	 */
	val = GET_MVP_REG(s, MVP_EIMR);
	if (val != 0) {
		r++;
		printk("After power on "
		       "MVP_EIMR = 0x%x expected 0x%x\n", val, 0);
	}
	PUT_MVP_REG(s, MVP_EIMR, MVP_IN_MASK);
	val = GET_MVP_REG(s, MVP_EIMR);
	if (val != MVP_IN_MASK) {
		r++;
		printk("Write to  MVP_EIMR = 0x%x\n"
		    "Read from MVP_EIMR = 0x%x\n",
		    MVP_IN_MASK, val);
	}
	PUT_MVP_REG(s, MVP_EIMR, 0);
	val = GET_MVP_REG(s, MVP_EIMR);
	if (val != 0) {
		r++;
		printk("Write to  MVP_EIMR = 0x%x\n"
		    "Read from MVP_EIMR = 0x%x\n",
		    0, val);
	}
	/*
	 * Start test MVP_EIPR.
	 */
	saved = GET_MVP_REG(s, MVP_EIPR);
	PUT_MVP_REG(s, MVP_EIPR, MVP_IN_MASK);
	val = GET_MVP_REG(s, MVP_EIPR);
	if (val != MVP_IN_MASK) {
		r++;
		printk("Write to  MVP_EIPR = 0x%x\n"
		    "Read from MVP_EIPR = 0x%x\n",
		    MVP_IN_MASK, val);
	}
	PUT_MVP_REG(s, MVP_EIPR, 0);
	val = GET_MVP_REG(s, MVP_EIPR);
	if (val != 0) {
		r++;
		printk("Write to  MVP_EIPR = 0x%x\n"
		    "Read from MVP_EIPR = 0x%x\n",
		    0, val);
	}
	PUT_MVP_REG(s, MVP_EIPR, saved);
	/*
	 * Start test MVP_OSR.
	 */
	val = GET_MVP_REG(s, MVP_OSR);
	if (val != 0) {
		/* r++; */
		printk("After power on "
		    "MVP_OSR = 0x%x expected 0x%x\n", val, 0);
	}
	PUT_MVP_REG(s, MVP_OSR, 0);
	val = GET_MVP_REG(s, MVP_OSR);
	if (val != 0) {
		r++;
		printk("Write to  MVP_OSR = 0x%x\n"
		    "Read from MVP_OSR = 0x%x\n",
		    0, val);
	}
	/*
	 * Start test MVP_OIR.
	 */
	val = GET_MVP_REG(s, MVP_OIR);
	if (val != 0) {
		r++;
		printk("After power on "
		    "MVP_OIR = 0x%x expected 0x%x\n", val, 0);
	}
	PUT_MVP_REG(s, MVP_OIR, 0);
	val = GET_MVP_REG(s, MVP_OIR);
	if (val != 0) {
		r++;
		printk("Write to  MVP_OIR = 0x%x\n"
		    "Read from MVP_OIR = 0x%x\n",
		    0, val);
	}
	if (r != 0) {
		printk("MVP hardware works unproperly!\n");
		return (1);
	}
	return (0);

}

static const struct of_device_id mvp_sbus_match[] = {
        {
#if IS_ENABLED(CONFIG_PCI2SBUS) || defined(CONFIG_E90_FASTBOOT)
                .name = "mvp",
#else            
                .name = MVP_NAME,
#endif                
        },
        {},
};

MODULE_DEVICE_TABLE(of, mvp_sbus_match);

static struct of_platform_driver mvp_sbus_driver = {
        .name           = MVP_NAME,
        .match_table    = mvp_sbus_match,
        .probe          = mvp_attach,
        .remove         = mvp_detach,
};


/* Find all the lance cards on the system and initialize them */
static int __init mvp_init(void)
{
	int err;

	mvp_sysctl_register();

	dbgmvpdetail("mvp_init: mvp_ioctl addr = 0x%lx\n", (unsigned long)mvp_ioctl); 

        err = of_register_driver(&mvp_sbus_driver, &of_platform_bus_type);

	if ( !mvp_major ) {
		printk("Failed to register MVP device: no such device. Make rmmod manually.\n");
	}

	return 0;
}

static void __exit mvp_exit(void)
{
        of_unregister_driver(&mvp_sbus_driver);
        unregister_chrdev(mvp_major, MVP_NAME);

	mvp_sysctl_unregister();
}


module_init(mvp_init);
module_exit(mvp_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MVP driver");

