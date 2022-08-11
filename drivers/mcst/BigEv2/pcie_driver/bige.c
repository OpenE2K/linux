/* Copyright 2012 Google Inc. All Rights Reserved. */

#include <asm/io.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/uio_driver.h>
#include <linux/uaccess.h>

//#include "../ewl/ewl_shared.h"
#include "bige.h"
#include "bige_ioctl.h"

#define HXDEC_MAX_CORES                 1

#define GOOGLE_DEC_REGS                 184

#define GOOGLE_DEC_FIRST_REG            0
#define GOOGLE_DEC_LAST_REG             GOOGLE_DEC_REGS-1

#define DEC_IO_SIZE             (GOOGLE_DEC_REGS * 4) /* bytes */

static const int DecHwId[] = {0x6732};
unsigned long base_port = -1;

static u32 multicorebase[HXDEC_MAX_CORES] = {-1};

static int irq = -1;
static int elements = 0;

/* module_param(name, type, perm) */
module_param(base_port, ulong, 0);
module_param(irq, int, 0);
module_param_array(multicorebase, uint, &elements, 0);

static int bige_major = 0; /* dynamic allocation */

/* here's all the must remember stuff */
typedef struct
{
    char *buffer;
    unsigned int iosize;
    volatile u8 *hwregs[HXDEC_MAX_CORES];
    int irq;
    int cores;
    struct fasync_struct *async_queue_dec;
} bige_t;

static bige_t bige_data; /* dynamic allocation? */

static int ReserveIO(void);
static void ReleaseIO(void);

/* PCIe resources */
/* TODO(mheikkinen) Implement multicore support. */

static struct pci_dev *gDev = NULL;    /* PCI device structure. */

static u32 gBaseHdwr;                  /* PCI base register address (Hardware address) */
static u32 gBaseLen;                   /* Base register address Length */
static void *gBaseVirt = NULL;         /* Base register virtual address */
static u32 gHantroRegBase = 0;         /* Base register for Hantro IP */
static void* gHantroRegVirt = NULL;     /* Virtual register for Hantro IP */

static int PcieInit(void);
static void ResetAsic(bige_t * dev);

#ifdef BIGE_DEBUG
static void dump_regs(bige_t *dev);
#endif

/* Enable/disable interrupt for userland */
static int bige_irqcontrol(struct uio_info *info, s32 irq_on);

/* IRQ handler */
static irqreturn_t bige_isr(int irq, struct uio_info *dev_info);

//static u32 dec_regs[HXDEC_MAX_CORES][DEC_IO_SIZE/4];
static struct semaphore dec_core_sem;

//static int dec_irq = 0;

//static atomic_t irq_rx = ATOMIC_INIT(0);
//static atomic_t irq_tx = ATOMIC_INIT(0);

static struct file* dec_owner[HXDEC_MAX_CORES];

//static DEFINE_SPINLOCK(owner_lock);

static DECLARE_WAIT_QUEUE_HEAD(dec_wait_queue);
static DECLARE_WAIT_QUEUE_HEAD(hw_queue);

#define DWL_CLIENT_TYPE_PP               4U
#define DWL_CLIENT_TYPE_VP9_DEC          11U
#define DWL_CLIENT_TYPE_HEVC_DEC         12U

//static u32 cfg[HXDEC_MAX_CORES];

static void ReadCoreConfig(bige_t *dev)
{
//    int c;
//    u32 reg, tmp;
//
//    memset(cfg, 0, sizeof(cfg));
//
//    for(c = 0; c < dev->cores; c++)
//    {
//        /* Decoder configuration */
//        reg = ioread32(dev->hwregs[c] + BIGE_SYNTH_CFG_2 * 4);
//
//        tmp = (reg >> DWL_HEVC_E) & 0x3U;
//        if(tmp) printk(KERN_INFO "bige: core[%d] has HEVC\n", c);
//        cfg[c] |= tmp ? 1 << DWL_CLIENT_TYPE_HEVC_DEC : 0;
//
//        tmp = (reg >> DWL_VP9_E) & 0x03U;
//        if(tmp) printk(KERN_INFO "bige: core[%d] has VP9\n", c);
//        cfg[c] |= tmp ? 1 << DWL_CLIENT_TYPE_VP9_DEC : 0;
//
//        /* Post-processor configuration */
//        reg = ioread32(dev->hwregs[c] + BIGEPP_SYNTH_CFG * 4);
//
//        tmp = (reg >> DWL_PP_E) & 0x01U;
//        if(tmp) printk(KERN_INFO "bige: core[%d] has PP\n", c);
//        cfg[c] |= tmp ? 1 << DWL_CLIENT_TYPE_PP : 0;
//    }
}

//static int CoreHasFormat(const void* cfg, int core, u32 format)
//{
//    return (cfg[core] & (1 << format)) ? 1 : 0;
//}
//
//int GetDecCore(long core, bige_t *dev, struct file* filp)
//{
//    int success = 0;
//    unsigned long flags;
//
//    PDEBUG("GetDecCore\n");
//    spin_lock_irqsave(&owner_lock, flags);
//    if(dec_owner[core] == NULL )
//    {
//        dec_owner[core] = filp;
//        success = 1;
//    }
//
//    spin_unlock_irqrestore(&owner_lock, flags);
//    PDEBUG("spin_lock_irqstore GetDecCore\n");
//
//    return success;
//}
//
//int GetDecCoreAny(long *core, bige_t *dev, struct file* filp,
//        unsigned long format)
//{
//    int success = 0;
//    long c;
//
//    *core = -1;
//
//    for(c = 0; c < dev->cores; c++)
//    {
//        /* a free core that has format */
//        if(CoreHasFormat(cfg, c, format) && GetDecCore(c, dev, filp))
//        {
//            success = 1;
//            *core = c;
//            break;
//        }
//    }
//
//    PDEBUG("GetCoreAny Success\n");
//    return success;
//}
//
//long ReserveDecoder(bige_t *dev, struct file* filp, unsigned long format)
//{
//    long core = -1;
//
//    PDEBUG("Reserve core\n");
//    /* reserve a core */
//    if (down_interruptible(&dec_core_sem))
//        return -ERESTARTSYS;
//
//    /* lock a core that has specific format*/
//    if(wait_event_interruptible(hw_queue,
//            GetDecCoreAny(&core, dev, filp, format) != 0 ))
//        return -ERESTARTSYS;
//
//    PDEBUG("Reserve core, reserved\n");
//    return core;
//}

void ReleaseDecoder(bige_t *dev, long core)
{
//    u32 status;
//    unsigned long flags;
//    u32 counter = 0;
//
//
//    status = ioread32(dev->hwregs[core] + BIGE_IRQ_STAT_DEC_OFF);
//
//    /* make sure HW is disabled */
//    if(status & BIGE_DEC_E)
//    {
//        printk(KERN_INFO "bige: DEC[%li] still enabled -> reset\n", core);
//
//        while(status & BIGE_DEC_E)
//        {
//            if(!(counter & 0x7FF))
//                PDEBUG("bige: Killed, wait for HW finish\n", core);
//            status = ioread32(dev->hwregs[core] + BIGE_IRQ_STAT_DEC_OFF);
//            if(++counter > 500000){
//
//                printk(KERN_INFO "bige: Killed, timeout\n", core);
//                break;
//            }
//        }
//
//        iowrite32(0, dev->hwregs[core] + BIGE_IRQ_STAT_DEC_OFF);
//
//    }
//
//    spin_lock_irqsave(&owner_lock, flags);
//
//    dec_owner[core] = NULL;
//
//    spin_unlock_irqrestore(&owner_lock, flags);
//
//    up(&dec_core_sem);
//
//    wake_up_interruptible_all(&hw_queue);
}

//long DecFlushRegs(bige_t *dev, struct core_desc *core)
//{
//    long ret = 0, i;
//
//    u32 id = core->id;
//
//    ret = copy_from_user(dec_regs[id], core->regs, GOOGLE_DEC_REGS*4);
//    if (ret)
//    {
//        PDEBUG("copy_from_user failed, returned %li\n", ret);
//        return -EFAULT;
//    }
//
//    /* write all regs but the status reg[1] to hardware */
//    for(i = 2; i <= GOOGLE_DEC_LAST_REG; i++)
//        iowrite32(dec_regs[id][i], dev->hwregs[id] + i*4);
//
//    /* write the status register, which may start the decoder */
//    iowrite32(dec_regs[id][1], dev->hwregs[id] + 4);
//
//    PDEBUG("flushed registers on core %d %x\n", id, dec_regs[id][1]);
//
//    return 0;
//}
//
//long DecRefreshRegs(bige_t *dev, struct core_desc *core)
//{
//    long ret, i;
//    u32 id = core->id;
//
//    /* user has to know exactly what they are asking for */
//    if(core->size != (GOOGLE_DEC_REGS * 4)) {
//        PDEBUG("DecRefreshRegs failed, wrong size %d\n", core->size);
//        return -EFAULT;
//    }
//    /* read all registers from hardware */
//    for(i = 0; i <= GOOGLE_DEC_LAST_REG; i++)
//        dec_regs[id][i] = ioread32(dev->hwregs[id] + i*4);
//
//    /* put registers to user space*/
//    ret = copy_to_user(core->regs, dec_regs[id], GOOGLE_DEC_REGS*4);
//    if (ret)
//    {
//        PDEBUG("copy_to_user failed, returned %li\n", ret);
//        return -EFAULT;
//    }
//
//    return 0;
//}
//
//static int CheckDecIrq(bige_t *dev, int id)
//{
//    unsigned long flags;
//    int rdy = 0;
//
//    const u32 irq_mask = (1 << id);
//
//    spin_lock_irqsave(&owner_lock, flags);
//
//    if(dec_irq & irq_mask)
//    {
//        /* reset the wait condition(s) */
//        dec_irq &= ~irq_mask;
//        rdy = 1;
//    }
//
//    spin_unlock_irqrestore(&owner_lock, flags);
//
//    return rdy;
//}
//
//long WaitDecReadyAndRefreshRegs(bige_t *dev, struct core_desc *core)
//{
//    u32 id = core->id;
//
//    PDEBUG("wait_event_interruptible DEC[%d]\n", id);
//
//    if(wait_event_interruptible(dec_wait_queue, CheckDecIrq(dev, id)))
//    {
//        PDEBUG("DEC[%d]  wait_event_interruptible interrupted\n", id);
//        return -ERESTARTSYS;
//    }
//
//    atomic_inc(&irq_tx);
//
//    /* refresh registers */
//    return DecRefreshRegs(dev, core);
//}
//
//long PPFlushRegs(bige_t *dev, struct core_desc *core)
//{
//    long ret = 0;
//    u32 id = core->id;
//    u32 i;
//
//    ret = copy_from_user(dec_regs[id] + GOOGLE_DEC_REGS, core->regs,
//            GOOGLE_PP_REGS*4);
//    if (ret)
//    {
//        PDEBUG("copy_from_user failed, returned %li\n", ret);
//        return -EFAULT;
//    }
//
//    /* write all regs but the status reg[1] to hardware */
//    for(i = GOOGLE_PP_FIRST_REG + 1; i <= GOOGLE_PP_LAST_REG; i++)
//        iowrite32(dec_regs[id][i], dev->hwregs[id] + i*4);
//
//    /* write the stat reg, which may start the PP */
//    iowrite32(dec_regs[id][GOOGLE_PP_FIRST_REG],
//            dev->hwregs[id] + GOOGLE_PP_FIRST_REG * 4);
//
//    return 0;
//}
//
//long PPRefreshRegs(bige_t *dev, struct core_desc *core)
//{
//    long i, ret;
//    u32 id = core->id;
//
//    /* user has to know exactly what they are asking for */
//    if(core->size != (GOOGLE_PP_REGS * 4))
//        return -EFAULT;
//
//    /* read all registers from hardware */
//    for(i = GOOGLE_PP_FIRST_REG; i <= GOOGLE_PP_LAST_REG; i++)
//        dec_regs[id][i] = ioread32(dev->hwregs[id] + i*4);
//
//    /* put registers to user space*/
//    ret = copy_to_user(core->regs, dec_regs[id] + GOOGLE_PP_FIRST_REG,
//            GOOGLE_PP_REGS * 4);
//    if (ret)
//    {
//        PDEBUG("copy_to_user failed, returned %li\n", ret);
//        return -EFAULT;
//    }
//
//    return 0;
//}

/*------------------------------------------------------------------------------
 Function name   : bige_ioctl
 Description     : communication method to/from the user space

 Return type     : long
------------------------------------------------------------------------------*/

static long bige_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
  int err = 0;
//  long tmp;

#ifdef HW_PERFORMANCE
  struct timeval *end_time_arg;
#endif

  PDEBUG("ioctl cmd 0x%08x\n", cmd);

  // extract the type and number bitfields, and don't decode
  // wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
  if (_IOC_TYPE(cmd) != BIGE_IOC_MAGIC)
    return -ENOTTY;
  if (_IOC_NR(cmd) > BIGE_IOC_MAXNR)
    return -ENOTTY;

  // the direction is a bitmask, and VERIFY_WRITE catches R/W
  // transfers. `Type' is user-oriented, while
  // access_ok is kernel-oriented, so the concept of "read" and
  // "write" is reversed
  if (_IOC_DIR(cmd) & _IOC_READ)
    err = !access_ok((void *) arg, _IOC_SIZE(cmd));
  else if (_IOC_DIR(cmd) & _IOC_WRITE)
    err = !access_ok((void *) arg, _IOC_SIZE(cmd));

  if (err)
    return -EFAULT;

//  switch (cmd)
//  {
//    case BIGE_IOC_CLI:
//      disable_irq(bige_data.irq);
//      break;
//    case BIGE_IOC_STI:
//      enable_irq(bige_data.irq);
//      break;
//    case BIGE_IOCGHWOFFSET:
//      __put_user(multicorebase[0], (unsigned long *) arg);
//      break;
//    case BIGE_IOCGHWIOSIZE:
//      __put_user(bige_data.iosize, (unsigned int *) arg);
//      break;
//    case BIGE_IOC_MC_OFFSETS:
//    {
//        tmp = copy_to_user((size_t*) arg, multicorebase, sizeof(multicorebase));
//        if (err)
//        {
//            PDEBUG("copy_to_user failed, returned %li\n", tmp);
//            return -EFAULT;
//        }
//        break;
//    }
//    case BIGE_IOC_MC_CORES:
//        __put_user(bige_data.cores, (unsigned int *) arg);
//        break;
//    case BIGE_IOCS_DEC_PUSH_REG:
//    {
//        struct core_desc core;
//
//        /* get registers from user space*/
//        tmp = copy_from_user(&core, (void*)arg, sizeof(struct core_desc));
//        if (tmp)
//        {
//            PDEBUG("copy_from_user failed, returned %li\n", tmp);
//            return -EFAULT;
//        }
//
//        DecFlushRegs(&bige_data, &core);
//        break;
//    }
//    case BIGE_IOCS_PP_PUSH_REG:
//    {
//        struct core_desc core;
//
//        /* get registers from user space*/
//        tmp = copy_from_user(&core, (void*)arg, sizeof(struct core_desc));
//        if (tmp)
//        {
//            PDEBUG("copy_from_user failed, returned %li\n", tmp);
//            return -EFAULT;
//        }
//
//        PPFlushRegs(&bige_data, &core);
//        break;
//    }
//    case BIGE_IOCS_DEC_PULL_REG:
//    {
//        struct core_desc core;
//
//        PDEBUG("start BIGE_IOCS_DEC_PULL_REG\n");
//  
//        /* get registers from user space*/
//        tmp = copy_from_user(&core, (void*)arg, sizeof(struct core_desc));
//        if (tmp)
//        {
//            PDEBUG("copy_from_user failed, returned %li\n", tmp);
//            return -EFAULT;
//        }
//
//        return DecRefreshRegs(&bige_data, &core);
//    }
//    case BIGE_IOCS_PP_PULL_REG:
//    {
//        struct core_desc core;
//
//        /* get registers from user space*/
//        tmp = copy_from_user(&core, (void*)arg, sizeof(struct core_desc));
//        if (tmp)
//        {
//            PDEBUG("copy_from_user failed, returned %li\n", tmp);
//            return -EFAULT;
//        }
//
//        return PPRefreshRegs(&bige_data, &core);
//    }
//    case BIGE_IOCH_DEC_RESERVE:
//    {
//        PDEBUG("Reserve DEC core, format = %li\n", arg);
//        return ReserveDecoder(&bige_data, filp, arg);
//    }
//    case BIGE_IOCT_DEC_RELEASE:
//    {
//        
//        PDEBUG("Release DEC, core = %li\n", arg);
//        if(arg >= bige_data.cores || dec_owner[arg] != filp)
//        {
//            PDEBUG("bogus DEC release, core = %li\n", arg);
//            return -EFAULT;
//        }
//
//        PDEBUG("Release DEC, core = %li\n", arg);
//
//        ReleaseDecoder(&bige_data, arg);
//
//        break;
//    }
//    case BIGE_IOCQ_PP_RESERVE:
//        return ReservePostProcessor(&bige_data, filp);
//    case BIGE_IOCT_PP_RELEASE:
//    {
//        if(arg != 0 || pp_owner[arg] != filp)
//        {
//            PDEBUG("bogus PP release %li\n", arg);
//            return -EFAULT;
//        }
//
//        ReleasePostProcessor(&bige_data, arg);
//
//        break;
//    }
//    case BIGE_IOCX_DEC_WAIT:
//    {
//        struct core_desc core;
//
//        PDEBUG("BIGE_IOCX_DEC_WAIT\n", tmp);
//        /* get registers from user space */
//        tmp = copy_from_user(&core, (void*)arg, sizeof(struct core_desc));
//        if (tmp)
//        {
//            PDEBUG("copy_from_user failed, returned %li\n", tmp);
//            return -EFAULT;
//        }
//
//        return WaitDecReadyAndRefreshRegs(&bige_data, &core);
//    }
//    case BIGE_IOCX_PP_WAIT:
//    {
//        struct core_desc core;
//
//        /* get registers from user space */
//        tmp = copy_from_user(&core, (void*)arg, sizeof(struct core_desc));
//        if (tmp)
//        {
//            PDEBUG("copy_from_user failed, returned %li\n", tmp);
//            return -EFAULT;
//        }
//
//        return WaitPPReadyAndRefreshRegs(&bige_data, &core);
//    }
//    case BIGE_IOX_ASIC_ID:
//    {
//        u32 id;
//        __get_user(id, (size_t*)arg);
//
//        if(id >= bige_data.cores)
//        {
//            return -EFAULT;
//        }
//        id = ioread32(bige_data.hwregs[id]);
//        __put_user(id, (size_t*) arg);
//    }
//    case BIGE_DEBUG_STATUS:
//    {
//        printk(KERN_INFO "bige: dec_irq     = 0x%08x \n", dec_irq);
//
//        printk(KERN_INFO "bige: IRQs received/sent2user = %d / %d \n",
//                atomic_read(&irq_rx), atomic_read(&irq_tx));
//
//        for (tmp = 0; tmp < bige_data.cores; tmp++)
//        {
//            printk(KERN_INFO "bige: dec_core[%li] %s\n",
//                    tmp, dec_owner[tmp] == NULL ? "FREE" : "RESERVED");
//            printk(KERN_INFO "bige: pp_core[%li]  %s\n",
//                    tmp, pp_owner[tmp] == NULL ? "FREE" : "RESERVED");
//        }
//    }
//    default:
//        return -ENOTTY;
//  }

  return 0;
}

/*------------------------------------------------------------------------------
 Function name   : bige_open
 Description     : open method

 Return type     : int
------------------------------------------------------------------------------*/

static int bige_open(struct inode *inode, struct file *filp)
{
    PDEBUG("dev opened\n");
    return 0;
}

/*------------------------------------------------------------------------------
 Function name   : bige_release
 Description     : Release driver

 Return type     : int
------------------------------------------------------------------------------*/

static int bige_release(struct inode *inode, struct file *filp)
{
  int n;
  bige_t *dev = &bige_data;

  PDEBUG("closing ...\n");

  for (n = 0; n < dev->cores; n++) {
    if (dec_owner[n] == filp) {
      PDEBUG("releasing dec core %i lock\n", n);
      ReleaseDecoder(dev, n);
    }
  }
  return 0;
}

/* VFS methods */
static struct file_operations bige_fops =
{
  .owner = THIS_MODULE,
  .open = bige_open,
  .release = bige_release,
  .unlocked_ioctl = bige_ioctl,
  .fasync = NULL
};

/*------------------------------------------------------------------------------
 Function name   : bige_init
 Description     : Initialize the driver

 Return type     : int
------------------------------------------------------------------------------*/

int __init bige_init(void)
{
  int result, i;
  /* u32 buf[4]; */

  printk(KERN_INFO "bige: Initializing\n");

  result = PcieInit();
  if (result)
    goto err;

  multicorebase[0] = gHantroRegBase;
  elements = 1;

  // Find the IRQ
  if (irq > 0)
    irq = gDev->irq;

  bige_data.iosize = DEC_IO_SIZE;
  bige_data.irq = irq;

  for(i=0; i< HXDEC_MAX_CORES; i++)
  {
      bige_data.hwregs[i] = 0;
      /* If user gave less core bases that we have by default,
       * invalidate default bases
       */
      if(elements && i>=elements)
      {
          multicorebase[i] = -1;
      }
  }

  bige_data.async_queue_dec = NULL;

  result = register_chrdev(bige_major, "bige", &bige_fops);
  if (result < 0) {
    printk(KERN_ERR "bige: unable to get major %d\n", bige_major);
    goto err;
  } else if (result != 0) {
    bige_major = result;
  }

  result = ReserveIO();
  if (result < 0) {
      goto err;
  }

  memset(dec_owner, 0, sizeof(dec_owner));

  sema_init(&dec_core_sem, bige_data.cores);
#if 0
  // TODO(trevorbunker): Do some sanity reads and writes. These can be removed
  // when driver works.
  memset_io(gHantroRegVirt, 0, 256*4);

  memset(buf, 0, 4*4);
  memcpy_fromio(buf, gHantroRegVirt, 4*4);
  printk(KERN_INFO "Before: buf[0] = 0x%X\n", buf[0]);
  printk(KERN_INFO "Before: buf[1] = 0x%X\n", buf[1]);
  printk(KERN_INFO "Before: buf[2] = 0x%X\n", buf[2]);
  printk(KERN_INFO "Before: buf[3] = 0x%X\n", buf[3]);

  buf[0] = 0xDEADBEEF;
  buf[1] = 0x12345678;
  buf[2] = 0xBEE3FEED;
  buf[3] = 0x98765432;
  memcpy_toio(gHantroRegVirt, buf, 4*4);

  memset(buf, 0, 4*4);
  memcpy_fromio(buf, gHantroRegVirt, 4*4);

  printk(KERN_INFO "After: buf[0] = 0x%X\n", buf[0]);
  printk(KERN_INFO "After: buf[1] = 0x%X\n", buf[1]);
  printk(KERN_INFO "After: buf[2] = 0x%X\n", buf[2]);
  printk(KERN_INFO "After: buf[3] = 0x%X\n", buf[3]);
#endif
  // read configuration fo all cores
  ReadCoreConfig(&bige_data);

  /* reset hardware */
  ResetAsic(&bige_data);

  if (irq <= 0) {
    printk(KERN_INFO "bige: IRQ not in use!\n");
  }
  printk(KERN_INFO "bige: module inserted. Major = %d\n", bige_major);

  return 0;

err:
  ReleaseIO();
  unregister_chrdev(bige_major, "bige");
  printk(KERN_INFO "bige: module not inserted\n");
  return result;
}

/*------------------------------------------------------------------------------
 Function name   : bige_cleanup
 Description     : clean up

 Return type     : int
------------------------------------------------------------------------------*/

void __exit bige_cleanup(void)
{
  bige_t *dev = &bige_data;

  /* reset hardware */
  ResetAsic(dev);

  // Release all of the PCI regions and mappings
  ReleaseIO();

  unregister_chrdev(bige_major, "bige");

  printk(KERN_INFO "bige: module removed\n");
  return;
}

/*------------------------------------------------------------------------------
 Function name   : PcieInit
 Description     : Initialize PCI Hw access

 Return type     : int
 ------------------------------------------------------------------------------*/

static int PcieInit(void)
{
  int rc = 0;
  struct uio_info *info;

  // Look for a device on the PCIe bus that matches the vendor and device ID
  gDev = pci_get_device(BIGE_PCI_VENDOR_ID, BIGE_PCI_DEVICE_ID, gDev);
  if (gDev == NULL) {
    gDev = pci_get_device(PCI_VENDOR_ID_MCST_TMP, 0x803b, gDev);
  }
  if (gDev == NULL) {
    printk(KERN_ERR "bige: pci_get_device() failed.\n");
    return -1;
  }

  // Allocate space for the uio_info struct
  info = kzalloc(sizeof(struct uio_info), GFP_KERNEL);
  if (!info) {
    printk(KERN_ERR "bige: kzalloc() failed for uio_info struct.\n");
    return -ENOMEM;
  }

  // Enable the PCIe device
  rc = pci_enable_device(gDev);
  if (rc) {
    printk(KERN_ERR "bige: pci_enable_device() failed.\n");
    return -1;
  }

  // Check that BAR 0 exists
  if (!(pci_resource_flags(gDev, BIGE_CONTROL_BAR) & IORESOURCE_MEM)) {
    printk(KERN_ERR "bige: BAR %d is configured incorrectly or missing.\n",
           BIGE_CONTROL_BAR);
    return -1;
  }

  // Request owernship of PCI device
  rc = pci_request_regions(gDev, "bige");
  if (rc) {
    printk(KERN_ERR "bige: pci_request_regions() failed.\n");
    return -1;
  }

  // Get base address of BAR 0
  gBaseHdwr = pci_resource_start(gDev, BIGE_CONTROL_BAR);
  gBaseLen = pci_resource_len (gDev, BIGE_CONTROL_BAR);
  if (gBaseHdwr < 0) {
    printk(KERN_ERR "bige: invalid base address of BAR %d.\n",
           BIGE_CONTROL_BAR);
    return (-1);
  }
  printk(KERN_INFO "bige: BAR %d is located at 0x%X and is %d bytes\n",
         BIGE_CONTROL_BAR, (unsigned int)gBaseHdwr, (unsigned int)gBaseLen);

  // Remap the I/O register block so that it can be safely accessed.
  gBaseVirt = pci_ioremap_bar(gDev, BIGE_CONTROL_BAR);
  if (!gBaseVirt) {
    printk(KERN_ERR "bige: pci_ioremap_bar() failed.\n");
    return -1;
  }
  pci_set_master(gDev);

#ifdef CONFIG_E90S
  rc = pci_alloc_irq_vectors(gDev, 1, 1, PCI_IRQ_MSIX);
  if (rc < 0) {
    printk(KERN_ERR "bige: unable to allocate MSIX irq vector.\n");
    return rc;
  }
  irq = pci_irq_vector(gDev, 0);
#else /* E2K */
  // Try to setup the interrupt
  if (pci_enable_msi(gDev)) {
    printk(KERN_ERR "bige: pci_enable_msi() failed.\n");
//    return -1;
  }
  irq = gDev->irq;
#endif
  printk(KERN_INFO "bige: IRQ = %d\n", gDev->irq);

  gHantroRegBase = gBaseHdwr + BIGE_REG_OFFSET;
  gHantroRegVirt = (unsigned int *)gBaseVirt + BIGE_REG_OFFSET/4;
  //((unsigned int*)gBaseVirt)[HLINA_ADDR_TRANSL_REG] = HLINA_TRANSL_BASE;
  //printk("bige: Address translation base for %x\n",
  //        (((unsigned int*)gBaseVirt)[HLINA_ADDR_TRANSL_REG]));
  //

  // Create uio_info type
  info->name = "bige";
  info->version = "0.0.2";
  info->mem[0].addr = gBaseHdwr;
  info->mem[0].internal_addr = gBaseVirt;
  info->mem[0].size = gBaseLen;
  info->mem[0].memtype = UIO_MEM_PHYS;
  info->mem[0].name = "BigEv2 regs";
  info->irq = irq;
  info->irq_flags = IRQF_SHARED;
  info->handler = bige_isr;
  info->irqcontrol = bige_irqcontrol;

  /* Try to register the UIO device */
  rc = uio_register_device(&gDev->dev, info);
  if (rc) {
    printk(KERN_ERR "bige: uio_register_device() failed (%d).\n", rc);
    return -1;
  }

  // Store the uio_info struct
  pci_set_drvdata(gDev, info);

  return 0;
}

///*------------------------------------------------------------------------------
// Function name   : CheckHwId
// Return type     : int
//------------------------------------------------------------------------------*/
//static int CheckHwId(bige_t * dev)
//{
//    long int hwid;
//    int i;
//    size_t numHw = sizeof(DecHwId) / sizeof(*DecHwId);
//
//    int found = 0;
//
//    for (i = 0; i < dev->cores; i++)
//    {
//        if (dev->hwregs[i] != NULL )
//        {
//            hwid = readl(dev->hwregs[i]);
//            printk(KERN_INFO "bige: Core %d HW ID=0x%08lx\n", i, hwid);
//            hwid = (hwid >> 16) & 0xFFFF; /* product version only */
//
//            while (numHw--)
//            {
//                if (hwid == DecHwId[numHw])
//                {
//                    printk(KERN_INFO "bige: Supported HW found at 0x%08x\n",
//                            multicorebase[i]);
//                    found++;
//                    break;
//                }
//            }
//            if (!found)
//            {
//                printk(KERN_INFO "bige: Unknown HW found at 0x%08x\n",
//                        multicorebase[i]);
//                return 0;
//            }
//            found = 0;
//            numHw = sizeof(DecHwId) / sizeof(*DecHwId);
//        }
//    }
//
//    return 1;
//}

static int ReserveIO(void)
{
//  bige_data.hwregs[0] = (volatile u8 *) gHantroRegVirt;
//
//  if (bige_data.hwregs[0] == NULL )
//  {
//      printk(KERN_INFO "bige: failed to ioremap HW regs\n");
//      ReleaseIO();
//      return -EBUSY;
//  }
//
//  bige_data.cores = 1;
//  /* check for correct HW */
//  if (!CheckHwId(&bige_data))
//  {
//      ReleaseIO();
//      return -EBUSY;
//  }

  return 0;
}
/*------------------------------------------------------------------------------
 Function name   : releaseIO
 Description     : release

 Return type     : void
------------------------------------------------------------------------------*/

static void ReleaseIO(void)
{
  PDEBUG("Release IO\n");
  if (gBaseVirt != NULL)
    pci_iounmap(gDev, gBaseVirt);
  if (gDev != NULL) {
    struct uio_info *info = pci_get_drvdata(gDev);
    uio_unregister_device(info);
    kfree(info);

    pci_release_regions(gDev);
    pci_disable_device(gDev);
  }
}

/* Enable/disable interrupt for userland */
static int bige_irqcontrol(struct uio_info *info, s32 irq_on)
{
    /* TODO: real need this?.. */
    return 0;
}

/*------------------------------------------------------------------------------
 Function name   : bige_isr
 Description     : interrupt handler

 Return type     : irqreturn_t
------------------------------------------------------------------------------*/
static irqreturn_t bige_isr(int irq, struct uio_info *dev_info)
{
    unsigned int handled = IRQ_NONE;
    void __iomem *hwregs = dev_info->mem[0].internal_addr;
    u32 irq_status_enc;

    /* interrupt status register read */
    irq_status_enc = ioread32(hwregs + BIGE_IRQ_STAT_ENC_OFF);
    if (irq_status_enc & (BIGE_IRQ_MASK
			  | BIGE_IRQ_AXI_READ_DATA_OVERFLOW_MASK
			  | BIGE_IRQ_AXI_WRITE_DATA_UNDERFLOW_MASK
			  | BIGE_IRQ_STREAM_BUF_OVERFLOW
			  | BIGE_IRQ_IDCT_OVERFLOW)) {
	/* clear encoder IRQ and disable IRQ */
	irq_status_enc &= ~(BIGE_IRQ_MASK | BIGE_IRQ_EN_MASK);
	iowrite32(irq_status_enc, hwregs + BIGE_IRQ_STAT_ENC_OFF);
	handled = IRQ_HANDLED;
    }
    return IRQ_RETVAL(handled);
}

/*------------------------------------------------------------------------------
 Function name   : ResetAsic
 Description     : reset asic

 Return type     :
------------------------------------------------------------------------------*/
void ResetAsic(bige_t * dev)
{
//    int i, j;
//    u32 status;
//
//    for (j = 0; j < dev->cores; j++)
//    {
//        status = ioread32(dev->hwregs[j] + BIGE_IRQ_STAT_DEC_OFF);
//
//        if( status & BIGE_DEC_E)
//        {
//        /* abort with IRQ disabled */
//            status = BIGE_DEC_ABORT | BIGE_DEC_IRQ_DISABLE;
//            iowrite32(status, dev->hwregs[j] + BIGE_IRQ_STAT_DEC_OFF);
//        }
//
//        /* reset PP */
//        iowrite32(0, dev->hwregs[j] + BIGE_IRQ_STAT_PP_OFF);
//
//        for (i = 4; i < dev->iosize; i += 4)
//        {
//            iowrite32(0, dev->hwregs[j] + i);
//        }
//    }
}
//
///*------------------------------------------------------------------------------
// Function name   : dump_regs
// Description     : Dump registers
//
// Return type     :
//------------------------------------------------------------------------------*/
#ifdef BIGE_DEBUG
void dump_regs(bige_t *dev)
{
//    int i,c;
//
//    PDEBUG("Reg Dump Start\n");
//    for(c = 0; c < dev->cores; c++)
//    {
//        for(i = 0; i < dev->iosize; i += 4*4)
//        {
//            PDEBUG("\toffset %04X: %08X  %08X  %08X  %08X\n", i,
//                    ioread32(dev->hwregs[c] + i),
//                    ioread32(dev->hwregs[c] + i + 4),
//                    ioread32(dev->hwregs[c] + i + 16),
//                    ioread32(dev->hwregs[c] + i + 24));
//        }
//    }
//    PDEBUG("Reg Dump End\n");
}
#endif

module_init(bige_init);
module_exit(bige_cleanup);

/* module description */
//MODULE_LICENSE("Proprietary");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Google");
MODULE_DESCRIPTION("Driver module for VP9 encoder (BigE)");

