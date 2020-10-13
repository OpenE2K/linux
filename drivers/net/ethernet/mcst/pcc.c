/* pcc.c - driver for MCST's PCI Communication Controller */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/sysctl.h>

#define DRV_NAME "pcc"
#define pcc_dbg(arg...) printk(KERN_ALERT "PCC: "arg)
#define pcc_err(arg...) printk(KERN_ERR "PCC: " arg)

enum {
	PCC_PIO = 0,
	PCC_POLL,
	PCC_DMA,
};

const char *mode_name[] = {
	"PIO",
	"POLL",
	"DMA",
};

int drv_mode = PCC_DMA;
module_param(drv_mode, int, 0);
MODULE_PARM_DESC(drv_mode, "driver mode: 0=PIO, 1=POLL, 2=DMA");

int init_wait = 60; /* in seconds */
module_param(init_wait, int, 0);
MODULE_PARM_DESC(init_wait, "delay in seconds to wait remote answer: "
			    "zero and negative is infinity");

MODULE_DESCRIPTION("MCST PCC driver");
MODULE_AUTHOR("Kirill V. Tkhai <thay@mcst.ru>");

static struct mutex pcc_driver_mutex;
static LIST_HEAD(pcc_device_list);

#define PCC_MTU		((16 * 1024) + 20 + 20 + 12) /* Borrowed from loopback */
#define PCC_FRAME_LEN	(PCC_MTU + ETH_HLEN)
#define PCC_NAPI_WEIGHT	16
#define PCC_DMA_ALIGN	4 /* 4 bytes alignment */
#define FIFO_OFFSET	0x10 /* Reserved space */
#define FIFO_STEP	0x04 /* FIFO increment, step */
#define PCC_PTR_ALIGN(off)	(((off)+4-1)&(~(4-1)))
#define IS_INIT_PTR(p)	(p < FIFO_OFFSET)
#define MEMMAP_WIN_MASK	0xffff
#define MEMMAP_MIN_SIZE (1*1024*1024)

/* Note: I use FIFO pointers (rxr, rxw, txr, txw)    *
 * as number of written/read bytes, not as pointers. *
 * Size of FIFO isn't bigger than 32768 while rxr's  *
 * max value is 65535. So, it's possible to do this. */

/* Initialization order:                             *
 * 1)Write 'FIFO_SIZE >> 1' or '0x0' to txw to send  *
 * interrupt to remote side.                         *
 * 2)Wait until remote side read it (we will get     *
 * TRSM_BUF_EM interrupt).                           *
 * 3)Start network queue                             */

/* MEMMAP buffer is a ring buffer with one exception.*
 * If there is no room for a new message from current*
 * write position to end of buffer, the message is   *
 * writting from the buffer start. It's necessary for*
 * DMA linear copying. Also, (msg_start % 4) == 0    */

struct pcc_bar0 {
	u32 fifo_rxr;
	u32 fifo_rxw;
	u32 fifo_size;
	u32 unused0[13];
	u32 memmap_lrwena;
	u32 memmap_lbaddr;
	u32 memmap_lmask;
	u32 unused1[13];
	u32 dma_laddr;
	u32 dma_rvaddr;
	u32 dma_dir;
	u32 dma_size;
	u32 dma_lrwena;
	u32 dma_lbaddr;
	u32 dma_lmask;
	u32 dma_stat;
	u32 dma_en;
	u32 unused2[7];
	u32 intreg;
};

struct pcc_bar3 {
	u32 fifo_txr; /* R/W */
	u32 fifo_txw; /* W/O */
};

/* It is in the beginning of BAR1 */
struct pcc_header {
	/* Remote side writes this data for us */
	u32 memmap_size;
	u32 memmap_rptr; /* Memmap is a ring buffer */
};

enum {
	PCC_OK = 0,
	PCC_STOP,
	PCC_RESTART,
};

struct pcc {
	raw_spinlock_t lock;
	wait_queue_head_t wait;
	int status;

	struct sk_buff *skb;
	u32 dma_addr;
	u32 dma_size;

	u32 prev_dma_addr;
	u32 prev_dma_size;

	struct tasklet_struct dma_rx_tasklet;

	void __iomem *bar[4];
	struct pcc_bar0 __iomem *bar0;
	void __iomem *bar1;
	void __iomem *bar2;
	struct pcc_bar3 __iomem *bar3;

	u32 fifo_size;
	u32 fifo_txw;

	u32 memmap_busa; /* Start BUS addr of memmap window in local physmem */
	u32 memmap_size;
	void *memmap_va; /* Virtual address of above */
	u32 memmap_na_busa; /* Not-aligned address given by alloc_coherent */
	u32 memmap_na_size;
	void *memmap_na_va;

	u32 remote_memmap_size;
	u32 memmap_wptr; /* Written by us */
	u32 memmap_rptr; /* Read by us    */
	u32 old_memmap_rptr; /* Read by us    */ 

	struct list_head device_list;

	struct net_device_stats stats;
	struct pci_dev *pdev;
};

static struct pci_device_id pcc_id_table[] = {
	{ 0x8086, 0xE3F4, 0xAAA4, 0xAA02, 0, 0 }, /* host  */
	{ 0x8086, 0xE3F4, 0xAAA4, 0xAA01, 0, 0 }, /* iohub */
	{},
};

static int pcc_online_debug = 0;

static int pcc_proc_handler(struct ctl_table *table, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos);

static struct ctl_table_header *pcc_table_header;

static ctl_table pcc_ctl[] = {
	{
		.procname	= "pcc_debug",
		.data		= &pcc_online_debug,
		.maxlen		= sizeof(pcc_online_debug),
		.mode		= S_IRUSR|S_IWUSR,
		.proc_handler	= pcc_proc_handler,
	},
	{}
};

#define RECV_BUF_NE	(1 << 0) /* Receive buffer isn't empty */
#define TRSM_BUF_EM	(1 << 1) /* Transmit buffer is empty   */
#define DMA_FINISHED	(1 << 2) /* DMA's finished local */

static inline u32 intreg2req(u32 intreg)
{
	return (intreg >> 16) & 7;
}
static inline u32 req2intreg(u32 req)
{
	BUG_ON(req & ~(RECV_BUF_NE | TRSM_BUF_EM | DMA_FINISHED));

	return req << 16;
}
static inline u32 intreg2ena(u32 intreg)
{
	return intreg & 7;
}
static inline u32 ena2intreg(u32 mask)
{
	BUG_ON(mask & ~(RECV_BUF_NE | TRSM_BUF_EM | DMA_FINISHED));

	return mask;
}

static inline void enable_pcc_intr(struct pcc *pcc, u32 mask)
{
	u32 intreg = ena2intreg(mask) | 0x80000000;

	writel(intreg, &pcc->bar0->intreg);
}
static inline void disable_pcc_intr(struct pcc *pcc, u32 mask)
{
	u32 intreg = ena2intreg(mask) | 0x00000000;

	writel(intreg, &pcc->bar0->intreg);
}
static inline void ack_pcc_intr(struct pcc *pcc, u32 req)
{
	u32 intreg = req2intreg(req);

	writel(intreg, &pcc->bar0->intreg);
}

static inline u32 fifo_next(struct pcc *pcc, u32 ptr)
{
	BUG_ON(ptr < FIFO_OFFSET);

	if (ptr == pcc->fifo_size)
		ptr = FIFO_OFFSET;
	ptr += FIFO_STEP;
	if (ptr == pcc->fifo_size)
		return FIFO_OFFSET;
	return ptr;
}

static inline void load_remote_memmap_size(struct pcc *pcc)
{
	struct pcc_header __iomem *pcc_header;
	u32 size;

	pcc_header = (struct pcc_header *)pcc->bar1;
	size = readl(&pcc_header->memmap_size);
	pcc->remote_memmap_size = size;

	pcc_dbg("size of remote memmap space is 0x%x\n", size);
}

static void pcc_show_regs(struct pcc *pcc)
{
	u32 rxr = readl(&pcc->bar0->fifo_rxr);
	u32 rxw = readl(&pcc->bar0->fifo_rxw);
	u32 txr = readl(&pcc->bar3->fifo_txr);
	u32 txw = readl(&pcc->bar3->fifo_txw);
	u32 intreg = readl(&pcc->bar0->intreg);
	struct pcc_header __iomem *pcc_header = pcc->bar1;
	u32 remote_rptr = readl(&pcc_header->memmap_rptr);

	pcc_dbg("rxr=%x rxw=%x txr=%x txw=%x\n", rxr, rxw, txr, txw);
	pcc_dbg("intreg=%x, memmap: remote rptr=%x, local: "
		"rptr=%x, wptr=%x\n", intreg, remote_rptr,
		pcc->memmap_rptr, pcc->memmap_wptr);
	pcc_dbg("dma %s: laddr=%x rvaddr=%x, size=%x, stat=%x",
		pcc->skb ? "in process" : "not active",
		readl(&pcc->bar0->dma_laddr), readl(&pcc->bar0->dma_rvaddr),
		readl(&pcc->bar0->dma_size), readl(&pcc->bar0->dma_stat));
}

static int pcc_proc_handler(struct ctl_table *table, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct pcc *pcc;
	int ret;

	mutex_lock(&pcc_driver_mutex);
	list_for_each_entry(pcc, &pcc_device_list, device_list)
		pcc_show_regs(pcc);
	mutex_unlock(&pcc_driver_mutex);

	ret = proc_dointvec(table, write, buffer, lenp, ppos);

	pcc_dbg("pcc_online_debug=%d\n", pcc_online_debug);

	return ret;
}


static int pio_get_rx_pkt(struct net_device *netdev, u32 rxr, struct sk_buff **rb)
{
	struct pcc *pcc = netdev_priv(netdev);
	struct pcc_header __iomem *pcc_header;
	struct sk_buff *skb;
	u32 msg, len, full_len, rptr, end_rptr, size;
	char *data;

	*rb = NULL;

	pcc_header = pcc->bar1;
	
	msg = readl(pcc->bar1 + rxr);
	len = (u16)msg;

	/* Check control sum */
	if (len > PCC_FRAME_LEN || ((~msg) >> 16) != len) {
		pcc_err("pio_get_rx_pkt: msg=0x%x, len=%x\n", msg, len);
		WARN_ON(1);
		pcc->stats.rx_errors++;
		return -EIO;
	}

	full_len = max(len, (u32)ETH_ZLEN);

	rptr = pcc->memmap_rptr;
	size = pcc->remote_memmap_size;

	/* Skip first two bytes */
	rptr += NET_IP_ALIGN;

	/* Whole piece */
	if (rptr + len > size)
		rptr = 0x0 + NET_IP_ALIGN;
	
	end_rptr = PCC_PTR_ALIGN(rptr + len);
	if (end_rptr == size)
		end_rptr = 0x0;

	/* Allocate skb */
	skb = __netdev_alloc_skb(netdev, full_len + NET_IP_ALIGN,
				 GFP_DMA|GFP_ATOMIC);
	if (!skb) {
		pcc_err("Cannot allocate skb\n");
		pcc->memmap_rptr = end_rptr;
		writel(end_rptr, &pcc_header->memmap_rptr);
		pcc->stats.rx_dropped++;
		return 0;
	}

	/* Prepare skb */
	skb_reserve(skb, NET_IP_ALIGN);
	data = skb_put(skb, full_len);

	/* Copy packet to skb */
	memcpy_fromio(data, pcc->bar2 + rptr, len);
	data += len;
	memset(data, 0, full_len-len);

	/* Notify remote side about read by us bytes */
	pcc->memmap_rptr = end_rptr;
	writel(end_rptr, &pcc_header->memmap_rptr);

	/* Queue skb */
	skb->protocol = eth_type_trans(skb, netdev);

	/* Result skb */
	*rb = skb;

	/* Statistics */
	pcc->stats.rx_bytes   += len;
	pcc->stats.rx_packets ++;
	
	return 0;
}

static inline int pio_rx(struct net_device *netdev, u32 rxw, u32 rxr)
{
	struct pcc *pcc = netdev_priv(netdev);
	struct sk_buff *skb;
	/* rxr may be < FIFO_OFFSET if there is the first rx after restart */
	if (IS_INIT_PTR(rxr))
		rxr = FIFO_OFFSET;
	
	BUG_ON(rxw >= pcc->fifo_size);

	do {
		int err = pio_get_rx_pkt(netdev, rxr, &skb);
		if (err < 0)
			return err;
		else
			netif_rx(skb);
		rxr = fifo_next(pcc, rxr);
	} while (rxr != rxw);

	return 0;
}

static void pcc_restart(struct pcc *pcc);

static void dma_rx_tasklet(unsigned long pcc_ptr)
{
	struct pcc *pcc = (void *)pcc_ptr;
	struct net_device *netdev = pci_get_drvdata(pcc->pdev);
	struct pcc_header __iomem *pcc_header = pcc->bar1;
	u32 msg, len, full_len, rptr, end_rptr, size;
	struct sk_buff *skb;
	dma_addr_t dma_addr;
	u32 prev_dma_addr = 0;
	u32 prev_dma_size = 0;
	u32 dma_la, rxw, rxr;
	char *data;
	unsigned long flags;

	if (pcc->status != PCC_OK)
		goto out;

	rxw = readl(&pcc->bar0->fifo_rxw);
	rxr = readl(&pcc->bar0->fifo_rxr);

	/* Restart request */
	if (IS_INIT_PTR(rxw)) {
		raw_spin_lock_irqsave(&pcc->lock, flags);
		pcc_restart(pcc);
		goto unlock;
	}

	/* rxr may be < FIFO_OFFSET if there is the first rx after restart */
	if (IS_INIT_PTR(rxr))
		rxr = FIFO_OFFSET;

	if (unlikely(rxr == rxw || pcc->skb)) {
		WARN(1, "dma_rx_tasklet: rxw=0x%x, rxr=0x%x, skb=%p\n",
			 rxw, rxr, pcc->skb);
		goto out;
	}

	/* Size of slice */
	msg = readl(pcc->bar1 + rxr);
	len = (u16)msg;

	/* Check control sum */
	if (len > PCC_FRAME_LEN || ((~msg) >> 16) != len) {
		WARN(1, "dma_rx_tasklet: msg=0x%x, len=%x. Shit happens...\n",
			 msg, len);
		pcc->stats.rx_errors++;
		raw_spin_lock_irqsave(&pcc->lock, flags);
		pcc_restart(pcc);
		goto unlock;
	}

	full_len = max(len, (u32)ETH_ZLEN);

	rptr = pcc->memmap_rptr;
	size = pcc->remote_memmap_size;

	/* Include first two bytes: DMA is aligned */
	len      += NET_IP_ALIGN;
	full_len += NET_IP_ALIGN;

	/* Whole piece */
	if (rptr + len > size)
		rptr = 0x0;
	
	end_rptr = PCC_PTR_ALIGN(rptr + len);
	if (end_rptr == size)
		end_rptr = 0x0;

	/* Allocate skb */
	skb = __netdev_alloc_skb(netdev, full_len, GFP_DMA|GFP_ATOMIC);
	if (!skb) {
		/* Be careful! */
		pcc_err("Cannot allocate skb\n");
		goto err;
	}

	/* Prepare skb */
	skb_reserve(skb, NET_IP_ALIGN);
	data  = skb_put(skb, full_len - NET_IP_ALIGN);
	data -= NET_IP_ALIGN;
	len = PCC_PTR_ALIGN(len);

	/* Map skb */
	dma_addr = pci_map_single(pcc->pdev, data, len, PCI_DMA_FROMDEVICE);

	if (unlikely(pci_dma_mapping_error(pcc->pdev, dma_addr))) {
		/* Be careful! */
		pcc_err("Cannot map skb buf\n");
		dev_kfree_skb(skb);
		goto err;
	}

	BUG_ON(dma_addr & (PCC_DMA_ALIGN - 1));

	dma_la = (u32)dma_addr;
	pcc->dma_addr = dma_la;
	pcc->dma_size = len;

	raw_spin_lock_irqsave(&pcc->lock, flags);

	if (pcc->status != PCC_OK) {
		pcc->dma_addr = 0;
		pcc->dma_size = 0;
		raw_spin_unlock_irqrestore(&pcc->lock, flags);
		pci_unmap_single(pcc->pdev, dma_addr, len, PCI_DMA_FROMDEVICE);
		dev_kfree_skb(skb);
		goto out;
	}

	/* New rptr will be written to remote side in the interrupt handler */
	pcc->old_memmap_rptr = rptr;
	pcc->memmap_rptr = end_rptr;

	/* Prepare DMA */
	writel(0, &pcc->bar0->dma_en);
	writel(dma_la, &pcc->bar0->dma_laddr );
	writel(rptr,   &pcc->bar0->dma_rvaddr);
	writel(len,    &pcc->bar0->dma_size  );

	/* Start DMA */
	writel(1, &pcc->bar0->dma_en);

	pcc->skb = skb;

	/* We probably have to unmap previous skb */
	prev_dma_addr = pcc->prev_dma_addr;
	prev_dma_size = pcc->prev_dma_size;
	pcc->prev_dma_addr = 0;
	pcc->prev_dma_size = 0;
unlock:
	raw_spin_unlock_irqrestore(&pcc->lock, flags);

	/* Unmap previous skb out of rawspinlock */
	if (prev_dma_addr) {
		pci_unmap_single(pcc->pdev, (dma_addr_t)prev_dma_addr,
				 prev_dma_size, PCI_DMA_FROMDEVICE);
	}
out:
	return;
err:
	/* Great Scott!!! */
	raw_spin_lock_irqsave(&pcc->lock, flags);
	pcc->memmap_rptr = end_rptr;
	writel(end_rptr, &pcc_header->memmap_rptr);

	rxr = fifo_next(pcc, rxr);
	writel(rxr, &pcc->bar0->fifo_rxr);

	pcc->stats.rx_dropped++;
	enable_pcc_intr(pcc, RECV_BUF_NE);

	goto unlock;
}

static int dma_finished(struct net_device *netdev)
{
	struct pcc *pcc = netdev_priv(netdev);
	struct pcc_header __iomem *pcc_header;
	u32 rxw = readl(&pcc->bar0->fifo_rxw);
	u32 rxr = readl(&pcc->bar0->fifo_rxr);
	struct sk_buff *skb = pcc->skb;
	u32 size, stat;

	pcc->skb = NULL;
	if (!skb) {
		WARN(1, "dma_finished: skb is NULL, rxr=%x rxw=%x\n", rxr, rxw);
		return 0;
	}

	if (IS_INIT_PTR(rxr))
		rxr = FIFO_OFFSET;
	rxr = fifo_next(pcc, rxr);
	BUG_ON(rxw < FIFO_OFFSET);

	pcc_header = pcc->bar1;

	/* Notify remote side */
	writel(pcc->memmap_rptr, &pcc_header->memmap_rptr);
	writel(rxr, &pcc->bar0->fifo_rxr);

	size = readl(&pcc->bar0->dma_size);
	stat = readl(&pcc->bar0->dma_stat);
	if (size || stat) {
		pcc_err("Unfinished dma transaction: stat=0x%x, size=0x%x\n",
			 stat, size);
		dev_kfree_skb(skb);
		pcc->stats.rx_errors ++;
		goto add_for_unmap;
	}

	pci_dma_sync_single_for_cpu(pcc->pdev, pcc->dma_addr, pcc->dma_size,
				    PCI_DMA_FROMDEVICE);
	if (pcc_online_debug) {
		u32 rptr = pcc->old_memmap_rptr + NET_IP_ALIGN;
		int i;

		printk(KERN_ALERT "rcv,m=%x,l=%x:", rptr, skb->len);

		for (i = 0; i < skb->len; i ++) {
			unsigned char pio = readb(pcc->bar2 + rptr + i);
			unsigned char dma = ((unsigned char *)(skb->data))[i];

			if (pio == dma)
				printk(KERN_CONT " %x", dma);
			else
				printk(KERN_CONT "\npio != dma: (%x != %x), "
						 "i = %d\n", pio, dma, i);
		}
		printk(KERN_CONT "\n");
       } 

	skb->dev = netdev;
	skb->protocol = eth_type_trans(skb, netdev);

	netif_rx(skb);

	/* Statistics */
	pcc->stats.rx_bytes   += skb->len;
	pcc->stats.rx_packets ++;
add_for_unmap:
	/* Will unmap in tasklet or during exit */
	pcc->prev_dma_addr = pcc->dma_addr;
	pcc->prev_dma_size = pcc->dma_size;

	return (rxr != rxw);
}

static irqreturn_t pcc_interrupt(int irq, void *dev_id)
{
	struct net_device *netdev = dev_id;
	struct pcc *pcc = netdev_priv(netdev);
	u32 intreg = readl(&pcc->bar0->intreg);
	u32 req, ena;
	unsigned long flags;
	int status;

	req = intreg2req(intreg);

	if (!req) /* Not our interrupt */
		return IRQ_NONE;

	ena = intreg2ena(intreg);
	req = req & ena;

	raw_spin_lock_irqsave(&pcc->lock, flags);
	if (req && pcc_online_debug)
		printk(KERN_ALERT "intr: req=%x(%x)\n", req, ena);

	if (!req) { /* Not our interrupt */
		raw_spin_unlock_irqrestore(&pcc->lock, flags);
		return IRQ_NONE;
	}

	status = pcc->status;
	if (status == PCC_STOP)
		goto unlock;

	ack_pcc_intr(pcc, req);
	if (status != PCC_OK)
		pcc_dbg("req=%x, status=%x\n", req, status);
	
	if (req & RECV_BUF_NE) {
		u32 rxw = readl(&pcc->bar0->fifo_rxw);
		u32 rxr = readl(&pcc->bar0->fifo_rxr);
		
		/* Echo of previous interrupt */
		if (rxr == rxw && !IS_INIT_PTR(rxw))
			goto trsm;

		/* Restart request from remote side */
		if (IS_INIT_PTR(rxw) && !IS_INIT_PTR(pcc->fifo_txw)) {
			netif_stop_queue(netdev);
			enable_pcc_intr(pcc, TRSM_BUF_EM);
			pcc_restart(pcc);
		}

		/* Incomming packet */
		if (!IS_INIT_PTR(rxw) && status != PCC_RESTART) {
			if (drv_mode == PCC_PIO) {
				if (pio_rx(netdev, rxw, rxr))
					pcc_restart(pcc);
			} else {
				/* DMA is not in process */
				if (!pcc->skb)
					tasklet_schedule(&pcc->dma_rx_tasklet);
				/* Will be enabled after DMA finish */
				disable_pcc_intr(pcc, RECV_BUF_NE);
				goto trsm;
			}
		}

		writel(rxw, &pcc->bar0->fifo_rxr);

		/* Was changed in pcc_restart() */
		if (status != pcc->status)
			goto unlock;
	}
trsm:
	if (req & TRSM_BUF_EM) {
		u32 txr = readl(&pcc->bar3->fifo_txr);
		u32 txw = pcc->fifo_txw;

		/* Remote side answer to our restart request */
		if (IS_INIT_PTR(txr) && IS_INIT_PTR(txw)) {
			load_remote_memmap_size(pcc);
			netif_start_queue(netdev);
			disable_pcc_intr(pcc, TRSM_BUF_EM);

			/* Notify pcc_open() */
			pcc->status = PCC_OK;
			raw_spin_unlock_irqrestore(&pcc->lock, flags);
			wake_up_interruptible(&pcc->wait);
			goto out;
		}
		/* Remote side has read all of data */
		if (!IS_INIT_PTR(txw)) {
			WARN_ON(txr != txw);
			WARN_ON(!netif_queue_stopped(netdev));
			netif_wake_queue(netdev);
			disable_pcc_intr(pcc, TRSM_BUF_EM);
		}
	}

	if (req & DMA_FINISHED) {
		if (status != PCC_OK) {
			WARN_ON(1);
			goto unlock;
		}

		if (dma_finished(netdev))
			tasklet_schedule(&pcc->dma_rx_tasklet);
		else
			enable_pcc_intr(pcc, RECV_BUF_NE);
	}
unlock:
	raw_spin_unlock_irqrestore(&pcc->lock, flags);
out:
	return IRQ_HANDLED;
}

static void pcc_restart(struct pcc *pcc)
{
	struct pcc_header __iomem *pcc_header = pcc->bar1;

	if (pcc->status == PCC_RESTART)
		return;

	pcc->status = PCC_RESTART;

	ack_pcc_intr(pcc, TRSM_BUF_EM);

	pcc->memmap_wptr = 0x0;
	pcc->memmap_rptr = 0x0;
	writel(pcc->memmap_rptr, &pcc_header->memmap_rptr);
	writel(pcc->memmap_size, &pcc_header->memmap_size);
	/* Temporary crutch */
	if (readl(&pcc->bar3->fifo_txw) == 0x6)
		pcc->fifo_txw = 0x8;
	else
	/* */
	if (readl(&pcc->bar3->fifo_txw) != 0x0)
		pcc->fifo_txw = 0x0;
	else
		pcc->fifo_txw = FIFO_OFFSET >> 1;

	writel(pcc->fifo_txw, &pcc->bar3->fifo_txw);
	smp_mb();
}

static int pcc_open(struct net_device *netdev)
{
	struct pcc *pcc = netdev_priv(netdev);
	int err = 0;
	u32 mask  = RECV_BUF_NE | TRSM_BUF_EM;
	unsigned long flags;

	pcc_restart(pcc);
	err = request_irq(netdev->irq, pcc_interrupt, IRQF_SHARED, netdev->name, netdev); 
	if (err) {
		pcc_err("Cannot request irq\n");
		goto out;
	}

	raw_spin_lock_irqsave(&pcc->lock, flags);
	if (drv_mode == PCC_DMA)
		mask |= DMA_FINISHED;
	enable_pcc_intr(pcc, mask);
	raw_spin_unlock_irqrestore(&pcc->lock, flags);

	/* I call netif_start_queue() in the interrupt handler.    *
	 * There is no sense to start queue unless remote is alive */
	if (init_wait > 0)
		err = wait_event_interruptible_timeout(pcc->wait,
			pcc->status == PCC_OK, init_wait * HZ);
	else {
		err = wait_event_interruptible(pcc->wait,
			pcc->status == PCC_OK);
		err = !err ? 1 : 0;
	}

	if (err > 0) {
		/* Successfully */
		err = 0;
	} else {
		/* Interrupted or timeout elapsed */
		pcc_err("pcc_open error: status=%x\n", pcc->status);
		raw_spin_lock_irqsave(&pcc->lock, flags);
		disable_pcc_intr(pcc, mask);
		pcc->status = PCC_STOP;
		raw_spin_unlock_irqrestore(&pcc->lock, flags);
		free_irq(netdev->irq, netdev);
		err = (err ? -EINTR : -EAGAIN);
	}
out:
	return err;
}

static int pcc_stop(struct net_device *netdev)
{
	struct pcc *pcc = netdev_priv(netdev);
	u32 prev_dma_addr = 0;
	u32 prev_dma_size = 0;
	unsigned long flags;

	netif_stop_queue(netdev);
	tasklet_kill(&pcc->dma_rx_tasklet);
	raw_spin_lock_irqsave(&pcc->lock, flags);
	
	disable_pcc_intr(pcc, RECV_BUF_NE | TRSM_BUF_EM | DMA_FINISHED);
	pcc->status = PCC_STOP;
	prev_dma_addr = pcc->prev_dma_addr;
	prev_dma_size = pcc->prev_dma_size;
	pcc->prev_dma_addr = 0;
	pcc->prev_dma_size = 0;
	raw_spin_unlock_irqrestore(&pcc->lock, flags);

	if (prev_dma_addr) {
		pci_unmap_single(pcc->pdev, (dma_addr_t)prev_dma_addr,
				 prev_dma_size, PCI_DMA_FROMDEVICE);
	}

	free_irq(netdev->irq, netdev);

	return 0;
}

static inline int pio_transmit(struct pcc *pcc, u32 size, u32 wptr, struct sk_buff *skb)
{
	void *data = skb->data;
	u32    len = skb->len;
	u32 txr, txw, msg;

	memcpy(pcc->memmap_va + wptr, data, len);

	if (pcc_online_debug) {
		int i;
		printk(KERN_ALERT "send,w=%x,l=%x:", wptr, len);
		for (i = 0; i < len; i ++) {
			printk(KERN_CONT " %x", ((unsigned char *)(skb->data))[i]);
		}
		printk(KERN_INFO "\n");
	} 

	wptr = PCC_PTR_ALIGN(wptr + len);
	if (wptr == size)
		wptr = 0x0;

	pcc->memmap_wptr = wptr; /* New memmap_wptr */

	txr = readl(&pcc->bar3->fifo_txr);
	txw = pcc->fifo_txw;

	if (txr == pcc->fifo_size || IS_INIT_PTR(txr))
		txr = FIFO_OFFSET;
	if (txw == pcc->fifo_size || IS_INIT_PTR(txw))
		txw = FIFO_OFFSET;
	BUG_ON(fifo_next(pcc, txw) == txr);

	BUG_ON(len != (u16)len); /* low 16 bits */

	/* Make a message for remote side */
	msg = len | ((~len) << 16);
	writel(msg, pcc->bar1 + txw);

	txw = fifo_next(pcc, txw);
	writel(txw, &pcc->bar3->fifo_txw);
	pcc->fifo_txw = txw;

	pcc->stats.tx_bytes += len;
	pcc->stats.tx_packets++;

	if (fifo_next(pcc, txw) == txr)
		return 1;
	
	return 0;
}

/* Is there enough space in the "ring" buffer ? 1 == yes, 0 == no */
static inline int enough_space(u32 wptr, u32 rptr, u32 buf_size, u32 len)
{
	if (len > buf_size) {
		WARN_ON(1);
		return 0;
	}
	if (wptr == buf_size)
		wptr = 0x0;
	if (rptr == buf_size)
		rptr = 0x0;

	len = PCC_PTR_ALIGN(len);

	if (wptr < rptr)
		return (wptr + len < rptr);

	if (wptr + len > buf_size)
		wptr = 0x0;
	else if (wptr + len == buf_size)
		return (rptr != 0x0);
	else
		return 1;

	return (len < rptr);
}

static int pcc_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct pcc *pcc = netdev_priv(netdev);
	struct pcc_header __iomem *pcc_header;
	unsigned int len, ret = 1;
	u32 rptr; /* Read pointer of remote side */
	u32 wptr; /* Write pointer of local side */
	u32 size; /* Size of local side memmap   */
	unsigned long flags;

	pcc_header = pcc->bar1;

	len = skb->len;

	raw_spin_lock_irqsave(&pcc->lock, flags);

	if (pcc->status != PCC_OK)
		goto unlock;

	if (netif_queue_stopped(netdev))
		goto unlock;

	rptr = readl(&pcc_header->memmap_rptr);
	wptr = pcc->memmap_wptr;
	size = pcc->memmap_size;

	if (!enough_space(wptr, rptr, size, len + NET_IP_ALIGN)) {
		pcc->stats.tx_dropped ++;
		netif_stop_queue(netdev);
		enable_pcc_intr(pcc, TRSM_BUF_EM);
		goto unlock;
	}

	wptr += NET_IP_ALIGN;
	/* Whole piece */
	if (wptr + len > size)
		wptr = 0x0 + NET_IP_ALIGN;

	/* Send is always PIO */
	if (pio_transmit(pcc, size, wptr, skb)) {
		netif_stop_queue(netdev);
		enable_pcc_intr(pcc, TRSM_BUF_EM);
	}

	netdev->trans_start = jiffies;
	ret = 0;
unlock:
	raw_spin_unlock_irqrestore(&pcc->lock, flags);
	dev_kfree_skb(skb);
	return ret;
}

static int pcc_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	return 0;
}

static struct net_device_stats* pcc_stats(struct net_device *netdev)
{
	struct pcc *pcc = netdev_priv(netdev);
	return &pcc->stats;
}

static int pcc_rebuild_header(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *) skb->data;
	struct net_device *dev = skb->dev;

	memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x3;   /* dest is us xor 0x3 */
	return 0;
}

static int pcc_hard_header(struct sk_buff *skb, struct net_device *dev,
			   unsigned short type, const void *daddr, const void *saddr,
			   unsigned int len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb, ETH_HLEN);

	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);

	eth->h_dest[ETH_ALEN-1] ^= 0x3;   /* dest is us xor 0x3 */
	return (dev->hard_header_len);
}

static int pcc_change_mtu(struct net_device *netdev, int new_mtu)
{
	if(new_mtu < ETH_ZLEN || new_mtu > PCC_MTU)
		return -EINVAL;
	netdev->mtu = new_mtu;
	return 0;
}

static void pcc_tx_timeout(struct net_device *netdev)
{
	struct pcc *pcc = netdev_priv(netdev);
	printk(KERN_ALERT "timeout: size=%x, stat=%d\n", readl(&pcc->bar0->dma_size), readl(&pcc->bar0->dma_stat));
}

static const struct net_device_ops pcc_netdev_ops = {
	.ndo_open = pcc_open,
	.ndo_stop = pcc_stop,
	.ndo_start_xmit = pcc_start_xmit,
	.ndo_change_mtu = pcc_change_mtu,
	.ndo_tx_timeout = pcc_tx_timeout,
	.ndo_do_ioctl = pcc_ioctl,
	.ndo_get_stats = pcc_stats,

};

static const struct header_ops pcc_header_ops = {
	.create = pcc_hard_header,
	.rebuild = pcc_rebuild_header,
};

static void setup_pcc_netdev(struct net_device *netdev)
{
	struct pcc *pcc = netdev_priv(netdev);

	memset(pcc, 0, sizeof(struct pcc));

	ether_setup(netdev);

	netdev->netdev_ops = &pcc_netdev_ops;
	netdev->header_ops = &pcc_header_ops;

	netdev->watchdog_timeo = 5*HZ; /* jiffies */
	netdev->mtu = PCC_MTU;

	/* keep the default flags, just add NOARP */
	netdev->flags |= IFF_NOARP;
}

static inline int pcc_map_bars(struct pci_dev *pdev, struct pcc *pcc)
{
	int bar;
	for (bar = 0; bar < 4; bar ++) {
		unsigned long start = pci_resource_start(pdev, bar);
		unsigned long len   = pci_resource_len(pdev, bar);
		unsigned long flags = pci_resource_flags(pdev, bar);

		flags &= IORESOURCE_MEM;
		if (!flags) {
			pcc_err("Region #%d isn't a MMIO res, aborting\n", bar);
			goto out_err;
		}
		pcc->bar[bar] = ioremap(start, len);	
		if (!pcc->bar[bar]) {
			pcc_err("Cannot remap PCI BAR %d\n", bar);
			goto out_err;
		}
		pcc_dbg("BAR %d enabled, addr=0x%lx (%lx), size=0x%lx\n",
			 bar, start, (unsigned long)pcc->bar[bar], len);
	}
	pcc->bar0 = pcc->bar[0];
	pcc->bar1 = pcc->bar[1];
	pcc->bar2 = pcc->bar[2];
	pcc->bar3 = pcc->bar[3];

	return 0;
out_err:
	while (bar --)
		iounmap(pcc->bar[bar]);
	return -ENODEV;
}

static inline void pcc_unmap_bars(struct pcc *pcc)
{
	int bar;

	for (bar = 0; bar < 4; bar ++)
		iounmap(pcc->bar[bar]);
}

static inline int pcc_prepare_memmap(struct pci_dev *pdev, struct pcc *pcc)
{
	unsigned int size, order, mask, alig_size;
	void *virt_addr = NULL;
	dma_addr_t dma_addr, alig_dma, alig_end;

	/* size must be less than all BAR2 space */
	size  = pci_resource_len(pdev, 2);
	order = get_order(size);
	order = order > MAX_ORDER-1 ? MAX_ORDER-1 : order;
	size  = (1 << order) * PAGE_SIZE;

	while (size >= PAGE_SIZE) {
		virt_addr = pci_alloc_consistent(pdev, size, &dma_addr);
		if (virt_addr)
			break;
		size >>= 1;
	}

	if (!virt_addr)
		return -ENOMEM;
	
	pcc->memmap_na_busa = (u32)dma_addr;
	pcc->memmap_na_size = (u32)size;
	pcc->memmap_na_va   = virt_addr;

	/* Alignment */
	alig_size = (1 << __fls(size));
	alig_dma = 0; /* Prevents compiler warning */

	for (; alig_size >= MEMMAP_MIN_SIZE; alig_size >>= 1) {
		mask = alig_size - 1;

		alig_dma = __ALIGN_MASK(dma_addr, mask);
		alig_end = alig_dma + alig_size;

		if (alig_end <= dma_addr + size)
			break;
	}

	if (alig_size < MEMMAP_MIN_SIZE) {
		pci_free_consistent(pdev, pcc->memmap_na_size,
					  pcc->memmap_na_va,
					  pcc->memmap_na_busa);
		return -ENOMEM;
	}

	virt_addr += alig_dma - dma_addr;
	dma_addr = alig_dma;
	size = alig_size; 

	pcc_dbg("MEMMAP virt=0x%lx, size=0x%x\n", (unsigned long)virt_addr, size);

	BUG_ON((dma_addr + size - 1) & ~DMA_BIT_MASK(32));

	memset(virt_addr, 0x1F, size);

	pcc->memmap_busa = (u32)dma_addr;
	pcc->memmap_va   = virt_addr;
	pcc->memmap_size = size;

	pcc_dbg("MEMMAP=[0x%x, 0x%x]\n",
			pcc->memmap_busa, pcc->memmap_busa + size - 1);

	writel(pcc->memmap_busa,     &pcc->bar0->memmap_lbaddr);
	writel(pcc->memmap_size - 1, &pcc->bar0->memmap_lmask );
	/* Enable MEMMAP */
	writel(1,                    &pcc->bar0->memmap_lrwena);
	pcc_dbg("MEMMAP lbaddr=0x%x, lmask=0x%x\n",
				readl(&pcc->bar0->memmap_lbaddr),
				readl(&pcc->bar0->memmap_lmask));
	/* DMA */
	writel(pcc->memmap_busa,     &pcc->bar0->dma_lbaddr);
	writel(pcc->memmap_size - 1, &pcc->bar0->dma_lmask );
	writel(0, /* remote->local */&pcc->bar0->dma_dir   );
	/* Enable DMA */
	writel(1,                    &pcc->bar0->dma_lrwena);

	return 0;
}

static inline void pcc_free_memmap(struct pci_dev *pdev, struct pcc *pcc)
{
	/* Disable DMA */
	writel(0, &pcc->bar0->dma_lrwena);
	writel(0, &pcc->bar0->dma_lbaddr);
	writel(0, &pcc->bar0->dma_lmask );

	/* Disable MEMMAP */
	writel(0, &pcc->bar0->memmap_lrwena);
	writel(0, &pcc->bar0->memmap_lbaddr);
	writel(0, &pcc->bar0->memmap_lmask );

	pci_free_consistent(pdev, pcc->memmap_na_size, pcc->memmap_na_va,
			    pcc->memmap_na_busa);
}

static int pcc_init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct net_device *netdev = NULL;
	struct pcc *pcc = NULL;
	int err = 0;

	BUILD_BUG_ON(FIFO_OFFSET < sizeof(struct pcc_header));
	/* rxr, rxw, txr and txw increment*/
	BUILD_BUG_ON(FIFO_OFFSET % FIFO_STEP != 0);
	/* Every rxr interval contains two packet sizes: direct and inverted */
	BUILD_BUG_ON((1ULL << (BITS_PER_BYTE * sizeof(u32)))-1 < 2*PCC_FRAME_LEN);

	netdev = alloc_netdev(sizeof(struct pcc), "pcc%d", setup_pcc_netdev);

	if (!netdev) {
		pcc_err("Cannot allocate netdev\n");
		err = -ENOMEM;
		goto out;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);
	pci_set_drvdata(pdev, netdev);
	
	if ((err = pci_enable_device(pdev))) {
		pcc_err("Cannot enable PCI device\n");
		goto out_free_netdev;
	}

	pci_set_master(pdev);

	if ((err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32)))) {
		pcc_err("No usable DMA configuration, aborting.\n");
		goto out_disable_pcidev;
	}

	if ((err = pci_request_regions(pdev, DRV_NAME))) {
		pcc_err("Cannot request regions\n");
		goto out_disable_pcidev;
	}

	pcc = netdev_priv(netdev);

	if ((err = pcc_map_bars(pdev, pcc)))
		goto out_release_regions;
	
	pcc->fifo_size = readl(&pcc->bar0->fifo_size);
	pcc_dbg("FIFO size=0x%x\n", pcc->fifo_size);
	BUG_ON(pcc->fifo_size % FIFO_STEP != 0);
	if (pcc->fifo_size > pci_resource_len(pdev, 1)/2) {
		pcc_err("bad device: FIFO size=0x%x, BAR1 len=0x%llx\n",
			 pcc->fifo_size, pci_resource_len(pdev, 1));
		err = -EIO;
		goto out_unmap_bars;
	}

	if ((err = pcc_prepare_memmap(pdev, pcc))) {
		pcc_err("Cannot allocate memory for memmap\n");
		goto out_unmap_bars;
	}

	raw_spin_lock_init(&pcc->lock);
	init_waitqueue_head(&pcc->wait);
	tasklet_init(&pcc->dma_rx_tasklet, dma_rx_tasklet, (unsigned long)pcc);

	pcc->status  = PCC_STOP;
	pcc->pdev = pdev;
	pcc->skb  = NULL;

	pcc->prev_dma_addr = 0;
	pcc->prev_dma_size = 0;

	netdev->irq = pdev->irq;
	/* The way to get different mac addresses for int and ext boards */
	memcpy(netdev->dev_addr, "\0\0PCC\0", ETH_ALEN);
	netdev->dev_addr[ETH_ALEN-1] = (pdev->subsystem_device & 0x3);

	err = register_netdev(netdev);
	if (err) {
		pcc_err("Cannot register net_device\n");
		goto out_free_memmap;
	}

	mutex_lock(&pcc_driver_mutex);
	list_add(&pcc->device_list, &pcc_device_list);
	mutex_unlock(&pcc_driver_mutex);

	return 0;

out_free_memmap:
	pcc_free_memmap(pdev, pcc);
out_unmap_bars:
	pcc_unmap_bars(pcc);
out_release_regions:
	pci_release_regions(pdev);
out_disable_pcidev:
	pci_disable_device(pdev);
out_free_netdev:
	free_netdev(netdev);
out:
	return err;
}

static void pcc_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct pcc *pcc = netdev_priv(netdev);

	if (netdev) {
		mutex_lock(&pcc_driver_mutex);
		list_del(&pcc->device_list);
		mutex_unlock(&pcc_driver_mutex);

		unregister_netdev(netdev);
		pcc_free_memmap(pdev, pcc);
		pcc_unmap_bars(pcc);
		pci_release_regions(pdev);
		pci_disable_device(pdev);
		free_netdev(netdev);
	}
}

static struct pci_driver pcc_driver = {
	.name		= DRV_NAME,
	.id_table	= pcc_id_table,
	.probe		= pcc_init_one,
	.remove		= pcc_remove,
};

static int __init pcc_init_module(void)
{
	mutex_init(&pcc_driver_mutex);

	pcc_table_header = register_sysctl_table(pcc_ctl);

	switch (drv_mode) {
		case PCC_PIO :
		case PCC_DMA :
			pcc_dbg("drv_mode=%s\n", mode_name[drv_mode]);
			break;
		case PCC_POLL:
		default:
			pcc_err("wrong drv_mode. Will use PCC_DMA instead\n");
			drv_mode = PCC_DMA;
	}
	return pci_register_driver(&pcc_driver);
}

static void __exit pcc_cleanup_module(void)
{
	unregister_sysctl_table(pcc_table_header);

	pci_unregister_driver(&pcc_driver);
}

module_init(pcc_init_module);
module_exit(pcc_cleanup_module);
