/* $Id: sunlance.c,v 1.112 2002/01/15 06:48:55 davem Exp $
 * lance.c: Linux/Sparc/Lance driver
 *
 *	Written 1995, 1996 by Miguel de Icaza
 * Sources:
 *	The Linux  depca driver
 *	The Linux  lance driver.
 *	The Linux  skeleton driver.
 *	The NetBSD Sparc/Lance driver.
 *	Theo de Raadt (deraadt@openbsd.org)
 *	NCR92C990 Lan Controller manual
 *
 * 1.4:
 *	Added support to run with a ledma on the Sun4m
 *
 * 1.5:
 *	Added multiple card detection.
 *
 *	 4/17/96: Burst sizes and tpe selection on sun4m by Eddie C. Dost
 *		  (ecd@skynet.be)
 *
 *	 5/15/96: auto carrier detection on sun4m by Eddie C. Dost
 *		  (ecd@skynet.be)
 *
 *	 5/17/96: lebuffer on scsi/ether cards now work David S. Miller
 *		  (davem@caip.rutgers.edu)
 *
 *	 5/29/96: override option 'tpe-link-test?', if it is 'false', as
 *		  this disables auto carrier detection on sun4m. Eddie C. Dost
 *		  (ecd@skynet.be)
 *
 * 1.7:
 *	 6/26/96: Bug fix for multiple ledmas, miguel.
 *
 * 1.8:
 *		  Stole multicast code from depca.c, fixed lance_tx.
 *
 * 1.9:
 *	 8/21/96: Fixed the multicast code (Pedro Roque)
 *
 *	 8/28/96: Send fake packet in lance_open() if auto_select is true,
 *		  so we can detect the carrier loss condition in time.
 *		  Eddie C. Dost (ecd@skynet.be)
 *
 *	 9/15/96: Align rx_buf so that eth_copy_and_sum() won't cause an
 *		  MNA trap during chksum_partial_copy(). (ecd@skynet.be)
 *
 *	11/17/96: Handle LE_C0_MERR in lance_interrupt(). (ecd@skynet.be)
 *
 *	12/22/96: Don't loop forever in lance_rx() on incomplete packets.
 *		  This was the sun4c killer. Shit, stupid bug.
 *		  (ecd@skynet.be)
 *
 * 1.10:
 *	 1/26/97: Modularize driver. (ecd@skynet.be)
 *
 * 1.11:
 *	12/27/97: Added sun4d support. (jj@sunsite.mff.cuni.cz)
 *
 * 1.12:
 * 	 11/3/99: Fixed SMP race in lance_start_xmit found by davem.
 * 	          Anton Blanchard (anton@progsoc.uts.edu.au)
 * 2.00: 11/9/99: Massive overhaul and port to new SBUS driver interfaces.
 *		  David S. Miller (davem@redhat.com)
 * 2.01:
 *      11/08/01: Use library crc32 functions (Matt_Domsch@dell.com)
 *
* 2.02-mcst:
 *      14/04/06: MCST le100 hardware bug walkaround
 * 3.00-mcst:
 *      22/08/07: PCI Sunlance support
 *                Shmelev Alexander (ashmelev@task.sun.mcst.ru) 
 * 3.01-mcst:
 *      26/01/09: PCI Sunlance is now unsupported here
 *                see pci_sunlance.c
 *                Alexey V. Sitnikov (alexmipt@mcst.ru)
 * 3.02-mcst:
 *      04/16/10: Merging to kernel 2.6.33
 *                Vadim Revyakin  (rev@mcst.ru)
 */


#define DEBUG_DRIVER    0

#define dbg_print       if (DEBUG_DRIVER) printk

static char lancestr[] = "LANCE";

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/socket.h> /* Used for the temporal inet entries and routing */
#include <linux/route.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <linux/bitops.h>
#include <linux/irq.h>
#include <linux/dma-mapping.h>
#include <linux/mii.h>

#include <asm/io.h>
#include <asm/dma.h>
#include <asm/pgtable.h>
#include <asm/byteorder.h>	/* Used by the checksum routines */

#ifdef	CONFIG_MCST
#include <asm/setup.h>
#endif

#ifdef CONFIG_COMPAT
#include <asm/compat.h>
#endif

#ifdef SUNLANCE_BODY_FOR_SBUS
#ifndef __e2k__
#include <asm/idprom.h>
#include <asm/auxio.h>		/* For tpe-link-test? setting */
#endif
#endif
#if defined CONFIG_PCI2SBUS || defined CONFIG_PCI2SBUS_MODULE
#include <linux/mcst/p2ssbus.h>
#endif

#ifdef SUNLANCE_BODY_FOR_PCI
#include <linux/pci.h>
#define SUNLANCE_PCI_VENDOR_ID 0x8086
#define SUNLANCE_PCI_DEVICE_ID 0x4d45
#endif
#include <asm/irq.h>

#include <linux/mcst_net_rt.h>

#ifdef CONFIG_MCST_RT
//#define SUNLANCE_USES_POLL
#endif

#ifndef CONFIG_SPARC
#define DMA_CSR          0x00UL            /* rw  DMA control/status register    0x00   */
#define DMA_ADDR         0x04UL            /* rw  DMA transfer address register  0x04   */
#define DMA_COUNT        0x08UL            /* rw  DMA transfer count register    0x08   */
#define DMA_TEST         0x0cUL            /* rw  DMA test/debug register        0x0c   */
#define DMA_HNDL_ERROR   0x00000002        /* We need to take an error */
#define DMA_FIFO_ISDRAIN 0x0000000c        /* The DMA FIFO is draining */
#define DMA_E_BURSTS     0x000c0000        /* ENET: r/w burst mask */
#define DMA_E_BURST32    0x00040000        /* ENET: 32 byte r/w burst */
#define DMA_E_BURST16    0x00000000        /* ENET: 16 byte r/w burst */
#define DMA_DSBL_RD_DRN  0x00001000        /* No EC drain on slave reads */
#define DMA_BURST32      0x20
#define DMA_DSBL_WR_INV  0x00020000        /* No EC inval. on slave writes */
#define DMA_FIFO_INV     0x00000020        /* Invalidate the FIFO */
#define DMA_3CLKS        0x00400000        /* Each transfer = 3 clock ticks */
#define DMA_EN_ENETAUI   DMA_3CLKS         /* Put lance into AUI-cable mode */
#define DMA_INT_ENAB     0x00000010        /* Turn on interrupts */
#define DMA_RST_SCSI     0x00000080        /* Reset the SCSI controller */
#define DMA_RST_ENET     DMA_RST_SCSI      /* Reset the ENET controller */
#define DMA_BURSTBITS    0x7f
#define AUXIO_LTE_ON     1

#define SBUS_DREGS_BAR  0
#define SBUS_LREGS_BAR  1

#endif

#define SBUS_IOCTL_BAR  2

#define LANCE_WATCHDOG_TIMEOUT (jiffies + (2 * HZ))

#define LANCE_MSG_DEFAULT (NETIF_MSG_DRV | NETIF_MSG_PROBE \
                               | NETIF_MSG_LINK  /* | NETIF_MSG_TX_QUEUED | NETIF_MSG_PKTDATA*/ \
                               | NETIF_MSG_RX_ERR | NETIF_MSG_TX_ERR /*| NETIF_MSG_INTR*/)


#define DRV_NAME	"sunlance"
#define DRV_VERSION    "3.02-mcst"
#define DRV_RELDATE    "16 Apr 2010"
#define DRV_AUTHOR	"Miguel de Icaza (miguel@nuclecu.unam.mx) + mcst"

static char version[] =
	LANCE_TYPE_NAME " " DRV_RELDATE " " DRV_AUTHOR "\n";

MODULE_VERSION(DRV_VERSION);
MODULE_AUTHOR(DRV_AUTHOR);
MODULE_DESCRIPTION("Sun Lance ethernet driver");
MODULE_LICENSE("GPL");

/* Define: 2^4 Tx buffers and 2^4 Rx buffers */
#ifndef LANCE_LOG_TX_BUFFERS
#define LANCE_LOG_TX_BUFFERS 6
#endif
#ifndef LANCE_LOG_RX_BUFFERS
#define LANCE_LOG_RX_BUFFERS 6
#endif

#define LE_CSR0 0
#define LE_CSR1 1
#define LE_CSR2 2
#define LE_CSR3 3

#define LE_MO_PROM      0x8000  /* Enable promiscuous mode */
#define LE_MO_FULLBUF   0x400  /* Catch full pkt into buf before start xmit */
#define LE_MO_TR128     0x800   /* Transmit birst 128/32 */
#define LE_MO_RC128     0x1000  /* Receive birst  128/32 */

#define	LE_C0_ERR	0x8000	/* Error: set if BAB, SQE, MISS or ME is set */
#define	LE_C0_BABL	0x4000	/* BAB:  Babble: tx timeout. */
#define	LE_C0_CERR	0x2000	/* SQE:  Signal quality error */
#define	LE_C0_MISS	0x1000	/* MISS: Missed a packet */
#define	LE_C0_MERR	0x0800	/* ME:   Memory error */
#define	LE_C0_RINT	0x0400	/* Received interrupt */
#define	LE_C0_TINT	0x0200	/* Transmitter Interrupt */
#define	LE_C0_IDON	0x0100	/* IFIN: Init finished. */
#define	LE_C0_INTR	0x0080	/* Interrupt or error */
#define	LE_C0_INEA	0x0040	/* Interrupt enable */
#define	LE_C0_RXON	0x0020	/* Receiver on */
#define	LE_C0_TXON	0x0010	/* Transmitter on */
#define	LE_C0_TDMD	0x0008	/* Transmitter demand */
#define	LE_C0_STOP	0x0004	/* Stop the card */
#define	LE_C0_STRT	0x0002	/* Start the card */
#define	LE_C0_INIT	0x0001	/* Init the card */

#define	LE_C3_BSWP	0x4     /* SWAP */
#define	LE_C3_ACON	0x2	/* ALE Control */
#define	LE_C3_BCON	0x1	/* Byte control */

/* Receive message descriptor 1 */
#define LE_R1_OWN       0x80    /* Who owns the entry */
#define LE_R1_ERR       0x40    /* Error: if FRA, OFL, CRC or BUF is set */
#define LE_R1_FRA       0x20    /* FRA: Frame error */
#define LE_R1_OFL       0x10    /* OFL: Frame overflow */
#define LE_R1_CRC       0x08    /* CRC error */
#define LE_R1_BUF       0x04    /* BUF: Buffer error */
#define LE_R1_SOP       0x02    /* Start of packet */
#define LE_R1_EOP       0x01    /* End of packet */
#define LE_R1_POK       0x03    /* Packet is complete: SOP + EOP */

#define LE_T1_OWN       0x80    /* Lance owns the packet */
#define LE_T1_ERR       0x40    /* Error summary */
#define LE_T1_EMORE     0x10    /* Error: more than one retry needed */
#define LE_T1_EONE      0x08    /* Error: one retry needed */
#define LE_T1_EDEF      0x04    /* Error: deferred */
#define LE_T1_SOP       0x02    /* Start of packet */
#define LE_T1_EOP       0x01    /* End of packet */
#define LE_T1_POK	0x03	/* Packet is complete: SOP + EOP */

#define LE_T3_BUF       0x8000  /* Buffer error */
#define LE_T3_UFL       0x4000  /* Error underflow */
#define LE_T3_LCOL      0x1000  /* Error late collision */
#define LE_T3_CLOS      0x0800  /* Error carrier loss */
#define LE_T3_RTY       0x0400  /* Error retry */
#define LE_T3_TDR       0x03ff  /* Time Domain Reflectometry counter */

#define TX_RING_SIZE			(1 << (LANCE_LOG_TX_BUFFERS))
#define TX_RING_MOD_MASK		(TX_RING_SIZE - 1)
#define TX_RING_LEN_BITS		((LANCE_LOG_TX_BUFFERS) << 29)
#define TX_NEXT(__x)			(((__x)+1) & TX_RING_MOD_MASK)

#define RX_RING_SIZE			(1 << (LANCE_LOG_RX_BUFFERS))
#define RX_RING_MOD_MASK		(RX_RING_SIZE - 1)
#define RX_RING_LEN_BITS		((LANCE_LOG_RX_BUFFERS) << 29)
#define RX_NEXT(__x)			(((__x)+1) & RX_RING_MOD_MASK)

#define ETHERNET_BUF_SIZE              1544
#define ETHERNET_BUF_SIZE_ALIGN32      1568
/* I suggest that 1568 = 1514 + 14 + 6 + 2 + 32 */
#define ETHERNET_BUF_SIZE_ALIGN128	1664

#define RX_BUFF_SIZE                   ETHERNET_BUF_SIZE_ALIGN32
#define TX_BUFF_SIZE                   ETHERNET_BUF_SIZE

#define RX_BUFF_SIZE_ALIGN32            ETHERNET_BUF_SIZE_ALIGN32
#define TX_BUFF_SIZE_ALIGN128           ETHERNET_BUF_SIZE_ALIGN128
#define RX_BUFF_SIZE_ALIGN128           ETHERNET_BUF_SIZE_ALIGN128


/* Some of PHY (DP83865) registers */
#define PHY_AUX_CTRL   0x12       /* Auxiliary Control Register */
#define PHY_LED_CTRL   0x13       /* LED Control Register */
#define PHY_BIST_CFG2  0x1a       /* BIST configuration Register 2 */

/* Some of PHY_AUX_CTRL's fields */
#define RGMII_EN_1     (1 << 13)
#define RGMII_EN_0     (1 << 12)
/* This two fields enable either RGMII or GMII/MII */
       /* 1:1 - RGMII 3com mode 
        * 1:0 - RGMII Hp mode 
        * 0:1 - GMII/MII mode
        * 0:0 - GMII/MII mode 
        */

/* Some of PHY_LED_CTRL's fields */
#define RED_LEN_EN     (1 << 5) /* Reduced LED enable */
       
/* Some of PHY_BIST_CFG2's fields */
#define LINK_SEL       (1 << 0) /* Link/Link-ACT selector */
/* When RED_LEN_EN bit is enabled:
*      LINK_SEL = 1 - 10M Link LED displays 10/100/1000 Link 
*      LINK_SEL = 0 - 10M Link LED displays 10/100/1000 Link
*                      and ACT 
*/
/* Bits for MGIO_DATA registers */
#define                MGIO_DATA_OFF           0
#define                MGIO_CS_OFF             16
#define                MGIO_REG_AD_OFF         18
#define                MGIO_PHY_AD_OFF         23
#define                MGIO_OP_CODE_OFF        28
#define                MGIO_ST_OF_F_OFF        30

/* MGIO_CSR regiter bits */
#define RRDY           (1 << 13)  /* RC RESULT READY */


#define DEBUG_MDIO_RD_ON       0       /* Debug for mdio_read primitive */
#define DEBUG_MDIO_WR_ON       0       /* Debug for mdio_write primitive */
#define DEBUG_RD_E_CSR_ON      0       /* Debug for read_e_csr primitive */
#define DEBUG_WR_E_CSR_ON      0       /* Debug for write_e_csr primitive */
#define DEBUG_INIT_RING_ON     0       /* Debug for init_ring function */
#define        DEBUG_E1000_RX_ON       0       /* Debug for rx function */
#define DEBUG_E1000_RX_HEAD_ON 0       /* Show rx packet header */
#define DEBUG_E1000_RX_BODY_ON 0       /* Show rx packet body  */
#define DEBUG_E1000_RESTART_ON  0
#define DEBUG_LOOPBACK_ON      0       
#define        DEBUG_PROBE_ON          0
#define        DEBUG_SETPHT_ON         0
#define DEBUG_MULT_CAST_ON     0
#define        DEBUG_INIT_BLOCK_ON     1

#define DEBUG_MDIO_RD if (DEBUG_MDIO_RD_ON) pr_warning
#define DEBUG_MDIO_WR if (DEBUG_MDIO_WR_ON) printk
#define DEBUG_INIT_RING if (DEBUG_INIT_RING_ON) printk
#define DEBUG_RD_E_CSR if (DEBUG_RD_E_CSR_ON) printk
#define DEBUG_WR_E_CSR if (DEBUG_WR_E_CSR_ON) printk   
#define DEBUG_E1000_RX if (DEBUG_E1000_RX_ON) printk
#define DEBUG_E1000_RX_HEAD if (DEBUG_E1000_RX_HEAD_ON) printk
#define DEBUG_E1000_RX_BODY if (DEBUG_E1000_RX_BODY_ON) printk
#define DEBUG_E1000_RESTART if (DEBUG_E1000_RESTART_ON)        printk
#define DEBUG_LOOPBACK if (DEBUG_LOOPBACK_ON)  printk
#define DEBUG_PROBE    if (DEBUG_PROBE_ON)     printk
#define DEBUG_SETPHY   if (DEBUG_SETPHT_ON)    printk
#define DEBUG_MULT_CAST if (DEBUG_MULT_CAST_ON) printk

#if defined(__LITTLE_ENDIAN) && (defined(SUNLANCE_BODY_FOR_PCI) || \
		(defined(SUNLANCE_BODY_FOR_SBUS) && defined(__e2k__) && \
		!defined(CONFIG_P2S_TWISTING))) /* e2k & SBUS ~ pci2sbus */

static inline u32 rotate_32 (u32 l)
{
       return ((l&0xff)<<24) | (((l>>8)&0xff)<<16) |
                       (((l>>16)&0xff)<<8)| ((l>>24)&0xff);
}
static inline u16 rotate_16 (u16 l)
{
       return ((l&0xff)<<8) | ((l>>8)&0xff);
}
#define flip_32(x)     rotate_32(x)
#define flip_16(x)     rotate_16(x)

#else /* BIG_ENDIAN */

#define flip_32(x)     (x)
#define flip_16(x)     (x)

#endif /* __LITTLE_ENDIAN */

#if defined(SUNLANCE_BODY_FOR_SBUS) && !defined(CONFIG_P2S_TWISTING)
#define lance_writew(w, addr) __raw_writew(w, addr)
#define lance_writel(l, addr) __raw_writel(l, addr)
#define lance_readw(addr) __raw_readw(addr)
#define lance_readl(addr) __raw_readl(addr)
#else /* ! FOR_SBUS */
/*	mfe-pci as well as mfe-sbus are big-endian (should be twisted in e2k) */
/*	we have to use __raw_* to avoid twisting in E90 */
#define lance_writew(b, addr) __raw_writew(cpu_to_be16(b), addr)
#define lance_writel(b, addr) __raw_writel(cpu_to_be32(b), addr)
#define lance_readw(addr) be16_to_cpu(__raw_readw(addr))
#define lance_readl(addr) be32_to_cpu(__raw_readl(addr))
#endif /* SBUS || P2S_TWISTING */

/* special commands for mcst sunlance */

#define R_DATA  0x14
#define R_CMD   0x18

#define DATA_READY      0x2000
#define CH2_POLL_CMD    0x60820000U     /* ON after RESET */
#define CH1_POLL_CMD    0x60020000U
#define CH2_OFF_CMD     0x50821400U
#define CH1_OFF_CMD     0x50021400U
#define CH2_ON_CMD      0x50821000U
#define CH1_ON_CMD      0x50021000U
#define CHANS_MASK      0x180           /* 8,7 ВЙФЩ */

#define NILL_DATA       0xffffffff


struct lance_rx_desc {
	u16	rmd0;		/* low address of packet */
	u8	rmd1_bits;	/* descriptor bits */
	u8	rmd1_hadr;	/* high address of packet */
	s16	length;		/* This length is 2s complement (negative)!
				 * Buffer length
				 */
	u16	mblength;	/* This is the actual number of bytes received */
};

struct lance_tx_desc {
	u16	tmd0;		/* low address of packet */
	u8 	tmd1_bits;	/* descriptor bits */
	u8 	tmd1_hadr;	/* high address of packet */
	s16 	length;		/* Length is 2s complement (negative)! */
	u16 	misc;
};

/* The LANCE initialization block, described in databook. */
/* On the Sparc, this block should be on a DMA region     */
struct lance_init_block {
	u16	mode;		/* Pre-set mode (reg. 15) */
	u8	phys_addr[6];	/* Physical ethernet address */
	u32	filter[2];	/* Multicast filter. */

	/* Receive and transmit ring base, along with extra bits. */
	u16	rx_ptr;		/* receive descriptor addr */
	u16	rx_len;		/* receive len and high addr */
	u16	tx_ptr;		/* transmit descriptor addr */
	u16	tx_len;		/* transmit len and high addr */

	/* The Tx and Rx ring entries must aligned on 8-byte boundaries. */
       struct lance_rx_desc brx_ring[RX_RING_SIZE] __attribute__((aligned(8)));
       struct lance_tx_desc btx_ring[TX_RING_SIZE] __attribute__((aligned(8)));
	/* New firmware requires 128 byte alignment. It's suitable for old firmware too */
       u8      tx_buf [TX_RING_SIZE][TX_BUFF_SIZE_ALIGN128] __attribute__((aligned(128)));
       u8	pad[2];		/* align rx_buf for copy_and_sum(). */
       u8      rx_buf [RX_RING_SIZE][RX_BUFF_SIZE_ALIGN128] __attribute__((aligned(128)));
};

#define libdesc_offset(rt, elem) \
((__u32)(((unsigned long)(&(((struct lance_init_block *)0)->rt[elem])))))

#define libbuff_offset(rt, elem) \
((__u32)(((unsigned long)(&(((struct lance_init_block *)0)->rt[elem][0])))))

#ifdef CONFIG_MCST_RT
struct lance_rt;
/* Bits for RT synchronization */
#define	RT_BIT_OPEN	0
#define	RT_BIT_READY	1
#define	RT_BIT_RD	2
#define	RT_BIT_WR	3

#endif


struct sunlance_access;

#define MAX_DSK_TX_WAIT 20
#define MAX_DSK_RX_WAIT 5
#define DESK_WAIT_TIME 10
#define LANCE_NAPI_WEIGHT 64

struct lance_private {
       /* Lance RAP/RDP regs.          */
       struct {
               void __iomem    *vbase; /* Lance regs virtual base address */
               void __iomem    *rdp;   /* RDP reg virtual address */
               void __iomem    *rap;   /* RAP reg virtual address */
       } lregs;
	int csr0;	/* to save csr0 in primary handler for threaded fn */
        void __iomem    *ioctl_lregs;   /* Lance channels ioctl regs    */
        spinlock_t      ioctl_lock;
	void __iomem	*dregs;		/* DMA controller regs.		*/
	struct lance_init_block __iomem *init_block_iomem;
	struct lance_init_block *init_block_mem;
#ifdef CONFIG_MCST_RT
	unsigned long	rt_bits;
        raw_spinlock_t    rt_stuff_lock;
        struct lance_rt  *rt_stuff;
#ifdef CONFIG_E90
        unsigned long long   t_start;
        int                  t_max_loop;
        int                  calculate_t_max_loop;
#endif
#endif
	struct napi_struct	napi;
        raw_spinlock_t		lock;
        raw_spinlock_t		init_lock;
	int		rx_new, tx_new;
	int		rx_old, tx_old;

	char		burst_sizes;	/* ledma SBus burst sizes	*/
	char		pio_buffer;	/* init block in PIO space?	*/

	unsigned short	busmaster_regval;

	void (*init_ring)(struct net_device *);
	void (*rx)(struct net_device *);
	void (*tx)(struct net_device *);

        struct sunlance_access *a;

        struct mii_if_info     mii_if;
        unsigned int            mii:1;         /* mii port available */
        struct timer_list      watchdog_timer;

        u32                    msg_enable;     /* debug message level */

	char	       	       *name;
	dma_addr_t		init_block_dvma;
	struct net_device      *dev;		  /* Backpointer	*/
#ifdef SUNLANCE_BODY_FOR_SBUS
	struct of_device       *op;
	struct of_device       *lebuffer;
        struct of_device *ledma;        /* If set this points to ledma  */
#endif
#ifdef SUNLANCE_BODY_FOR_P2S
	struct sbus_dev *sdev;
#endif
#ifdef SUNLANCE_BODY_FOR_PCI
	struct pci_dev *pdev;
#endif
	struct timer_list       multicast_timer;
        int stat_tx_delay[MAX_DSK_TX_WAIT];
        int stat_rx_delay[MAX_DSK_RX_WAIT];

#ifdef SUNLANCE_CHECK_TMD
	u16	saved_tmd0[TX_RING_SIZE];
	u8	saved_tmdh[TX_RING_SIZE];
#endif
        // for debug and dump device
#define LAST_RCV_LEN  80 
        char    lasl_rcv[LAST_RCV_LEN];
        int     lasl_entry;
        int     lasl_len;
};

#define TX_BUFFS_AVAIL ((lp->tx_old<=lp->tx_new)?\
			lp->tx_old+TX_RING_MOD_MASK-lp->tx_new:\
			lp->tx_old - lp->tx_new-1)

/* Lance registers. */

#if defined(SUNLANCE_BODY_FOR_SBUS) || defined(SUNLANCE_BODY_FOR_P2S)
#define RDP                        0x00UL          /* SBus register data port      */
#define RAP                        0x02UL          /* SBus register address port   */
#endif
#ifdef SUNLANCE_BODY_FOR_PCI
#define RDP                         0x00UL          /* PCI register data port       */
#define RAP                         0x04UL          /* PCI register address port    */
#endif

#define LANCE_REG_SIZE_BAGET    0x30UL

/* Lance PCI resources */
#define PCI_DREGS_BAR   0
#define PCI_LREGS_BAR   1


#define LANCE_REG_SIZE	0x04UL


#define STOP_LANCE(__lp)				\
do {   lance_writew(LE_CSR0,    (__lp)->lregs.rap);		\
	while (!(lance_readw((__lp)->lregs.rdp) & LE_C0_STOP)) {\
		lance_writew(LE_C0_STOP, (__lp)->lregs.rdp);	\
		udelay(1);					\
	}						\
} while (0)


static int stop_lance(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);
	int i;
	u16 rdp;
	for (i = 0; i < 500; i++) {
		lance_writew(LE_CSR0, lp->lregs.rap);
		lance_writew(LE_C0_STOP, lp->lregs.rdp);
		udelay(1);
		lance_writew(LE_CSR0, lp->lregs.rap);
		rdp = lance_readw(lp->lregs.rdp);
		if (rdp & LE_C0_STOP) {
			return 0;
		}
	}
	pr_err("%s : Can't stop device. rdp = 0x%04x\n", dev->name, rdp);
	return 1;
}

static int sparc_lance_debug = 2;
/* The Lance uses 24 bit addresses */
/* On the Sun4c the DVMA will provide the remaining bytes for us */
/* On the Sun4m we have to instruct the ledma to provide them    */
/* Even worse, on scsi/ether SBUS cards, the init block and the
 * transmit/receive buffers are addresses as offsets from absolute
 * zero on the lebuffer PIO area. -DaveM
 */

#define LANCE_ADDR(x) ((u32)(x) & ~(u32)0xff000000)


static int start_tx_afterfill = 0; /* mfe start tx after buffer is filled */
module_param( start_tx_afterfill , int , 1 );
MODULE_PARM_DESC(start_tx_afterfill,"used for mfe start tx after buffer filled ");


static u32 sunlance_read_mgio_csr(struct lance_private *lp){
	if (lp && lp->dregs) {
		return (u32)lance_readl(lp->dregs + DMA_ADDR);
	}
       return 0xabcdefab;
}

static void sunlance_write_mgio_csr(struct lance_private *lp, int val){
	if (lp && lp->dregs) {
		lance_writel((u32)val, lp->dregs + DMA_ADDR);
	}
}

static u32 sunlance_read_mgio_data(struct lance_private *lp){
	if (lp && lp->dregs) {
		return (u32)lance_readl(lp->dregs + DMA_COUNT);
	}
	return 0xabcdefab;
}

static void sunlance_write_mgio_data(struct lance_private *lp, int val){
	if (lp && lp->dregs) {
		lance_writel((u32)val, lp->dregs + DMA_COUNT);
	}
}

struct sunlance_access {
    u32        (*read_mgio_csr)(struct lance_private *lp);
    void       (*write_mgio_csr)(struct lance_private *lp, int);
    u32        (*read_mgio_data)(struct lance_private *lp);
    void       (*write_mgio_data)(struct lance_private *lp, int);
};

static struct sunlance_access sunlance_io = {
       .read_mgio_csr          =       sunlance_read_mgio_csr, 
       .write_mgio_csr         =       sunlance_write_mgio_csr,
       .read_mgio_data         =       sunlance_read_mgio_data,
       .write_mgio_data        =       sunlance_write_mgio_data,
};


static void mdio_write(struct net_device *dev, int phy_id, int reg_num, int val)
{
    struct lance_private *ep = netdev_priv(dev);
    u32 wr;
    int i = 0;

 //   if (!ep->mii)
 //      return;

if (reg_num == 0) {
	pr_warning(" !!!!!!!!! %s: attempt to write 0x%04x to BMCR", dev->name, val);
	WARN_ON(1);
}
    wr = 0;
    wr |= 0x2 << MGIO_CS_OFF;
    wr         |= 0x1 << MGIO_ST_OF_F_OFF;
    wr |= 0x1 << MGIO_OP_CODE_OFF; /* Write */
    wr |= (phy_id  & 0x1f) << MGIO_PHY_AD_OFF;
    wr |= (reg_num & 0x1f) << MGIO_REG_AD_OFF;
    wr |= val & 0xffff;

    DEBUG_MDIO_WR("*************>> mdio_write : reg 0x%x <<<<<< 0x%x\n",
                               reg_num, val);
    ep->a->write_mgio_data(ep, wr);
    for (i = 0; i != 1000; i++){
       if (ep->a->read_mgio_csr(ep) & RRDY)
               return;
    }
    DEBUG_MDIO_WR("mdio_write: Unable to write MGIO_DATA reg: val = 0x%x\n", wr);
    return;
}

/* This routine assumes that the ep->lock is held */
static int mdio_read(struct net_device *dev, int phy_id, int reg_num)
{
    struct lance_private *ep = netdev_priv(dev);
    u32 rd, wr;
    u16 val_out = 0;
    int i = 0;
    u32 csr;

//    if (!ep->mii)
//       return 0;

    wr = 0;
    wr |= 0x2 << MGIO_CS_OFF;
    wr |= 0x1 << MGIO_ST_OF_F_OFF;
    wr |= 0x2 << MGIO_OP_CODE_OFF; /* Read */
    wr |= (phy_id  & 0x1f) << MGIO_PHY_AD_OFF;
    wr |= (reg_num & 0x1f) << MGIO_REG_AD_OFF;


    ep->a->write_mgio_data(ep, wr);
    rd = 0;
    for (i = 0; i != 1000; i++) {
       csr = ep->a->read_mgio_csr(ep);
       if (csr & RRDY){
               rd = (u16)ep->a->read_mgio_data(ep);
               val_out = rd & 0xffff;
               DEBUG_MDIO_RD("*************>> mdio_read : reg 0x%x >>>>>> 0x%x\n",
                                reg_num, val_out);
               return val_out;
       }
    } 

    DEBUG_MDIO_RD("mdio_read: Unable to read from MGIO_DATA reg=%d "
    	"wr = 0x%08x, mgio_csr = 0x%08x\n", reg_num, wr, csr);
    return 0;
}



 static u32 lance_get_link(struct net_device *dev)
 {
    struct lance_private *ep = netdev_priv(dev);
//    unsigned long flags;
    int r;

//    raw_spin_lock_irqsave(&ep->lock, flags);
    if (ep->mii) {
       r = mii_link_ok(&ep->mii_if);
    } else {
       /* FIXME */
       r = 0;
    }
//    raw_spin_unlock_irqrestore(&ep->lock, flags);

    return r;
 }


static int lance_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
    struct lance_private *ep = netdev_priv(dev);
//    unsigned long flags;
    int r = -EOPNOTSUPP;

    if (ep->mii) {
//       raw_spin_lock_irqsave(&ep->lock, flags);
       mii_ethtool_gset(&ep->mii_if, cmd);
//       raw_spin_unlock_irqrestore(&ep->lock, flags);
       r = 0;
    }
    return r;
}

static int lance_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
    struct lance_private *ep = netdev_priv(dev);
//    unsigned long flags;
    int r = -EOPNOTSUPP;

    if (ep->mii) {
//       raw_spin_lock_irqsave(&ep->lock, flags);
       r = mii_ethtool_sset(&ep->mii_if, cmd);
//       raw_spin_unlock_irqrestore(&ep->lock, flags);
    }
    return r;
}

static int lance_nway_reset(struct net_device *dev)
{
    struct lance_private *ep = netdev_priv(dev);
//    unsigned long flags;
    int r = -EOPNOTSUPP;

    if (ep->mii) {
  //     raw_spin_lock_irqsave(&ep->lock, flags);
       r = mii_nway_restart(&ep->mii_if);
  //     raw_spin_unlock_irqrestore(&ep->lock, flags);
    }
    return r;
}

static u32 lance_get_msglevel(struct net_device *dev)
{
    struct lance_private *lp = netdev_priv(dev);
    return lp->msg_enable;
}

static void lance_set_msglevel(struct net_device *dev, u32 value)
{
    struct lance_private *lp = netdev_priv(dev);
    lp->msg_enable = value;
}

static void lance_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strcpy(info->driver, LANCE_TYPE_NAME);
        strcpy(info->version, "3.00-mcst");
}

 static struct ethtool_ops lance_ethtool_ops = {
        .get_settings          = lance_get_settings,
        .set_settings          = lance_set_settings,
        .get_drvinfo            = lance_get_drvinfo,
        .get_msglevel          = lance_get_msglevel,
        .set_msglevel          = lance_set_msglevel,
        .nway_reset            = lance_nway_reset,
        .get_link              = lance_get_link,
 };



static void sunlance_watchdog(unsigned long arg)
{
    struct net_device *dev = (struct net_device *)arg;
    struct lance_private *lp = netdev_priv(dev);
//    unsigned long flags;

    /* Print the link status if it has changed */
    if (lp->mii) {
//       raw_spin_lock_irqsave(&lp->lock, flags);
       mii_check_media (&lp->mii_if, netif_msg_link(lp), 0);
//       raw_spin_unlock_irqrestore(&lp->lock, flags);
    }

    mod_timer (&(lp->watchdog_timer), LANCE_WATCHDOG_TIMEOUT);
}



static netdev_tx_t lance_start_xmit_generic(struct sk_buff *skb, struct net_device *dev, struct lance_private *lp);
#ifdef CONFIG_MCST_RT
static int lance_set_promuscuous(struct net_device *dev, int on);
#endif

#ifndef MODULE
static int sunlance_uses_poll = 0;

static int __init set_sunlance_uses_poll(char *str)
{
        get_option(&str, &sunlance_uses_poll);
        if (sunlance_uses_poll) {
#if 0
               printk("SunLance uses net-poll\n");
#else
        printk("sunlance_uses_poll not implemented yet\n");
	sunlance_uses_poll = 0;
#endif
        }
        return 1;
}
__setup("sunlance_uses_poll=", set_sunlance_uses_poll);
#endif

#ifdef CONFIG_MCST_RT
        /*
             lance RT stuff handling. It's implemented for fast
              poit-to-point sequential data exchange
         */
struct lance_rt {
        char rx_buf[ETH_DATA_LEN];
        struct sk_buff *skb_tx;
        int recieved;
        int rx_len;
        int proto;
        struct task_struct *rx_waiter;
        u16    saved_mode;
};

static int
sunlance_rt_open(struct net_device *dev, struct lance_private *lp)
{
        struct lance_rt *rt_stuff;
        struct sk_buff *skb_tx;
        struct lance_init_block *ib_mem = lp->init_block_mem;
        u16 mode;
        int r = 0;

	if (test_and_set_bit(RT_BIT_OPEN, &lp->rt_bits)) {
		return -EBUSY;
	}
	if (test_bit(RT_BIT_READY, &lp->rt_bits)) {
		clear_bit(RT_BIT_OPEN, &lp->rt_bits);
		return 0;
	}
        rt_stuff = kmalloc(sizeof ( struct lance_rt), GFP_KERNEL);
        if (rt_stuff == NULL) {
                return -ENOMEM;
        }
        skb_tx = dev_alloc_skb(ETH_DATA_LEN + 2);
        if (skb_tx == NULL) {
                kfree(rt_stuff);
                return -ENOMEM;
        }
        memset(rt_stuff, 0, sizeof ( struct lance_rt));
        rt_stuff->skb_tx = skb_tx;
        mode = flip_16(ib_mem->mode);
        rt_stuff->saved_mode = mode;
        if (!(mode & LE_MO_PROM)) {
                r = lance_set_promuscuous(dev, 1);
        }
        lp->rt_stuff = rt_stuff;
	if (lp->mii) {
		del_timer_sync(&lp->watchdog_timer);
	}
	set_bit(RT_BIT_READY, &lp->rt_bits);
	clear_bit(RT_BIT_OPEN, &lp->rt_bits);
        return 0;
}


static void
sunlance_rt_close(struct net_device *dev, struct lance_private *lp)
{
        struct lance_rt *rt_stuff;
        u16 mode;

	while (test_and_set_bit(RT_BIT_OPEN, &lp->rt_bits)) {
		cpu_relax();
	}
	if (!test_and_clear_bit(RT_BIT_READY, &lp->rt_bits)) {
		clear_bit(RT_BIT_OPEN, &lp->rt_bits);
		return;
	}
	while (test_bit(RT_BIT_RD, &lp->rt_bits)) {
		cpu_relax();
	}
	while (test_bit(RT_BIT_WR, &lp->rt_bits)) {
		cpu_relax();
	}
        rt_stuff = lp->rt_stuff;
        if (rt_stuff == NULL) {
                raw_spin_unlock_irq(&lp->rt_stuff_lock);
                return;
        }
        lp->rt_stuff = NULL;
        mode = rt_stuff->saved_mode;
        if (!(mode & LE_MO_PROM)) {
                 lance_set_promuscuous(dev, 0);
        }
        if (rt_stuff->skb_tx) {
                dev_kfree_skb(rt_stuff->skb_tx);
        }
        if (rt_stuff->rx_waiter) {
                wake_up_process(rt_stuff->rx_waiter);
        }
        kfree(rt_stuff);
	if (lp->mii) {
		mod_timer(&(lp->watchdog_timer), LANCE_WATCHDOG_TIMEOUT);
	}
	clear_bit(RT_BIT_OPEN, &lp->rt_bits);
        return;
}

static void
sunlance_rt_rx_complete(struct lance_private *lp, char *data, int len)
{
        unsigned long flags;
        struct lance_rt *rt_stuff;
         struct task_struct *rx_waiter;

        raw_spin_lock_irqsave(&lp->rt_stuff_lock, flags);
	rt_stuff = lp->rt_stuff;
        if (rt_stuff == NULL) {
                 raw_spin_unlock_irqrestore(&lp->rt_stuff_lock, flags);
                return;
        }
        memcpy(rt_stuff->rx_buf, data + ETH_HLEN, len - ETH_HLEN);
        rt_stuff->rx_len = len - ETH_HLEN;
        rt_stuff->recieved++;
	rt_stuff->proto = (int)be16_to_cpu(*((u16 *)(data + 2 * ETH_ALEN)));
        rx_waiter = rt_stuff->rx_waiter;
        raw_spin_unlock_irqrestore(&lp->rt_stuff_lock, flags);
        if (rx_waiter) {
                wake_up_process(rx_waiter);
        }
}

extern asmlinkage void __sched schedule(void);
static int sunlance_rt_read(struct lance_private *lp, struct ifreq *rq)
{
        struct lance_rt *rt_stuff;
        el_netdev_udata_t *ud;
        char *buf = NULL;
        int skipped;
        int proto;
        int len = -1;
        int r;
        int timeout= -1;

	if (test_and_set_bit(RT_BIT_RD, &lp->rt_bits)) {
		return -EBUSY;
	}
	if (!test_bit(RT_BIT_READY, &lp->rt_bits)) {
		clear_bit(RT_BIT_RD, &lp->rt_bits);
		return -EINVAL;
	}
        ud = (el_netdev_udata_t *)(rq->ifr_data);
        r = get_user(len, &ud->rx_len);
        r |= get_user(timeout, &ud->timeout);
        r |= get_user(buf, &ud->rx_buf);
        if (r) {
		clear_bit(RT_BIT_RD, &lp->rt_bits);
                return -EFAULT;
        }
	if (len < ETH_HLEN) {
		clear_bit(RT_BIT_RD, &lp->rt_bits);
		return -EINVAL;
	}
        if (timeout > 0) {
                timeout = (timeout * HZ) / 1000;
        }
        rt_stuff = lp->rt_stuff;
retry :
        raw_spin_lock_irq(&lp->rt_stuff_lock);
        if (!rt_stuff->recieved) {
                // we dont have data
                if (timeout == 0) {
                        raw_spin_unlock_irq(&lp->rt_stuff_lock);
			clear_bit(RT_BIT_RD, &lp->rt_bits);
                        return -ETIMEDOUT;
                }
                current->state = TASK_INTERRUPTIBLE;
                rt_stuff->rx_waiter = current;
                raw_spin_unlock_irq(&lp->rt_stuff_lock);
                if (timeout > 0) {
                        timeout = schedule_timeout(timeout);
                } else {
                        schedule();
                }
                rt_stuff->rx_waiter = NULL;
                if (rt_stuff->recieved) {
                        goto retry;
                }
		clear_bit(RT_BIT_RD, &lp->rt_bits);
                return -ETIMEDOUT;
        }
        skipped = rt_stuff->recieved - 1;
        proto = rt_stuff->proto;
        len = (len > rt_stuff->rx_len) ? rt_stuff->rx_len : len;
        rt_stuff->recieved = 0;
        raw_spin_unlock_irq(&lp->rt_stuff_lock);
        if (copy_to_user(buf, rt_stuff->rx_buf, len)) {
		clear_bit(RT_BIT_RD, &lp->rt_bits);
                return -EFAULT;
        }
        r  = put_user(len, &ud->rx_len);
        r |= put_user(skipped, &ud->skipped);
        r |= put_user(proto, &ud->proto);
	clear_bit(RT_BIT_RD, &lp->rt_bits);
        if (r) {
                return -EFAULT;
        }
        return 0;
}




static int sunlance_rt_write(struct net_device *dev, struct ifreq *rq)
{
        struct lance_private *lp = netdev_priv(dev);
        el_netdev_udata_t ud, *udp;
        struct lance_rt *rt_stuff;
        struct sk_buff *skb;
        int r;

	if (test_and_set_bit(RT_BIT_WR, &lp->rt_bits)) {
		return -EBUSY;
	}
	if (!test_bit(RT_BIT_READY, &lp->rt_bits)) {
		clear_bit(RT_BIT_WR, &lp->rt_bits);
		return -EINVAL;
	}
        udp = (el_netdev_udata_t *)(rq->ifr_data);
        if (copy_from_user(&ud, udp, sizeof (el_netdev_udata_t))) {
		clear_bit(RT_BIT_WR, &lp->rt_bits);
                return -EFAULT;
        }
	if (ud.tx_len <= 0) {
		clear_bit(RT_BIT_WR, &lp->rt_bits);
		return -EINVAL;
	}
        if (ud.tx_len > ETH_DATA_LEN) {
		clear_bit(RT_BIT_WR, &lp->rt_bits);
                return -EINVAL;
        }
        rt_stuff = lp->rt_stuff;
        skb = rt_stuff->skb_tx;
        if (copy_from_user(skb->data + ETH_HLEN, ud.tx_buf, ud.tx_len)) {
		clear_bit(RT_BIT_WR, &lp->rt_bits);
                return -EFAULT;
        }
        memcpy(skb->data, ud.dst_mac, ETH_ALEN);
        memcpy(skb->data + ETH_ALEN, ud.src_mac, ETH_ALEN);
	*((u16 *)(skb->data + 2 * ETH_ALEN)) = cpu_to_be16((u16)(ud.proto));
        skb->len = ud.tx_len + ETH_HLEN;
        raw_spin_lock_irq(&lp->lock);
        r = lance_start_xmit_generic(skb, dev, lp);
        raw_spin_unlock_irq(&lp->lock);
	clear_bit(RT_BIT_WR, &lp->rt_bits);
        return r;
}

#ifdef CONFIG_COMPAT



static int sunlance_rt_compat_read(struct lance_private *lp, struct ifreq *rq)
{
        struct lance_rt *rt_stuff;
        el_netdev_udata_compat_t *udp, ud;
        char *buf = NULL;
        int skipped;
        int proto;
        int len = -1;
        int r;
        int timeout= -1;

	if (test_and_set_bit(RT_BIT_RD, &lp->rt_bits)) {
		return -EBUSY;
	}
	if (!test_bit(RT_BIT_READY, &lp->rt_bits)) {
		clear_bit(RT_BIT_RD, &lp->rt_bits);
		return -EINVAL;
	}
        udp = (el_netdev_udata_compat_t *)(rq->ifr_data);
        if (copy_from_user(&ud, udp, sizeof (el_netdev_udata_t))) {
		clear_bit(RT_BIT_RD, &lp->rt_bits);
                return -EFAULT;
        }
        len = ud.rx_len;
	if (len < ETH_HLEN) {
		clear_bit(RT_BIT_RD, &lp->rt_bits);
		return -EINVAL;
	}
        timeout = ud.timeout;
        buf = (char *)(long)ud.rx_buf;
        if (timeout > 0) {
                timeout = (timeout * HZ) / 1000;
        }
        rt_stuff = lp->rt_stuff;
retry :
        raw_spin_lock_irq(&lp->rt_stuff_lock);
        if (!rt_stuff->recieved) {
                // we dont have data
                if (timeout == 0) {
                        raw_spin_unlock_irq(&lp->rt_stuff_lock);
			clear_bit(RT_BIT_RD, &lp->rt_bits);
                        return -ETIMEDOUT;
                }
                current->state = TASK_INTERRUPTIBLE;
                rt_stuff->rx_waiter = current;
                raw_spin_unlock_irq(&lp->rt_stuff_lock);
                if (timeout > 0) {
                        timeout = schedule_timeout(timeout);
                } else {
                        schedule();
                }
                rt_stuff->rx_waiter = NULL;
                if (rt_stuff->recieved) {
                        goto retry;
                }
		clear_bit(RT_BIT_RD, &lp->rt_bits);
                return -ETIMEDOUT;
        }
        skipped = rt_stuff->recieved - 1;
        proto = rt_stuff->proto;
        len = (len > rt_stuff->rx_len) ? rt_stuff->rx_len : len;
        rt_stuff->recieved = 0;
        raw_spin_unlock_irq(&lp->rt_stuff_lock);
        if (copy_to_user(buf, rt_stuff->rx_buf, len)) {
		clear_bit(RT_BIT_RD, &lp->rt_bits);
                return -EFAULT;
        }
        r  = put_user(len, &udp->rx_len);
        r |= put_user(skipped, &udp->skipped);
        r |= put_user(proto, &udp->proto);
	clear_bit(RT_BIT_RD, &lp->rt_bits);
        if (r) {
                return -EFAULT;
        }
        return 0;
}



static int sunlance_rt_compat_write(struct net_device *dev, struct ifreq *rq)
{
        struct lance_private *lp = netdev_priv(dev);
        el_netdev_udata_compat_t ud, *udp;
        struct lance_rt *rt_stuff;
        struct sk_buff *skb;
	char *buf;
        int r;

	if (test_and_set_bit(RT_BIT_WR, &lp->rt_bits)) {
		return -EBUSY;
	}
	if (!test_bit(RT_BIT_READY, &lp->rt_bits)) {
		clear_bit(RT_BIT_WR, &lp->rt_bits);
		return -EINVAL;
	}
        udp = (el_netdev_udata_compat_t *)(rq->ifr_data);
        if (copy_from_user(&ud, udp, sizeof (el_netdev_udata_t))) {
		clear_bit(RT_BIT_WR, &lp->rt_bits);
                return -EFAULT;
        }
	if (ud.tx_len <= 0) {
		clear_bit(RT_BIT_WR, &lp->rt_bits);
		return -EINVAL;
	}
        if (ud.tx_len > ETH_DATA_LEN) {
		clear_bit(RT_BIT_WR, &lp->rt_bits);
                return -EINVAL;
        }
        rt_stuff = lp->rt_stuff;
	buf = (char *)(long)ud.tx_buf;
        skb = rt_stuff->skb_tx;
        if (copy_from_user(skb->data + ETH_HLEN, buf, ud.tx_len)) {
		clear_bit(RT_BIT_WR, &lp->rt_bits);
                return -EFAULT;
        }
        memcpy(skb->data, ud.dst_mac, ETH_ALEN);
        memcpy(skb->data + ETH_ALEN, ud.src_mac, ETH_ALEN);
	*((u16 *)(skb->data + 2 * ETH_ALEN)) = cpu_to_be16((u16)(ud.proto));
        skb->len = ud.tx_len + ETH_HLEN;
        raw_spin_lock_irq(&lp->lock);
        r = lance_start_xmit_generic(skb, dev, lp);
        raw_spin_unlock_irq(&lp->lock);
	clear_bit(RT_BIT_WR, &lp->rt_bits);
        return r;
}

#endif //CONFIG_COMPAT
#endif  /* CONFIG_MCST_RT */


#if defined(CONFIG_E90) && defined(SUNLANCE_BODY_FOR_SBUS)

static unsigned int read_rdata(void * base_reg)
{
        int i, res;

        for (i=0;i<10;i++) {
		res = (lance_readl(base_reg + R_DATA) >> 13) & 1;
                if (res) {
			res = lance_readl(base_reg + R_CMD) & 0xfffffff;
                        return(res);
                }
                udelay(10000);
        }
        return NILL_DATA;
}


/* Lance channels ioctl */
static int lance_ioctl (struct net_device *dev, struct ifreq *rq, int cmd)
{
        struct lance_private *lp = netdev_priv(dev);
        int res;
        int w;
        unsigned long flags;

        spin_lock_irqsave(&lp->ioctl_lock,flags);

        switch (cmd) {
        case RESET_IOCTL:
		w = lance_readl(lp->ioctl_lregs + R_DATA);
                w |= 0x4;
		lance_writel(w, lp->ioctl_lregs + R_DATA);
		w = lance_readl(lp->ioctl_lregs + R_DATA);
                w &= ~(0x4);
		lance_writel(w, lp->ioctl_lregs + R_DATA);
                res = 0;
                break;

        case CHANEL_OFFLINE1_IOCTL:
		lance_writel((unsigned int)CH1_OFF_CMD,
			lp->ioctl_lregs + R_CMD);
                if ((res = read_rdata(lp->ioctl_lregs)) == NILL_DATA) {
                        printk("Offline: Don't ready channel register\n");
                        res = -1;
                        break;
                }
		w = lance_readl(lp->ioctl_lregs + R_DATA);
                w |= 0x180;
		lance_writel(w, lp->ioctl_lregs + R_DATA);
                res = 0;
                break;

        case CHANEL_OFFLINE2_IOCTL:
		lance_writel((unsigned int)CH2_OFF_CMD,
			lp->ioctl_lregs + R_CMD);
                if ((res = read_rdata(lp->ioctl_lregs)) == NILL_DATA) {
                        printk("Offline: Don't ready channel register\n");
                        res = -1;
                        break;
                }
		w = lance_readl(lp->ioctl_lregs + R_DATA);
                w |= 0x180;
		lance_writel(w, lp->ioctl_lregs + R_DATA);
                res = 0;
                break;

        case CHANEL_ONLINE1_IOCTL:
		lance_writel((unsigned int)CH2_OFF_CMD,
			lp->ioctl_lregs + R_CMD);
		if ((res = read_rdata(lp->ioctl_lregs)) == NILL_DATA) {
                        printk("Offline: Don't ready channel register\n");
                        res = -1;
                        break;
                }
		w = lance_readl(lp->ioctl_lregs + R_DATA);
                w |= 0x180;
		lance_writel(w, lp->ioctl_lregs + R_DATA);

		lance_writel(CH1_ON_CMD, lp->ioctl_lregs + R_CMD);
                if ((res = read_rdata(lp->ioctl_lregs)) == NILL_DATA) {
                        printk("Online: Don't ready channel register\n");
                        res = -1;
                        break;
                }      
		w = lance_readl(lp->ioctl_lregs + R_DATA);
                w &= ~(0x100);
		lance_writel(w, lp->ioctl_lregs + R_DATA);
                res = 0;
                break;

        case CHANEL_ONLINE2_IOCTL:
		lance_writel((unsigned int)CH1_OFF_CMD,
			lp->ioctl_lregs + R_CMD);
                if ((res = read_rdata(lp->ioctl_lregs)) == NILL_DATA) {
                        printk("Offline: Don't ready channel register\n");
                        res = -1;
                        break;
                }
		w = lance_readl(lp->ioctl_lregs + R_DATA);
                w |= 0x180;
		lance_writel(w, lp->ioctl_lregs + R_DATA);

		lance_writel(CH2_ON_CMD, lp->ioctl_lregs + R_CMD);
                if ((res = read_rdata(lp->ioctl_lregs)) == NILL_DATA) {
                        printk("Online: Don't ready channel register\n");
                        res = -1;
                        break;
                }
		w = lance_readl(lp->ioctl_lregs + R_DATA);
                w &= ~(0x80);
		lance_writel(w, lp->ioctl_lregs + R_DATA);
                res = 0;
                break;

        case POLL_STATUS1_IOCTL:
		lance_writel(CH1_POLL_CMD, lp->ioctl_lregs + R_CMD);
                if ((res = read_rdata(lp->ioctl_lregs)) == NILL_DATA) {
                        res = -1;
                        break;
                }
                res = (res >> 10) & 1;
                break;

        case POLL_STATUS2_IOCTL:
		lance_writel(CH2_POLL_CMD, lp->ioctl_lregs + R_CMD);
                if ((res = read_rdata(lp->ioctl_lregs)) == NILL_DATA) {
                        res = -1;
                        break;
                }
                res = (res >> 10) & 1;
                break;

        default:
                res = -EOPNOTSUPP;
        }

        spin_unlock_irqrestore(&lp->ioctl_lock,flags);
        return res;
}
#endif	// FOR_SBUS && E90

static void lance_print_media(struct mii_if_info *mii)
{
	int advertise, lpa, media;

	advertise = mii->mdio_read(mii->dev, mii->phy_id, MII_ADVERTISE);
	lpa = mii->mdio_read(mii->dev, mii->phy_id, MII_LPA);
	media = mii_nway_result(lpa & advertise);
	pr_warning("link %s, %sMbps, %s-duplex, lpa 0x%04x advertise 0x%04x\n",
		mii_link_ok(mii) ? "up" : "down",
		media & (ADVERTISE_100FULL | ADVERTISE_100HALF) ? "100" : "10",
		(media & ADVERTISE_FULL) ? "full" : "half",
		lpa, advertise);
	pr_warning("BMCR = 0x%04x, BMSR = 0x%04x, PHYDID1 = 0x%04x, PHYSID2 = 0x%04x\n",
		mii->mdio_read(mii->dev, mii->phy_id, MII_BMCR),
		mii->mdio_read(mii->dev, mii->phy_id, MII_BMSR),
		mii->mdio_read(mii->dev, mii->phy_id, MII_PHYSID1),
		mii->mdio_read(mii->dev, mii->phy_id, MII_PHYSID2));
	pr_warning("reg16 = 0x%04x, reg17 = 0x%04x, red18 = 0x%04x, reg19 = 0x%04x\n",
		mii->mdio_read(mii->dev, mii->phy_id, 16),
		mii->mdio_read(mii->dev, mii->phy_id, 17),
		mii->mdio_read(mii->dev, mii->phy_id, 18),
		mii->mdio_read(mii->dev, mii->phy_id, 19));
}

static int our_ioctl (struct net_device *dev, struct ifreq *rq, int cmd)
{
        struct lance_private *lp = netdev_priv(dev);
        struct lance_init_block *ib = lp->init_block_mem;
        int res = -EINVAL;
        int i;
//	unsigned long flags;

        switch (cmd) {
        case SIOCDEVPRIVATE + 10 :
                printk("\n============= IOCTL for %s ===============\n", dev->name);
		lance_print_media(&lp->mii_if);	
		lance_writew(LE_CSR0, lp->lregs.rap);

		pr_warning("csr0= 0x%hx (addr:%p)   init_block_dvma= 0x%llx\n",
			lance_readw(lp->lregs.rdp), lp->lregs.rdp,
			(unsigned long long)lp->init_block_dvma);
		pr_warning("DMA_CSR= 0x%x  DMA_ADDR= 0x%x DMA_COUNT= 0x%x DMA_TEST=0x%x\n",
			lance_readl(lp->dregs + DMA_CSR),
			lance_readl(lp->dregs + DMA_ADDR),
			lance_readl(lp->dregs + DMA_COUNT),
			lance_readl(lp->dregs + DMA_TEST));
                printk("lp=%p; ib=%p; mode=0x%x\n", lp, ib, flip_16(ib->mode));
                printk("ib->mode = 0x%x\n", flip_16(ib->mode));
		i = lance_readw(lp->lregs.rdp);
       
               printk("lance_init_block rx=%p tx=%p\n", ib->brx_ring, ib->btx_ring);
               printk("Tx desk wait delay (mksec) -- number\n");
               for (i=0; i < MAX_DSK_TX_WAIT; i++) {
                       if (lp->stat_tx_delay[i] == 0 ) continue;
                       printk("%d, \t%d\n", DESK_WAIT_TIME * i, lp->stat_tx_delay[i]);
                       lp->stat_tx_delay[i] = 0;
               }
               printk("Rx desk wait delay (mksec) -- number\n");
               for (i=0; i < MAX_DSK_RX_WAIT; i++) {
                       if (lp->stat_rx_delay[i] == 0 ) continue;
                       printk("%d, \t%d\n", DESK_WAIT_TIME * i, lp->stat_rx_delay[i]);
                       lp->stat_rx_delay[i] = 0;
               }

                /* print the Tx ring entries */
                printk("TX RING: tx_new = %d; old = %d; tx_ptr = 0x%x; tx_len = 0x%x\n",
                         (lp->tx_new - 1) & TX_RING_MOD_MASK,
                         (lp->tx_old) & TX_RING_MOD_MASK,
                         flip_16(ib->tx_ptr), flip_16(ib->tx_len));
                {int *lst_rcv = (int *)(&ib->tx_buf[(lp->tx_new - 1) & TX_RING_MOD_MASK][0]);
                        printk("Last transmitted buffer: %d \n",
                             (lp->tx_new - 1) & TX_RING_MOD_MASK);
                        for (i = 0; i < LAST_RCV_LEN / sizeof (int); i += sizeof (int)) {
                                printk("0x%08x  0x%08x  0x%08x  0x%08x\n",
                                  *(lst_rcv + i), *(lst_rcv + i + 1), *(lst_rcv + i + 2), *(lst_rcv + i + 3));
                        }
                }
		i = (lp->tx_old) & TX_RING_MOD_MASK;
		pr_err("Old tmd0 = 0x%x (unFlipped: %llx); tmd1_hadr = 0x%x; tmd1_bits = 0x%x; misc = 0x%x\n",
			flip_16(ib->btx_ring[i].tmd0),
			*((long long *)(&(ib->btx_ring[i]))),
			ib->btx_ring[i].tmd1_hadr,
                        ib->btx_ring [i].tmd1_bits, flip_16(ib->btx_ring [i].misc));
                for (i = 0; i < TX_RING_SIZE; i++) {
                        u16 *packet;
                        packet = (u16 *)(ib->tx_buf[i]);
                        if ((i - lp->tx_new) > 3) {
                                continue;
                        }
                        if ((lp->tx_new - i) > 3) {
                                continue;
                        }
                        printk("tx buf %d(%p): 0x%04hx%04hx%04hx 0x%04hx%04hx%04hx 0x%04hx: ",
                                i, ib->tx_buf[i],
                                 *packet, *(packet+1),
                                *(packet+2), *(packet+3), *(packet+4), *(packet+5), *(packet+6));
                        packet += 21;  // remove eth, ip, udp headers
                        printk("0x%04x%hx 0x%04x%hx 0x%04x%hx 0x%04x%hx %d %d  0x%x\n",
                                *packet, *(packet + 1), *(packet + 2), *(packet + 3),
                                *(packet + 4), *(packet + 5), *(packet + 6), *(packet + 7),
                                (int)(*(packet + 8)<<16 | *(packet + 9)),
                                (int)(*(packet + 10)<<16 | *(packet + 11)),
                                (int)(*(packet + 12)<<16 | *(packet + 13)));
			printk("    tmd0 = 0x%x; tmd1_hadr = 0x%x;"
				" tmd1_bits = 0x%x (addr:%p);"
				" length = 0x%x; misc = 0x%x\n",
				flip_16(ib->btx_ring[i].tmd0),
				ib->btx_ring[i].tmd1_hadr,
				ib->btx_ring[i].tmd1_bits,
				&(ib->btx_ring[i].tmd1_bits),
				flip_16(ib->btx_ring[i].length),
				flip_16(ib->btx_ring[i].misc));
                }
                printk("\n");

                /* print the Rx ring entries */
                        printk("RX RING: curr = %d; rx_ptr = 0x%x, rx_len = 0x%x\n",
                                 lp->rx_new, flip_16(ib->rx_ptr), flip_16(ib->rx_len));
#if 0 /* FIXME */
                {int *lst_rcv = (int *)(&lp->lasl_rcv[0]);
                        printk("Last recieved buffer: %d (len = %d)\n", lp->lasl_entry, lp->lasl_len);
                        for (i = 0; i < LAST_RCV_LEN / 4; i += 4) {
                                printk("0x%08x  0x%08x  0x%08x  0x%08x\n",
                                  *(lst_rcv + i), *(lst_rcv + i + 1), *(lst_rcv + i + 2), *(lst_rcv + i + 3));
                        }
                }
#endif
                for (i = 0; i < RX_RING_SIZE; i++) {
                        u16 *packet;
                        packet = (u16 *)(ib->rx_buf[i]);
                        if ((i - lp->rx_new) > 3) {
                                if ((lp->rx_new + RX_RING_SIZE - i) > 3) {
                                        continue;
                                }
                        }
                        packet = (u16 *)(ib->rx_buf[i]);
                        if ((lp->rx_new - i) > 3) {
                                if ((i + RX_RING_SIZE - lp->rx_new) > 3) {
                                      continue;
                                }
                        }

                        printk("rxbuf %d(%p): 0x%04hx%04hx%04hx 0x%04hx%04hx%04hx 0x%04hx ",
                                i, ib->rx_buf[i],
                                 *packet, *(packet+1),
                                *(packet+2), *(packet+3), *(packet+4), *(packet+5), *(packet+6));
                        packet += 21;  // remove eth, ip, udp headers
                        printk("0x%04x%hx 0x%04x%hx 0x%04x%hx 0x%04x%hx %d %d  0x%x\n",
                                *packet, *(packet + 1), *(packet + 2), *(packet + 3),
                                *(packet + 4), *(packet + 5), *(packet + 6), *(packet + 7),
                                (int)(*(packet + 8)<<16 | *(packet + 9)),
                                (int)(*(packet + 10)<<16 | *(packet + 11)),
                                (int)(*(packet + 12)<<16 | *(packet + 13)));
                        printk("    rmd0 = 0x%x; rmd1_hadr = 0x%x; rmd1_bits = 0x%x; "
                                "length = 0x%x; mblength = 0x%x\n",
                                flip_16(ib->brx_ring [i].rmd0), ib->brx_ring [i].rmd1_hadr,
                                ib->brx_ring [i].rmd1_bits, flip_16(ib->brx_ring [i].length),
                                flip_16(ib->brx_ring [i].mblength));
                }

                res = 0;
                break;
#if defined(CONFIG_MCST_RT) && defined(CONFIG_E90)
        case SIOCDEVPRIVATE + 11 :
                i = lp->t_max_loop;
                lp->calculate_t_max_loop = rq->ifr_ifindex;
                lp->t_max_loop = 0;
                rq->ifr_ifindex = i;
		res = 0;
                break;
#endif
#ifdef CONFIG_MCST_RT
        case SIOCDEV_RTND_OPEN :
                res = sunlance_rt_open(dev, lp);
                break;
        case SIOCDEV_RTND_CLOSE :
                sunlance_rt_close(dev, lp);
                res = 0;
                break;
        case SIOCDEV_RTND_READ :
#ifdef CONFIG_COMPAT
		if (is_compat_task()) {
			res = sunlance_rt_compat_read(lp, rq);
			break;
		}
#endif
                res = sunlance_rt_read(lp, rq);
                break;
        case SIOCDEV_RTND_WRITE :
#ifdef CONFIG_COMPAT
		if (is_compat_task()) {
                        res = sunlance_rt_compat_write(dev, rq);
                        break;
		}
#endif
                res = sunlance_rt_write(dev, rq);
                break;
#endif
        default:
#if defined(CONFIG_E90) && defined(SUNLANCE_BODY_FOR_SBUS)
                res =  lance_ioctl(dev, rq, cmd);
#endif
               /* SIOC[GS]MIIxxx ioctls */
                if (lp->mii) {
//		    unsigned long flags;
//                    raw_spin_lock_irqsave(&lp->lock, flags);
                    res = generic_mii_ioctl(&lp->mii_if, if_mii(rq), cmd, NULL);
//                    raw_spin_unlock_irqrestore(&lp->lock, flags);
                } else {
                    res = -EOPNOTSUPP;
                }
                break;
        }
        return res;
}


/* Load the CSR registers */
static void load_csrs(struct lance_private *lp)
{
	u32 leptr;

	if (lp->pio_buffer)
		leptr = 0;
	else
		leptr = LANCE_ADDR(lp->init_block_dvma);
	lance_writew(LE_CSR1,              lp->lregs.rap);
	lance_writew(leptr & 0xffff,       lp->lregs.rdp);
	lance_writew(LE_CSR2,              lp->lregs.rap);
	lance_writew(leptr >> 16,          lp->lregs.rdp);
	lance_writew(LE_CSR3,              lp->lregs.rap);
	lance_writew(lp->busmaster_regval, lp->lregs.rdp);

        /* Point back to csr0 */
	lance_writew(LE_CSR0, lp->lregs.rap);
}

/* Setup the Lance Rx and Tx rings */
static void lance_init_ring_dvma(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);
	struct lance_init_block *ib = lp->init_block_mem;
	dma_addr_t aib = lp->init_block_dvma;
	__u32 leptr;
	int i;

	/* Lock out other processes while setting up hardware */
	netif_stop_queue(dev);
	lp->rx_new = lp->tx_new = 0;
	lp->rx_old = lp->tx_old = 0;

	/* Copy the ethernet address to the lance init block
	 * Note that on the sparc you need to swap the ethernet address.
	 */
	ib->phys_addr [0] = dev->dev_addr [1];
	ib->phys_addr [1] = dev->dev_addr [0];
	ib->phys_addr [2] = dev->dev_addr [3];
	ib->phys_addr [3] = dev->dev_addr [2];
	ib->phys_addr [4] = dev->dev_addr [5];
	ib->phys_addr [5] = dev->dev_addr [4];

	/* Setup the Tx ring entries */
	for (i = 0; i < TX_RING_SIZE; i++) {
                leptr = LANCE_ADDR(aib + libbuff_offset(tx_buf, i));
                ib->btx_ring [i].tmd0      = flip_16((u16)leptr);
                ib->btx_ring [i].tmd1_hadr = (u8)(leptr >> 16);
#ifdef SUNLANCE_CHECK_TMD
		lp->saved_tmd0[i] = ib->btx_ring[i].tmd0;
                lp->saved_tmdh[i] = ib->btx_ring[i].tmd1_hadr;
#endif
                ib->btx_ring [i].tmd1_bits = 0;
                ib->btx_ring [i].length    = flip_16(0xf000); /* The ones required by tmd2 */
                ib->btx_ring [i].misc      = 0;
	}

	/* Setup the Rx ring entries */
	for (i = 0; i < RX_RING_SIZE; i++) {
                leptr = LANCE_ADDR(aib + libbuff_offset(rx_buf, i));
                ib->brx_ring [i].rmd0      = flip_16((u16)leptr);
                ib->brx_ring [i].rmd1_hadr = leptr >> 16;
                ib->brx_ring [i].rmd1_bits = LE_R1_OWN;
                ib->brx_ring [i].length    = flip_16(-RX_BUFF_SIZE | 0xf000);
                ib->brx_ring [i].mblength  = 0;
	}

	/* Setup the initialization block */

	/* Setup rx descriptor pointer */
        leptr = LANCE_ADDR(aib + libdesc_offset(brx_ring, 0));
        ib->rx_len = flip_16((LANCE_LOG_RX_BUFFERS << 13) | (leptr >> 16));
        ib->rx_ptr = flip_16(leptr);
        /* Setup tx descriptor pointer */
        leptr = LANCE_ADDR(aib + libdesc_offset(btx_ring, 0));
        ib->tx_len = flip_16((LANCE_LOG_TX_BUFFERS << 13) | (leptr >> 16));
        ib->tx_ptr = flip_16(leptr);
}

#if 0
static void lance_init_ring_pio(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);
	struct lance_init_block __iomem *ib = lp->init_block_iomem;
	u32 leptr;
	int i;

	/* Lock out other processes while setting up hardware */
	netif_stop_queue(dev);
	lp->rx_new = lp->tx_new = 0;
	lp->rx_old = lp->tx_old = 0;

	/* Copy the ethernet address to the lance init block
	 * Note that on the sparc you need to swap the ethernet address.
	 */
	writeb(dev->dev_addr[1], &ib->phys_addr[0]);
	writeb(dev->dev_addr[0], &ib->phys_addr[1]);
	writeb(dev->dev_addr[3], &ib->phys_addr[2]);
	writeb(dev->dev_addr[2], &ib->phys_addr[3]);
	writeb(dev->dev_addr[5], &ib->phys_addr[4]);
	writeb(dev->dev_addr[4], &ib->phys_addr[5]);

	/* Setup the Tx ring entries */
	for (i = 0; i < TX_RING_SIZE; i++) {
		leptr = libbuff_offset(tx_buf, i);
		lance_writew(leptr, &ib->btx_ring[i].tmd0);
		writeb(leptr >> 16, &ib->btx_ring[i].tmd1_hadr);
		writeb(0,		&ib->btx_ring[i].tmd1_bits);

		/* The ones required by tmd2 */
		lance_writew(0xf000,	&ib->btx_ring[i].length);
		lance_writew(0,		&ib->btx_ring[i].misc);
	}

	/* Setup the Rx ring entries */
	for (i = 0; i < RX_RING_SIZE; i++) {
		leptr = libbuff_offset(rx_buf, i);

		lance_writew(leptr,	&ib->brx_ring[i].rmd0);
		writeb(leptr >> 16,&ib->brx_ring [i].rmd1_hadr);
		writeb(LE_R1_OWN,	&ib->brx_ring[i].rmd1_bits);
		lance_writew(-RX_BUFF_SIZE|0xf000,
			    &ib->brx_ring [i].length);
		lance_writew(0,	&ib->brx_ring[i].mblength);
	}

	/* Setup the initialization block */

	/* Setup rx descriptor pointer */
	leptr = libdesc_offset(brx_ring, 0);
	lance_writew((LANCE_LOG_RX_BUFFERS << 13) | (leptr >> 16),
		    &ib->rx_len);
	lance_writew(leptr, &ib->rx_ptr);

	/* Setup tx descriptor pointer */
	leptr = libdesc_offset(btx_ring, 0);
	lance_writew((LANCE_LOG_TX_BUFFERS << 13) | (leptr >> 16),
		    &ib->tx_len);
	lance_writew(leptr, &ib->tx_ptr);
}
#endif /* SUNLANCE_BODY_FOR_PCI */


static void init_restart_ledma(struct lance_private *lp)
{
	u32 csr = lance_readl(lp->dregs + DMA_CSR);

	if (!(csr & DMA_HNDL_ERROR)) {
		/* E-Cache draining */
		while (lance_readl(lp->dregs + DMA_CSR) & DMA_FIFO_ISDRAIN)
			barrier();
	}

	csr = lance_readl(lp->dregs + DMA_CSR);
	csr &= ~DMA_E_BURSTS;
	if (lp->burst_sizes & DMA_BURST32)
		csr |= DMA_E_BURST32;
	else
		csr |= DMA_E_BURST16;

	csr |= (DMA_DSBL_RD_DRN | DMA_DSBL_WR_INV | DMA_FIFO_INV);

        udelay(40);
	lance_writel(csr, lp->dregs + DMA_CSR);
        udelay(400);
}

static int init_restart_lance(struct lance_private *lp)
{
	u16 regval = 0;
	int i;

	load_csrs(lp);
	if (lp->dregs)
		init_restart_ledma(lp);
 
//	lance_writew(LE_CSR0,    lp->lregs.rap);
	lance_writew(LE_C0_INIT, lp->lregs.rdp);

	/* Wait for the lance to complete initialization */
	for (i = 0; i < 1000; i++) {
		regval = lance_readw(lp->lregs.rdp);

		if (regval & (LE_C0_ERR | LE_C0_IDON))
			break;
		barrier();
	}
	if (i == 1000 || (regval & LE_C0_ERR)) {
		printk(KERN_ERR "LANCE unopened after %d ticks, csr0=%4.4x.\n",
		       i, regval);
		if (lp->dregs)
			pr_err("dcsr=%8.8x\n",
				lance_readl(lp->dregs + DMA_CSR));
		return -1;
	}

	/* Clear IDON by writing a "1", enable interrupts and start lance */
	lance_writew(LE_C0_IDON, lp->lregs.rdp);
	lance_writew(LE_C0_INEA | LE_C0_STRT,	lp->lregs.rdp);

	if (lp->dregs) {
		u32 csr = lance_readl(lp->dregs + DMA_CSR);

		csr |= DMA_INT_ENAB;
		lance_writel(csr, lp->dregs + DMA_CSR);
	}

	return 0;
}

static int lance_rx_dvma(struct net_device *dev, int budget)
{
	struct lance_private *lp = netdev_priv(dev);
	struct lance_init_block *ib = lp->init_block_mem;
	struct lance_rx_desc *rd;
	u8 bits;
	int len, entry, work_done = 0;
	struct sk_buff *skb;

#if defined(CONFIG_MCST_RT) && defined(CONFIG_E90)
        if (lp->calculate_t_max_loop && lp->t_start) {
                int t = (int)(get_cycles() - lp->t_start);
                if (t > lp->t_max_loop) {
                        lp->t_max_loop = t;
                }
                lp->t_start = 0;
        }
#endif

        entry = lp->rx_new;
        rd = &ib->brx_ring [entry];

#ifdef CONFIG_SBUS
	if (rd->rmd1_bits & LE_R1_OWN)
                udelay(5);
#endif
	for (rd = &ib->brx_ring [entry];
	     !((bits = rd->rmd1_bits) & LE_R1_OWN);
	     rd = &ib->brx_ring [entry]) {

	        if (work_done >= budget)
			break;

#ifdef CONFIG_SBUS
		while (lance_readw(lp->lregs.rdp) & LE_C0_RINT)
			lance_writew(LE_C0_RINT, lp->lregs.rdp);
#endif
		/* We got an incomplete frame? */
		if (unlikely((bits & LE_R1_POK) != LE_R1_POK)) {
			dev->stats.rx_over_errors++;
			dev->stats.rx_errors++;
                        printk("lance_rx: for %s, we got incompl frame, bits 0x%x\n", dev->name, bits);
// WALKAROUND BEGIN
                } else if (unlikely(rd->mblength == flip_16(0x5000))) {
                        // When happens rx overflow card writes flags to invalid location (mblength)
                        dev->stats.rx_over_errors++;
// WALKAROUND END
		} else if (bits & LE_R1_ERR) {
			/* Count only the end frame as a rx error,
			 * not the beginning
			 */
			if (bits & LE_R1_BUF) dev->stats.rx_fifo_errors++;
			if (bits & LE_R1_CRC) dev->stats.rx_crc_errors++;
			if (bits & LE_R1_OFL) dev->stats.rx_over_errors++;
			if (bits & LE_R1_FRA) dev->stats.rx_frame_errors++;
			if (bits & LE_R1_EOP) dev->stats.rx_errors++;
                  //      printk("lance_rx: for %s, we got an err, bits 0x%x\n", dev->name, bits);
                } else {
                        len = (flip_16(rd->mblength) & 0xfff) - 4;
#ifdef CONFIG_MCST_RT
                        if (unlikely(lp->rt_stuff)) {
                                sunlance_rt_rx_complete(lp, ib->rx_buf [entry], len);
                                goto complete;
                        }
#endif
			skb = dev_alloc_skb(len + 2);

			if (unlikely(skb == NULL)) {
				printk(KERN_INFO "%s: Memory squeeze, deferring packet.\n",
				       dev->name);
				dev->stats.rx_dropped++;
				rd->mblength = 0;
				rd->rmd1_bits = LE_R1_OWN;
				lp->rx_new = RX_NEXT(entry);
				return work_done;
			}

                        skb->dev = dev;
			skb_reserve(skb, 2);		/* 16 byte align */
			skb_put(skb, len);		/* make room */

                        // Just for debug and dump device
//                      memcpy(lp->lasl_rcv, (char *)&(ib->rx_buf [entry][0]), LAST_RCV_LEN);
                        lp->lasl_entry = entry;
                        lp->lasl_len = len;

			skb_copy_to_linear_data(skb,
					 (unsigned char *)&(ib->rx_buf [entry][0]),
					 len);
			skb->protocol = eth_type_trans(skb, dev);
                        netif_receive_skb(skb);
#ifdef CONFIG_MCST_RT
complete :
#endif
                        dev->stats.rx_bytes += len;
			dev->stats.rx_packets++;
			work_done++;
		}

		/* Return the packet to the pool */
		rd->mblength = 0;
		rd->rmd1_bits = LE_R1_OWN;
		entry = RX_NEXT(entry);
	}

	lp->rx_new = entry;
	return work_done;
}


static int lance_tx_dvma(struct net_device *dev, int fast)
{
	struct lance_private *lp = netdev_priv(dev);
	struct lance_init_block *ib = lp->init_block_mem;
	int i, j;
        int got = 0;
        int local_counter = 0;
        unsigned long flags;
	struct lance_tx_desc *td;
	u8 bits;
	int ret = 0;
#ifdef CONFIG_E90
	dma_addr_t      bufaddr;
#endif
        j = lp->tx_old;
        raw_spin_lock_irqsave(&lp->lock, flags);
try_tx_again:
	for (i = j; i != lp->tx_new; i = j) {
		td = &ib->btx_ring [i];
		bits = td->tmd1_bits;

#ifdef CONFIG_SBUS
		while (lance_readw(lp->lregs.rdp) & LE_C0_TINT)
			lance_writew(LE_C0_TINT, lp->lregs.rdp);
#endif
		/* If we hit a packet not owned by us, stop */
		if (bits & LE_T1_OWN)
			break;
                got = 1;
#ifdef CONFIG_E90   /* workaround hw bug */
               bufaddr =  LANCE_ADDR(lp->init_block_dvma + libbuff_offset(tx_buf, i)); 
               if (bufaddr!= ((td->tmd1_hadr << 16) | td->tmd0)) {
                        // HW bug. Fortunately it can be fixed dy SW
                        static int print = 10;
                        if (print > 0) {
                                printk("%s (lance_tx_dvma) : corrupted tx desk %d: 0x%x != 0x%x\n",
                                         dev->name, i, (lp->saved_tmdh[i] << 16) | lp->saved_tmd0[i],
                                         ((td->tmd1_hadr << 16) | td->tmd0));
                                print--;
                        }
                        td->tmd0 = bufaddr & 0xffff;
                        td->tmd1_hadr = (bufaddr & 0xff0000) >> 16;
                }
#endif

		if (unlikely(bits & LE_T1_ERR)) {
                        u16 status = flip_16(td->misc);

			if (fast) {
				ret = 1;
				goto out;
			}
			dev->stats.tx_errors++;
			if (status & LE_T3_RTY)  dev->stats.tx_aborted_errors++;
			if (status & LE_T3_LCOL) dev->stats.tx_window_errors++;

			if (status & LE_T3_CLOS) {
				dev->stats.tx_carrier_errors++;
			}

			/* Buffer errors and underflows turn off the
			 * transmitter, restart the adapter.
			 */
			if (status & (LE_T3_BUF|LE_T3_UFL)) {
				dev->stats.tx_fifo_errors++;

//				printk(KERN_ERR "%s: Tx: ERR_BUF|ERR_UFL, restarting\n",
//				       dev->name);
				raw_spin_lock(&lp->init_lock);
				STOP_LANCE(lp);
				lp->init_ring(dev);
				init_restart_lance(lp);
				raw_spin_unlock(&lp->init_lock);
				goto out;
			}
		} else if ((bits & LE_T1_POK) == LE_T1_POK) {
			/*
			 * So we don't count the packet more than once.
			 */
			td->tmd1_bits = bits & ~(LE_T1_POK);

			/* One collision before packet was sent. */
			if (unlikely(bits & LE_T1_EONE))
				dev->stats.collisions++;

			/* More than one collision, be optimistic. */
			if (unlikely(bits & LE_T1_EMORE))
				dev->stats.collisions += 2;

			dev->stats.tx_packets++;
		}

		j = TX_NEXT(j);
	}
	lp->tx_old = j;
	if (got == 0 || !(lance_readw(lp->lregs.rdp) & LE_C0_TXON)) {
                if (local_counter >= MAX_DSK_TX_WAIT - 1) {
                        //printk("TX: %s: Waiting for descriptor too long.\n", dev->name);                      
                        lp->stat_tx_delay[local_counter]++;
                        goto out;
                }
                raw_spin_unlock_irqrestore(&lp->lock, flags);
                udelay(DESK_WAIT_TIME);
                local_counter++;
                raw_spin_lock_irqsave(&lp->lock, flags);
                goto try_tx_again;
        }
        lp->stat_tx_delay[local_counter]++;

out:
	if (netif_queue_stopped(dev) && TX_BUFFS_AVAIL > 0) {
		netif_wake_queue(dev);
	}
        raw_spin_unlock_irqrestore(&lp->lock, flags);
	return ret;
}


#if 0

static void lance_piocopy_to_skb(struct sk_buff *skb, void __iomem *piobuf, int len)
{
	u16 *p16 = (u16 *) skb->data;
	u32 *p32;
	u8 *p8;
	void __iomem *pbuf = piobuf;

	/* We know here that both src and dest are on a 16bit boundary. */
	*p16++ = lance_readw(pbuf);
	p32 = (u32 *) p16;
	pbuf += 2;
	len -= 2;

	while (len >= 4) {
		*p32++ = lance_readl(pbuf);
		pbuf += 4;
		len -= 4;
	}
	p8 = (u8 *) p32;
	if (len >= 2) {
		p16 = (u16 *) p32;
		*p16++ = lance_readw(pbuf);
		pbuf += 2;
		len -= 2;
		p8 = (u8 *) p16;
	}
	if (len >= 1)
		*p8 = readb(pbuf);
}

#if 0
static void lance_rx_pio(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);
	struct lance_init_block __iomem *ib = lp->init_block_iomem;
	struct lance_rx_desc __iomem *rd;
	unsigned char bits;
	int len, entry;
	struct sk_buff *skb;

	entry = lp->rx_new;
	for (rd = &ib->brx_ring [entry];
	     !((bits = readb(&rd->rmd1_bits)) & LE_R1_OWN);
	     rd = &ib->brx_ring [entry]) {

		/* We got an incomplete frame? */
		if ((bits & LE_R1_POK) != LE_R1_POK) {
			dev->stats.rx_over_errors++;
			dev->stats.rx_errors++;
// WALKAROUND BEGIN
		} else if (lance_readw(&rd->mblength) == 0x5000) {
                        // When happens rx overflow card writes flags to invalid location (mblength)
                        dev->stats.rx_over_errors++;
// WALKAROUND END
		} else if (bits & LE_R1_ERR) {
			/* Count only the end frame as a rx error,
			 * not the beginning
			 */
			if (bits & LE_R1_BUF) dev->stats.rx_fifo_errors++;
			if (bits & LE_R1_CRC) dev->stats.rx_crc_errors++;
			if (bits & LE_R1_OFL) dev->stats.rx_over_errors++;
			if (bits & LE_R1_FRA) dev->stats.rx_frame_errors++;
			if (bits & LE_R1_EOP) dev->stats.rx_errors++;
		} else {
			len = (lance_readw(&rd->mblength) & 0xfff) - 4;
			skb = dev_alloc_skb(len + 2);

			if (skb == NULL) {
				printk(KERN_INFO "%s: Memory squeeze, deferring packet.\n",
				       dev->name);
				dev->stats.rx_dropped++;
				lance_writew(0, &rd->mblength);
				writeb(LE_R1_OWN, &rd->rmd1_bits);
				lp->rx_new = RX_NEXT(entry);
				return;
			}

			dev->stats.rx_bytes += len;

			skb_reserve (skb, 2);		/* 16 byte align */
			skb_put(skb, len);		/* make room */
			lance_piocopy_to_skb(skb, &(ib->rx_buf[entry][0]), len);
			skb->protocol = eth_type_trans(skb, dev);
                        if (lp->using_poll) {
                                netif_receive_skb(skb);
                        } else {
                                netif_rx(skb);
                        }
			dev->stats.rx_packets++;
		}

		/* Return the packet to the pool */
		lance_writew(0, &rd->mblength);
		writeb(LE_R1_OWN, &rd->rmd1_bits);
		entry = RX_NEXT(entry);
	}

	lp->rx_new = entry;
}

static void lance_tx_pio(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);
	struct lance_init_block __iomem *ib = lp->init_block_iomem;
	int i, j;

	raw_spin_lock(&lp->lock);

	j = lp->tx_old;
	for (i = j; i != lp->tx_new; i = j) {
		struct lance_tx_desc __iomem *td = &ib->btx_ring [i];
		u8 bits = readb(&td->tmd1_bits);

		/* If we hit a packet not owned by us, stop */
		if (bits & LE_T1_OWN)
			break;

		if (bits & LE_T1_ERR) {
			u16 status = lance_readw(&td->misc);

			dev->stats.tx_errors++;
			if (status & LE_T3_RTY)  dev->stats.tx_aborted_errors++;
			if (status & LE_T3_LCOL) dev->stats.tx_window_errors++;

			if (status & LE_T3_CLOS) {
				dev->stats.tx_carrier_errors++;
				printk(KERN_NOTICE "%s: Carrier Lost, retrying\n",
				       dev->name);
				STOP_LANCE(lp);
				lp->init_ring(dev);
				load_csrs(lp);
				init_restart_lance(lp);
				goto out;
			}

			/* Buffer errors and underflows turn off the
			 * transmitter, restart the adapter.
			 */
			if (status & (LE_T3_BUF|LE_T3_UFL)) {
				dev->stats.tx_fifo_errors++;

				printk(KERN_ERR "%s: Tx: ERR_BUF|ERR_UFL, restarting\n",
				       dev->name);
				STOP_LANCE(lp);
				lp->init_ring(dev);
				load_csrs(lp);
				init_restart_lance(lp);
				goto out;
			}
		} else if ((bits & LE_T1_POK) == LE_T1_POK) {
			/*
			 * So we don't count the packet more than once.
			 */
			writeb(bits & ~(LE_T1_POK), &td->tmd1_bits);

			/* One collision before packet was sent. */
			if (bits & LE_T1_EONE)
				dev->stats.collisions++;

			/* More than one collision, be optimistic. */
			if (bits & LE_T1_EMORE)
				dev->stats.collisions += 2;

			dev->stats.tx_packets++;
		}

		j = TX_NEXT(j);
	}
	lp->tx_old = j;
out:
	if (netif_queue_stopped(dev) &&
	    TX_BUFFS_AVAIL > 0)
		netif_wake_queue(dev);
	raw_spin_unlock(&lp->lock);
}

#endif

#endif

static int lance_poll(struct napi_struct *napi, int budget)
{
	struct lance_private *lp = container_of(napi, struct lance_private,
						napi);
	struct net_device *dev = lp->dev;
	int work_done = 0;
	int csr0;

	lance_writew((LE_C0_RINT | LE_C0_TINT | LE_C0_MERR), lp->lregs.rdp);
	csr0 = lp->csr0;
	lp->csr0 = 0;

	lance_tx_dvma(dev, 0);
	work_done = lance_rx_dvma(dev, budget);

	if (unlikely(csr0 & LE_C0_MERR)) {
		if (lp->dregs) {
			u32 addr = lance_readl(lp->dregs + DMA_ADDR);

			printk(KERN_ERR "%s: Memory error, status %04x, addr %06x\n",
			       dev->name, csr0, addr & 0xffffff);
		} else {
			printk(KERN_ERR "%s: Memory error, status %04x\n",
			       dev->name, csr0);
		}

		raw_spin_lock_irq(&lp->init_lock);
		dev->stats.rx_frame_errors++;
		lance_writew(LE_C0_STOP, lp->lregs.rdp);

		if (lp->dregs) {
			u32 dma_csr = lance_readl(lp->dregs + DMA_CSR);

			dma_csr |= DMA_FIFO_INV;
			lance_writel(dma_csr, lp->dregs + DMA_CSR);
		}

		lp->init_ring(dev);
		init_restart_lance(lp);
		raw_spin_unlock_irq(&lp->init_lock);
		netif_wake_queue(dev);
	}

	if (likely(work_done < budget)) {
		napi_complete(napi);
		lance_writew(LE_C0_INEA, lp->lregs.rdp);
	}

	return work_done;
}

static irqreturn_t lance_interrupt(int irq, void *dev_id)
{
        struct net_device *dev = dev_id;
        struct lance_private *lp = netdev_priv(dev);
        int csr0, csr0_orig;

//	lance_writew(LE_CSR0, lp->lregs.rap);
	csr0 = lance_readw(lp->lregs.rdp);

	csr0 &= (LE_C0_INTR | LE_C0_TINT | LE_C0_RINT | LE_C0_BABL |
		 LE_C0_ERR | LE_C0_MISS | LE_C0_CERR | LE_C0_MERR);
	
        if (!csr0)
		return IRQ_NONE;

	csr0_orig = csr0;

	/* These bits are contained in others */
	csr0 &= ~(LE_C0_INTR|LE_C0_ERR);

	if (unlikely(csr0 & LE_C0_BABL)) {
		dev->stats.tx_errors++;
                csr0 &= ~LE_C0_BABL;
	}
	if (unlikely(csr0 & LE_C0_MISS)) {
		dev->stats.rx_errors++;
                csr0 &= ~LE_C0_MISS;
	}
	if (unlikely(csr0 & LE_C0_CERR)) {
		dev->stats.collisions++;
                csr0 &= ~LE_C0_CERR;
	}

	if (csr0 & LE_C0_TINT) {
		if (likely(lance_tx_dvma(dev, 1) == 0))
			csr0 &= ~LE_C0_TINT;
	}
	
	if (csr0) {
		lp->csr0 = csr0;
		lance_writew(csr0_orig &
			~(LE_C0_TINT | LE_C0_RINT | LE_C0_MERR), lp->lregs.rdp);
	} else {
		lance_writew(LE_C0_INEA | csr0_orig, lp->lregs.rdp);
		return IRQ_HANDLED;
	}
#ifdef CONFIG_MCST_RT
	if (unlikely(lp->rt_stuff))
		lance_poll(&lp->napi, LANCE_NAPI_WEIGHT);
	else
#endif
		/* we will ack (LE_C0_TINT | LE_C0_RINT | LE_C0_MERR) in
		 * lance_poll. If we could not start (&lp->napi);
		 * we will get interrupts again
		 */
		if (likely(napi_schedule_prep(&lp->napi)))
			__napi_schedule(&lp->napi);

	return IRQ_HANDLED;
}

/* Build a fake network packet and send it to ourselves. */
static void build_fake_packet(struct lance_private *lp)
{
	struct net_device *dev = lp->dev;
	int i, entry;
        unsigned long flags;

        raw_spin_lock_irqsave(&lp->lock, flags);

	entry = lp->tx_new & TX_RING_MOD_MASK;
	if (lp->pio_buffer) {
		struct lance_init_block __iomem *ib = lp->init_block_iomem;
		u16 __iomem *packet = (u16 __iomem *) &(ib->tx_buf[entry][0]);
		struct ethhdr __iomem *eth = (struct ethhdr __iomem *) packet;
		for (i = 0; i < (ETH_ZLEN / sizeof(u16)); i++)
			lance_writew(0, &packet[i]);
		for (i = 0; i < 6; i++) {
			writeb(dev->dev_addr[i], &eth->h_dest[i]);
			writeb(dev->dev_addr[i], &eth->h_source[i]);
		}
		lance_writew((-ETH_ZLEN) | 0xf000, &ib->btx_ring[entry].length);
		lance_writew(0, &ib->btx_ring[entry].misc);
		writeb(LE_T1_POK|LE_T1_OWN, &ib->btx_ring[entry].tmd1_bits);
	} else {
		struct lance_init_block *ib = lp->init_block_mem;
                struct ethhdr *packet = (struct ethhdr *) &(ib->tx_buf[entry][0]);
                struct ethhdr *eth = packet;
		memset(packet, 0, ETH_ZLEN);
		for (i = 0; i < 6; i++) {
			eth->h_dest[i] = dev->dev_addr[i];
			eth->h_source[i] = dev->dev_addr[i];
		}
                ib->btx_ring[entry].length = flip_16(((-ETH_ZLEN) | 0xf000));
		ib->btx_ring[entry].misc = 0;
		ib->btx_ring[entry].tmd1_bits = (LE_T1_POK|LE_T1_OWN);
	}
	lp->tx_new = TX_NEXT(entry);

        raw_spin_unlock_irqrestore(&lp->lock, flags);
}






static int lance_open(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);
	int status = 0;
        u16     mode = 0;
	unsigned long flags = 0;
	int i;
/*
	STOP_LANCE(lp);
*/
	if (stop_lance(dev))
		return -EINVAL;

	flags = IRQF_SHARED | IRQF_NO_THREAD;

#ifdef SUNLANCE_BODY_FOR_SBUS
#if defined(CONFIG_SBUS)
	if (lance_request_threaded_irq(dev->irq, &lance_interrupt, NULL,
                        flags, dev->name, (void *) dev)) {
                printk(KERN_ERR "Lance: Can't get irq %d\n", dev->irq);
		return -EAGAIN;
	}
#elif defined(CONFIG_PCI2SBUS) || defined(CONFIG_PCI2SBUS_MODULE)  
        if (sbus_request_irq(dev->irq, &lance_interrupt, NULL,
                        flags, dev->name, (void *) dev)) {
                printk(KERN_ERR "Lance: Can't get irq %d\n", dev->irq);
		return -EAGAIN;
	}
#else
        printk("sbus_sunlance driver may be loaded only under SBUS || PCI2SBUS || PCI2SBUS_MODULE configs\n");
        return -EAGAIN;
#endif
#else /* Seems to be SUNLANCE_BODY_FOR_PCI */
        if (request_irq(dev->irq, &lance_interrupt, flags, dev->name, (void *)dev)) {
                printk(KERN_ERR "Lance: Can't get irq %u\n", dev->irq);
		return -EAGAIN;
	}
#endif        

        raw_spin_lock_irq(&lp->init_lock);

        STOP_LANCE(lp);
	/* On the 4m, setup the ledma to provide the upper bits for buffers */
	if (lp->dregs) {
		u32 regval = lp->init_block_dvma & 0xff000000;

		lance_writel(regval, lp->dregs + DMA_TEST);
	}

	/* Set mode and clear multicast filter only at device open,
	 * so that lance_init_ring() called at any error will not
	 * forget multicast filters.
	 *
	 * BTW it is common bug in all lance drivers! --ANK
	 */
	if (lp->pio_buffer) {
		struct lance_init_block __iomem *ib = lp->init_block_iomem;
		lance_writew(0, &ib->mode);
		lance_writel(0, &ib->filter[0]);
		lance_writel(0, &ib->filter[1]);
	} else {
		struct lance_init_block *ib = lp->init_block_mem;
                if (start_tx_afterfill) {
                    mode |= LE_MO_FULLBUF;
                }
#if !defined(CONFIG_E90) && \
	!(defined(SUNLANCE_BODY_FOR_SBUS) && defined(__e2k__))
		mode |= LE_MO_TR128 | LE_MO_RC128;
#endif
                ib->mode = flip_16(mode);
		ib->filter [0] = 0;
		ib->filter [1] = 0;
	}
	lp->init_ring(dev);
        status = init_restart_lance(lp);
        raw_spin_unlock_irq(&lp->init_lock);

	napi_enable(&lp->napi);
	netif_start_queue(dev);

        /* If we have mii, print the link status and start the watchdog */
       if (lp->mii) {
               mii_check_media (&lp->mii_if, netif_msg_link(lp), 1);
               mod_timer(&(lp->watchdog_timer), LANCE_WATCHDOG_TIMEOUT);
       }

        if (status) {
		lance_free_irq(dev->irq, (void *)dev);
                return status;
	}
	if (!status) {
		build_fake_packet(lp);
		lance_writew(LE_C0_INEA | LE_C0_TDMD, lp->lregs.rdp);
	}

        for (i=0; i < MAX_DSK_TX_WAIT; i++) {
                lp->stat_tx_delay[i] = 0;
        }
        for (i=0; i < MAX_DSK_RX_WAIT; i++) {
                lp->stat_rx_delay[i] = 0;
        }
	return status;
}

static int lance_close(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);

        del_timer_sync(&lp->watchdog_timer);
	napi_disable(&lp->napi);
	netif_stop_queue(dev);
	del_timer_sync(&lp->multicast_timer);

	STOP_LANCE(lp);
        lance_free_irq(dev->irq, (void *)dev);
	return 0;
}

static int lance_reset(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);
	int status;

        raw_spin_lock_irq(&lp->init_lock);
	STOP_LANCE(lp);

	/* On the 4m, reset the dma too */
	if (lp->dregs) {
		u32 csr, addr;

		printk(KERN_ERR "resetting ledma\n");
		csr = lance_readl(lp->dregs + DMA_CSR);
		lance_writel(csr | DMA_RST_ENET, lp->dregs + DMA_CSR);
		udelay(400);
		lance_writel(csr & ~DMA_RST_ENET, lp->dregs + DMA_CSR);

		addr = lp->init_block_dvma & 0xff000000;
		lance_writel(addr, lp->dregs + DMA_TEST);
	}
	lp->init_ring(dev);
	dev->trans_start = jiffies;
	status = init_restart_lance(lp);
        raw_spin_unlock_irq(&lp->init_lock);
	return status;
}

static void lance_piocopy_from_skb(void __iomem *dest, unsigned char *src, int len)
{
	void __iomem *piobuf = dest;
	u32 *p32;
	u16 *p16;
	u8 *p8;

	switch ((unsigned long)src & 0x3) {
	case 0:
		p32 = (u32 *) src;
		while (len >= 4) {
			lance_writel(*p32, piobuf);
			p32++;
			piobuf += 4;
			len -= 4;
		}
		src = (char *) p32;
		break;
	case 1:
	case 3:
		p8 = (u8 *) src;
		while (len >= 4) {
			u32 val;

			val  = p8[0] << 24;
			val |= p8[1] << 16;
			val |= p8[2] << 8;
			val |= p8[3];
			lance_writel(val, piobuf);
			p8 += 4;
			piobuf += 4;
			len -= 4;
		}
		src = (char *) p8;
		break;
	case 2:
		p16 = (u16 *) src;
		while (len >= 4) {
			u32 val = p16[0]<<16 | p16[1];
			lance_writel(val, piobuf);
			p16 += 2;
			piobuf += 4;
			len -= 4;
		}
		src = (char *) p16;
		break;
	};
	if (len >= 2) {
		u16 val = src[0] << 8 | src[1];
		lance_writew(val, piobuf);
		src += 2;
		piobuf += 2;
		len -= 2;
	}
	if (len >= 1)
		writeb(src[0], piobuf);
}

static void lance_piozero(void __iomem *dest, int len)
{
	void __iomem *piobuf = dest;

	if ((unsigned long)piobuf & 1) {
		writeb(0, piobuf);
		piobuf += 1;
		len -= 1;
		if (len == 0)
			return;
	}
	if (len == 1) {
		writeb(0, piobuf);
		return;
	}
	if ((unsigned long)piobuf & 2) {
		lance_writew(0, piobuf);
		piobuf += 2;
		len -= 2;
		if (len == 0)
			return;
	}
	while (len >= 4) {
		lance_writel(0, piobuf);
		piobuf += 4;
		len -= 4;
	}
	if (len >= 2) {
		lance_writew(0, piobuf);
		piobuf += 2;
		len -= 2;
	}
	if (len >= 1)
		writeb(0, piobuf);
}

static void lance_tx_timeout(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);

	printk(KERN_ERR "%s: transmit timed out, status %04x, reset\n",
	       dev->name, lance_readw(lp->lregs.rdp));
	/* dump card state */
	our_ioctl(dev, NULL, SIOCDEVPRIVATE + 10);
	lance_reset(dev);
	netif_wake_queue(dev);
}

static  netdev_tx_t lance_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);
        netdev_tx_t r = NETDEV_TX_BUSY;

	raw_spin_lock_irq(&lp->lock);
#ifdef CONFIG_MCST_RT
	if (lp->rt_stuff) {
		/* card works in special rt mode */
		raw_spin_unlock_irq(&lp->lock);
		return NETDEV_TX_BUSY;
	}
#endif
	r = lance_start_xmit_generic(skb, dev, lp);
	raw_spin_unlock_irq(&lp->lock);
        dev_kfree_skb(skb);
        return r;
}

static
netdev_tx_t lance_start_xmit_generic(struct sk_buff *skb, struct net_device *dev, struct lance_private *lp)
{
	int entry, skblen, len;

	skblen = skb->len;

	len = (skblen <= ETH_ZLEN) ? ETH_ZLEN : skblen;


	dev->stats.tx_bytes += len;

	entry = lp->tx_new & TX_RING_MOD_MASK;
	if (lp->pio_buffer) {
		struct lance_init_block __iomem *ib = lp->init_block_iomem;
		lance_writew((-len) | 0xf000, &ib->btx_ring[entry].length);
		lance_writew(0, &ib->btx_ring[entry].misc);
		lance_piocopy_from_skb(&ib->tx_buf[entry][0], skb->data, skblen);
		if (len != skblen)
			lance_piozero(&ib->tx_buf[entry][skblen], len - skblen);
		writeb(LE_T1_POK | LE_T1_OWN, &ib->btx_ring[entry].tmd1_bits);
	} else {
		struct lance_init_block *ib = lp->init_block_mem;
                ib->btx_ring [entry].length = flip_16(((-len) | 0xf000));
		ib->btx_ring [entry].misc = 0;
		skb_copy_from_linear_data(skb, &ib->tx_buf [entry][0], skblen);
		if (len != skblen)
			memset((char *) &ib->tx_buf [entry][skblen], 0, len - skblen);
		ib->btx_ring [entry].tmd1_bits = (LE_T1_POK | LE_T1_OWN);
	}

	lp->tx_new = TX_NEXT(entry);

	if (TX_BUFFS_AVAIL <= 0)
		netif_stop_queue(dev);
#if defined(CONFIG_MCST_RT) && defined(CONFIG_E90)
        if (lp->calculate_t_max_loop) {
                lp->t_start = get_cycles();
        }
#endif

	/* Kick the lance: transmit now */
//	lance_writew(LE_CSR0, lp->lregs.rap);
	lance_writew(LE_C0_INEA | LE_C0_TDMD, lp->lregs.rdp);

	/* Read back CSR to invalidate the E-Cache.
	 * This is needed, because DMA_DSBL_WR_INV is set.
	 */
	if (lp->dregs)
		(void) lance_readw(lp->lregs.rdp);


	dev->trans_start = jiffies;

	return NETDEV_TX_OK;
}



static struct net_device_stats *lance_get_stats(struct net_device *dev)
{

        return &dev->stats;
}



static void lance_load_multicast(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);
	struct netdev_hw_addr *ha;
	u32 crc;
	u32 val;

	/* set all multicast bits */
	if (dev->flags & IFF_ALLMULTI)
		val = ~0;
	else
		val = 0;

	if (lp->pio_buffer) {
		struct lance_init_block __iomem *ib = lp->init_block_iomem;
		lance_writel(val, &ib->filter[0]);
		lance_writel(val, &ib->filter[1]);
	} else {
		struct lance_init_block *ib = lp->init_block_mem;
#if 0
u16 mode = 0;
		if (start_tx_afterfill) {
			mode |= LE_MO_FULLBUF;
		}
#if !defined(CONFIG_E90)
		mode |= LE_MO_TR128 | LE_MO_RC128;
#endif
		ib->mode = flip_16(mode);
#endif
		ib->filter [0] = val;
		ib->filter [1] = val;
	}

	if (dev->flags & IFF_ALLMULTI)
		return;
	/* Add addresses */
	netdev_for_each_mc_addr(ha, dev) {
		crc = ether_crc_le(6, ha->addr);
		crc = crc >> 26;
		if (lp->pio_buffer) {
			struct lance_init_block __iomem *ib = lp->init_block_iomem;
			u16 __iomem *mcast_table = (u16 __iomem *) &ib->filter;
			u16 tmp = lance_readw(&mcast_table[crc>>4]);
			tmp |= 1 << (crc & 0xf);
			lance_writew(tmp, &mcast_table[crc>>4]);
		} else {
			struct lance_init_block *ib = lp->init_block_mem;
			u16 *mcast_table = (u16 *) &ib->filter;
			u16 tmp = flip_16(mcast_table [crc >> 4]);
			tmp |= 1 << (crc & 0xf);
			mcast_table [crc >> 4] = flip_16(tmp);
		}
	}
}


#ifdef CONFIG_MCST_RT
static int lance_set_promuscuous(struct net_device *dev, int on)
{
        struct lance_private *lp = netdev_priv(dev);
        struct lance_init_block *ib_mem = lp->init_block_mem;
        struct lance_init_block __iomem *ib_iomem = lp->init_block_iomem;
        u16 mode;

	dev->trans_start = jiffies;
        netif_stop_queue(dev);

        raw_spin_lock_irq(&lp->init_lock);
        STOP_LANCE(lp);
        lp->init_ring(dev);

        if (lp->pio_buffer)
		mode = lance_readw(&ib_iomem->mode);
        else
                mode = flip_16(ib_mem->mode);
        if (on) {
                mode |= LE_MO_PROM;
                if (lp->pio_buffer)
			lance_writew(mode, &ib_iomem->mode);
                else
                        ib_mem->mode = flip_16(mode);
        } else {
                mode &= ~LE_MO_PROM;
                if (lp->pio_buffer)
			lance_writew(mode, &ib_iomem->mode);
                else
                        ib_mem->mode = flip_16(mode);
        }
        init_restart_lance(lp);
        raw_spin_unlock_irq(&lp->init_lock);
        netif_wake_queue(dev);
        return 0;
}
#endif


static void lance_set_multicast(struct net_device *dev)
{
	struct lance_private *lp = netdev_priv(dev);
	struct lance_init_block *ib_mem = lp->init_block_mem;
	struct lance_init_block __iomem *ib_iomem = lp->init_block_iomem;
	u16 mode;

	if (!netif_running(dev))
		return;

	if (lp->tx_old != lp->tx_new) {
		mod_timer(&lp->multicast_timer, jiffies + 4);
		netif_wake_queue(dev);
		return;
	}

	netif_stop_queue(dev);

        raw_spin_lock_irq(&lp->init_lock);
	STOP_LANCE(lp);
	lp->init_ring(dev);

        if (lp->pio_buffer)
		mode = lance_readw(&ib_iomem->mode);
        else
                mode = flip_16(ib_mem->mode);

	if (dev->flags & IFF_PROMISC) {
		mode |= LE_MO_PROM;
		if (lp->pio_buffer)
			lance_writew(mode, &ib_iomem->mode);
		else
                       ib_mem->mode = flip_16(mode);
	} else {
		mode &= ~LE_MO_PROM;
		if (lp->pio_buffer)
			lance_writew(mode, &ib_iomem->mode);
		else
                       ib_mem->mode = flip_16(mode);
		lance_load_multicast(dev);
	}
	init_restart_lance(lp);
        raw_spin_unlock_irq(&lp->init_lock);
	netif_wake_queue(dev);
}

static void lance_set_multicast_retry(unsigned long _opaque)
{
	struct net_device *dev = (struct net_device *) _opaque;

	lance_set_multicast(dev);
}



static void lance_setup_mac(struct net_device *dev)
{
        dev->dev_addr[0] = l_base_mac_addr[0];
        dev->dev_addr[1] = l_base_mac_addr[1];
        dev->dev_addr[2] = l_base_mac_addr[2];
        dev->dev_addr[3] = l_base_mac_addr[3];
        dev->dev_addr[4] = l_base_mac_addr[4];
        dev->dev_addr[5] = l_cards_without_mac & 0xff;
	l_cards_without_mac++;
}

static const struct net_device_ops lance_ops = {
        .ndo_open               = lance_open,
        .ndo_stop               = lance_close,
        .ndo_start_xmit         = lance_start_xmit,
        .ndo_set_rx_mode	= lance_set_multicast,
        .ndo_tx_timeout         = lance_tx_timeout,
        .ndo_change_mtu         = eth_change_mtu,
        .ndo_set_mac_address    = eth_mac_addr,
        .ndo_validate_addr      = eth_validate_addr,
        .ndo_get_stats          = lance_get_stats,
        .ndo_do_ioctl           = our_ioctl,
#ifdef CONFIG_MCST_RT
	.ndo_unlocked_ioctl	= 1,
#endif
};




static int lance_common_init(struct net_device *dev, struct lance_private *lp)
{
	int phy_id, csr;
        lp->mii_if.full_duplex = 1;
        lp->mii_if.supports_gmii = 0;
        lp->mii_if.phy_id_mask = 0x1f;
        lp->mii_if.reg_num_mask = 0x1f;
        lp->mii_if.dev = dev;
        lp->mii_if.mdio_read = mdio_read;
        lp->mii_if.mdio_write = mdio_write;
        lp->mii = 1;
        lp->msg_enable =  netif_msg_init(-1, LANCE_MSG_DEFAULT);
        lp->a = &sunlance_io;

        /* Set the mii phy_id so that we can query the link state */
	// Usualy phy_id = 1, but on some sbus MB it deffers.
	// Try to determinate it in tricky way
	for (phy_id = 0; phy_id < 32; phy_id++) {
		csr = mdio_read(dev, phy_id, 0);
		if ((csr & 0xffff) == 0x3000) {
			break;
		}
	}
	if (phy_id == 32) {
		phy_id = 1;
	}
	printk("%s uses phy_id = %d, csr = 0x%08x\n", dev->name, phy_id, csr);
        lp->mii_if.phy_id = phy_id;

        dev->ethtool_ops = &lance_ethtool_ops;
        init_timer (&lp->watchdog_timer);
        lp->watchdog_timer.data = (unsigned long) dev;
        lp->watchdog_timer.function = sunlance_watchdog;
        dev->watchdog_timeo = 5*HZ;

	netif_napi_add(dev, &lp->napi, lance_poll, LANCE_NAPI_WEIGHT);

        dev->netdev_ops = &lance_ops;

       /* We cannot sleep if the chip is busy during a 
         * multicast list update event, because such events 
         * can occur from interrupts (ex. IPv6).  So we 
         * use a timer to try again later when necessary. -DaveM 
         */ 
        init_timer(&lp->multicast_timer);
        lp->multicast_timer.data = (unsigned long) dev;
        lp->multicast_timer.function = &lance_set_multicast_retry;

        if (register_netdev(dev)) {
                printk(KERN_ERR "SunLance: Cannot register device.\n");
                return 1;
        }

	return 0;
}




