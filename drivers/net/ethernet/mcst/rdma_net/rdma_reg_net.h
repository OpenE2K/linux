/*
 * Copyright (c) 2011 by MCST.
 * rdma_reg_net.h
 * Implementation of networking protocols TCP\IP via rdma
 */
#ifndef __LINUX_RDMA1_REG_H__
#define __LINUX_RDMA1_REG_H__

#ifdef	__cplusplus
extern "C" {
#endif

/*Temporary changes to the memcpy*/
#ifdef CONFIG_E90S
//#define MEM_COPY_LCC_V9		1
#endif 
#include <linux/string.h>
#ifdef MEM_COPY_LCC_V9
#undef  memcpy
extern void *memcpy(void *to, const void *from, size_t len);
#endif

#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/if_ether.h>
#include <asm/types.h>
#include <linux/ioport.h>
#include <linux/spinlock.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/numa.h>
#include <net/neighbour.h>
#include <net/ipx.h>
#include <asm/bitops.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <asm/pgtable.h>
#include <linux/errno.h>
#include <asm/byteorder.h>	/* Used by the checksum routines */
#include <linux/semaphore.h>	
#ifdef CONFIG_E90
#include <asm/idprom.h>
#include <asm/e90.h>
#endif
#ifdef CONFIG_E2K
#include <asm/iolinkmask.h>
#include <linux/topology.h>
#include <asm/apic.h>
#include <asm/e2k.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/e2k_sic.h>
#include <asm/uaccess.h>
#endif
#ifdef CONFIG_E90S
#include <asm/apic.h>
#include <asm/e90s.h>
#include <asm/mpspec.h>
#endif
#include <linux/vmalloc.h>
#include <linux/byteorder/generic.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <linux/netdevice.h>
#include <net/sch_generic.h>
#include <net/sock.h>
#include <linux/kthread.h>
#include <linux/syscalls.h>

/* Perhaps use for sparc V8 (R500S), spark V9, E2K */

#ifndef CONFIG_E90
#define BOTTOM_HALF_RX_THREAD_RDMA	1
#ifdef BOTTOM_HALF_RX_THREAD_RDMA
//#define BOTTOM_HALF_RX_ANY_SKB	1
#define BOTTOM_HALF_RX_REFILL_SKB	1
#endif
#endif

#define CHECK_MEMORY_E90S	1
#ifndef CONFIG_E90
#define RDMA_REBOOT		1
#else
#define RDMA_REBOOT		0
#endif
#define AOE_DBG			0
#define RDMA_PROC_FS		0

#ifdef CONFIG_E90
#define MAX_RDMA_NET_DEV 4
#else
//#define MAX_NODES MACH_MAX_NUMIOLINKS
//#define MAX_RDMA_NET_DEV MAX_NUMIOLINKS
#define MAX_RDMA_NET_DEV MACH_MAX_NUMIOLINKS
#endif

#ifdef CONFIG_E90S
extern unsigned int	node_online_rdma_map ;

#undef	SIC_io_reg_offset	/* FIXME: this macros should be defined */
				/* at common arch/l/include/asm/sic_regs.h */

#define NBSR_INF_CFG	   	0x7088     	/* 4    Node Configuration Information */ 
#define IO_HAB_FLAG 		0x00000080
#define E90_IO_CSR_ch_on 	0x80000000
#define E90_RDMA_CS_ch_on	0x80000000
#define	IOHUB_IOL_MODE		0		/* controller is IO HUB */
#define	RDMA_IOL_MODE		1		/* controller is RDMA 	*/
#define	IOHUB_ONLY_IOL_ABTYPE	1		/* abonent has only IO HUB controller 		*/
#define	RDMA_ONLY_IOL_ABTYPE	2		/* abonent has only RDMA  controller 		*/
#define	RDMA_IOHUB_IOL_ABTYPE	3		/* abonent has RDMA and IO HUB controller	*/
#define E90_IOL_CSR_abtype_mask	0x007f0000
#undef  numa_node_id
#define	numa_node_id()			e90s_cpu_to_node(raw_smp_processor_id())
#undef  num_possible_rdmas
#define num_possible_rdmas()		node_rdma_num
#undef  num_online_rdmas
#define num_online_rdmas()		node_online_rdma_num
#undef  for_each_online_rdma
#define for_each_online_rdma(node) 	for (node = 0; node < MAX_NUMIOLINKS; node++ )\
						if (!((node_online_rdma_map >> node) & 0x00000001))\
							continue; else 
#define	SIC_io_reg_offset(io_link, reg)	((reg) + 0x1000 * (io_link))
#endif

#define CONFIG_CMD_RDMA(bus,devfn, where)   (0x80000000 | (bus << 16) | (devfn << 8) | (where & ~3))
#define PCI_VENDOR_ID_MCST_RDMA		0x8086
#define PCI_DEVICE_ID_MCST_RDMA		0x7191

/* Indexes of pci_dev.resource[] */
#define PCI_MMIO_BAR		0
#define PCI_MEM_BAR		1

#define RCode_32 0x00000000
#define RCode_64 0x02000000
#define WCode_32 0x04000000
#define WCode_64 0x06000000
#define OCode_xx 0x0ff00000

#define RDMA_IO_TRACE 	0
#define RDMA_TIME_TRACE 0
#define DESK_DBG	0
#define RDMA_INT_TRACE	0
#define REG_TRACE_EVENT 0

#define PROC_FILENAME "rdma_"

#ifndef EVENT_REGS
#define EVENT_REGS	0
#endif /* RDMA_EVENT */
#define	event_regs	if(EVENT_REGS) fix_event

#ifndef EVENT_QUEUE
#define EVENT_QUEUE	1
#endif /* RDMA_EVENT */
#define	event_queue	if(EVENT_QUEUE) fix_event

#ifndef EVENT_QUEUE_NET
#define EVENT_QUEUE_NET	1
#endif /* RDMA_EVENT */
#define	event_queue_net	if(EVENT_QUEUE_NET) fix_event


#ifndef EVENT_INTR
#define EVENT_INTR	0
#endif /* RDMA_EVENT */
#define event_intr	if(EVENT_INTR) fix_event

#ifndef EVENT_INTR_START
#define EVENT_INTR_START	1
#endif /* RDMA_EVENT */
#define event_intr_start	if(EVENT_INTR_START) fix_event

#ifndef EVENT_READ
#define EVENT_READ	0
#endif /* RDMA_EVENT */
#define event_read	if(EVENT_READ) fix_event

#ifndef EVENT_WRITE
#define EVENT_WRITE	0
#endif /* RDMA_EVENT */
#define event_write	if(EVENT_WRITE) fix_event

#ifndef EVENT_SNDMSG
#define EVENT_SNDMSG	0
#endif /* RDMA_EVENT */
#define event_sndmsg	if(EVENT_SNDMSG) fix_event

#ifndef EVENT_LVNET
#define EVENT_LVNET	0
#endif /* RDMA_EVENT */
#define event_lvnet	if(EVENT_LVNET) fix_event

#ifndef EVENT_MEM
#define EVENT_MEM	1
#endif /* RDMA_EVENT */
#define event_mem	if(EVENT_MEM) fix_event


#ifndef RDMA_DBG
#define RDMA_DBG 	0
#endif /* RDMA_DBG */

#ifndef DBG_INTR
#define DBG_INTR 	0
#endif /* RDMA_DBG */

#ifndef DBG_INIT
#define DBG_INIT 	0
#endif /* RDMA_DBG */

#ifndef DBG_ATTACH
#define DBG_ATTACH 	0
#endif /* RDMA_DBG */

#ifndef RDMA_IO_TRACE
#define RDMA_IO_TRACE 	0
#endif /* RDMA_IO_TRACE */

#ifndef DESK_DBG
#define DESK_DBG	0
#endif /* DESK_DBG */

#ifndef RDMA_INT_TRACE
#define RDMA_INT_TRACE	0
#endif /* RDMA_INT_TRACE */

#ifndef RDMA_REG_TRACE
#define RDMA_REG_TRACE  0
#endif /* RDMA_REG_TRACE */

#ifndef DBG_MUTEX
#define DBG_MUTEX  	0
#endif /* DBG_MUTEX */

#ifndef INTERRUPT_REG_DEBUG
#define INTERRUPT_REG_DEBUG 0
#endif /* INTERRUPT_REG_DEBUG */

#ifndef DBG_MSG	
#define DBG_MSG 	0
#endif /* DBG_MSG */

#ifndef DBG_SEND_MSG
#define DBG_SEND_MSG 	0
#endif /* DBG_SEND_MSG */

#ifndef DBG_IOCTL
#define DBG_IOCTL 	0
#endif /* DBG_IOCTL */

#ifndef DBG_WRITE_BUF
#define DBG_WRITE_BUF 	0
#endif /* DBG_WRITE_BUF */

#ifndef DBG_READ_BUF
#define DBG_READ_BUF 	0
#endif /* DBG_READ_BUF */

#ifndef DBG_MMAP
#define DBG_MMAP 	0
#endif /* DBG_MMAP */

#ifndef DBG_INIT_CHAIN
#define DBG_INIT_CHAIN 	0
#endif /* DBG_INIT_CHAIN */

#ifndef DBG_TM
#define DBG_TM 		0
#endif /* DBG_TM */

#ifndef DBG_ARP
#define DBG_ARP 	0
#endif /* DBG_ARP */

#ifndef DBG_NET
#define DBG_NET 	0
#endif /* DBG_NET */

#ifndef DBG_NET_1
#define DBG_NET_1 	0
#endif /* DBG_NET_1 */

#ifndef DBG_PRINT_BUFS
#define DBG_PRINT_BUFS 	0
#endif /* DBG_PRINT_BUFS */

#ifndef DBG_NET_HEADER
#define DBG_NET_HEADER 	0
#endif /* DBG_NET_HEADER */

#ifndef DBG_MALLOC
#define DBG_MALLOC 	0
#endif /* DBG_MALLOC */

#ifndef DBG_MEM_MALLOC
#define DBG_MEM_MALLOC 	0
#endif /* DBG_MEM_MALLOC */

#ifndef DBG_rw_state_init
#define DBG_rw_state_init 0
#endif /* DBG_rw_state_init */

#ifndef DBG_asi
#define DBG_asi 	0
#endif /* DBG_asi */

#ifndef DBG_LVNET_TX
#define DBG_LVNET_TX 	0
#endif /* DBG_LVNET_TX */

#ifndef DBG_CHECK_MSG
#define DBG_CHECK_MSG 	0
#endif /* DBG_CHECK_MSG */

#ifndef DBG_RDMA_INTR
#define DBG_RDMA_INTR 	0 
#endif /* DBG_RDMA_INTR */

#ifndef DBG_QUEUE
#define DBG_QUEUE 	0
#endif /* INTERRUPT_REG_DEBUG */

#ifndef DBG_DHCP
#define DBG_DHCP 	0
#endif	/* DBG_DHCP */

#ifndef DBG_ERROR
#define DBG_ERROR 	1
#endif	/* DBG_DHCP */

#define dbg_error(x...)		if(DBG_ERROR) printk(x)
#define dbg_net_header(x...)	if(DBG_NET_HEADER) printk(x)
#define dbg_net(x...)		if(DBG_NET) printk(x)
#define dbg_net_1(x...)		if(DBG_NET_1) printk(x)
#define dbg_tm(x...)		if(DBG_TM) printk(x)
#define rdma_dbg(x...)		if(RDMA_DBG) printk(x)
#define dbg_intr(x...)		if(DBG_INTR) printk(x)
#define dbg_ioctl(x...)		if(DBG_IOCTL) printk(x)
#define dbg_init(x...)		if(DBG_INIT) printk(x)
#define dbg_attach(x...)	if(DBG_ATTACH) printk(x)
#define dbg_mutex(x...)		if(DBG_MUTEX) printk(x)
#define dbg_msg(x...)		if(DBG_MSG) printk(x)
#define dbg_write_buf(x...)	if(DBG_WRITE_BUF) printk(x)
#define dbg_read_buf(x...)	if(DBG_READ_BUF) printk(x)
#define dbg_send_msg(x...)	if(DBG_SEND_MSG) printk(x)
#define mmap_dbg(x...)		if(DBG_MMAP) printk(x)
#define dbg_init_chain(x...)	if(DBG_INIT_CHAIN) printk(x)
#define dbg_arp(x...)		if(DBG_ARP) printk(x)
#define dbg_rw_state_init(x...)	if(DBG_rw_state_init) printk(x)
#define dbg_asi(x...)		if(DBG_asi) printk(x)
#define dbg_malloc(x...)	if(DBG_MALLOC) printk(x)
#define dbg_mem_malloc(x...)	if(DBG_MEM_MALLOC) printk(x)
#define dbg_lvnet_tx(x...)	if(DBG_LVNET_TX) printk(x)
//#define dbg_check_msg(x...)	if(DBG_CHECK_MSG) printk(x)
//#define dbg_rdma_intr(x...)	if(DBG_RDMA_INTR) printk(x)
#define dbg_queue(x...)		if(DBG_QUEUE) printk(x)
#define dbg_dhcp(x...)		if(DBG_DHCP) printk(x)


#ifdef	__sparc__ /* E90 */

#define read_asi(__reg, asi) \
({	u32 __ret; \
	__asm__ __volatile__("lda [%1] %2, %0" \
			     : "=r" (__ret) \
			     : "r" (__reg), "i" (asi)  \
			     : "memory"); \
	__ret; \
})

#define write_asi(__reg, __val, asi) \
({	__asm__ __volatile__("sta %0, [%1] %2" \
			     : 		\
			     : "r" (__val), "r" (__reg), "i" (asi) \
			     : "memory"); })

#define rdma_rrg(__reg) \
({	u32 __ret; \
	__asm__ __volatile__("lda [%1] %2, %0" \
			     : "=r" (__ret) \
			     : "r" (__reg), "i" (0x2e)  \
			     : "memory"); \
	__ret; \
})

#define rdma_wrg(__reg, __val) \
({	__asm__ __volatile__("sta %0, [%1] %2" \
			     : 		\
			     : "r" (__val), "r" (__reg), "i" (0x2e) \
			     : "memory"); })

#endif /* E90 */

struct __raw_wait_queue_head {
        raw_spinlock_t lock;
        struct list_head task_list;
};

typedef struct __raw_wait_queue_head raw_wait_queue_head_t;

#define kcondvar_t 		raw_wait_queue_head_t

typedef unsigned long   	ulong_t;
typedef unsigned int   		uint_t;
typedef unsigned char   	uchar_t;
typedef unsigned short   	ushort_t;
typedef long long 		hrtime_t;


struct	rdma_event {
	unsigned	int event[SIZE_EVENT];
	unsigned	int event_cur;
	raw_spinlock_t	mu_fix_event;
};

typedef struct mutex   kmutex_t;	

typedef struct dev_rdma_sem {
	char 		*dev_name;
	unsigned long 	timeout;
	long 		irq_count;		/* counter does not interrupt processedс (as ules 1) */
	wait_queue_head_t wait_head;
	unsigned int	num_obmen;
	wait_queue_t 	wait_entry;
	raw_spinlock_t	lock;
	raw_spinlock_t	lock_no_irq;
	kcondvar_t	cond_var;
} dev_rdma_sem_t;

typedef	unsigned int	half_addr_t;		/* single word (32 bits) */

typedef	struct rdma_addr_fields {
	half_addr_t	haddr;			/* [31:0] */
	half_addr_t	laddr;			/* [63:32] */
} rdma_addr_fields_t;

typedef	union rdma_addr_struct {		/* Structure of word */
	rdma_addr_fields_t	fields;		/* as fields */
	u32		addr;			/* as entier register */
} rdma_addr_struct_t;



typedef struct spin_snd_msg_rdma {
	raw_spinlock_t	lock;
} spin_snd_msg_rdma_p;


#define ALLIGN_RDMA     	256
#define IO_TIMEOUT		10000000 /* n000000: n sec i/o timeout */
#define REPEAT_TRWD_MAX		5
#define REPEAT_WAIT_RD_MAX	50
#define TIME_OUT_WAIT_RD	60 /* test rdma ok 	*/
#define TIME_OUT_WAIT_WR	40 /* test rdma ok	*/
#define TIME_OUT_WAIT_FS	100


#define	module_name_rdma 	"rdma"
#define board_name		"MCST,rdmaon"	/* should be same as FCODE.name */
#define board_name0		"MCST,rdmach0"	/* should be same as FCODE.name */
#define board_name1		"MCST,rdmach1"	/* should be same as FCODE.name */

#define DEV_DEVN(d)		(getminor(d))		/* dev_t -> minor (dev_num) */
#define DEV_inst(m)		(m >> 7)		/* minor -> instance 3 */
#define DEV_chan(m)		(m & 0x7f)		/* minor -> channel 0x7 */
#define DEV_MINOR(i, c)		((i << 7) | (c))	/* instance + channel -> minor 3 */
#define DEV_INST(d)		DEV_inst(DEV_DEVN(d))	/* dev_t -> instance */
#define DEV_CHAN(d)		DEV_chan(DEV_DEVN(d)) 	/* dev_t -> channel */

#define RDMA_CHANNEL_MASK	0xf
#define RDMA_CHANNEL_SHIFT	0
#define RDMA_CHANNEL0		0x0
#define RDMA_CHANNEL1		0x1
#define RDMA_GET_CHANNEL(addr)		((addr & RDMA_CHANNEL_MASK) >> RDMA_CHANNEL_SHIFT)
#define RDMA_SET_CHANNEL(addr, channel)	(((channel << RDMA_CHANNEL_SHIFT) & RDMA_CHANNEL_MASK) | (addr & ~RDMA_CHANNEL_MASK))

#define RDMA_NODE_MASK		0xf0
#define RDMA_NODE_SHIFT		4
#define RDMA_NODE0		0x00
#define RDMA_NODE1		0x10
#define RDMA_NODE2		0x20
#define RDMA_NODE3		0x30
#define RDMA_GET_NODE(addr)		((addr & RDMA_NODE_MASK) >> RDMA_NODE_SHIFT)
#define RDMA_SET_NODE(addr, node)	(((node << RDMA_NODE_SHIFT) & RDMA_NODE_MASK) | (addr & ~RDMA_NODE_MASK))


#define IRQ_CH1 		0x00000035
#define IRQ_CH2 		0x00000035

#ifdef RDMA_MUTEX_MSG
#define mutex_enter_dbg(a) \
	dbg_mutex("rdma: mutex_enter: %p %d\n", a, __LINE__); \
	mutex_enter(a);
#define mutex_exit_dbg(a) \
	dbg_mutex("rdma: mutex_exit : %p %d\n", a, __LINE__); \
	mutex_exit(a);
#else
#define mutex_enter_dbg(a) \
	dbg_mutex("rdma: mutex_enter: %p %d\n", a, __LINE__); \
	spin_lock(a);
#define mutex_exit_dbg(a) \
	dbg_mutex("rdma: mutex_exit : %p %d\n", a, __LINE__); \
	spin_unlock(a);
#endif

extern unsigned int	SHIFT_VID;		/* RDMA VID 			*/
extern unsigned int	SHIFT_IOL_CSR;
extern unsigned int	SHIFT_IO_CSR;
extern unsigned int	SHIFT_CH0_IDT;		/* RDMA ID/Type E90/E3M1	*/
extern unsigned int	SHIFT_CH1_IDT;		/* RDMA ID/Type E90/E3M1	*/
extern unsigned int	SHIFT_CH_IDT;		/* RDMA ID/Type E3S/E90S	*/
extern unsigned int	SHIFT_CS;		/* RDMA Control/Status 000028a0	*/
extern unsigned int	SHIFT_DD_ID;		/* Data Destination ID 		*/
extern unsigned int	SHIFT_DMD_ID;		/* Data Message Destination ID 	*/
extern unsigned int	SHIFT_N_IDT;		/* Neighbour ID/Type 		*/
extern unsigned int	SHIFT_ES;		/* Event Status 		*/
extern unsigned int	SHIFT_IRQ_MC;		/* Interrupt Mask Control 	*/
extern unsigned int	SHIFT_DMA_TCS;		/* DMA Tx Control/Status 	*/
extern unsigned int	SHIFT_DMA_TSA;		/* DMA Tx Start Address 	*/
extern unsigned int	SHIFT_DMA_HTSA;		/* DMA Tx Start Address 	*/
extern unsigned int	SHIFT_DMA_TBC;		/* DMA Tx Byte Counter 		*/
extern unsigned int	SHIFT_DMA_RCS;		/* DMA Rx Control/Status 	*/
extern unsigned int	SHIFT_DMA_RSA;		/* DMA Rx Start Address 	*/
extern unsigned int	SHIFT_DMA_HRSA;		/* DMA Rx Start Address 	*/
extern unsigned int	SHIFT_DMA_RBC;		/* DMA Rx Byte Counter 		*/
extern unsigned int	SHIFT_MSG_CS;		/* Messages Control/Status 	*/
extern unsigned int	SHIFT_TDMSG;		/* Tx Data_Messages Buffer 	*/
extern unsigned int	SHIFT_RDMSG;		/* Rx Data_Messages Buffer 	*/
extern unsigned int	SHIFT_CAM;		/* CAM - channel alive management */

/*---------- Reg's for E90S ---------- */
#ifdef CONFIG_E90S

#define	IOL_CSR			0x900
#define	IO_VID			0x2000
#define	IO_CSR			0x2004
#define	RDMA_VID		0x3080
#define	RDMA_CH_IDT		0x3084
#define	RDMA_CS			0x3088
#define	RDMA_DD_ID		0x3000
#define	RDMA_DMD_ID		0x3004
#define	RDMA_N_IDT		0x3008
#define RDMA_ES			0x300c		/* Event Status 		*/
#define RDMA_IRQ_MC		0x3010		/* Interrupt Mask Control 	*/
#define RDMA_DMA_TCS		0x3014		/* DMA Tx Control/Status 	*/
#define RDMA_DMA_TSA		0x3018		/* DMA Tx Start Address 	*/
#define RDMA_DMA_TBC		0x301c		/* DMA Tx Byte Counter 		*/
#define RDMA_DMA_RCS		0x3020		/* DMA Rx Control/Status 	*/
#define RDMA_DMA_RSA		0x3024		/* DMA Rx Start Address 	*/
#define RDMA_DMA_RBC		0x3028		/* DMA Rx Byte Counter 		*/
#define RDMA_MSG_CS		0x302c		/* Messages Control/Status 	*/
#define RDMA_TDMSG		0x3030		/* Tx Data_Messages Buffer 	*/
#define RDMA_RDMSG		0x3034		/* Rx Data_Messages Buffer 	*/
#define RDMA_CAM		0x3038		/* CAM - channel alive management */
#define RDMA_DMA_HTSA		0x3058		/* DMA Tx Start Address 	*/
#define RDMA_DMA_HRSA		0x3064		/* DMA Tx Start Address 	*/

#endif /* E90S */

/*---------- Reg's for E3S & E3M ---------- */
#ifdef CONFIG_E2K
/* E3S */
#define	IOL_CSR			0x900
#define	IO_VID			0x700
#define	IO_CSR			0x704
#define	RDMA_VID		0x880
#define	RDMA_CH_IDT		0x884
#define	RDMA_CS			0x888
#define	RDMA_DD_ID		0x800
#define	RDMA_DMD_ID		0x804
#define	RDMA_N_IDT		0x808
#define RDMA_ES			0x80c		/* Event Status 		*/
#define RDMA_IRQ_MC		0x810		/* Interrupt Mask Control 	*/
#define RDMA_DMA_TCS		0x814		/* DMA Tx Control/Status 	*/
#define RDMA_DMA_TSA		0x818		/* DMA Tx Start Address 	*/
#define RDMA_DMA_TBC		0x81c		/* DMA Tx Byte Counter 		*/
#define RDMA_DMA_RCS		0x820		/* DMA Rx Control/Status 	*/
#define RDMA_DMA_RSA		0x824		/* DMA Rx Start Address 	*/
#define RDMA_DMA_RBC		0x828		/* DMA Rx Byte Counter 		*/
#define RDMA_MSG_CS		0x82c		/* Messages Control/Status 	*/
#define RDMA_TDMSG		0x830		/* Tx Data_Messages Buffer 	*/
#define RDMA_RDMSG		0x834		/* Rx Data_Messages Buffer 	*/
#define RDMA_CAM		0x838		/* CAM - channel alive management */
#define RDMA_DMA_HTSA		0x858		/* DMA Tx Start Address 	*/
#define RDMA_DMA_HRSA		0x864		/* DMA Tx Start Address 	*/

/* E3M */
#define E3M_RDMA_VID		0x00		/* RDMA VID 			*/
#define E3M_RDMA_CH0_IDT  	0x04		/* RDMA ID/Type 		*/
#define E3M_RDMA_CS      	0x08		/* RDMA Control/Status 000028a0	*/
#define E3M_RDMA_CH1_IDT	0x0c		/* RDMA ID/Type 		*/
#define E3M_RDMA_DD_ID		0x100		/* Data Destination ID 		*/
#define E3M_RDMA_DMD_ID		0x104		/* Data Message Destination ID 	*/
#define E3M_RDMA_N_IDT		0x108		/* Neighbour ID/Type 		*/
#define E3M_RDMA_ES		0x10c		/* Event Status 		*/
#define E3M_RDMA_IRQ_MC  	0x110		/* Interrupt Mask Control 	*/
#define E3M_RDMA_DMA_TCS	0x114		/* DMA Tx Control/Status 	*/
#define E3M_RDMA_DMA_TSA	0x118		/* DMA Tx Start Address 	*/
#define E3M_RDMA_DMA_TBC	0x11c		/* DMA Tx Byte Counter 		*/
#define E3M_RDMA_DMA_RCS	0x120		/* DMA Rx Control/Status 	*/
#define E3M_RDMA_DMA_RSA	0x124		/* DMA Rx Start Address 	*/
#define E3M_RDMA_DMA_RBC	0x128		/* DMA Rx Byte Counter 		*/
#define E3M_RDMA_MSG_CS		0x12c		/* Messages Control/Status 	*/
#define E3M_RDMA_TDMSG		0x130		/* Tx Data_Messages Buffer 	*/
#define E3M_RDMA_RDMSG		0x134		/* Rx Data_Messages Buffer 	*/
#define E3M_RDMA_CAM		0x138		/* CAM - channel alive management */
#define E3M_SHIFT_REG		0x100

#endif /*  E3S & E3M*/

/*---------- Reg's for E90 ---------- */
#ifdef CONFIG_E90

#define RDMA_VID		0x00		/* RDMA VID 			*/
#define RDMA_CH0_IDT 	  	0x04		/* RDMA ID/Type 		*/
#define RDMA_CS       	 	0x08		/* RDMA Control/Status 000028a0	*/
#define RDMA_CH1_IDT		0x0c		/* RDMA ID/Type 		*/
#define RDMA_DD_ID		0x00		/* Data Destination ID 		*/
#define RDMA_DMD_ID		0x04		/* Data Message Destination ID 	*/
#define RDMA_N_IDT		0x08		/* Neighbour ID/Type 		*/
#define RDMA_ES			0x0c		/* Event Status 		*/
#define RDMA_IRQ_MC   	 	0x10		/* Interrupt Mask Control 	*/
#define RDMA_DMA_TCS		0x14		/* DMA Tx Control/Status 	*/
#define RDMA_DMA_TSA		0x18		/* DMA Tx Start Address 	*/
#define RDMA_DMA_TBC		0x1c		/* DMA Tx Byte Counter 		*/
#define RDMA_DMA_RCS		0x20		/* DMA Rx Control/Status 	*/
#define RDMA_DMA_RSA		0x24		/* DMA Rx Start Address 	*/
#define RDMA_DMA_RBC		0x28		/* DMA Rx Byte Counter 		*/
#define RDMA_MSG_CS		0x2c		/* Messages Control/Status 	*/
#define RDMA_TDMSG		0x30		/* Tx Data_Messages Buffer 	*/
#define RDMA_RDMSG		0x34		/* Rx Data_Messages Buffer 	*/

#endif /* CONFIG_E90 */

/* VID_ID */
#define VID_ID    	0x0000ffff  /* VID:15-0: Vendor ID RO */

/* IDT */
#define IDT_RN		0xff000000  /* IDT:31-24: Revision Number RO */
#define IDT_DT    	0x00ff0000  /* IDT:23-16: Device Type: 0 - Endpoint, 1 - Switch. RO */
#define IDT_ID    	0x0000ffff  /* IDT:15-0: Identification Number W/R */
#define IDT_ID_w(r,n)	(r & 0xffff0000 | n)

/* CS */
#define CS_SIE       	0x80000000  /* CS:31: Slave Interface Error R/WC */
#define CS_C0_MOW    	0x40000000  /* CS:30: Channel 0: Master Outstanding Write R/O */
#define CS_C0_MOR    	0x20000000  /* CS:29: Channel 0: Master Outstanding Read R/O */
#define CS_C1_MOW	0x10000000  /* CS:28: Channel 1: Master Outstanding Write R/O */
#define CS_C1_MOR    	0x08000000  /* CS:27: Channel 1: Master Outstanding Read R/O */
#define CS_BUS	     	0x00020000  /* CS:17: BUS Mode R/W */
#define CS_BM        	0x00010000  /* CS:16: Bypass Mode 1 - Bypass, 0 - DMA. RO */
#define CS_C0ILN     	0x0000e000  /* CS:15-13: Channel 0 Interrupt Line Number R/W */
#define CS_C1ILN     	0x00001c00  /* CS:12-10: Channel 1 Interrupt Line Number R/W */
#define CS_PTOCL     	0x000003fe  /* CS:9-1: Packet Time Out Counter Load R/W */
#define CS_BME       	0x00000001  /* CS:0: Bypass Mode Enable R/W */

/* Channel's registers lvds */
/* Register Data Destination ID */
#define DD_ID         	0x0000ffff	/* DD_ID:15-0: Data Destination ID Number R/W*/
#define DD_ID_w(r,n) 	(r & 0xffff0000 | n)

/* Register Data Message Destination ID */
#define DMD_ID        	0x0000ffff	/* DMD_ID:15-0: Data_Message Destination ID Number R/W*/
#define DMD_ID_w(r,n) 	(r & 0xffff0000 | n)

/* Neighbour ID/Type */
#define N_IDT_N_RN     	0xff000000	/* N_IDT:31-24: Neighbour Revision Number RO       */
#define N_IDT_N_DT     	0x00ff0000	/* N_IDT:23-16: Neighbour Device Type RO           */
#define N_IDT_N_ID     	0x000000ff	/* N_IDT:15- 0: Neighbour Identification Number RO */
#define N_IDT_def      	0x0000ff00	/* N_IDT:15- 0: Neighbour Identification Number RO */

#define MASK_INTR_NET	0x03fc000f
#define MASK_SET_NET	0x07fc000f 
#define TR_ATL          0xc0000005
/* Register Received Data_Message Buffer RDMSG */
#define RDMSG          	0xffffffff	/* RDMSG:31-0: Received Data_Messages RO */

/* Register Transmit Data_Message Buffer TDMSG */
#define TDMSG          	0xffffffff	/* TDMSG:31-0: Transmit Data_Messages W/R */

/* Format Headers Packet */
#define HP_Type     	0x00000000000000ff	/* Headers Packet:7-0: Type Packet*/
#define HP_PNum         0x000000000000ff00	/* Headers Packet:15-8: Number Packet*/
#define HP_D_ID         0x00000000ffff0000	/* Headers Packet:31-16: Destination ID*/
#define HP_S_ID         0x0000ffff00000000	/* Headers Packet:47-32: Sender ID*/
#define HP_CRC          0xffff000000000000	/* Headers Packet:63-48: Header CRC*/
#define MSG_SIZE_NOCPY_WNET	0x0000ffff	/* Messages for user */
#define MSG_ALIGN_NOCPY_WNET	0x00ff0000	/* Messages for user */
#define SHIFT_ALIGN_WNET	16
#define MSG_TTL_IP	0x81000000
#define SHIFT_TTL	8
#define MASK_TTL	0x00000f00
#define SHIFT_IP	0
#define MASK_IP		0x000000ff
#define SHIFT_NODE	12
#define MASK_NODE	0x000ff000

#define	TRY_FROM_TCP	1
#define	TRY_SND_TRWD	2
#define	TRY_SND_READY	3

#define MSG_NEED_BYPASS	0xfffcffff
#define WASTE_PACKET	0xfbadbadf
#define WASTE_PACKET_	0xfbadbade
#define	NBLOCKS	1000

#define RDMA_LOG_TX_BUFFERS 6	///muw!!!
#define RDMA_LOG_RX_BUFFERS 2

#define TX_RING_SIZE			(1 << (RDMA_LOG_TX_BUFFERS))
#define TX_RING_MOD_MASK		(TX_RING_SIZE - 1)
#define TX_NEXT(__x)			(((__x)+1) & TX_RING_MOD_MASK)
#define NOT_ME(__fb, __fe, __avail)	(__fb == __fe)?\

#define PTX_BUFFS_AVAIL ((ptx->fb==ptx->fe)?\
			 ((ptx->btx_ring[ptx->fb].for_snd_trwd>1)?0:TX_RING_SIZE):\
			 (((ptx->fb<ptx->fe)?(TX_RING_SIZE-ptx->fe+ptx->fb):\
				(ptx->fb-ptx->fe))))

#define PRINT_BUFS(inst) \
if(DBG_PRINT_BUFS) \
{\
			int fb = ptx->fb;\
			int fe = ptx->fe;\
			struct rdma_tx_desc	*pbtxl;\
	printk("%u %02u %02u %02u %02u  %08u %08u ",\
		inst, ptx->fb, ptx->fe, ptx->frx, ptx->avail, ptx->rx, ptx->tx);\
		while (fb != fe) {\
\
			pbtxl = &ptx->btx_ring[fb];\
			switch (pbtxl->for_rec_trwd) {\
			case 1:\
				printk("1");\
				break;\
			case 0:\
				printk("0");\
				break;\
			default:\
				printk("d");\
			}\
			fb = TX_NEXT(fb);\
		}\
		printk("\n");\
}

#define PRINT_BUFS_(inst) \
{\
			int fb;\
			int fe;\
			struct rdma_tx_desc	*pbtxl;\
	struct rdma_tx_block	*ptxl;\
	ptxl = &net_sn0.tx_block[inst];\
			fb = ptxl->fb;\
			fe = ptxl->fe;\
	printk("%u %02u %02u %02u %02u  %08u %08u ",\
		inst, ptxl->fb, ptxl->fe, ptxl->frx, ptxl->avail, ptxl->rx, ptxl->tx);\
		if (fb == fe)\
			fb = TX_NEXT(fb);\
		while (fb != fe) {\
\
			pbtxl = &ptxl->btx_ring[fb];\
			switch (pbtxl->for_rec_trwd) {\
			case 1:\
				printk("1");\
				break;\
			case 0:\
				printk("0");\
				break;\
			default:\
				printk("d");\
			}\
			fb = TX_NEXT(fb);\
		}\
		printk("\n");\
}

#define RX_RING_SIZE		(1 << (RDMA_LOG_RX_BUFFERS))
#define RX_RING_MOD_MASK	(RX_RING_SIZE - 1)
#define RX_NEXT(__x)		(((__x)+1) & RX_RING_MOD_MASK)
#define RDMA_BUF_SIZE		SIZE_BUF_NET
#define RDMA_BUF_SIZE_ALIGN32	SIZE_BUF_NET

#define RX_BUFF_SIZE           	RDMA_BUF_SIZE_ALIGN32
#define TX_BUFF_SIZE           	RDMA_BUF_SIZE

#define RX_BUFF_SIZE_ALIGN32	RDMA_BUF_SIZE_ALIGN32
#define TX_BUFF_SIZE_ALIGN32	RDMA_BUF_SIZE_ALIGN32

#define RDMA_NET_DSF_MAX	20
#define rdma_gp0		0
#define rdma_gp1		1

#define REC_READY		11
#define REC_TRWD		12
#define SND_TRWD		13
#define T_DMA			14
#define R_DMA			15
#define SND_READY		16
#define MSG_WASTE		0xababcdcd

struct rdma_rx_desc {
	u32	num_obmen;
#ifdef CONFIG_E90
	u32	phaddr;
#else
	u64	phaddr;
#endif
	u8	*vaddr;
	struct sk_buff	*addr;
	u32	busy;
	u32	worked;
	u32	rest_rbc;
};

struct rdma_tx_desc {
#ifdef CONFIG_E90
	u32	phaddr;
#else
	u64	phaddr;
#endif
	u8	*vaddr;
	struct sk_buff	*addr;
#ifdef BOTTOM_HALF_RX_REFILL_SKB
	u8 	skb_in_steck_for_free;
#endif
	u32 	count_dsf;
	u32 	busy;
	u32 	worked;
	u32 	length;
	u32 	len;
	u32 	for_rec_trwd;
	u32 	for_snd_trwd;
	unsigned long	trans_start;
};

struct rdma_rx_block {
	u32	running;
	u32	avail;
	u32	fb;	/* first busy	*/
	u32	fe;	/* first empty	*/
	struct rdma_rx_desc brx_ring[RX_RING_SIZE+1] __attribute__((aligned(8)));
};

struct rdma_tx_block {
	raw_spinlock_t	lock;
	struct stat_rdma	*pst;
	u32	inst;
	u32	stat;
	u32	state_rx;
	u32	state_tx;
	unsigned long stat_tx_jiffies;
	u32	gp;
	u32	running;
	u32	avail;
	u32	fb;	/* first busy	*/
	u32	fe;	/* first empty	*/
	u32 	frx;
	u32 	rec_trwd_tx;
	u32 	rec_trwd_bc;
	u32 	rec_trwd_tr;
	u32 	last_snd_ready;
	u32 	rx;
	u32 	tx;
#ifdef CHECK_MEMORY_E90S
	u32	end_buf_csum;
	u32	bad_end_buf_csum;
#endif
	u32 	dsf;
	u32 	rec_trwd;
	u32 	rec_ready;
	u32 	snd_ready;
	u32 	snd_trwd;
	u32 	work_next_rdma;
	u32 	work_broadcast_rdma;
	u32 	work_transit_rdma;
	u32	temp_obmen;
#ifdef BOTTOM_HALF_RX_REFILL_SKB
	u32 	alloc_buf_skb;
#endif
	u32 	alloc_buf_rdma;
	struct rdma_tx_desc btx_ring[TX_RING_SIZE+1] __attribute__((aligned(8)));
};

struct rdma_private {
	raw_spinlock_t	lock;
	u32			inst;
	void __iomem 		*regbase;
	u32			size;
	struct net_device	*dev;
	struct rdma_private	*next_module;
#ifdef CONFIG_E90
//	struct sbus_dev 	*sdev;
#else
	int			node;
	struct pci_dev 		*pdev;
#endif
	struct rdma_tx_block	rt_block;
	struct rdma_tx_block	tx_block;
	struct net_device_stats net_stats;
	struct stat_rdma	stat_rdma;
	u32			irmsg;
	u32			iamsg;
	u32			reset;
	u32			snd_ir_msg;
	u32			opened;
#ifdef CONFIG_E90 /* E90 */
	u32			phaddr_r;
#else
	u64			phaddr_r; 
#endif
#ifdef BOTTOM_HALF_RX_THREAD_RDMA
	raw_spinlock_t		thread_lock;
	struct task_struct      *rdma_rx_tsk;
	u32 			start_thread;
#endif
	u8			timeout;
};

#define WHO_CHANN(chann)\
	chann==TCP_TX?"TCP_TX":(chann==TRANS_RX?"TRANS_RX":(chann==CAST_RX?"CAST_RX":"NICH"))
#define TX_BUFFS_AVAIL ((lp->tx_old<=lp->tx_new)?\
			lp->tx_old+TX_RING_MOD_MASK-lp->tx_new:\
			lp->tx_old - lp->tx_new-1)

#define MAX_CHANNEL	8 /* 8 eai => MAX_CHANNEL in*/

struct rdma_state {
//	struct pci_dev *dev_rdma;	
	unsigned int	major;
	kmutex_t	mu;
	unsigned long 	mmio_base;		/* phys address 	*/
	uint8_t*	mmio_vbase;		/* virtual address 	*/
	unsigned int	mmio_len;
	unsigned int	inited;
	int		size_rdma_state;
};

typedef struct rw_state rw_state_t;
typedef rw_state_t * rw_state_p;

#define MAX_max(a, b) 	 (a)>(b)?(a):(b)
#define MIN_min(a, b) 	 (a)>(b)?(b):(a)


struct	who_msg {
	int	chann;
	int	msg;
};

typedef struct	rdma_who {
	struct	who_msg who_rec_ready[MAX_RDMA_NET_DEV]; 
	struct	who_msg who_snd_ready[MAX_RDMA_NET_DEV]; 
} rdma_who_t;

/*
extern caddr_t e0rega;
extern caddr_t e1rega;
extern caddr_t e2rega;

extern unsigned char *e0rega;
extern unsigned char *e1rega;
extern unsigned char *e2rega;
extern unsigned char *e3rega;

extern unsigned long e0rega;
extern unsigned long e1rega;
extern unsigned long e2rega;
extern unsigned long e3rega;
*/

extern	u32			rdma_set_print_packets;
extern	int			va_to_fa_ld_lock(unsigned int va);
extern	struct net_device	*netdev_addr[MAX_RDMA_NET_DEV];
extern	spinlock_t 		rdma_printk_lock;
extern	unsigned long		count_read_sm_max;
extern	void			prn_reg_rdma(void __iomem *reg_base);
extern	void 			WRR(void __iomem *reg_base, unsigned int reg_offset, unsigned int reg_value, dev_rdma_sem_t *dev_sem);
extern	unsigned int 		RDR(void __iomem *reg_base, unsigned int reg_offset, dev_rdma_sem_t *dev_sem);
extern	unsigned int 		allign_dma(unsigned int n);
extern	int 			send_msg(struct rdma_private *rp, unsigned int msg, unsigned int instance, unsigned int cmd);
#ifdef CONFIG_E90
//extern	void			rdma_intr(int irq, void *arg, struct pt_regs *regs);
//extern	irqreturn_t		rdma_intr(int irq, void *arg, struct pt_regs *regs);
extern irqreturn_t rdma_intr(int irq, void *dev_instance);
#else
extern	void 			rdma_interrupt(struct pt_regs *regs);
#endif
extern	void			fix_event(unsigned int channel, unsigned int event, unsigned int val1, unsigned int val2);
extern	int			lvnet_tx(struct sk_buff *skb, struct net_device *dev);
extern	int			get_stat_rdma(void);
extern	int			try_send_ready(struct rdma_private *rp);
extern	int			try_send_trwd(struct rdma_private *rp);
extern	void 			reset_ptx(struct rdma_tx_block *ptx);
extern	int 			init_ptx(struct rdma_tx_block *ptx, struct rdma_private *rp);
extern	rdma_who_t 		who;
extern	int 			state_rx[MAX_RDMA_NET_DEV];
extern	int 			state_tx[MAX_RDMA_NET_DEV];
extern	void 			prn_puls( struct rdma_private *rp );
extern	unsigned long 		wake_jiffies;
extern	unsigned long 		stop_jiffies;
extern	void 			reset_ptx_tx(struct rdma_tx_block *ptx);
extern	struct	rdma_event 	rdma_event;
extern	int 			rdma_error;
extern	int 			get_pc_call(void);
extern	struct 	mfgid 		mfgid;
extern	inline int 		PTX_BUFFS_AVAIL_(int inst);
extern	u32			who_is_locked_spin_rdma;
extern	u32			who_locked_free_skb;
extern	u32			who_locked_tx;
extern	void			try_work(struct rdma_private *rp);
extern	int			get_event_rdma(void);
extern	hrtime_t 		rdma_gethrtime(void);


#define REC_MSG_SIZE 32
#define REC_MSG_MASK REC_MSG_SIZE - 1
#define NEXT_REC_MSG(fe_rec_msg) (fe_rec_msg + 1) & (REC_MSG_MASK)
#define PRN_REC_MSG(inst)\
{\
	int i;\
	printk("inst: %d fe_rec_msg: %d\n", inst, fe_rec_msg[inst]);\
	for (i=0;i<REC_MSG_SIZE;i++)\
		printk("0x%08x %d\n", rec_msg[inst][i], i);\
}

extern	u32 			rec_msg[MAX_RDMA_NET_DEV][REC_MSG_SIZE]; 
extern	u32 			fe_rec_msg[MAX_RDMA_NET_DEV];		
extern	void 			proc_rdma_event_init(void);
extern	void			proc_rdma_event_close(void);	
extern	void			(*rdma_interrupt_p)(struct pt_regs *regs);
extern	void			rdma_interrupt(struct pt_regs *regs);
extern	unsigned int		clear_es(struct rdma_private *rp, int reset);


///!!!extern	spinlock_t	mu_fix_event;

extern	int			rdc_byte[MAX_RDMA_NET_DEV];
extern	int			rdma_cards;
extern	int 			stop_rdma[MAX_RDMA_NET_DEV];
extern	int			print_header;
extern	spin_snd_msg_rdma_p	spin_snd_msg_rdma[MAX_RDMA_NET_DEV]; 
extern	void __iomem 		*e_rega[MAX_RDMA_NET_DEV];  /* e1rega, e2rega, e3rega; */
extern	void			*lvnet_dev[];
extern	void			lvnet_rx(struct net_device *dev, int ret, unsigned char *buf);
#if defined(E90S) || defined(E90)
extern	int			net_device_present;
#endif
extern	int 			rdma_event_init;
extern	int 			init_lvnet(struct net_device *dev);
extern struct			net_device lvnet_devs;
extern struct rdma_private	*root_rdma_dev;


#ifdef	__cplusplus
}
#endif

#endif /* __LINUX_RDMA1_REG_H__ */
