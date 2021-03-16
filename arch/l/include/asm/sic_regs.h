
#ifndef	_L_SIC_REGS_H_
#define	_L_SIC_REGS_H_

#ifdef __KERNEL__

#include <linux/topology.h>

#include <asm/types.h>
#include <asm/sic_regs.h>

#undef  DEBUG_ERALY_NBSR_MODE
#undef  DebugENBSR
#define	DEBUG_ERALY_NBSR_MODE	0	/* early NBSR access */
#ifndef	CONFIG_BOOT_E2K
#define	DebugENBSR(fmt, args...)		\
		({ if (DEBUG_ERALY_NBSR_MODE)	\
			printk(fmt, ##args); })
#else	/* CONFIG_BOOT_E2K */
#define	DebugENBSR(fmt, args...)		\
		({ if (DEBUG_ERALY_NBSR_MODE)	\
			rom_printk(fmt, ##args); })
#endif	/* ! CONFIG_BOOT_E2K */

#undef	DEBUG_NBSR_MODE
#undef	DebugNBSR
#define	DEBUG_NBSR_MODE		0	/* NBSR access */
#define	DebugNBSR(fmt, args...)			\
		({ if (DEBUG_NBSR_MODE)		\
			printk(fmt, ##args); })

#ifndef __ASSEMBLY__

static inline unsigned int
early_sic_read_node_nbsr_reg(int node_id, int reg_offset)
{
	unsigned char *node_nbsr;
	unsigned char *addr;
	unsigned int reg_value;

	node_nbsr = THE_NODE_NBSR_PHYS_BASE(node_id);
	addr = node_nbsr + reg_offset;
	reg_value = nbsr_early_read(addr);
	DebugENBSR("early_sic_read_node_nbsr_reg() node %d reg 0x%x read 0x%x "
		"from 0x%px\n",
		node_id, reg_offset, reg_value, addr);
	return reg_value;
}

static inline void
early_sic_write_node_nbsr_reg(int node_id, int reg_offset, unsigned int reg_val)
{
	unsigned char *node_nbsr;
	unsigned char *addr;

	node_nbsr = THE_NODE_NBSR_PHYS_BASE(node_id);
	DebugENBSR("early_sic_write_node_nbsr_reg() node NBSR is %px\n",
		node_nbsr);
	addr = node_nbsr + reg_offset;
	nbsr_early_write(reg_val, addr);
	DebugENBSR("early_sic_write_node_nbsr_reg() node %d reg 0x%x write "
		"0x%x to 0x%px\n",
		node_id, reg_offset, reg_val, addr);
}

static inline unsigned int
early_sic_read_node_iolink_nbsr_reg(int node_id, int io_link, int reg_offset)
{
	unsigned int reg_value;

#ifndef	CONFIG_BOOT_E2K
	if (io_link < 0 || io_link >= MACH_NODE_NUMIOLINKS) {
		printk(KERN_ERR "sic_read_node_iolink_nbsr_reg() bad IO link "
			"# %d (< 0 or >= max %d)\n",
			io_link, MACH_NODE_NUMIOLINKS);
		return (unsigned int)-1;
	}
#endif	/* ! CONFIG_BOOT_E2K */
	reg_value = early_sic_read_node_nbsr_reg(node_id,
			SIC_io_reg_offset(io_link, reg_offset));
	return reg_value;
}

static inline void
early_sic_write_node_iolink_nbsr_reg(int node_id, int io_link, int reg_offset,
					unsigned int reg_value)
{
#ifndef	CONFIG_BOOT_E2K
	if (io_link < 0 || io_link >= MACH_NODE_NUMIOLINKS) {
		printk(KERN_ERR "early_sic_write_node_iolink_nbsr_reg() bad "
			"IO link # %d (< 0 or >= max %d)\n",
			io_link, MACH_NODE_NUMIOLINKS);
		return;
	}
#endif	/* ! CONFIG_BOOT_E2K */
	early_sic_write_node_nbsr_reg(node_id,
			SIC_io_reg_offset(io_link, reg_offset), reg_value);
}

static inline unsigned int
sic_read_node_nbsr_reg(int node_id, int reg_offset)
{
	unsigned char *node_nbsr;
	unsigned int reg_value;

	node_nbsr = sic_get_node_nbsr_base(node_id);
	if (node_nbsr == NULL) {
		panic("sic_read_node_nbsr_reg() node #%d has not mapping "
			"to SIC(NBSR) registers\n", node_id);
	}
	reg_value = nbsr_read(&node_nbsr[reg_offset]);
	DebugNBSR("sic_read_node_nbsr_reg() node %d reg 0x%x read 0x%x "
		"from 0x%px\n",
		node_id, reg_offset, reg_value,
		&node_nbsr[reg_offset]);
	return reg_value;
}

static inline unsigned long
sic_readll_node_nbsr_reg(int node_id, int reg_offset)
{
	unsigned char *node_nbsr;
	unsigned long reg_value;

	node_nbsr = sic_get_node_nbsr_base(node_id);
	if (node_nbsr == NULL) {
		panic("sic_readll_node_nbsr_reg() node #%d has not mapping "
			"to SIC(NBSR) registers\n", node_id);
	}
	reg_value = nbsr_readll(&node_nbsr[reg_offset]);
	DebugNBSR("sic_readll_node_nbsr_reg() node %d reg 0x%x read 0x%lx "
		"from 0x%px\n",
		node_id, reg_offset, reg_value,
		&node_nbsr[reg_offset]);
	return reg_value;
}

static inline u16
sic_readw_node_nbsr_reg(int node_id, int reg_offset)
{
	unsigned char *node_nbsr;
	u16 reg_value;

	node_nbsr = sic_get_node_nbsr_base(node_id);
	if (node_nbsr == NULL) {
		panic("sic_readw_node_nbsr_reg() node #%d has not mapping "
			"to SIC(NBSR) registers\n", node_id);
	}
	reg_value = nbsr_readw(&node_nbsr[reg_offset]);
	DebugNBSR("sic_readw_node_nbsr_reg() node %d reg 0x%x read 0x%x "
		"from 0x%px\n",
		node_id, reg_offset, reg_value,
		&node_nbsr[reg_offset]);
	return reg_value;
}

static inline unsigned int
sic_read_node_iolink_nbsr_reg(int node_id, int io_link, int reg_offset)
{
	unsigned int reg_value;

	if (!HAS_MACHINE_L_SIC) {
		printk(KERN_ERR "sic_read_node_iolink_nbsr_reg() machine has "
			"not SIC\n");
		return (unsigned int)-1;
	}
	if (io_link < 0 || io_link >= MACH_NODE_NUMIOLINKS) {
		printk(KERN_ERR "sic_read_node_iolink_nbsr_reg() bad IO link "
			"# %d (< 0 or >= max %d)\n",
			io_link, MACH_NODE_NUMIOLINKS);
		return (unsigned int)-1;
	}
	reg_value = sic_read_node_nbsr_reg(node_id,
			SIC_io_reg_offset(io_link, reg_offset));
	return reg_value;
}

static inline unsigned long
sic_readll_node_iolink_nbsr_reg(int node_id, int io_link, int reg_offset)
{
	unsigned long reg_value;

	if (!HAS_MACHINE_L_SIC) {
		printk(KERN_ERR "sic_readll_node_iolink_nbsr_reg() machine has "
			"not SIC\n");
		return (unsigned int)-1;
	}
	if (io_link < 0 || io_link >= MACH_NODE_NUMIOLINKS) {
		printk(KERN_ERR "sic_readll_node_iolink_nbsr_reg() bad IO link "
			"# %d (< 0 or >= max %d)\n",
			io_link, MACH_NODE_NUMIOLINKS);
		return (unsigned int)-1;
	}
	reg_value = sic_readll_node_nbsr_reg(node_id,
			SIC_io_reg_offset(io_link, reg_offset));
	return reg_value;
}

static inline void
sic_write_node_nbsr_reg(int node_id, int reg_offset, unsigned int reg_value)
{
	unsigned char *node_nbsr;

	node_nbsr = sic_get_node_nbsr_base(node_id);
	if (node_nbsr == NULL) {
		panic("sic_write_node_nbsr_reg() node #%d has not mapping "
			"to SIC(NBSR) registers\n", node_id);
	}
	nbsr_write(reg_value, &node_nbsr[reg_offset]);
	DebugNBSR("sic_write_node_nbsr_reg() node %d reg 0x%x writenn 0x%x to "
		"0x%px\n",
		node_id, reg_offset, reg_value, &node_nbsr[reg_offset]);
}

static inline void sic_write_node_nbsr_reg_relaxed(int node_id, int reg_offset,
		unsigned int reg_value)
{
	unsigned char *node_nbsr;

	node_nbsr = sic_get_node_nbsr_base(node_id);
	if (node_nbsr == NULL) {
		panic("sic_write_node_nbsr_reg() node #%d has not mapping "
			"to SIC(NBSR) registers\n", node_id);
	}
	nbsr_write_relaxed(reg_value, &node_nbsr[reg_offset]);
	DebugNBSR("sic_write_node_nbsr_reg() node %d reg 0x%x writenn 0x%x to "
		"0x%px\n",
		node_id, reg_offset, reg_value, &node_nbsr[reg_offset]);
}

static inline void
sic_writell_node_nbsr_reg(int node_id, int reg_offset, unsigned long reg_value)
{
	unsigned char *node_nbsr;

	node_nbsr = sic_get_node_nbsr_base(node_id);
	if (node_nbsr == NULL) {
		panic("sic_writell_node_nbsr_reg() node #%d has not mapping "
			"to SIC(NBSR) registers\n", node_id);
	}
	nbsr_writell(reg_value, &node_nbsr[reg_offset]);
	DebugNBSR("sic_writell_node_nbsr_reg() node %d reg 0x%x written 0x%lx to "
		"0x%px\n",
		node_id, reg_offset, reg_value, &node_nbsr[reg_offset]);
}

static inline void
sic_writew_node_nbsr_reg(int node_id, int reg_offset, u16 reg_value)
{
	unsigned char *node_nbsr;

	node_nbsr = sic_get_node_nbsr_base(node_id);
	if (node_nbsr == NULL) {
		panic("sic_writew_node_nbsr_reg() node #%d has not mapping "
			"to SIC(NBSR) registers\n", node_id);
	}
	nbsr_writew(reg_value, &node_nbsr[reg_offset]);
	DebugNBSR("sic_writew_node_nbsr_reg() node %d reg 0x%x written 0x%x to "
		"0x%px\n",
		node_id, reg_offset, reg_value, &node_nbsr[reg_offset]);
}

static inline void
sic_write_node_iolink_nbsr_reg(int node_id, int io_link, int reg_offset,
				unsigned int reg_value)
{
	if (!HAS_MACHINE_L_SIC) {
		printk(KERN_ERR "sic_write_node_iolink_nbsr_reg() machine has "
			"not SIC\n");
		return;
	}
	if (io_link < 0 || io_link >= MACH_NODE_NUMIOLINKS) {
		printk(KERN_ERR "sic_write_node_iolink_nbsr_reg() bad IO link "
			"# %d (< 0 or >= max %d)\n",
			io_link, MACH_NODE_NUMIOLINKS);
		return;
	}
	sic_write_node_nbsr_reg(node_id,
			SIC_io_reg_offset(io_link, reg_offset), reg_value);
}

static inline void
sic_writell_node_iolink_nbsr_reg(int node_id, int io_link, int reg_offset,
				unsigned long reg_value)
{
	if (!HAS_MACHINE_L_SIC) {
		printk(KERN_ERR "sic_writell_node_iolink_nbsr_reg() machine has "
			"not SIC\n");
		return;
	}
	if (io_link < 0 || io_link >= MACH_NODE_NUMIOLINKS) {
		printk(KERN_ERR "sic_writell_node_iolink_nbsr_reg() bad IO link "
			"# %d (< 0 or >= max %d)\n",
			io_link, MACH_NODE_NUMIOLINKS);
		return;
	}
	sic_writell_node_nbsr_reg(node_id,
			SIC_io_reg_offset(io_link, reg_offset), reg_value);
}


static inline unsigned int
sic_read_nbsr_reg(int reg_offset)
{
	return sic_read_node_nbsr_reg(numa_node_id(), reg_offset);
}

static inline unsigned int
sic_read_iolink_nbsr_reg(int io_link, int reg_offset)
{
	return sic_read_node_iolink_nbsr_reg(numa_node_id(), io_link,
						reg_offset);
}

static inline void
sic_write_nbsr_reg(int reg_offset, unsigned int reg_value)
{
	sic_write_node_nbsr_reg(numa_node_id(), reg_offset, reg_value);
}

static inline void
sic_write_iolink_nbsr_reg(int io_link, int reg_offset, unsigned int reg_value)
{
	sic_write_node_iolink_nbsr_reg(numa_node_id(), io_link, reg_offset,
					reg_value);
}

#endif /* ! __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif  /* _L_SIC_REGS_H_ */
