#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/irq.h>

#include <linux/irq_work.h>
#include <linux/ftrace.h>

#include <asm/pil.h>
#include <asm/pcr.h>
#include <asm/nmi.h>
#include <asm/asi.h>
#include <asm/spitfire.h>


static u64 e90s_pcr_read(unsigned long reg_num)
{
	u64 val;
	rd_pcr(val);
	val &= ~(E90S_PCR_SC_MASK << E90S_PCR_SC_SHIFT);
	val |= reg_num << E90S_PCR_SC_SHIFT;
	return val;
}

static void e90s_pcr_write(unsigned long reg_num, u64 val)
{
	val &= ~(E90S_PCR_SC_MASK << E90S_PCR_SC_SHIFT);
	val |= reg_num << E90S_PCR_SC_SHIFT;
	wr_pcr(val);
}

static u64 e90s_pic_read(unsigned long reg_num)
{
	unsigned long pcr, old_pcr, pic;
	rd_pcr(old_pcr);
	pcr = old_pcr;
	pcr &= ~(E90S_PCR_USR | E90S_PCR_SYS | 
			(E90S_PCR_SC_MASK << E90S_PCR_SC_SHIFT))
			| E90S_PCR_ULRO | E90S_PCR_OVRO;

	wr_pcr(pcr | reg_num << E90S_PCR_SC_SHIFT);
	rd_pic(pic);
	wr_pcr(old_pcr);
	return pic;
}

static void e90s_pic_write(unsigned long reg_num, u64 val)
{
	unsigned long pcr, old_pcr;
	rd_pcr(old_pcr);
	pcr = old_pcr;
	pcr &= ~(E90S_PCR_USR | E90S_PCR_SYS | 
			(E90S_PCR_SC_MASK << E90S_PCR_SC_SHIFT))
			| E90S_PCR_ULRO | E90S_PCR_OVRO;

	wr_pcr(pcr | reg_num << E90S_PCR_SC_SHIFT);
	wr_pic(val);
	wr_pcr(old_pcr);
}

static u64 e90s_picl_value(unsigned int nmi_hz)
{
	u32 delta = local_cpu_data().clock_tick / nmi_hz;
	return ((u64)((0 - delta) & 0xffffffff)) << 32;
}

static const struct pcr_ops e90s_pcr_ops = {
	.read_pcr		= e90s_pcr_read,
	.write_pcr		= e90s_pcr_write,
	.read_pic		= e90s_pic_read,
	.write_pic		= e90s_pic_write,
	.nmi_picl_value		= e90s_picl_value,
	.pcr_nmi_enable		= (E90S_PCR_PRIV | E90S_PCR_SYS | E90S_PCR_USR | PCR_UTRACE),
	.pcr_nmi_disable	= E90S_PCR_PRIV,
};


const struct pcr_ops *pcr_ops = &e90s_pcr_ops;
EXPORT_SYMBOL_GPL(pcr_ops);
