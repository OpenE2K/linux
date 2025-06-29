#include "f_pll.h"

#ifdef DEBUG
static inline void e2c3_print_efuse_data(efuse_data_t *efuse_data)
{
	printk(KERN_DEBUG "efuse_data:\n"
	       "\tsign	    %d\n"
	       "\tdisable	    %d\n"
	       "\tparity	    %d\n"
	       "\taddr	    0x%x\n"
	       "\tbroadcast    %d\n"
	       "\tdata	    0x%x\n",
	       efuse_data->sign,
	       efuse_data->disable,
	       efuse_data->parity,
	       efuse_data->addr, efuse_data->broadcast, efuse_data->data);
}
#endif

static inline int64_t e2c3_get_nf(uint64_t *data)
{
	int64_t val = 0;
	val += (NF_MASK_LO & (data[0] >> NF_OFFSET_LO));
	val += data[1] << (EFUSE_DATA_SIZE - NF_OFFSET_LO);
	val += data[2] << (EFUSE_DATA_SIZE * 2 - NF_OFFSET_LO);
	val +=
	    ((NF_MASK_HI << NF_OFFSET_HI) & data[3]) << (EFUSE_DATA_SIZE * 3 -
							 NF_OFFSET_LO);

	return val;
}

/* http://bugzilla.lab.sun.mcst.ru/bugzilla-mcst/show_bug.cgi?id=130347#c14 */

int e2c3_get_f_pll(const int node)
{
	int addr;
	int f_pll = DEFAULT_F_PLL;
	uint64_t data[4];
	int i = 0;

	for (addr = EFUSE_START_ADDR; addr < EFUSE_END_ADDR; addr++) {

		efuse_data_t efuse_data;

#ifdef DEBUG
		e2c3_print_efuse_data(&efuse_data);
#endif
		sic_write_node_nbsr_reg(node, EFUSE_RAM_ADDR, addr);
		efuse_data.word = sic_read_node_nbsr_reg(node, EFUSE_RAM_DATA);
		if (efuse_data.sign && !efuse_data.disable
		    && efuse_data.broadcast && (efuse_data.addr >= 0x45)
		    && (efuse_data.addr <= 0x48)) {
			data[i++] = efuse_data.data;
		}
	}

	if (i == 4) {
		int64_t nr = e2c3_get_nr(data[3]);
		int64_t nf = e2c3_get_nf(data);
		int64_t od = e2c3_get_od(data[0]);

		int f_pll_calc = F_REF * nf / ((1LL << 33) * (nr + 1) * (od + 1));

		if (f_pll_calc >= MIN_F_PLL && f_pll_calc <= MAX_F_PLL)
			f_pll = f_pll_calc;
	}

	return f_pll;
}
