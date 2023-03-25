#ifndef _L3_H_
#define _L3_H_ 

#include <linux/string.h>
#include "ddk768_timer.h"


struct l3_pins {
	void (*setdat)(volatile unsigned char __iomem *, int);
	void (*setclk)(volatile unsigned char __iomem *, int);
	void (*setmode)(volatile unsigned char __iomem *, int);
	int data_hold;
	int data_setup;
	int clock_high;
	int mode_hold;
	int mode;
	int mode_setup;
};

int l3_write(volatile unsigned char __iomem *rmmio,
			struct l3_pins *adap, u8 addr,
			u8 *data, int len);

#endif
