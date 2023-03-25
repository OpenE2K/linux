
#include "l3.h"

/*
 * Send one byte of data to the chip.  Data is latched into the chip on
 * the rising edge of the clock.
 */
static void sendbyte(volatile unsigned char __iomem *rmmio,
				struct l3_pins *adap, unsigned int byte)
{
	int i;

	for (i = 0; i < 8; i++) {
		adap->setclk(rmmio, 0);
		sb_OS_WAIT_USEC_POLL(rmmio, adap->data_hold);
		adap->setdat(rmmio, byte & 1);
		sb_OS_WAIT_USEC_POLL(rmmio, adap->data_setup);
		adap->setclk(rmmio, 1);
		sb_OS_WAIT_USEC_POLL(rmmio, adap->clock_high);
		byte >>= 1;
	}
}

/*
 * Send a set of bytes to the chip.  We need to pulse the MODE line
 * between each byte, but never at the start nor at the end of the
 * transfer.
 */
static void sendbytes(volatile unsigned char __iomem *rmmio,
				struct l3_pins *adap, const u8 *buf,
				int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (i) {
			sb_OS_WAIT_USEC_POLL(rmmio, adap->mode_hold);
			adap->setmode(rmmio, 0);
			sb_OS_WAIT_USEC_POLL(rmmio, adap->mode);
		}
		adap->setmode(rmmio, 1);
		sb_OS_WAIT_USEC_POLL(rmmio, adap->mode_setup);
		sendbyte(rmmio, adap, buf[i]);
	}
}

int l3_write(volatile unsigned char __iomem *rmmio,
				struct l3_pins *adap,
				u8 addr, u8 *data, int len)
{
	adap->setclk(rmmio, 1);
	adap->setdat(rmmio, 1);
	adap->setmode(rmmio, 1);
	sb_OS_WAIT_USEC_POLL(rmmio, adap->mode);

	adap->setmode(rmmio, 0);
	sb_OS_WAIT_USEC_POLL(rmmio, adap->mode_setup);
	sendbyte(rmmio, adap, addr);
	sb_OS_WAIT_USEC_POLL(rmmio, adap->mode_hold);

	sendbytes(rmmio, adap, data, len);

	adap->setclk(rmmio, 1);
	adap->setdat(rmmio, 1);
	adap->setmode(rmmio, 0);

	return len;
}

