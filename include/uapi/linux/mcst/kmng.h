#ifndef _KMNG_H
#define _KMNG_H

#define KMNG_DATA_SHIFT	2
#define KMNG_DATA_SZ	(1 << KMNG_DATA_SHIFT)
#define KMNG_THRESHOLDS_NR	3


#define KMNG_FMT_UNSIGNED	(1 << 1)
#define KMNG_FMT_SIGNED	(1 << 2)
#define KMNG_FMT_2COMPLEMENT	(1 << 3)


#define KMNG_MAX_INT    0x7ffffff
#define KMNG_MAX_WRITES	64

struct kmng_data {
    int LowThreshold[KMNG_THRESHOLDS_NR];
    int UpThreshold[KMNG_THRESHOLDS_NR];
    int PosThdHysteresis; /* Positive Threshold Hysteresis */
    int NegThdHysteresis; /* Negative Threshold Hysteresis */
    int rw;
    int value;
    int bus;
    int addr;
    int reg[KMNG_DATA_SZ];
    int reg_nr;
    int reg_sz;
    unsigned mask;
    int little_endian;
    int format;
    int offset;
};

/**
 *		IOCTL COMMANDS
 **/

#define KMNG_IOC_MAGIC  'K'

#define	KMNG_IOCTL_POWER_ON	_IOWR(KMNG_IOC_MAGIC,  1, unsigned long)
#define	KMNG_IOCTL_POWER_OFF	_IOWR(KMNG_IOC_MAGIC,  2, unsigned long)
#define	KMNG_IOCTL_RESET	_IOWR(KMNG_IOC_MAGIC,  3, unsigned long)
#define	KMNG_IOCTL_SET_MONITOR	_IOWR(KMNG_IOC_MAGIC,  4, unsigned long)
#define	KMNG_IOCTL_RESET_ASSERT	_IOWR(KMNG_IOC_MAGIC,  5, unsigned long)
#define	KMNG_IOCTL_RESET_DEASSERT	_IOWR(KMNG_IOC_MAGIC,  6, unsigned long)

#endif /* !(_KMNG_H) */
