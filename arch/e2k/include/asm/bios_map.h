/*
 * $Id: bios_map.h,v 1.1 2009/01/15 13:47:21 kostin Exp $
 * Bios cmos map distribution.
 */
#ifndef _E2K_BIOS_MAP_H_
#define _E2K_BIOS_MAP_H_

#ifdef __KERNEL__
#define ECMOS_PORT(ext)	(0x70 + (ext))
/*
 * The yet supported machines all access the RTC index register via
 * an ISA port access but the way to access the date register differs ...
 */
#define ECMOS_READ(addr, ext) ({ \
outb_p((addr),ECMOS_PORT(ext + 0)); \
inb_p(ECMOS_PORT(ext + 1)); \
})
#define ECMOS_WRITE(val, addr, ext) ({ \
outb_p((addr),ECMOS_PORT(ext + 0)); \
outb_p((val),ECMOS_PORT(ext + 1)); \
})

static inline unsigned char bios_read(int addr)
{
	char byte;
	if (addr & 0x80) byte = ECMOS_READ(addr - 0x80, 2);
	else byte = ECMOS_READ(addr, 0);
	return byte;
}

static inline void bios_write(unsigned char val, int addr)
{
	if (addr & 0x80) ECMOS_WRITE(val, addr - 0x80, 2);
	else ECMOS_WRITE(val, addr, 0);
}
#endif /* __KERNEL__ */

//#define bios_read(addr) ECMOS_READ(addr)
//#define bios_write(val, addr) ECMOS_WRITE(val, addr)	

#define BIOS_UNSET_ONE	-1

#define name_length	15
#define cmdline_length	127

#define CMOS_BASE        	128 + 64
#define CMOS_SIZE		64
#define CMOS_FILE_LENGTH	15

#define BIOS_PROC_MASK		CMOS_BASE + 0
#define BIOS_DEV_NUM  		CMOS_BASE + 3  /* device number(0 - 3) */
#define BIOS_AUTOBOOT_TIMER	CMOS_BASE + 4  /* boot waiting seconds */
#define BIOS_BOOT_ITEM		CMOS_BASE + 5  /* boot item: kernel, lintel,
						  tests - 'Ñ','Ë','Ô' */
#define BIOS_BOOT_KNAME		CMOS_BASE + 6  /* kernel name */

#define BIOS_TEST_FLAG		0x6c
#define BIOS_TEST_FLAG2		0x6d
#define BIOS_SERIAL_RATE    	0x6e /* 3 - 38400 other - 115200 */

#define BIOS_MACHINE_TYPE	CMOS_BASE + 28 /* architecture type */

#define BIOS_PASSWD_FLAG	CMOS_BASE + 29
#define BIOS_PASSWD_FLAG2	CMOS_BASE + 30
#define BIOS_PASSWD1		CMOS_BASE + 31
#define BIOS_PASSWD2		CMOS_BASE + 32
#define BIOS_PASSWD3		CMOS_BASE + 33
#define BIOS_PASSWD4		CMOS_BASE + 34
#define BIOS_PASSWD5		CMOS_BASE + 35
#define BIOS_PASSWD6		CMOS_BASE + 36
#define BIOS_PASSWD7		CMOS_BASE + 37
#define BIOS_PASSWD8		CMOS_BASE + 38
#define BIOS_PASSWD9		CMOS_BASE + 39
#define BIOS_PASSWD10		CMOS_BASE + 40

#define BIOS_CSUM		CMOS_BASE + 61 /* checksum lsb */
#define BIOS_CSUM2		CMOS_BASE + 62 /* checksum msb */

typedef struct e2k_bios_param {
	char kernel_name[name_length + 1];
	char command_line[cmdline_length + 1];
	int booting_item;
	int dev_num;
	int serial_rate;
	int autoboot_timer;
	int machine_type;
} e2k_bios_param_t;

#ifdef __KERNEL__
static unsigned int _bios_csum(unsigned int counter, unsigned int len)
{
	unsigned int csum = 0;
 
	len = len + counter;
 

	while(counter < len) {
		csum += bios_read(counter);
		counter++;
	}
 
	return csum;
}

static inline unsigned int _bios_checksum(void)
{
	unsigned int csum = 0;

	csum = _bios_csum( 106, 6);
	csum += _bios_csum( 192, 21);
	csum += _bios_csum( 220, 12 );

	return csum;
}
#endif /* __KERNEL__ */
#endif /*_E2K_BIOS_MAP_H_ */
