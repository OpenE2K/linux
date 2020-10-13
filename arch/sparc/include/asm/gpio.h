#ifndef __ASM_SPARC_GPIO_H
#ifdef	CONFIG_E90S
#include <asm-l/gpio.h>
#else
#warning Include linux/gpio.h instead of asm/gpio.h
#include <linux/gpio.h>
#endif
#endif	/*__ASM_SPARC_GPIO_H*/

