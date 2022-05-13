
/*
 * Copyright (c) 1997, by MCST.
 */

#ifndef	_UAPI__LINUX_MVP_DEF_H__
#define	_UAPI__LINUX_MVP_DEF_H__

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef __KERNEL__
#include <sys/types.h>
#endif /* KERNEL */
#include <linux/mcst/define.h>

/*
 * Defines and structures useable by both the driver
 * and user application go here.
 */
/*
 * MVP Registers.
 */
#define	MVP_EIR		0x000	/* external interrupt	    reg 20 bits	*/
#define	MVP_EIMR	0x004	/* external interrupt mask  reg 20 bits	*/
#define	MVP_EIPR	0x008	/* external interrupt polar reg 20 bits	*/
#define	MVP_OSR		0x00C	/* out	    states	    reg 16 bits	*/
#define	MVP_EIR0	0x010	/* external interrupt	    reg 20 bits	*/
#define	MVP_OIR		0x01C	/* out	    interrupt	    reg 16 bits	*/
#define	MVP_SIR		0x020	/* shadow   interrupt	    reg 20 bits	*/
#define	MVP_PARITY	0x040	/* parity				*/

#define	MVP_N_IN_INTER	20
#define	MVP_N_OUT_INTER	16
#define	MVP_N_OUT_STAT	16

#define	MVP_IN_MASK	0xffc0ffc0u
#define	MVP_OUT_MASK	0xff00ff00u

#define	MVP_IOC			('M' << 8)

/*
 * IOCTLs for send minor
 */

#define	MVPIO_SEND_INTR		(MVP_IOC | 1)
#define	MVPIO_SET_POLAR		(MVP_IOC | 2)

/*
 * IOCTLs for state minor
 */

#define	MVPIO_SET_STATE		(MVP_IOC | 3)

/*
 * direct access to registers
 */
#define	MVPIO_GET_REG		(MVP_IOC | 20)
#define	MVPIO_SET_REG		(MVP_IOC | 21)
#define	MVPIO_AUTO_INTR		(MVP_IOC | 22)
#define	MVPIO_INFO		(MVP_IOC | 23)
#define	MVPIO_CLEAR_INFO	(MVP_IOC | 24)
#define	MVPIO_GET_INTR		(MVP_IOC | 25)
#define	MVPIO_GET_INTR_ALL	(MVP_IOC | 26)
#define MVPIO_SELF_TEST		(MVP_IOC | 99)
//#define MVPIO_POLLS_TRACE	(MVP_IOC | 46)

typedef struct mvp_op {
	int	reg;	/* register number		*/
	uint	val;	/* returned/passed value	*/
} mvp_op_t;

typedef struct mvp_info {
	ulong_t		intr_claimed;
	ulong_t		intr_unclaimed;
	ulong_t		first_lbolt;	/* interrupt send		*/
	ulong_t		last_lbolt;	/* interrupt recieved		*/
#ifdef __KERNEL__
	clock_t		tick;		/* 1 tick in microseconds	*/
#else
	long		tick;
#endif /* __KERNEL__ */	     
} mvp_info_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _UAPI__LINUX_MVP_DEF_H__ */
