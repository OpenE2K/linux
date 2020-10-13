#ifndef _E3M_IOHUB_H_
#define _E3M_IOHUB_H_

/*
 * IO links and IO controllers topology
 * E3M machines with IOHUB do not use Intel's chipset PIIX4 and connected
 * to IO as other machines using IO link.
 */
#define	E3M_IOHUB_MAX_NUMIOLINKS	1	/* e3m with IOHUB has only */
						/* one IO link connected to */
						/* IOHUB */
#define	E3M_IOHUB_NODE_IOLINKS		E3M_IOHUB_MAX_NUMIOLINKS

extern void __init boot_e3m_iohub_setup_arch(void);
extern void __init e3m_iohub_setup_arch(void);
extern void __init e3m_iohub_setup_machine(void);

#endif /* _E3M_IOHUB_H_ */
