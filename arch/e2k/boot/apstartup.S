/* $Id: apstartup.S,v 1.3 2005/08/16 12:32:40 atic Exp $ */
//
// primary application processor startup module
//

#define WSZ		0x20 			/* 20 quadwords	*/
#define RBS		0x10 			/* 10 quadwords	*/
#define RSZ		0x10 			/* 10 quadwords	*/

#define UPSR		0x1			/* fpu enabled */

#define OSEM_LO		0x0			/* no software traps enabled */
#define OSEM_HI		0x0

.section "text"
.global apstart
.global loader
#ifdef	CONFIG_SMP
.global aploader
#endif	/* CONFIG_SMP */

// We are starting first steps on AP and branch to ap_loader(). See aploader.S
// Static memory allocation is defined by romloader.lds

apstart:
{
	setwd	wsz = WSZ
	setbn	rbs = RBS, rsz = RSZ, rcur = 0x0
	setbp	psz = 0
}
	rws	UPSR, %upsr
#ifdef	CONFIG_SMP
	addd	0, [aploader], %r0
#else
	addd	0, [loader], %r0
#endif	/* CONFIG_SMP */
	movtd	%r0, %ctpr1
 	rwd	OSEM_LO, %osem
	ct %ctpr1
	.size	apstart, . - apstart


