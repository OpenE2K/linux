/* $Id: romstartup.S,v 1.8 2005/08/16 12:32:40 atic Exp $ */
//
// primary linux startup module
// lintel_startup.s, written by <karbo@lab.sun.mcst.ru>
// linux_startup.s, written by <atic@soft.sun.mcst.ru> as modification
// of 'lintel_startup.s' to start up linux secondary module
//

#define WSZ		0x20 			/* 20 quadwords	*/
#define RBS		0x10 			/* 10 quadwords	*/
#define RSZ		0x10 			/* 10 quadwords	*/

#define UPSR		0x1			/* fpu enabled */

#define OSEM_LO		0x0			/* no software traps enabled */
#define OSEM_HI		0x0

.section "text"
.global start
.global loader

// We are starting first steps and call loader(). See romloader.S
// Static memory allocation is defined by romloader.lds

start:
{
	setwd	wsz=WSZ
	setbn	rbs = RBS, rsz = RSZ, rcur = 0x0
	setbp	psz = 0
}
	rws UPSR,%upsr
	disp %ctpr1,loader
 	rwd OSEM_LO,%osem
	ct %ctpr1
	.size	start, . - start

/*

 [probably] pending stuff:

 physprot: address=0x70, val=addr, lower 12 buts unused
 pcilb: address=0x80, val=addr, lower 12 bits unused

 not needed stuff:

 *NO* USD;
 *NO* CU table and CUTD;
 *NO* turn virtual addressing on;

*/

