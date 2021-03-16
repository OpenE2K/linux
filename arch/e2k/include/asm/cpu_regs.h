
#ifndef	_E2K_CPU_REGS_H_
#define	_E2K_CPU_REGS_H_

#ifdef __KERNEL__

#include <asm/types.h>
#include <asm/cpu_regs_types.h>
#include <asm/cpu_regs_access.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/e2k.h>

#define	NATIVE_STRIP_PCSHTP_WINDOW()	NATIVE_WRITE_PCSHTP_REG_SVALUE(0)
#define	STRIP_PCSHTP_WINDOW()		WRITE_PCSHTP_REG_SVALUE(0)

/*
 * Read low double-word OS Compilation Unit Register (OSCUD)
 * from the low word structure
 * Register fields access:		fff = OSCUD_lo.OSCUD_lo_xxx;
 * Register double-word half access:	oscud_lo = OSCUD_lo.OSCUD_lo_half;
 */
#define	NATIVE_READ_OSCUD_LO_REG() \
({ \
	e2k_oscud_lo_t OSCUD_lo; \
	OSCUD_lo.OSCUD_lo_half = NATIVE_READ_OSCUD_LO_REG_VALUE(); \
	OSCUD_lo; \
})
#define	READ_OSCUD_LO_REG() \
({ \
	e2k_oscud_lo_t OSCUD_lo; \
	OSCUD_lo.OSCUD_lo_half = READ_OSCUD_LO_REG_VALUE(); \
	OSCUD_lo; \
})
#define	BOOT_READ_OSCUD_LO_REG() \
({ \
	e2k_oscud_lo_t OSCUD_lo; \
	OSCUD_lo.OSCUD_lo_half = BOOT_READ_OSCUD_LO_REG_VALUE(); \
	OSCUD_lo; \
})

static	inline	e2k_oscud_lo_t
native_read_OSCUD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSCUD_lo register 0x%lx\n",
			NATIVE_READ_OSCUD_LO_REG().OSCUD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_READ_OSCUD_LO_REG();
}
static	inline	e2k_oscud_lo_t
read_OSCUD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSCUD_lo register 0x%lx\n",
			READ_OSCUD_LO_REG().OSCUD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_OSCUD_LO_REG();
}
static	inline	e2k_oscud_lo_t
boot_read_OSCUD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSCUD_lo register 0x%lx\n",
			BOOT_READ_OSCUD_LO_REG().OSCUD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_OSCUD_LO_REG();
}

/*
 * Read high double-word OS Compilation Unit Register (OSCUD)
 * from the high word structure
 * Register fields access:		fff = OSCUD_hi.OSCUD_hi_xxx;
 * Register double-word half access:	oscud_lo = OSCUD_hi.OSCUD_hi_half;
 */
#define	NATIVE_READ_OSCUD_HI_REG() \
({ \
	e2k_oscud_hi_t OSCUD_hi; \
	OSCUD_hi.OSCUD_hi_half = NATIVE_READ_OSCUD_HI_REG_VALUE(); \
	OSCUD_hi; \
})
#define	READ_OSCUD_HI_REG() \
({ \
	e2k_oscud_hi_t OSCUD_hi; \
	OSCUD_hi.OSCUD_hi_half = READ_OSCUD_HI_REG_VALUE(); \
	OSCUD_hi; \
})
#define	BOOT_READ_OSCUD_HI_REG() \
({ \
	e2k_oscud_hi_t OSCUD_hi; \
	OSCUD_hi.OSCUD_hi_half = BOOT_READ_OSCUD_HI_REG_VALUE(); \
	OSCUD_hi; \
})

static	inline	e2k_oscud_hi_t
native_read_OSCUD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSCUD_hi register 0x%lx\n",
			NATIVE_READ_OSCUD_HI_REG().OSCUD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_READ_OSCUD_HI_REG();
}
static	inline	e2k_oscud_hi_t
read_OSCUD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSCUD_hi register 0x%lx\n",
			READ_OSCUD_HI_REG().OSCUD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_OSCUD_HI_REG();
}
static	inline	e2k_oscud_hi_t
boot_read_OSCUD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSCUD_hi register 0x%lx\n",
			BOOT_READ_OSCUD_HI_REG().OSCUD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_OSCUD_HI_REG();
}

/*
 * Read quad-word OS Compilation Unit Register (OSCUD) to the structure
 * Register fields access:		fff = OSCUD -> OSCUD_xxx
 * Register double-word halfs access:	OSCUD_lo = OSCUD -> OSCUD_lo_reg
 *					OSCUD_hi = OSCUD -> OSCUD_hi_reg
 */
#define	READ_OSCUD_REG() \
({ \
	oscud_struct_t OSCUD; \
	OSCUD.OSCUD_hi_struct = READ_OSCUD_HI_REG(); \
	OSCUD.OSCUD_lo_struct = READ_OSCUD_LO_REG(); \
	OSCUD; \
})
#define	READ_OSCUD_REG_TO(OSCUD) (*(OSCUD) = READ_OSCUD_REG())
#define	BOOT_READ_OSCUD_REG() \
({ \
	oscud_struct_t OSCUD; \
	OSCUD.OSCUD_hi_struct = BOOT_READ_OSCUD_HI_REG(); \
	OSCUD.OSCUD_lo_struct = BOOT_READ_OSCUD_LO_REG(); \
	OSCUD; \
})
#define	READ_OSCUD_REG_TO(OSCUD)	(*(OSCUD) = READ_OSCUD_REG())
#define	BOOT_READ_OSCUD_REG_TO(OSCUD) (*(OSCUD) = BOOT_READ_OSCUD_REG())

static inline void
read_OSCUD_reg(oscud_struct_t *OSCUD)
{
	READ_OSCUD_REG_TO(OSCUD);
}
static inline void
boot_read_OSCUD_reg(oscud_struct_t *OSCUD)
{
	BOOT_READ_OSCUD_REG_TO(OSCUD);
}

/*
 * Write low double-word OS Compilation Unit Register (OSCUD)
 * from the low word structure
 * Register fields filling:		OSCUD_lo.OSCUD_lo_xxx = fff;
 * Register double-word half filling:	OSCUD_lo.OSCUD_lo_half = oscud_lo;
 */
#define	NATIVE_WRITE_OSCUD_LO_REG(OSCUD_lo) \
({ \
	NATIVE_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo.OSCUD_lo_half); \
})
#define	WRITE_OSCUD_LO_REG(OSCUD_lo) \
({ \
	WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo.OSCUD_lo_half); \
})
#define	BOOT_WRITE_OSCUD_LO_REG(OSCUD_lo) \
({ \
	BOOT_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo.OSCUD_lo_half); \
})

static inline void
native_write_OSCUD_lo_reg(e2k_oscud_lo_t OSCUD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write OSCUD_lo register 0x%lx\n", OSCUD_lo.OSCUD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_WRITE_OSCUD_LO_REG(OSCUD_lo);
}
static inline void
write_OSCUD_lo_reg(e2k_oscud_lo_t OSCUD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write OSCUD_lo register 0x%lx\n", OSCUD_lo.OSCUD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_OSCUD_LO_REG(OSCUD_lo);
}

/*
 * Write high double-word OS Compilation Unit Register (OSCUD)
 * from the high word structure
 * Register fields filling:		OSCUD_hi.OSCUD_hi_xxx = fff;
 * Register double-word half filling:	OSCUD_hi.OSCUD_hi_half = oscud_lo;
 */
#define	NATIVE_WRITE_OSCUD_HI_REG(OSCUD_hi) \
({ \
	NATIVE_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi.OSCUD_hi_half); \
})
#define	WRITE_OSCUD_HI_REG(OSCUD_hi) \
({ \
	WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi.OSCUD_hi_half); \
})
#define	BOOT_WRITE_OSCUD_HI_REG(OSCUD_hi) \
({ \
	BOOT_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi.OSCUD_hi_half); \
})

static inline void
native_write_OSCUD_hi_reg(e2k_oscud_hi_t OSCUD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write OSCUD_hi register 0x%lx\n", OSCUD_hi.OSCUD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_WRITE_OSCUD_HI_REG(OSCUD_hi);
}
static inline void
write_OSCUD_hi_reg(e2k_oscud_hi_t OSCUD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write OSCUD_hi register 0x%lx\n", OSCUD_hi.OSCUD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_OSCUD_HI_REG(OSCUD_hi);
}

/*
 * Write high & low quad-word OS Compilation Unit Register (OSCUD)
 * from the high & low word structure
 */

#define	WRITE_OSCUD_REG_VALUE(OSCUD_hi_value, OSCUD_lo_value) \
({ \
	WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
	WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
})
#define	BOOT_WRITE_OSCUD_REG_VALUE(OSCUD_hi_value, OSCUD_lo_value) \
({ \
	BOOT_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
	BOOT_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
})
#define	WRITE_OSCUD_REG(OSCUD_hi, OSCUD_lo) \
({ \
	WRITE_OSCUD_REG_VALUE(OSCUD_hi.OSCUD_hi_half, \
					OSCUD_lo.OSCUD_lo_half); \
})
#define	BOOT_WRITE_OSCUD_REG(OSCUD_hi, OSCUD_lo) \
({ \
	BOOT_WRITE_OSCUD_REG_VALUE(OSCUD_hi.OSCUD_hi_half, \
					OSCUD_lo.OSCUD_lo_half); \
})

static inline void
write_OSCUD_hi_lo_reg(e2k_oscud_hi_t OSCUD_hi, e2k_oscud_lo_t OSCUD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write OSCUD_hi register 0x%lx\n", OSCUD_hi.OSCUD_hi_half);
	boot_printk("Write OSCUD_lo register 0x%lx\n", OSCUD_lo.OSCUD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_OSCUD_REG(OSCUD_hi, OSCUD_lo);
}

/*
 * Write quad-word OS Compilation Unit Register (OSCUD) from the structure
 * Register fields filling:		OSCUD.OSCUD_xxx = fff;
 * Register double-word halfs filling:	OSCUD.OSCUD_lo_reg = OSCUD_lo;
 *					OSCUD.OSCUD_hi_reg = OSCUD_hi;
 */
#define	WRITE_OSCUD_REG_VALUE(OSCUD_hi_value, OSCUD_lo_value) \
({ \
	WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
	WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
})
#define	BOOT_WRITE_OSCUD_REG_VALUE(OSCUD_hi_value, OSCUD_lo_value) \
({ \
	BOOT_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
	BOOT_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
})

static inline void
write_OSCUD_reg(oscud_struct_t OSCUD)
{
	WRITE_OSCUD_REG(OSCUD.OSCUD_hi_struct, OSCUD.OSCUD_lo_struct);
}

/*
 * Read low double-word OS Globals Register (OSGD)
 * from the low word structure
 * Register fields access:		fff = OSGD_lo.OSGD_lo_xxx;
 * Register double-word half access:	osgd_lo = OSGD_lo.OSGD_lo_half;
 */
#define	NATIVE_READ_OSGD_LO_REG() \
({ \
	e2k_osgd_lo_t OSGD_lo; \
	OSGD_lo.OSGD_lo_half = NATIVE_READ_OSGD_LO_REG_VALUE(); \
	OSGD_lo; \
})
#define	READ_OSGD_LO_REG() \
({ \
	e2k_osgd_lo_t OSGD_lo; \
	OSGD_lo.OSGD_lo_half = READ_OSGD_LO_REG_VALUE(); \
	OSGD_lo; \
})
#define	BOOT_READ_OSGD_LO_REG() \
({ \
	e2k_osgd_lo_t OSGD_lo; \
	OSGD_lo.OSGD_lo_half = BOOT_READ_OSGD_LO_REG_VALUE(); \
	OSGD_lo; \
})

static	inline	e2k_osgd_lo_t
native_read_OSGD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSGD_lo register 0x%lx\n",
			NATIVE_READ_OSGD_LO_REG().OSGD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_READ_OSGD_LO_REG();
}
static	inline	e2k_osgd_lo_t
read_OSGD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSGD_lo register 0x%lx\n",
			READ_OSGD_LO_REG().OSGD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_OSGD_LO_REG();
}
static	inline	e2k_osgd_lo_t
boot_read_OSGD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSGD_lo register 0x%lx\n",
			BOOT_READ_OSGD_LO_REG().OSGD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_OSGD_LO_REG();
}

/*
 * Read high double-word OS Globals Register (OSGD)
 * from the high word structure
 * Register fields access:		fff = OSGD_hi.OSGD_hi_xxx;
 * Register double-word half access:	osgd_lo = OSGD_hi.OSGD_hi_half;
 */
#define	NATIVE_READ_OSGD_HI_REG() \
({ \
	e2k_osgd_hi_t OSGD_hi; \
	OSGD_hi.OSGD_hi_half = NATIVE_READ_OSGD_HI_REG_VALUE(); \
	OSGD_hi; \
})
#define	READ_OSGD_HI_REG() \
({ \
	e2k_osgd_hi_t OSGD_hi; \
	OSGD_hi.OSGD_hi_half = READ_OSGD_HI_REG_VALUE(); \
	OSGD_hi; \
})
#define	BOOT_READ_OSGD_HI_REG() \
({ \
	e2k_osgd_hi_t OSGD_hi; \
	OSGD_hi.OSGD_hi_half = BOOT_READ_OSGD_HI_REG_VALUE(); \
	OSGD_hi; \
})

static	inline	e2k_osgd_hi_t
native_read_OSGD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSGD_hi register 0x%lx\n",
			NATIVE_READ_OSGD_HI_REG().OSGD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_READ_OSGD_HI_REG();
}
static	inline	e2k_osgd_hi_t
read_OSGD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSGD_hi register 0x%lx\n",
			READ_OSGD_HI_REG().OSGD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_OSGD_HI_REG();
}
static	inline	e2k_osgd_hi_t
boot_read_OSGD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read OSGD_hi register 0x%lx\n",
			BOOT_READ_OSGD_HI_REG().OSGD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_OSGD_HI_REG();
}

/*
 * Read quad-word OS Globals Register (OSGD) to the structure
 * Register fields access:		fff = OSGD -> OSGD_xxx
 * Register double-word halfs access:	OSGD_lo = OSGD -> OSGD_lo_reg
 *					OSGD_hi = OSGD -> OSGD_hi_reg
 */
#define	READ_OSGD_REG() \
({ \
	osgd_struct_t OSGD; \
	OSGD.OSGD_hi_struct = READ_OSGD_HI_REG(); \
	OSGD.OSGD_lo_struct = READ_OSGD_LO_REG(); \
	OSGD; \
})
#define	READ_OSGD_REG_TO(OSGD)		(*(OSGD) = READ_OSGD_REG())
#define	BOOT_READ_OSGD_REG() \
({ \
	osgd_struct_t OSGD; \
	OSGD.OSGD_hi_struct = BOOT_READ_OSGD_HI_REG(); \
	OSGD.OSGD_lo_struct = BOOT_READ_OSGD_LO_REG(); \
	OSGD; \
})
#define	BOOT_READ_OSGD_REG_TO(OSGD)	(*(OSGD) = BOOT_READ_OSGD_REG())

static inline void
read_OSGD_reg(osgd_struct_t *OSGD)
{
	READ_OSGD_REG_TO(OSGD);
}
static inline void
boot_read_OSGD_reg(osgd_struct_t *OSGD)
{
	BOOT_READ_OSGD_REG_TO(OSGD);
}

/*
 * Write low double-word OS Globals Register (OSGD)
 * from the low word structure
 * Register fields filling:		OSGD_lo.OSGD_lo_xxx = fff;
 * Register double-word half filling:	OSGD_lo.OSGD_lo_half = gd_lo;
 */
#define	NATIVE_WRITE_OSGD_LO_REG(OSGD_lo) \
({ \
	NATIVE_WRITE_OSGD_LO_REG_VALUE(OSGD_lo.OSGD_lo_half); \
})
#define	WRITE_OSGD_LO_REG(OSGD_lo) \
({ \
	WRITE_OSGD_LO_REG_VALUE(OSGD_lo.OSGD_lo_half); \
})
#define	BOOT_WRITE_OSGD_LO_REG(OSGD_lo) \
({ \
	BOOT_WRITE_OSGD_LO_REG_VALUE(OSGD_lo.OSGD_lo_half); \
})

static inline void
native_write_OSGD_lo_reg(e2k_osgd_lo_t OSGD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write OSGD_lo register 0x%lx\n", OSGD_lo.OSGD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_WRITE_OSGD_LO_REG(OSGD_lo);
}
static inline void
write_OSGD_lo_reg(e2k_osgd_lo_t OSGD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write OSGD_lo register 0x%lx\n", OSGD_lo.OSGD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_OSGD_LO_REG(OSGD_lo);
}

/*
 * Write high double-word OS Globals Register (OSGD)
 * from the high word structure
 * Register fields filling:		OSGD_hi.OSGD_hi_xxx = fff;
 * Register double-word half filling:	OSGD_hi.OSGD_hi_half = gd_lo;
 */
#define	NATIVE_WRITE_OSGD_HI_REG(OSGD_hi) \
({ \
	NATIVE_WRITE_OSGD_HI_REG_VALUE(OSGD_hi.OSGD_hi_half); \
})
#define	WRITE_OSGD_HI_REG(OSGD_hi) \
({ \
	WRITE_OSGD_HI_REG_VALUE(OSGD_hi.OSGD_hi_half); \
})
#define	BOOT_WRITE_OSGD_HI_REG(OSGD_hi) \
({ \
	BOOT_WRITE_OSGD_HI_REG_VALUE(OSGD_hi.OSGD_hi_half); \
})

static inline void
native_write_OSGD_hi_reg(e2k_osgd_hi_t OSGD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write OSGD_hi register 0x%lx\n", OSGD_hi.OSGD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_WRITE_OSGD_HI_REG(OSGD_hi);
}
static inline void
write_OSGD_hi_reg(e2k_osgd_hi_t OSGD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write OSGD_hi register 0x%lx\n", OSGD_hi.OSGD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_OSGD_HI_REG(OSGD_hi);
}

/*
 * Write high & low quad-word OS Globals Register (OSGD)
 * from the high & low word structure
 */

#define	WRITE_OSGD_REG_VALUE(OSGD_hi_value, OSGD_lo_value) \
({ \
	WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value); \
	WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value); \
})
#define	BOOT_WRITE_OSGD_REG_VALUE(OSGD_hi_value, OSGD_lo_value) \
({ \
	BOOT_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value); \
	BOOT_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value); \
})
#define	WRITE_OSGD_REG(OSGD_hi, OSGD_lo) \
({ \
	WRITE_OSGD_REG_VALUE(OSGD_hi.OSGD_hi_half, OSGD_lo.OSGD_lo_half); \
})
#define	BOOT_WRITE_OSGD_REG(OSGD_hi, OSGD_lo) \
({ \
	BOOT_WRITE_OSGD_REG_VALUE(OSGD_hi.OSGD_hi_half, \
						OSGD_lo.OSGD_lo_half); \
})

static inline void
write_OSGD_hi_lo_reg(e2k_osgd_hi_t OSGD_hi, e2k_osgd_lo_t OSGD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write OSGD_hi register 0x%lx\n", OSGD_hi.OSGD_hi_half);
	boot_printk("Write OSGD_lo register 0x%lx\n", OSGD_lo.OSGD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_OSGD_REG(OSGD_hi, OSGD_lo);
}

/*
 * Write quad-word OS Globals Register (OSGD) from the structure
 * Register fields filling:		OSGD.OSGD_xxx = fff;
 * Register double-word halfs filling:	OSGD.OSGD_lo_reg = OSGD_lo;
 *					OSGD.OSGD_hi_reg = OSGD_hi;
 */
static inline void
write_OSGD_reg(osgd_struct_t OSGD)
{
	WRITE_OSGD_REG(OSGD.OSGD_hi_struct, OSGD.OSGD_lo_struct);
}

/*
 * Read low double-word Compilation Unit Register (CUD)
 * from the low word structure
 * Register fields access:		fff = CUD_lo.CUD_lo_xxx;
 * Register double-word half access:	cud_lo = CUD_lo.CUD_lo_half;
 */
#define	NATIVE_READ_CUD_LO_REG() \
({ \
	e2k_cud_lo_t CUD_lo; \
	CUD_lo.CUD_lo_half = NATIVE_READ_CUD_LO_REG_VALUE(); \
	CUD_lo; \
})
#define	READ_CUD_LO_REG() \
({ \
	e2k_cud_lo_t CUD_lo; \
	CUD_lo.CUD_lo_half = READ_CUD_LO_REG_VALUE(); \
	CUD_lo; \
})
#define	BOOT_READ_CUD_LO_REG() \
({ \
	e2k_cud_lo_t CUD_lo; \
	CUD_lo.CUD_lo_half = BOOT_READ_CUD_LO_REG_VALUE(); \
	CUD_lo; \
})

static	inline	e2k_cud_lo_t
read_CUD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read CUD_lo register 0x%lx\n",
			READ_CUD_LO_REG().CUD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_CUD_LO_REG();
}

/*
 * Read high double-word Compilation Unit Register (CUD)
 * from the high word structure
 * Register fields access:		fff = CUD_hi.CUD_hi_xxx;
 * Register double-word half access:	cud_lo = CUD_hi.CUD_hi_half;
 */
#define	NATIVE_READ_CUD_HI_REG() \
({ \
	e2k_cud_hi_t CUD_hi; \
	CUD_hi.CUD_hi_half = NATIVE_READ_CUD_HI_REG_VALUE(); \
	CUD_hi; \
})
#define	READ_CUD_HI_REG() \
({ \
	e2k_cud_hi_t CUD_hi; \
	CUD_hi.CUD_hi_half = READ_CUD_HI_REG_VALUE(); \
	CUD_hi; \
})
#define	BOOT_READ_CUD_HI_REG() \
({ \
	e2k_cud_hi_t CUD_hi; \
	CUD_hi.CUD_hi_half = BOOT_READ_CUD_HI_REG_VALUE(); \
	CUD_hi; \
})

static	inline	e2k_cud_hi_t
read_CUD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read CUD_hi register 0x%lx\n",
			READ_CUD_HI_REG().CUD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_CUD_HI_REG();
}

/*
 * Read quad-word Compilation Unit Register (CUD) to the structure
 * Register fields access:		fff = CUD -> CUD_xxx
 * Register double-word halfs access:	CUD_lo = CUD -> CUD_lo_reg
 *					CUD_hi = CUD -> CUD_hi_reg
 */
#define	READ_CUD_REG() \
({ \
	cud_struct_t CUD; \
	CUD.CUD_hi_struct = READ_CUD_HI_REG(); \
	CUD.CUD_lo_struct = READ_CUD_LO_REG(); \
	CUD; \
})
#define	READ_CUD_REG_TO(CUD)		(*(CUD) = READ_CUD_REG())
#define	BOOT_READ_CUD_REG() \
({ \
	cud_struct_t CUD; \
	CUD.CUD_hi_struct = BOOT_READ_CUD_HI_REG(); \
	CUD.CUD_lo_struct = BOOT_READ_CUD_LO_REG(); \
	CUD; \
})
#define	BOOT_READ_CUD_REG_TO(CUD)	(*(CUD) = BOOT_READ_CUD_REG())

static inline void
read_CUD_reg(cud_struct_t *CUD)
{
	READ_CUD_REG_TO(CUD);
}
static inline void
boot_read_CUD_reg(cud_struct_t *CUD)
{
	BOOT_READ_CUD_REG_TO(CUD);
}

/*
 * Write low double-word Compilation Unit Register (CUD)
 * from the low word structure
 * Register fields filling:		CUD_lo.CUD_lo_xxx = fff;
 * Register double-word half filling:	CUD_lo.CUD_lo_half = cud_lo;
 */
#define	WRITE_CUD_LO_REG(CUD_lo) \
({ \
	WRITE_CUD_LO_REG_VALUE(CUD_lo.CUD_lo_half); \
})
#define	BOOT_WRITE_CUD_LO_REG(CUD_lo) \
({ \
	BOOT_WRITE_CUD_LO_REG_VALUE(CUD_lo.CUD_lo_half); \
})

static inline void
write_CUD_lo_reg(e2k_cud_lo_t CUD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CUD_lo register 0x%lx\n", CUD_lo.CUD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_CUD_LO_REG(CUD_lo);
}

/*
 * Write high double-word Compilation Unit Register (CUD)
 * from the high word structure
 * Register fields filling:		CUD_hi.CUD_hi_xxx = fff;
 * Register double-word half filling:	CUD_hi.CUD_hi_half = cud_lo;
 */
#define	WRITE_CUD_HI_REG(CUD_hi) \
({ \
	WRITE_CUD_HI_REG_VALUE(CUD_hi.CUD_hi_half); \
})
#define	BOOT_WRITE_CUD_HI_REG(CUD_hi) \
({ \
	BOOT_WRITE_CUD_HI_REG_VALUE(CUD_hi.CUD_hi_half); \
})

static inline void
write_CUD_hi_reg(e2k_cud_hi_t CUD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CUD_hi register 0x%lx\n", CUD_hi.CUD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_CUD_HI_REG(CUD_hi);
}

/*
 * Write high & low quad-word Compilation Unit Register (CUD)
 * from the high & low word structure
 */

#define	WRITE_CUD_REG_VALUE(CUD_hi_value, CUD_lo_value) \
({ \
	WRITE_CUD_HI_REG_VALUE(CUD_hi_value); \
	WRITE_CUD_LO_REG_VALUE(CUD_lo_value); \
})
#define	BOOT_WRITE_CUD_REG_VALUE(CUD_hi_value, CUD_lo_value) \
({ \
	BOOT_WRITE_CUD_HI_REG_VALUE(CUD_hi_value); \
	BOOT_WRITE_CUD_LO_REG_VALUE(CUD_lo_value); \
})
#define	WRITE_CUD_REG(CUD_hi, CUD_lo) \
({ \
	WRITE_CUD_REG_VALUE(CUD_hi.CUD_hi_half, CUD_lo.CUD_lo_half); \
})
#define	BOOT_WRITE_CUD_REG(CUD_hi, CUD_lo) \
({ \
	BOOT_WRITE_CUD_REG_VALUE(CUD_hi.CUD_hi_half, CUD_lo.CUD_lo_half); \
})

static inline void
write_CUD_hi_lo_reg(e2k_cud_hi_t CUD_hi, e2k_cud_lo_t CUD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CUD_hi register 0x%lx\n", CUD_hi.CUD_hi_half);
	boot_printk("Write CUD_lo register 0x%lx\n", CUD_lo.CUD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_CUD_REG(CUD_hi, CUD_lo);
}

/*
 * Write quad-word Compilation Unit Register (CUD) from the structure
 * Register fields filling:		CUD.CUD_xxx = fff;
 * Register double-word halfs filling:	CUD.CUD_lo_reg = CUD_lo;
 *					CUD.CUD_hi_reg = CUD_hi;
 */
static inline void
write_CUD_reg(cud_struct_t CUD)
{
	WRITE_CUD_REG(CUD.CUD_hi_struct, CUD.CUD_lo_struct);
}

/*
 * Read low double-word Globals Register (GD)
 * from the low word structure
 * Register fields access:		fff = GD_lo.GD_lo_xxx;
 * Register double-word half access:	gd_lo = GD_lo.GD_lo_half;
 */
#define	READ_GD_LO_REG() \
({ \
	e2k_gd_lo_t GD_lo; \
	GD_lo.GD_lo_half = READ_GD_LO_REG_VALUE(); \
	GD_lo; \
})
#define	BOOT_READ_GD_LO_REG() \
({ \
	e2k_gd_lo_t GD_lo; \
	GD_lo.GD_lo_half = BOOT_READ_GD_LO_REG_VALUE(); \
	GD_lo; \
})

static	inline	e2k_gd_lo_t
read_GD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read GD_lo register 0x%lx\n",
			READ_GD_LO_REG().GD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_GD_LO_REG();
}
static	inline	e2k_gd_lo_t
boot_read_GD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read GD_lo register 0x%lx\n",
			BOOT_READ_GD_LO_REG().GD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_GD_LO_REG();
}

/*
 * Read high double-word Globals Register (GD)
 * from the high word structure
 * Register fields access:		fff = GD_hi.GD_hi_xxx;
 * Register double-word half access:	gd_lo = GD_hi.GD_hi_half;
 */
#define	READ_GD_HI_REG() \
({ \
	e2k_gd_hi_t GD_hi; \
	GD_hi.GD_hi_half = READ_GD_HI_REG_VALUE(); \
	GD_hi; \
})
#define	BOOT_READ_GD_HI_REG() \
({ \
	e2k_gd_hi_t GD_hi; \
	GD_hi.GD_hi_half = BOOT_READ_GD_HI_REG_VALUE(); \
	GD_hi; \
})

static	inline	e2k_gd_hi_t
read_GD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read GD_hi register 0x%lx\n",
			READ_GD_HI_REG().GD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_GD_HI_REG();
}
static	inline	e2k_gd_hi_t
boot_read_GD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read GD_hi register 0x%lx\n",
			BOOT_READ_GD_HI_REG().GD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_GD_HI_REG();
}

/*
 * Read quad-word Globals Register (GD) to the structure
 * Register fields access:		fff = GD -> GD_xxx
 * Register double-word halfs access:	GD_lo = GD -> GD_lo_reg
 *					GD_hi = GD -> GD_hi_reg
 */
#define	READ_GD_REG() \
({ \
	gd_struct_t GD; \
	GD.GD_hi_struct = READ_GD_HI_REG(); \
	GD.GD_lo_struct = READ_GD_LO_REG(); \
	GD; \
})
#define	READ_GD_REG_TO(GD)	(*(GD) = READ_GD_REG())
#define	BOOT_READ_GD_REG() \
({ \
	gd_struct_t GD; \
	GD.GD_hi_struct = BOOT_READ_GD_HI_REG(); \
	GD.GD_lo_struct = BOOT_READ_GD_LO_REG(); \
	GD; \
})
#define	BOOT_READ_GD_REG_TO(GD)	(*(GD) = BOOT_READ_GD_REG())

static inline void
read_GD_reg(gd_struct_t *GD)
{
	READ_GD_REG_TO(GD);
}
static inline void
boot_read_GD_reg(gd_struct_t *GD)
{
	BOOT_READ_GD_REG_TO(GD);
}

/*
 * Write low double-word Globals Register (GD)
 * from the low word structure
 * Register fields filling:		GD_lo.GD_lo_xxx = fff;
 * Register double-word half filling:	GD_lo.GD_lo_half = gd_lo;
 */
#define	WRITE_GD_LO_REG(GD_lo)	\
		WRITE_GD_LO_REG_VALUE(GD_lo.GD_lo_half)
#define	BOOT_WRITE_GD_LO_REG(GD_lo)	\
		BOOT_WRITE_GD_LO_REG_VALUE(GD_lo.GD_lo_half)

static inline void
write_GD_lo_reg(e2k_gd_lo_t GD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write GD_lo register 0x%lx\n", GD_lo.GD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_GD_LO_REG(GD_lo);
}

/*
 * Write high double-word Globals Register (GD)
 * from the high word structure
 * Register fields filling:		GD_hi.GD_hi_xxx = fff;
 * Register double-word half filling:	GD_hi.GD_hi_half = gd_lo;
 */
#define	WRITE_GD_HI_REG(GD_hi)	\
		WRITE_GD_HI_REG_VALUE(GD_hi.GD_hi_half)
#define	BOOT_WRITE_GD_HI_REG(GD_hi)	\
		BOOT_WRITE_GD_HI_REG_VALUE(GD_hi.GD_hi_half)

static inline void
write_GD_hi_reg(e2k_gd_hi_t GD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write GD_hi register 0x%lx\n", GD_hi.GD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_GD_HI_REG(GD_hi);
}

/*
 * Write high & low quad-word Globals Register (GD)
 * from the high & low word structure
 */

#define	WRITE_GD_REG_VALUE(GD_hi_value, GD_lo_value) \
({ \
	WRITE_GD_HI_REG_VALUE(GD_hi_value); \
	WRITE_GD_LO_REG_VALUE(GD_lo_value); \
})
#define	BOOT_WRITE_GD_REG_VALUE(GD_hi_value, GD_lo_value) \
({ \
	BOOT_WRITE_GD_HI_REG_VALUE(GD_hi_value); \
	BOOT_WRITE_GD_LO_REG_VALUE(GD_lo_value); \
})
#define	WRITE_GD_REG(GD_hi, GD_lo) \
({ \
	WRITE_GD_REG_VALUE(GD_hi.GD_hi_half, GD_lo.GD_lo_half); \
})
#define	BOOT_WRITE_GD_REG(GD_hi, GD_lo) \
({ \
	BOOT_WRITE_GD_REG_VALUE(GD_hi.GD_hi_half, GD_lo.GD_lo_half); \
})

static inline void
write_GD_hi_lo_reg(e2k_gd_hi_t GD_hi, e2k_gd_lo_t GD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write GD_hi register 0x%lx\n", GD_hi.GD_hi_half);
	boot_printk("Write GD_lo register 0x%lx\n", GD_lo.GD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_GD_REG(GD_hi, GD_lo);
}

/*
 * Write quad-word Globals Register (GD) from the structure
 * Register fields filling:		GD.GD_xxx = fff;
 * Register double-word halfs filling:	GD.GD_lo_reg = GD_lo;
 *					GD.GD_hi_reg = GD_hi;
 */
static inline void
write_GD_reg(gd_struct_t GD)
{
	WRITE_GD_REG(GD.GD_hi_struct, GD.GD_lo_struct);
}

/*
 * Read quad-word Procedure Stack Pointer Register (PSP) to the structure
 * Register fields access:		PSP_hi = READ_PSP_HI_REG();
 *					fff = PSP_hi.PSP_hi_xxx;
 *					PSP_lo = READ_PSP_LO_REG();
 *					fff = PSP_lo.PSP_lo_xxx;
 */

#define	NATIVE_NV_READ_PSP_LO_REG() \
({ \
	e2k_psp_lo_t	PSP_lo; \
	PSP_lo.PSP_lo_half = NATIVE_NV_READ_PSP_LO_REG_VALUE(); \
	PSP_lo; \
})
#define	NATIVE_NV_READ_PSP_HI_REG() \
({ \
	e2k_psp_hi_t	PSP_hi; \
	PSP_hi.PSP_hi_half = NATIVE_NV_READ_PSP_HI_REG_VALUE(); \
	PSP_hi; \
})
#define	NATIVE_NV_READ_PSP_REG() \
({ \
	psp_struct_t	PSP; \
	PSP.PSP_hi_struct = NATIVE_NV_READ_PSP_HI_REG(); \
	PSP.PSP_lo_struct = NATIVE_NV_READ_PSP_LO_REG(); \
	PSP; \
})
#define	NATIVE_NV_READ_PSP_REG_TO(PSP) \
({ \
	*PSP = NATIVE_NV_READ_PSP_REG(); \
})

#define	READ_PSP_LO_REG() \
({ \
	e2k_psp_lo_t	PSP_lo; \
	PSP_lo.PSP_lo_half = READ_PSP_LO_REG_VALUE(); \
	PSP_lo; \
})
#define	READ_PSP_HI_REG() \
({ \
	e2k_psp_hi_t	PSP_hi; \
	PSP_hi.PSP_hi_half = READ_PSP_HI_REG_VALUE(); \
	PSP_hi; \
})
#define	READ_PSP_REG() \
({ \
	psp_struct_t	PSP; \
	PSP.PSP_hi_struct = READ_PSP_HI_REG(); \
	PSP.PSP_lo_struct = READ_PSP_LO_REG(); \
	PSP; \
})
#define	READ_PSP_REG_TO(PSP) \
({ \
	*PSP = READ_PSP_REG(); \
})

#define	BOOT_READ_PSP_LO_REG() \
({ \
	e2k_psp_lo_t	PSP_lo; \
	PSP_lo.PSP_lo_half = BOOT_READ_PSP_LO_REG_VALUE(); \
	PSP_lo; \
})
#define	BOOT_READ_PSP_HI_REG() \
({ \
	e2k_psp_hi_t	PSP_hi; \
	PSP_hi.PSP_hi_half = BOOT_READ_PSP_HI_REG_VALUE(); \
	PSP_hi; \
})
#define	BOOT_READ_PSP_REG() \
({ \
	psp_struct_t	PSP; \
	PSP.PSP_hi_struct = BOOT_READ_PSP_HI_REG(); \
	PSP.PSP_lo_struct = BOOT_READ_PSP_LO_REG(); \
	PSP; \
})
#define	BOOT_READ_PSP_REG_TO(PSP) \
({ \
	*PSP = BOOT_READ_PSP_REG(); \
})

/*
 * Read low double-word Procedure Stack Pointer Register (PSP)
 * from the low word structure
 * Register fields access:		fff = PSP_lo.PSP_lo_xxx;
 * Register double-word half access:	psp_lo = PSP_lo.PSP_lo_half;
 */
static	inline	e2k_psp_lo_t
native_nv_read_PSP_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PSP_lo register 0x%lx\n",
			NATIVE_NV_READ_PSP_LO_REG().PSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_PSP_LO_REG();
}
static	inline	e2k_psp_lo_t
read_PSP_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PSP_lo register 0x%lx\n",
			READ_PSP_LO_REG().PSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_PSP_LO_REG();
}
static	inline	e2k_psp_lo_t
boot_read_PSP_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PSP_lo register 0x%lx\n",
			BOOT_READ_PSP_LO_REG().PSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_PSP_LO_REG();
}

/*
 * Read high double-word Procedure Stack Pointer Register (PSP)
 * from the high word structure
 * Register fields access:		fff = PSP_hi.PSP_hi_xxx;
 * Register double-word half access:	psp_lo = PSP_hi.PSP_hi_half;
 */
static	inline	e2k_psp_hi_t
native_nv_read_PSP_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PSP_hi register 0x%lx\n",
			NATIVE_NV_READ_PSP_HI_REG().PSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_PSP_HI_REG();
}
static	inline	e2k_psp_hi_t
read_PSP_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PSP_hi register 0x%lx\n",
			READ_PSP_HI_REG().PSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_PSP_HI_REG();
}
static	inline	e2k_psp_hi_t
boot_read_PSP_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PSP_hi register 0x%lx\n",
			BOOT_READ_PSP_HI_REG().PSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_PSP_HI_REG();
}

/*
 * Read quad-word Procedure Stack Pointer Register (PSP) to the structure
 * Register fields access:		fff = PSP -> PSP_xxx
 * Register double-word halfs access:	PSP_lo_word = PSP -> PSP_lo_reg
 *					PSP_hi_word = PSP -> PSP_hi_reg
 */
static inline void
native_nv_read_PSP_reg(psp_struct_t *PSP)
{
	NATIVE_NV_READ_PSP_REG_TO(PSP);
}
static inline void
read_PSP_reg(psp_struct_t *PSP)
{
	READ_PSP_REG_TO(PSP);
}
static inline void
boot_read_PSP_reg(psp_struct_t *PSP)
{
	BOOT_READ_PSP_REG_TO(PSP);
}

/*
 * Write low double-word Procedure Stack Pointer Register (PSP)
 * from the low word structure
 * Register fields filling:		PSP_lo.PSP_lo_xxx = fff;
 * Register double-word half filling:	PSP_lo.PSP_lo_half = psp_lo;
 */
#define	NATIVE_NV_WRITE_PSP_LO_REG(PSP_lo) \
({ \
	NATIVE_NV_WRITE_PSP_LO_REG_VALUE(PSP_lo.PSP_lo_half); \
})
#define	WRITE_PSP_LO_REG(PSP_lo) \
({ \
	WRITE_PSP_LO_REG_VALUE(PSP_lo.PSP_lo_half); \
})
#define	BOOT_WRITE_PSP_LO_REG(PSP_lo) \
({ \
	BOOT_WRITE_PSP_LO_REG_VALUE(PSP_lo.PSP_lo_half); \
})

static inline void
native_nv_write_PSP_lo_reg(e2k_psp_lo_t PSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PSP_lo register 0x%lx\n", PSP_lo.PSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_WRITE_PSP_LO_REG(PSP_lo);
}
static inline void
write_PSP_lo_reg(e2k_psp_lo_t PSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PSP_lo register 0x%lx\n", PSP_lo.PSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_PSP_LO_REG(PSP_lo);
}

static inline void
boot_write_PSP_lo_reg(e2k_psp_lo_t PSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PSP_lo register 0x%lx\n", PSP_lo.PSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	BOOT_WRITE_PSP_LO_REG(PSP_lo);
}

/*
 * Write high double-word Procedure Stack Pointer Register (PSP)
 * from the high word structure
 * Register fields filling:		PSP_hi.PSP_hi_xxx = fff;
 * Register double-word half filling:	PSP_hi.PSP_hi_half = psp_lo;
 */
#define	NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG(PSP_hi) \
({ \
	NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG_VALUE(PSP_hi.PSP_hi_half); \
})
#define	WRITE_PSP_HI_REG(PSP_hi) \
({ \
	WRITE_PSP_HI_REG_VALUE(PSP_hi.PSP_hi_half); \
})
#define	BOOT_WRITE_PSP_HI_REG(PSP_hi) \
({ \
	BOOT_WRITE_PSP_HI_REG_VALUE(PSP_hi.PSP_hi_half); \
})

static inline void
native_nv_noirq_write_PSP_hi_reg(e2k_psp_hi_t PSP_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PSP_hi register 0x%lx\n", PSP_hi.PSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG(PSP_hi);
}
static inline void
write_PSP_hi_reg(e2k_psp_hi_t PSP_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PSP_hi register 0x%lx\n", PSP_hi.PSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_PSP_HI_REG(PSP_hi);
}

static inline void
boot_write_PSP_hi_reg(e2k_psp_hi_t PSP_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PSP_hi register 0x%lx\n", PSP_hi.PSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	BOOT_WRITE_PSP_HI_REG(PSP_hi);
}

/*
 * Write high & low quad-word Procedure Stack Pointer Register (PSP)
 * from the high & low word structure
 */

#define	NATIVE_NV_WRITE_PSP_REG_VALUE(PSP_hi_value, PSP_lo_value) \
({ \
	NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG_VALUE(PSP_hi_value); \
	NATIVE_NV_WRITE_PSP_LO_REG_VALUE(PSP_lo_value); \
})
#define	NATIVE_NV_WRITE_PSP_REG(PSP_hi, PSP_lo) \
({ \
	NATIVE_NV_WRITE_PSP_REG_VALUE(PSP_hi.PSP_hi_half, PSP_lo.PSP_lo_half); \
})
#define	WRITE_PSP_REG_VALUE(PSP_hi_value, PSP_lo_value) \
({ \
	WRITE_PSP_HI_REG_VALUE(PSP_hi_value); \
	WRITE_PSP_LO_REG_VALUE(PSP_lo_value); \
})
#define	WRITE_PSP_REG(PSP_hi, PSP_lo) \
({ \
	WRITE_PSP_REG_VALUE(PSP_hi.PSP_hi_half, PSP_lo.PSP_lo_half); \
})
#define	BOOT_WRITE_PSP_REG_VALUE(PSP_hi_value, PSP_lo_value) \
({ \
	BOOT_WRITE_PSP_HI_REG_VALUE(PSP_hi_value); \
	BOOT_WRITE_PSP_LO_REG_VALUE(PSP_lo_value); \
})
#define	BOOT_WRITE_PSP_REG(PSP_hi, PSP_lo) \
({ \
	BOOT_WRITE_PSP_REG_VALUE(PSP_hi.PSP_hi_half, PSP_lo.PSP_lo_half); \
})

static inline void
native_nv_write_PSP_hi_lo_reg(e2k_psp_hi_t PSP_hi, e2k_psp_lo_t PSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PSP_hi register 0x%lx\n", PSP_hi.PSP_hi_half);
	boot_printk("Write PSP_lo register 0x%lx\n", PSP_lo.PSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_WRITE_PSP_REG(PSP_hi, PSP_lo);
}
static inline void
write_PSP_hi_lo_reg(e2k_psp_hi_t PSP_hi, e2k_psp_lo_t PSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PSP_hi register 0x%lx\n", PSP_hi.PSP_hi_half);
	boot_printk("Write PSP_lo register 0x%lx\n", PSP_lo.PSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_PSP_REG(PSP_hi, PSP_lo);
}
static inline void
boot_write_PSP_hi_lo_reg(e2k_psp_hi_t PSP_hi, e2k_psp_lo_t PSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PSP_hi register 0x%lx\n", PSP_hi.PSP_hi_half);
	boot_printk("Write PSP_lo register 0x%lx\n", PSP_lo.PSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	BOOT_WRITE_PSP_REG(PSP_hi, PSP_lo);
}

/*
 * Write quad-word Procedure Stack Pointer Register (PSP) from the structure
 * Register fields filling:		PSP.PSP_xxx = fff;
 * Register double-word halfs filling:	PSP.PSP_lo_reg = PSP_lo;
 *					PSP.PSP_hi_reg = PSP_hi;
 */
static inline void
native_nv_write_PSP_reg(psp_struct_t PSP)
{
	NATIVE_NV_WRITE_PSP_REG(PSP.PSP_hi_struct, PSP.PSP_lo_struct);
}
static inline void
write_PSP_reg(psp_struct_t PSP)
{
	WRITE_PSP_REG(PSP.PSP_hi_struct, PSP.PSP_lo_struct);
}
static inline void
boot_write_PSP_reg(psp_struct_t PSP)
{
	BOOT_WRITE_PSP_REG(PSP.PSP_hi_struct, PSP.PSP_lo_struct);
}


/*
 * Read quad-word Procedure Chain Stack Pointer Register (PCSP) to the structure
 * Register fields access:		PCSP_hi = READ_PCSP_HI_REG();
 *					fff = PCSP_hi.PCSP_hi_xxx;
 *					PCSP_lo = READ_PCSP_LO_REG();
 *					fff = PCSP_lo.PCSP_lo_xxx;
 */

#define	NATIVE_NV_READ_PCSP_LO_REG() \
({ \
	e2k_pcsp_lo_t PCSP_lo; \
	PCSP_lo.PCSP_lo_half = NATIVE_NV_READ_PCSP_LO_REG_VALUE(); \
	PCSP_lo; \
})
#define	NATIVE_NV_READ_PCSP_HI_REG() \
({ \
	e2k_pcsp_hi_t PCSP_hi; \
	PCSP_hi.PCSP_hi_half = NATIVE_NV_READ_PCSP_HI_REG_VALUE(); \
	PCSP_hi; \
})
#define	READ_PCSP_LO_REG() \
({ \
	e2k_pcsp_lo_t PCSP_lo; \
	PCSP_lo.PCSP_lo_half = READ_PCSP_LO_REG_VALUE(); \
	PCSP_lo; \
})
#define	READ_PCSP_HI_REG() \
({ \
	e2k_pcsp_hi_t PCSP_hi; \
	PCSP_hi.PCSP_hi_half = READ_PCSP_HI_REG_VALUE(); \
	PCSP_hi; \
})
#define	NATIVE_NV_READ_PCSP_REG() \
({ \
	pcsp_struct_t	PCSP; \
	PCSP.PCSP_hi_struct = NATIVE_NV_READ_PCSP_HI_REG(); \
	PCSP.PCSP_lo_struct = NATIVE_NV_READ_PCSP_LO_REG(); \
	PCSP; \
})
#define	NATIVE_NV_READ_PCSP_REG_TO(PCSP) \
({ \
	*PCSP = NATIVE_NV_READ_PCSP_REG(); \
})
#define	READ_PCSP_REG() \
({ \
	pcsp_struct_t	PCSP; \
	PCSP.PCSP_hi_struct = READ_PCSP_HI_REG(); \
	PCSP.PCSP_lo_struct = READ_PCSP_LO_REG(); \
	PCSP; \
})
#define	READ_PCSP_REG_TO(PCSP) \
({ \
	*PCSP = READ_PCSP_REG(); \
})
#define	BOOT_READ_PCSP_LO_REG() \
({ \
	e2k_pcsp_lo_t PCSP_lo; \
	PCSP_lo.PCSP_lo_half = BOOT_READ_PCSP_LO_REG_VALUE(); \
	PCSP_lo; \
})
#define	BOOT_READ_PCSP_HI_REG() \
({ \
	e2k_pcsp_hi_t PCSP_hi; \
	PCSP_hi.PCSP_hi_half = BOOT_READ_PCSP_HI_REG_VALUE(); \
	PCSP_hi; \
})
#define	BOOT_READ_PCSP_REG() \
({ \
	pcsp_struct_t	PCSP; \
	PCSP.PCSP_hi_struct = BOOT_READ_PCSP_HI_REG(); \
	PCSP.PCSP_lo_struct = BOOT_READ_PCSP_LO_REG(); \
	PCSP; \
})
#define	BOOT_READ_PCSP_REG_TO(PCSP) \
({ \
	*PCSP = BOOT_READ_PCSP_REG(); \
})

/*
 * Read low double-word Procedure Chain Stack Pointer Register (PCSP)
 * from the low word structure
 * Register fields access:		fff = PCSP_lo.PCSP_lo_xxx;
 * Register double-word half access:	pcsp_lo = PCSP_lo.PCSP_lo_half;
 */
static	inline	e2k_pcsp_lo_t
native_nv_read_PCSP_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PCSP_lo register 0x%lx\n",
			NATIVE_NV_READ_PCSP_LO_REG().PCSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_PCSP_LO_REG();
}
static	inline	e2k_pcsp_lo_t
read_PCSP_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PCSP_lo register 0x%lx\n",
			READ_PCSP_LO_REG().PCSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_PCSP_LO_REG();
}
static	inline	e2k_pcsp_lo_t
boot_read_PCSP_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PCSP_lo register 0x%lx\n",
			BOOT_READ_PCSP_LO_REG().PCSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_PCSP_LO_REG();
}

/*
 * Read high double-word Procedure Chain Stack Pointer Register (PCSP)
 * from the high word structure
 * Register fields access:		fff = PCSP_hi.PCSP_hi_xxx;
 * Register double-word half access:	pcsp_lo = PCSP_hi.PCSP_hi_half;
 */
static	inline	e2k_pcsp_hi_t
native_nv_read_PCSP_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PCSP_hi register 0x%lx\n",
			NATIVE_NV_READ_PCSP_HI_REG().PCSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_PCSP_HI_REG();
}
static	inline	e2k_pcsp_hi_t
read_PCSP_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PCSP_hi register 0x%lx\n",
			READ_PCSP_HI_REG().PCSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_PCSP_HI_REG();
}
static	inline	e2k_pcsp_hi_t
boot_read_PCSP_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PCSP_hi register 0x%lx\n",
			BOOT_READ_PCSP_HI_REG().PCSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_PCSP_HI_REG();
}

/*
 * Read quad-word Procedure Chain Stack Pointer Register (PCSP) to the structure
 * Register fields access:		fff = PCSP -> PCSP_xxx
 * Register double-word halfs access:	PCSP_lo_word = PCSP -> PCSP_lo_reg
 *					PCSP_hi_word = PCSP -> PCSP_hi_reg
 */

static inline void
native_nv_read_PCSP_reg(pcsp_struct_t *PCSP)
{
	NATIVE_NV_READ_PCSP_REG_TO(PCSP);
}
static inline void
read_PCSP_reg(pcsp_struct_t *PCSP)
{
	READ_PCSP_REG_TO(PCSP);
}
static inline void
boot_read_PCSP_reg(pcsp_struct_t *PCSP)
{
	BOOT_READ_PCSP_REG_TO(PCSP);
}

/*
 * Write low double-word Procedure Chain Stack Pointer Register (PCSP)
 * from the low word structure
 * Register fields filling:		PCSP_lo.PCSP_lo_xxx = fff;
 * Register double-word half filling:	PCSP_lo.PCSP_lo_half = pcsp_lo;
 */
#define	NATIVE_NV_WRITE_PCSP_LO_REG(PCSP_lo) \
({ \
	NATIVE_NV_WRITE_PCSP_LO_REG_VALUE(PCSP_lo.PCSP_lo_half); \
})
#define	WRITE_PCSP_LO_REG(PCSP_lo) \
({ \
	WRITE_PCSP_LO_REG_VALUE(PCSP_lo.PCSP_lo_half); \
})
#define	BOOT_WRITE_PCSP_LO_REG(PCSP_lo) \
({ \
	BOOT_WRITE_PCSP_LO_REG_VALUE(PCSP_lo.PCSP_lo_half); \
})

static inline void
native_nv_write_PCSP_lo_reg(e2k_pcsp_lo_t PCSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PCSP_lo register 0x%lx\n", PCSP_lo.PCSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_WRITE_PCSP_LO_REG(PCSP_lo);
}
static inline void
write_PCSP_lo_reg(e2k_pcsp_lo_t PCSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PCSP_lo register 0x%lx\n", PCSP_lo.PCSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_PCSP_LO_REG(PCSP_lo);
}
static inline void
boot_write_PCSP_lo_reg(e2k_pcsp_lo_t PCSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PCSP_lo register 0x%lx\n", PCSP_lo.PCSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	BOOT_WRITE_PCSP_LO_REG(PCSP_lo);
}

/*
 * Write high double-word Procedure Chain Stack Pointer Register (PCSP)
 * from the high word structure
 * Register fields filling:		PCSP_hi.PCSP_hi_xxx = fff;
 * Register double-word half filling:	PCSP_hi.PCSP_hi_half = pcsp_lo;
 */
#define	NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG(PCSP_hi) \
({ \
	NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG_VALUE(PCSP_hi.PCSP_hi_half); \
})
#define	WRITE_PCSP_HI_REG(PCSP_hi) \
({ \
	WRITE_PCSP_HI_REG_VALUE(PCSP_hi.PCSP_hi_half); \
})
#define	BOOT_WRITE_PCSP_HI_REG(PCSP_hi) \
({ \
	BOOT_WRITE_PCSP_HI_REG_VALUE(PCSP_hi.PCSP_hi_half); \
})

static inline void
native_nv_noirq_write_PCSP_hi_reg(e2k_pcsp_hi_t PCSP_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PCSP_hi register 0x%lx\n", PCSP_hi.PCSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG(PCSP_hi);
}
static inline void
write_PCSP_hi_reg(e2k_pcsp_hi_t PCSP_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PCSP_hi register 0x%lx\n", PCSP_hi.PCSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_PCSP_HI_REG(PCSP_hi);
}
static inline void
boot_write_PCSP_hi_reg(e2k_pcsp_hi_t PCSP_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PCSP_hi register 0x%lx\n", PCSP_hi.PCSP_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	BOOT_WRITE_PCSP_HI_REG(PCSP_hi);
}

/*
 * Write high & low quad-word Procedure Chain Stack Pointer Register (PCSP)
 * from the high & low word structure
 */

#define	NATIVE_NV_WRITE_PCSP_REG_VALUE(PCSP_hi_value, PCSP_lo_value) \
({ \
	NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value); \
	NATIVE_NV_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value); \
})
#define	WRITE_PCSP_REG_VALUE(PCSP_hi_value, PCSP_lo_value) \
({ \
	WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value); \
	WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value); \
})
#define	BOOT_WRITE_PCSP_REG_VALUE(PCSP_hi_value, PCSP_lo_value) \
({ \
	BOOT_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value); \
	BOOT_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value); \
})
#define	NATIVE_NV_WRITE_PCSP_REG(PCSP_hi, PCSP_lo) \
({ \
	NATIVE_NV_WRITE_PCSP_REG_VALUE(PCSP_hi.PCSP_hi_half, \
					PCSP_lo.PCSP_lo_half); \
})
#define	WRITE_PCSP_REG(PCSP_hi, PCSP_lo) \
({ \
	WRITE_PCSP_REG_VALUE(PCSP_hi.PCSP_hi_half, \
					PCSP_lo.PCSP_lo_half); \
})
#define	BOOT_WRITE_PCSP_REG(PCSP_hi, PCSP_lo) \
({ \
	BOOT_WRITE_PCSP_REG_VALUE(PCSP_hi.PCSP_hi_half, \
					PCSP_lo.PCSP_lo_half); \
})

static inline void
native_nv_write_PCSP_hi_lo_reg(e2k_pcsp_hi_t PCSP_hi, e2k_pcsp_lo_t PCSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PCSP_hi register 0x%lx\n", PCSP_hi.PCSP_hi_half);
	boot_printk("Write PCSP_lo register 0x%lx\n", PCSP_lo.PCSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_WRITE_PCSP_REG(PCSP_hi, PCSP_lo);
}
static inline void
write_PCSP_hi_lo_reg(e2k_pcsp_hi_t PCSP_hi, e2k_pcsp_lo_t PCSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PCSP_hi register 0x%lx\n", PCSP_hi.PCSP_hi_half);
	boot_printk("Write PCSP_lo register 0x%lx\n", PCSP_lo.PCSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_PCSP_REG(PCSP_hi, PCSP_lo);
}
static inline void
boot_write_PCSP_hi_lo_reg(e2k_pcsp_hi_t PCSP_hi, e2k_pcsp_lo_t PCSP_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PCSP_hi register 0x%lx\n", PCSP_hi.PCSP_hi_half);
	boot_printk("Write PCSP_lo register 0x%lx\n", PCSP_lo.PCSP_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	BOOT_WRITE_PCSP_REG(PCSP_hi, PCSP_lo);
}

/*
 * Write quad-word Procedure Chain Stack Pointer Register (PCSP) from the
 * structure
 * Register fields filling:		PCSP.PCSP_xxx = fff;
 * Register double-word halfs filling:	PCSP.PCSP_lo_reg = PCSP_lo;
 *					PCSP.PCSP_hi_reg = PCSP_hi;
 */
static inline void
native_nv_write_PCSP_reg(pcsp_struct_t PCSP)
{
	NATIVE_NV_WRITE_PCSP_REG(PCSP.PCSP_hi_struct, PCSP.PCSP_lo_struct);
}
static inline void
write_PCSP_reg(pcsp_struct_t PCSP)
{
	WRITE_PCSP_REG(PCSP.PCSP_hi_struct, PCSP.PCSP_lo_struct);
}
static inline void
boot_write_PCSP_reg(pcsp_struct_t PCSP)
{
	BOOT_WRITE_PCSP_REG(PCSP.PCSP_hi_struct, PCSP.PCSP_lo_struct);
}

/*
 * Read Current Chain Register (CR0/CR1) to the structure
 * Register fields access:		crX_hi = READ_CRx_HI_REG();
 *					fff = CRx_hi.CRx_hi_xxx;
 *					CRx_lo = READ_CRx_LO_REG();
 *					fff = CRx_lo.CRx_lo_xxx;
 */

#define	NATIVE_NV_READ_CR0_LO_REG() \
({ \
	e2k_cr0_lo_t CR0_lo; \
	CR0_lo.CR0_lo_half = NATIVE_NV_READ_CR0_LO_REG_VALUE(); \
	CR0_lo; \
})
#define	NATIVE_NV_READ_CR0_HI_REG() \
({ \
	e2k_cr0_hi_t CR0_hi; \
	CR0_hi.CR0_hi_half = NATIVE_NV_READ_CR0_HI_REG_VALUE(); \
	CR0_hi; \
})
#define	NATIVE_NV_READ_CR1_LO_REG() \
({ \
	e2k_cr1_lo_t CR1_lo; \
	CR1_lo.CR1_lo_half = NATIVE_NV_READ_CR1_LO_REG_VALUE(); \
	CR1_lo; \
})
#define	NATIVE_NV_READ_CR1_HI_REG() \
({ \
	e2k_cr1_hi_t CR1_hi; \
	CR1_hi.CR1_hi_half = NATIVE_NV_READ_CR1_HI_REG_VALUE(); \
	CR1_hi; \
})
#define	READ_CR0_LO_REG() \
({ \
	e2k_cr0_lo_t CR0_lo; \
	CR0_lo.CR0_lo_half = READ_CR0_LO_REG_VALUE(); \
	CR0_lo; \
})
#define	READ_CR0_HI_REG() \
({ \
	e2k_cr0_hi_t CR0_hi; \
	CR0_hi.CR0_hi_half = READ_CR0_HI_REG_VALUE(); \
	CR0_hi; \
})
#define	READ_CR1_LO_REG() \
({ \
	e2k_cr1_lo_t CR1_lo; \
	CR1_lo.CR1_lo_half = READ_CR1_LO_REG_VALUE(); \
	CR1_lo; \
})
#define	READ_CR1_HI_REG() \
({ \
	e2k_cr1_hi_t CR1_hi; \
	CR1_hi.CR1_hi_half = READ_CR1_HI_REG_VALUE(); \
	CR1_hi; \
})

static	inline	e2k_cr0_lo_t
native_nv_read_CR0_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read CR0_lo register 0x%lx\n",
			NATIVE_NV_READ_CR0_LO_REG().CR0_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_CR0_LO_REG();
}
static	inline	e2k_cr0_hi_t
native_nv_read_CR0_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read CR0_hi register 0x%lx\n",
			NATIVE_NV_READ_CR0_HI_REG().CR0_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_CR0_HI_REG();
}

static	inline	e2k_cr1_lo_t
native_nv_read_CR1_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read CR1_lo register 0x%lx\n",
			NATIVE_NV_READ_CR1_LO_REG().CR1_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_CR1_LO_REG();
}
static	inline	e2k_cr1_hi_t
native_nv_read_CR1_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read CR1_hi register 0x%lx\n",
			NATIVE_NV_READ_CR1_HI_REG().CR1_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_CR1_HI_REG();
}
static	inline	e2k_cr0_lo_t
read_CR0_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read CR0_lo register 0x%lx\n",
			READ_CR0_LO_REG().CR0_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_CR0_LO_REG();
}
static	inline	e2k_cr0_hi_t
read_CR0_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read CR0_hi register 0x%lx\n",
			READ_CR0_HI_REG().CR0_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_CR0_HI_REG();
}

static	inline	e2k_cr1_lo_t
read_CR1_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read CR1_lo register 0x%lx\n",
			READ_CR1_LO_REG().CR1_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_CR1_LO_REG();
}
static	inline	e2k_cr1_hi_t
read_CR1_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read CR1_hi register 0x%lx\n",
			READ_CR1_HI_REG().CR1_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_CR1_HI_REG();
}

/*
 * Write Current Chain Register (CR0/CR1)
 * from the low word structure
 * Register fields filling:		CRx_lo.CRx_lo_xxx = fff;
 * Register double-word half filling:	CRx_lo.CRx_lo_half = crX_lo;
 */
#define	NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG(CR0_lo) \
({ \
	NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG_VALUE(CR0_lo.CR0_lo_half); \
})
#define	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(CR0_hi) \
({ \
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG_VALUE(CR0_hi.CR0_hi_half); \
})
#define	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(CR1_lo) \
({ \
	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG_VALUE(CR1_lo.CR1_lo_half); \
})
#define	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG(CR1_hi) \
({ \
	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG_VALUE(CR1_hi.CR1_hi_half); \
})
#define	WRITE_CR0_LO_REG(CR0_lo) \
({ \
	WRITE_CR0_LO_REG_VALUE(CR0_lo.CR0_lo_half); \
})
#define	WRITE_CR0_HI_REG(CR0_hi) \
({ \
	WRITE_CR0_HI_REG_VALUE(CR0_hi.CR0_hi_half); \
})
#define	WRITE_CR1_LO_REG(CR1_lo) \
({ \
	WRITE_CR1_LO_REG_VALUE(CR1_lo.CR1_lo_half); \
})
#define	WRITE_CR1_HI_REG(CR1_hi) \
({ \
	WRITE_CR1_HI_REG_VALUE(CR1_hi.CR1_hi_half); \
})
static inline void
native_nv_noirq_write_CR0_lo_reg(e2k_cr0_lo_t CR0_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CR0_lo register 0x%lx\n", CR0_lo.CR0_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG(CR0_lo);
}
static inline void
native_nv_noirq_write_CR0_hi_reg(e2k_cr0_hi_t CR0_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CR0_hi register 0x%lx\n", CR0_hi.CR0_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(CR0_hi);
}
static inline void
native_nv_noirq_write_CR1_lo_reg(e2k_cr1_lo_t CR1_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CR1_lo register 0x%lx\n", CR1_lo.CR1_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(CR1_lo);
}
static inline void
native_nv_noirq_write_CR1_hi_reg(e2k_cr1_hi_t CR1_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CR1_hi register 0x%lx\n", CR1_hi.CR1_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG(CR1_hi);
}
static inline void
write_CR0_lo_reg(e2k_cr0_lo_t CR0_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CR0_lo register 0x%lx\n", CR0_lo.CR0_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_CR0_LO_REG(CR0_lo);
}
static inline void
write_CR0_hi_reg(e2k_cr0_hi_t CR0_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CR0_hi register 0x%lx\n", CR0_hi.CR0_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_CR0_HI_REG(CR0_hi);
}
static inline void
write_CR1_lo_reg(e2k_cr1_lo_t CR1_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CR1_lo register 0x%lx\n", CR1_lo.CR1_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_CR1_LO_REG(CR1_lo);
}
static inline void
write_CR1_hi_reg(e2k_cr1_hi_t CR1_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write CR1_hi register 0x%lx\n", CR1_hi.CR1_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_CR1_HI_REG(CR1_hi);
}

/*
 * Read double-word Control Transfer Preparation Registers (CTPR1/CTPR2/CTPR3)
 * to the structure
 * Register fields access:		fff = CTPRn -> CTPRn_xxx
 * Register entire access:		CTPRn_entire = CTPRn -> CTPRn_reg
 */
#define	NATIVE_NV_READ_CTPR1_REG_VALUE()	NATIVE_NV_READ_CTPR_REG_VALUE(1)
#define	NATIVE_NV_READ_CTPR2_REG_VALUE()	NATIVE_NV_READ_CTPR_REG_VALUE(2)
#define	NATIVE_NV_READ_CTPR3_REG_VALUE()	NATIVE_NV_READ_CTPR_REG_VALUE(3)
#define	READ_CTPR1_REG_VALUE()		READ_CTPR_REG_VALUE(1)
#define	READ_CTPR2_REG_VALUE()		READ_CTPR_REG_VALUE(2)
#define	READ_CTPR3_REG_VALUE()		READ_CTPR_REG_VALUE(3)
#define	NATIVE_NV_READ_CTPR_REG(reg_no) \
({ \
	e2k_ctpr_t CTPR; \
	CTPR.CTPR_reg = NATIVE_NV_READ_CTPR_REG_VALUE(reg_no); \
	CTPR; \
})
#define	NATIVE_NV_READ_CTPR1_REG()		NATIVE_NV_READ_CTPR_REG(1)
#define	NATIVE_NV_READ_CTPR2_REG()		NATIVE_NV_READ_CTPR_REG(2)
#define	NATIVE_NV_READ_CTPR3_REG()		NATIVE_NV_READ_CTPR_REG(3)
#define	READ_CTPR_REG(reg_no) \
({ \
	e2k_ctpr_t CTPR; \
	CTPR.CTPR_reg = READ_CTPR_REG_VALUE(reg_no); \
	CTPR; \
})
#define	READ_CTPR1_REG()		READ_CTPR_REG(1)
#define	READ_CTPR2_REG()		READ_CTPR_REG(2)
#define	READ_CTPR3_REG()		READ_CTPR_REG(3)
static	inline	e2k_ctpr_t
read_CTPR_reg(int reg_no)
{
	switch (reg_no) {
	case 1: return READ_CTPR1_REG();
	case 2: return READ_CTPR2_REG();
	case 3: return READ_CTPR3_REG();
	default:
		return READ_CTPR1_REG();
	}
}
static	inline	e2k_ctpr_t
read_CTPR1_reg(void)
{
	return read_CTPR_reg(1);
}
static	inline	e2k_ctpr_t
read_CTPR2_reg(void)
{
	return read_CTPR_reg(2);
}
static	inline	e2k_ctpr_t
read_CTPR3_reg(void)
{
	return read_CTPR_reg(3);
}

#define	NATIVE_READ_CTPR1_HI_REG_VALUE() NATIVE_READ_CTPR_HI_REG_VALUE(1)
#define	NATIVE_READ_CTPR2_HI_REG_VALUE() NATIVE_READ_CTPR_HI_REG_VALUE(2)
#define	NATIVE_READ_CTPR3_HI_REG_VALUE() NATIVE_READ_CTPR_HI_REG_VALUE(3)

/*
 * Write double-word Control Transfer Preparation Registers (CTPR1/CTPR2/CTPR3)
 * from the structure
 * Register fields filling:		CTPRn.CTPR_xxx = fff;
 * Register entire filling:		CTPRn.CTPR_reg = CTPRn_value;
 */
#define	NATIVE_WRITE_CTPR1_REG_VALUE(CTPR_value)		\
		NATIVE_WRITE_CTPR_REG_VALUE(1, CTPR_value)
#define	NATIVE_WRITE_CTPR2_REG_VALUE(CTPR_value)		\
		NATIVE_WRITE_CTPR_REG_VALUE(2, CTPR_value)
#define	NATIVE_WRITE_CTPR3_REG_VALUE(CTPR_value)		\
		NATIVE_WRITE_CTPR_REG_VALUE(3, CTPR_value)
#define	NATIVE_WRITE_CTPR_REG(reg_no, CTPR)			\
		NATIVE_WRITE_CTPR_REG_VALUE(reg_no, CTPR.CTPR_reg)
#define	NATIVE_WRITE_CTPR1_REG(CTPR)	NATIVE_WRITE_CTPR_REG(1, CTPR)
#define	NATIVE_WRITE_CTPR2_REG(CTPR)	NATIVE_WRITE_CTPR_REG(2, CTPR)
#define	NATIVE_WRITE_CTPR3_REG(CTPR)	NATIVE_WRITE_CTPR_REG(3, CTPR)
#define	WRITE_CTPR1_REG_VALUE(CTPR_value)		\
		WRITE_CTPR_REG_VALUE(1, CTPR_value)
#define	WRITE_CTPR2_REG_VALUE(CTPR_value)		\
		WRITE_CTPR_REG_VALUE(2, CTPR_value)
#define	WRITE_CTPR3_REG_VALUE(CTPR_value)		\
		WRITE_CTPR_REG_VALUE(3, CTPR_value)
#define	WRITE_CTPR_REG(reg_no, CTPR)			\
		WRITE_CTPR_REG_VALUE(reg_no, CTPR.CTPR_reg)
#define	WRITE_CTPR1_REG(CTPR)	WRITE_CTPR_REG(1, CTPR)
#define	WRITE_CTPR2_REG(CTPR)	WRITE_CTPR_REG(2, CTPR)
#define	WRITE_CTPR3_REG(CTPR)	WRITE_CTPR_REG(3, CTPR)

static inline void
write_CTPR_reg(int reg_no, e2k_ctpr_t CTPR)
{
	switch (reg_no) {
	case 1:
		WRITE_CTPR1_REG(CTPR);
		break;
	case 2:
		WRITE_CTPR2_REG(CTPR);
		break;
	case 3:
		WRITE_CTPR3_REG(CTPR);
		break;
	default:
		break;
	}
}
static inline void
write_CTPR1_reg(e2k_ctpr_t CTPR)
{
	write_CTPR_reg(1, CTPR);
}
static inline void
write_CTPR2_reg(e2k_ctpr_t CTPR)
{
	write_CTPR_reg(2, CTPR);
}
static inline void
write_CTPR3_reg(e2k_ctpr_t CTPR)
{
	write_CTPR_reg(3, CTPR);
}

#define	NATIVE_WRITE_CTPR1_HI_REG_VALUE(CTPR_value)		\
		NATIVE_WRITE_CTPR_HI_REG_VALUE(1, CTPR_value)
#define	NATIVE_WRITE_CTPR2_HI_REG_VALUE(CTPR_value)		\
		NATIVE_WRITE_CTPR_HI_REG_VALUE(2, CTPR_value)
#define	NATIVE_WRITE_CTPR3_HI_REG_VALUE(CTPR_value)		\
		NATIVE_WRITE_CTPR_HI_REG_VALUE(3, CTPR_value)

/*
 * Read signed word-register Procedure Chain Stack Hardware
 * Top Pointer (PCSHTP)
 */

static inline e2k_pcshtp_t
read_PCSHTP_reg(void)
{
	return READ_PCSHTP_REG_SVALUE();
}

/*
 * Write signed word-register Procedure Chain Stack Hardware
 * Top Pointer (PCSHTP)
 */

static inline void
write_PCSHTP_reg(e2k_pcshtp_t PCSHTP)
{
	WRITE_PCSHTP_REG_SVALUE(PCSHTP);
}


/*
 * Read low double-word Non-Protected User Stack Descriptor Register (USD)
 * as the low word structure
 * Register fields access:		USD_lo = READ_USD_LO_REG();
 *					fff = USD_lo.USD_lo_xxx;
 */
#define	NATIVE_NV_READ_USD_LO_REG() \
({ \
	e2k_usd_lo_t	USD_lo; \
	USD_lo.USD_lo_half = NATIVE_NV_READ_USD_LO_REG_VALUE(); \
	USD_lo; \
})
#define	READ_USD_LO_REG() \
({ \
	e2k_usd_lo_t	USD_lo; \
	USD_lo.USD_lo_half = READ_USD_LO_REG_VALUE(); \
	USD_lo; \
})
#define	BOOT_READ_USD_LO_REG() \
({ \
	e2k_usd_lo_t	USD_lo; \
	USD_lo.USD_lo_half = BOOT_READ_USD_LO_REG_VALUE(); \
	USD_lo; \
})

static	inline	e2k_usd_lo_t
native_nv_read_USD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read USD_lo register 0x%lx\n",
			NATIVE_NV_READ_USD_LO_REG().USD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_USD_LO_REG();
}
static	inline	e2k_usd_lo_t
read_USD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read USD_lo register 0x%lx\n",
			READ_USD_LO_REG().USD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_USD_LO_REG();
}
static	inline	e2k_usd_lo_t
boot_read_USD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read USD_lo register 0x%lx\n",
			BOOT_READ_USD_LO_REG().USD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_USD_LO_REG();
}

/*
 * Read high double-word Non-Protected User Stack Descriptor Register (USD)
 * as the high word structure
 * Register fields access:		USD_hi = READ_USD_HI_REG();
 *					fff = USD_hi.USD_hi_xxx;
 */
#define	NATIVE_NV_READ_USD_HI_REG() \
({ \
	e2k_usd_hi_t	USD_hi; \
	USD_hi.USD_hi_half = NATIVE_NV_READ_USD_HI_REG_VALUE(); \
	USD_hi; \
})
#define	READ_USD_HI_REG() \
({ \
	e2k_usd_hi_t	USD_hi; \
	USD_hi.USD_hi_half = READ_USD_HI_REG_VALUE(); \
	USD_hi; \
})
#define	BOOT_READ_USD_HI_REG() \
({ \
	e2k_usd_hi_t	USD_hi; \
	USD_hi.USD_hi_half = BOOT_READ_USD_HI_REG_VALUE(); \
	USD_hi; \
})

static	inline	e2k_usd_hi_t
native_nv_read_USD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read USD_hi register 0x%lx\n",
			NATIVE_NV_READ_USD_HI_REG().USD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_USD_HI_REG();
}
static	inline	e2k_usd_hi_t
read_USD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read USD_hi register 0x%lx\n",
			READ_USD_HI_REG().USD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_USD_HI_REG();
}
static	inline	e2k_usd_hi_t
boot_read_USD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read USD_hi register 0x%lx\n",
			BOOT_READ_USD_HI_REG().USD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return BOOT_READ_USD_HI_REG();
}

/*
 * Read quad-word Non-Protected User Stack Descriptor Register (USD)
 * to the structure
 * Register fields access:		fff = USD -> USD_xxx
 * Register double-word halfs access:	USD_lo = USD -> USD_lo_reg
 *					USD_hi = USD -> USD_hi_reg
 */
#define	READ_USD_REG() \
({ \
	usd_struct_t	USD; \
	USD.USD_hi_struct = READ_USD_HI_REG(); \
	USD.USD_lo_struct = READ_USD_LO_REG(); \
	USD; \
})
#define	READ_USD_REG_TO(USD) \
({ \
	*USD = READ_USD_REG(); \
})
#define	BOOT_READ_USD_REG() \
({ \
	usd_struct_t	USD; \
	USD.USD_hi_struct = BOOT_READ_USD_HI_REG(); \
	USD.USD_lo_struct = BOOT_READ_USD_LO_REG(); \
	USD; \
})
#define	BOOT_READ_USD_REG_TO(USD) \
({ \
	*USD = BOOT_READ_USD_REG(); \
})

static inline void
read_USD_reg(usd_struct_t *USD)
{
	READ_USD_REG_TO(USD);
}
static inline void
boot_read_USD_reg(usd_struct_t *USD)
{
	BOOT_READ_USD_REG_TO(USD);
}

/*
 * Write low double-word Non-Protected User Stack Descriptor Register (USD)
 * from the low word structure
 * Register fields filling:		USD_lo.USD_lo_xxx = fff;
 * Register double-word half filling:	USD_lo.USD_lo_half = usd_lo;
 */
#define	NATIVE_NV_WRITE_USD_LO_REG(USD_lo) \
		NATIVE_NV_WRITE_USD_LO_REG_VALUE(USD_lo.USD_lo_half)
#define	WRITE_USD_LO_REG(USD_lo) \
		WRITE_USD_LO_REG_VALUE(USD_lo.USD_lo_half)
#define	BOOT_WRITE_USD_LO_REG(USD_lo)	\
		BOOT_WRITE_USD_LO_REG_VALUE(USD_lo.USD_lo_half)

static inline void
native_nv_write_USD_lo_reg(e2k_usd_lo_t USD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write USD_lo register 0x%lx\n", USD_lo.USD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_WRITE_USD_LO_REG(USD_lo);
}
static inline void
write_USD_lo_reg(e2k_usd_lo_t USD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write USD_lo register 0x%lx\n", USD_lo.USD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_USD_LO_REG(USD_lo);
}
static inline void
boot_write_USD_lo_reg(e2k_usd_lo_t USD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write USD_lo register 0x%lx\n", USD_lo.USD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	BOOT_WRITE_USD_LO_REG(USD_lo);
}

/*
 * Write high double-word Non-Protected User Stack Descriptor Register (USD)
 * from the high word structure
 * Register fields filling:		USD_hi.USD_hi_xxx = fff;
 * Register double-word half filling:	USD_hi.USD_hi_half = usd_hi;
 */
#define	NATIVE_NV_WRITE_USD_HI_REG(USD_hi) \
		NATIVE_NV_WRITE_USD_HI_REG_VALUE(USD_hi.USD_hi_half)
#define	WRITE_USD_HI_REG(USD_hi) \
		WRITE_USD_HI_REG_VALUE(USD_hi.USD_hi_half)
#define	BOOT_WRITE_USD_HI_REG(USD_hi)	\
		BOOT_WRITE_USD_HI_REG_VALUE(USD_hi.USD_hi_half)

static inline void
native_nv_write_USD_hi_reg(e2k_usd_hi_t USD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write USD_hi register 0x%lx\n", USD_hi.USD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_WRITE_USD_HI_REG(USD_hi);
}
static inline void
write_USD_hi_reg(e2k_usd_hi_t USD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write USD_hi register 0x%lx\n", USD_hi.USD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_USD_HI_REG(USD_hi);
}
static inline void
boot_write_USD_hi_reg(e2k_usd_hi_t USD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write USD_hi register 0x%lx\n", USD_hi.USD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	BOOT_WRITE_USD_HI_REG(USD_hi);
}

/*
 * Write high & low quad-word Non-Protected User Stack Descriptor Register (USD)
 * from the high & low word structure
 */
#define	WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value) \
({ \
	WRITE_USD_HI_REG_VALUE(USD_hi_value); \
	WRITE_USD_LO_REG_VALUE(USD_lo_value); \
})
#define	WRITE_USD_REG(USD_hi, USD_lo) \
({ \
	WRITE_USD_REG_VALUE(USD_hi.USD_hi_half, USD_lo.USD_lo_half); \
})
#define	BOOT_WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value) \
({ \
	BOOT_WRITE_USD_HI_REG_VALUE(USD_hi_value); \
	BOOT_WRITE_USD_LO_REG_VALUE(USD_lo_value); \
})
#define	BOOT_WRITE_USD_REG(USD_hi, USD_lo) \
({ \
	BOOT_WRITE_USD_REG_VALUE(USD_hi.USD_hi_half, USD_lo.USD_lo_half); \
})

#define	WRITE_USBR_USD_REG_VALUE(usbr, USD_hi, USD_lo) \
do { \
	WRITE_USBR_REG_VALUE(usbr); \
	WRITE_USD_REG_VALUE(USD_hi, USD_lo); \
} while (0)

#define	WRITE_USBR_USD_REG(usbr, USD_hi, USD_lo) \
do { \
	WRITE_USBR_REG(usbr); \
	WRITE_USD_REG(USD_hi, USD_lo); \
} while (0)


static inline void
write_USD_hi_lo_reg(e2k_usd_hi_t USD_hi, e2k_usd_lo_t USD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write USD_hi register 0x%lx\n", USD_hi.USD_hi_half);
	boot_printk("Write USD_lo register 0x%lx\n", USD_lo.USD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_USD_REG(USD_hi, USD_lo);
}
static inline void
boot_write_USD_hi_lo_reg(e2k_usd_hi_t USD_hi, e2k_usd_lo_t USD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write USD_hi register 0x%lx\n", USD_hi.USD_hi_half);
	boot_printk("Write USD_lo register 0x%lx\n", USD_lo.USD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	BOOT_WRITE_USD_REG(USD_hi, USD_lo);
}

/*
 * Write quad-word Non-Protected User Stack Descriptor Register (USD)
 * from the structure
 * Register fields filling:		USD.USD_xxx = fff;
 * Register double-word halfs filling:	USD.USD_lo_reg = USD_lo;
 *					USD.USD_hi_reg = USD_hi;
 */
static inline void
write_USD_reg(usd_struct_t USD)
{
	WRITE_USD_REG(USD.USD_hi_struct, USD.USD_lo_struct);
}
static inline void
boot_write_USD_reg(usd_struct_t USD)
{
	BOOT_WRITE_USD_REG(USD.USD_hi_struct, USD.USD_lo_struct);
}

/*
 * Read low double-word Protected User Stack Descriptor Register (PUSD)
 * as the low word structure
 * Register fields access:		PUSD_lo = READ_PUSD_LO_REG();
 *					fff = PUSD_lo.PUSD_lo_xxx;
 */
#define	NATIVE_NV_READ_PUSD_LO_REG() \
({ \
	e2k_pusd_lo_t	PUSD_lo; \
	PUSD_lo.PUSD_lo_half = NATIVE_NV_READ_PUSD_LO_REG_VALUE(); \
	PUSD_lo; \
})
#define	READ_PUSD_LO_REG() \
({ \
	e2k_pusd_lo_t	PUSD_lo; \
	PUSD_lo.PUSD_lo_half = READ_PUSD_LO_REG_VALUE(); \
	PUSD_lo; \
})
static	inline	e2k_pusd_lo_t
native_nv_read_PUSD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PUSD_lo register 0x%lx\n",
			NATIVE_NV_READ_PUSD_LO_REG().PUSD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_PUSD_LO_REG();
}
static	inline	e2k_pusd_lo_t
read_PUSD_lo_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PUSD_lo register 0x%lx\n",
			READ_PUSD_LO_REG().PUSD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_PUSD_LO_REG();
}

/*
 * Read high double-word Protected User Stack Descriptor Register (PUSD)
 * as the high word structure
 * Register fields access:		PUSD_hi = READ_PUSD_HI_REG();
 *					fff = PUSD_hi.PUSD_hi_xxx;
 */
#define	NATIVE_NV_READ_PUSD_HI_REG() \
({ \
	e2k_pusd_hi_t	PUSD_hi; \
	PUSD_hi.PUSD_hi_half = NATIVE_NV_READ_PUSD_HI_REG_VALUE(); \
	PUSD_hi; \
})
#define	READ_PUSD_HI_REG() \
({ \
	e2k_pusd_hi_t	PUSD_hi; \
	PUSD_hi.PUSD_hi_half = READ_PUSD_HI_REG_VALUE(); \
	PUSD_hi; \
})
static	inline	e2k_pusd_hi_t
native_nv_read_PUSD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PUSD_hi register 0x%lx\n",
			NATIVE_NV_READ_PUSD_HI_REG().PUSD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return NATIVE_NV_READ_PUSD_HI_REG();
}
static	inline	e2k_pusd_hi_t
read_PUSD_hi_reg(void)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Read PUSD_hi register 0x%lx\n",
			READ_PUSD_HI_REG().PUSD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	return READ_PUSD_HI_REG();
}

/*
 * Read quad-word User Protected Stack Descriptor Register (PUSD)
 * to the structure
 * Register fields access:		fff = PUSD -> PUSD_xxx
 * Register double-word halfs access:	PUSD_lo = PUSD -> PUSD_lo_reg
 *					PUSD_hi = PUSD -> PUSD_hi_reg
 */
#define	NATIVE_NV_READ_PUSD_REG() \
({ \
	pusd_struct_t	PUSD; \
	PUSD.PUSD_hi_struct = NATIVE_NV_READ_PUSD_HI_REG(); \
	PUSD.PUSD_lo_struct = NATIVE_NV_READ_PUSD_LO_REG(); \
	PUSD; \
})
#define	NATIVE_NV_READ_PUSD_REG_TO(PUSD) \
({ \
	*PUSD = NATIVE_NV_READ_PUSD_REG(); \
})
#define	READ_PUSD_REG() \
({ \
	pusd_struct_t	PUSD; \
	PUSD.PUSD_hi_struct = READ_PUSD_HI_REG(); \
	PUSD.PUSD_lo_struct = READ_PUSD_LO_REG(); \
	PUSD; \
})
#define	READ_PUSD_REG_TO(PUSD) \
({ \
	*PUSD = READ_PUSD_REG(); \
})
static inline void
native_nv_read_PUSD_reg(pusd_struct_t *PUSD)
{
	NATIVE_NV_READ_PUSD_REG_TO(PUSD);
}
static inline void
read_PUSD_reg(pusd_struct_t *PUSD)
{
	READ_PUSD_REG_TO(PUSD);
}

/*
 * Write low double-word Protected User Stack Descriptor Register (PUSD)
 * from the low word structure
 * Register fields filling:		PUSD_lo.PUSD_lo_xxx = fff;
 * Register double-word half filling:	PUSD_lo.PUSD_lo_half = pusd_lo;
 */
#define	NATIVE_NV_WRITE_PUSD_LO_REG(PUSD_lo) \
		NATIVE_NV_WRITE_PUSD_LO_REG_VALUE(PUSD_lo.PUSD_lo_half)
#define	WRITE_PUSD_LO_REG(PUSD_lo) \
		WRITE_PUSD_LO_REG_VALUE(PUSD_lo.PUSD_lo_half)

static inline void
native_nv_write_PUSD_lo_reg(e2k_pusd_lo_t PUSD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PUSD_lo register 0x%lx\n", PUSD_lo.PUSD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_WRITE_PUSD_LO_REG(PUSD_lo);
}
static inline void
write_PUSD_lo_reg(e2k_pusd_lo_t PUSD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PUSD_lo register 0x%lx\n", PUSD_lo.PUSD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_PUSD_LO_REG(PUSD_lo);
}

/*
 * Write high double-word Protected User Stack Descriptor Register (PUSD)
 * from the high word structure
 * Register fields filling:		PUSD_hi.PUSD_hi_xxx = fff;
 * Register double-word half filling:	PUSD_hi.PUSD_hi_half = pusd_hi;
 */
#define	NATIVE_NV_WRITE_PUSD_HI_REG(PUSD_hi) \
		NATIVE_NV_WRITE_PUSD_HI_REG_VALUE(PUSD_hi.PUSD_hi_half)
#define	WRITE_PUSD_HI_REG(PUSD_hi) \
		WRITE_PUSD_HI_REG_VALUE(PUSD_hi.PUSD_hi_half)

static inline void
native_nv_write_PUSD_hi_reg(e2k_pusd_hi_t PUSD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PUSD_hi register 0x%lx\n", PUSD_hi.PUSD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_WRITE_PUSD_HI_REG(PUSD_hi);
}
static inline void
write_PUSD_hi_reg(e2k_pusd_hi_t PUSD_hi)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PUSD_hi register 0x%lx\n", PUSD_hi.PUSD_hi_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_PUSD_HI_REG(PUSD_hi);
}

/*
 * Write high & low quad-word Protected User Stack Descriptor Register (PUSD)
 * from the high & low word structure
 */
#define	NATIVE_NV_WRITE_PUSD_REG_VALUE(PUSD_hi_value, PUSD_lo_value) \
({ \
	NATIVE_NV_WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value); \
	NATIVE_NV_WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value); \
})
#define	NATIVE_NV_WRITE_PUSD_REG(PUSD_hi, PUSD_lo) \
({ \
	NATIVE_NV_WRITE_PUSD_REG_VALUE(PUSD_hi.PUSD_hi_half, \
					PUSD_lo.PUSD_lo_half); \
})
#define	WRITE_PUSD_REG_VALUE(PUSD_hi_value, PUSD_lo_value) \
({ \
	WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value); \
	WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value); \
})
#define	WRITE_PUSD_REG(PUSD_hi, PUSD_lo) \
({ \
	WRITE_PUSD_REG_VALUE(PUSD_hi.PUSD_hi_half, PUSD_lo.PUSD_lo_half); \
})
static inline void
native_nv_write_PUSD_hi_lo_reg(e2k_pusd_hi_t PUSD_hi, e2k_pusd_lo_t PUSD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PUSD_hi register 0x%lx\n", PUSD_hi.PUSD_hi_half);
	boot_printk("Write PUSD_lo register 0x%lx\n", PUSD_lo.PUSD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	NATIVE_NV_WRITE_PUSD_REG(PUSD_hi, PUSD_lo);
}
static inline void
write_PUSD_hi_lo_reg(e2k_pusd_hi_t PUSD_hi, e2k_pusd_lo_t PUSD_lo)
{
#ifdef	_E2K_BOOT_CPU_REGS_TRACE_
	boot_printk("Write PUSD_hi register 0x%lx\n", PUSD_hi.PUSD_hi_half);
	boot_printk("Write PUSD_lo register 0x%lx\n", PUSD_lo.PUSD_lo_half);
#endif	/* _E2K_BOOT_CPU_REGS_TRACE_ */
	WRITE_PUSD_REG(PUSD_hi, PUSD_lo);
}

/*
 * Write quad-word User Protected Stack Descriptor Register (PUSD)
 * from the structure
 * Register fields filling:		PUSD.PUSD_xxx = fff;
 * Register double-word halfs filling:	PUSD.PUSD_lo_reg = PUSD_lo;
 *					PUSD.PUSD_hi_reg = PUSD_hi;
 */
static inline void
write_PUSD_reg(pusd_struct_t PUSD)
{
	WRITE_PUSD_REG(PUSD.PUSD_hi_struct, PUSD.PUSD_lo_struct);
}

/*
 * Read double-word User Stacks Base Register (USBR) to the structure
 * Register fields access:		fff = USBR -> USBR_xxx
 * Register entire access:		USBR_entire = USBR -> USBR_reg
 */
#define	READ_USBR_REG() \
({ \
	e2k_usbr_t USBR; \
	USBR.USBR_reg = READ_USBR_REG_VALUE(); \
	USBR; \
})
#define	NATIVE_NV_READ_USBR_REG() \
({ \
	e2k_usbr_t USBR; \
	USBR.USBR_reg = NATIVE_NV_READ_USBR_REG_VALUE(); \
	USBR; \
})
#define	BOOT_READ_USBR_REG() \
({ \
	e2k_usbr_t USBR; \
	USBR.USBR_reg = BOOT_READ_USBR_REG_VALUE(); \
	USBR; \
})
static	inline	e2k_usbr_t
read_USBR_reg(void)
{
	return READ_USBR_REG();
}
static	inline	e2k_usbr_t
boot_read_USBR_reg(void)
{
	return BOOT_READ_USBR_REG();
}

/*
 * Write double-word User Stacks Base Register (USBR) from the structure
 * Register fields filling:		USBR.USBR_xxx = fff;
 * Register entire filling:		USBR.USBR_reg = USBR_value;
 */
#define	WRITE_USBR_REG(USBR)		WRITE_USBR_REG_VALUE(USBR.USBR_reg)
#define	BOOT_WRITE_USBR_REG(USBR)	\
		BOOT_WRITE_USBR_REG_VALUE(USBR.USBR_reg)

static inline void
write_USBR_reg(e2k_usbr_t USBR)
{
	WRITE_USBR_REG(USBR);
}
static inline void
boot_write_USBR_reg(e2k_usbr_t USBR)
{
	BOOT_WRITE_USBR_REG(USBR);
}

/*
 * Read double-word Stacks Base Register (SBR) to the structure
 * Register fields access:		fff = SBR -> SBR_xxx
 * Register entire access:		SBR_entire = SBR -> SBR_reg
 */
#define	NATIVE_NV_READ_SBR_REG() \
({ \
	e2k_sbr_t SBR; \
	SBR.SBR_reg = NATIVE_NV_READ_SBR_REG_VALUE(); \
	SBR; \
})
#define	READ_SBR_REG() \
({ \
	e2k_sbr_t SBR; \
	SBR.SBR_reg = READ_SBR_REG_VALUE(); \
	SBR; \
})
#define	BOOT_READ_SBR_REG() \
({ \
	e2k_sbr_t SBR; \
	SBR.SBR_reg = BOOT_READ_SBR_REG_VALUE(); \
	SBR; \
})

static	inline	e2k_sbr_t
native_nv_read_SBR_reg(void)
{
	return NATIVE_NV_READ_SBR_REG();
}
static	inline	e2k_sbr_t
read_SBR_reg(void)
{
	return READ_SBR_REG();
}
static	inline	e2k_sbr_t
boot_read_SBR_reg(void)
{
	return BOOT_READ_SBR_REG();
}

/*
 * Write double-word Stacks Base Register (SBR) from the structure
 * Register fields filling:		SBR.SBR_xxx = fff;
 * Register entire filling:		SBR.SBR_reg = SBR_value;
 */
#define	NATIVE_NV_WRITE_SBR_REG(SBR)	\
		NATIVE_NV_WRITE_SBR_REG_VALUE(SBR.SBR_reg)
#define	WRITE_SBR_REG(SBR)	\
		WRITE_SBR_REG_VALUE(SBR.SBR_reg)
#define	BOOT_WRITE_SBR_REG(SBR)	\
		BOOT_WRITE_SBR_REG_VALUE(SBR.SBR_reg)

static inline void
native_nv_write_SBR_reg(e2k_sbr_t SBR)
{
	NATIVE_NV_WRITE_SBR_REG(SBR);
}
static inline void
write_SBR_reg(e2k_sbr_t SBR)
{
	WRITE_SBR_REG(SBR);
}
static inline void
boot_write_SBR_reg(e2k_sbr_t SBR)
{
	BOOT_WRITE_SBR_REG(SBR);
}

#define	NATIVE_NV_READ_PSHTP_REG() \
({ \
	e2k_pshtp_t PSHTP_reg; \
	PSHTP_reg.word = NATIVE_NV_READ_PSHTP_REG_VALUE(); \
	PSHTP_reg; \
})
#define	READ_PSHTP_REG() \
({ \
	e2k_pshtp_t PSHTP_reg; \
	PSHTP_reg.word = READ_PSHTP_REG_VALUE(); \
	PSHTP_reg; \
})

#define	NATIVE_WRITE_PSHTP_REG(PSHTP_reg) \
({ \
	NATIVE_WRITE_PSHTP_REG_VALUE(AS_WORD(PSHTP_reg)); \
})
#define	NATIVE_STRIP_PSHTP_WINDOW()	NATIVE_WRITE_PSHTP_REG_VALUE(0)
#define	WRITE_PSHTP_REG(PSHTP_reg) \
({ \
	WRITE_PSHTP_REG_VALUE(AS_WORD(PSHTP_reg)); \
})
#define	STRIP_PSHTP_WINDOW()		WRITE_PSHTP_REG_VALUE(0)

/*
 * Read double-word Window Descriptor Register (WD) to the structure
 * Register fields access:		fff = WD -> WD_xxx
 * Register entire access:		WD_entire = WD -> WD_reg
 */
#define	NATIVE_READ_WD_REG() \
({ \
	e2k_wd_t WD; \
	WD.WD_reg = NATIVE_READ_WD_REG_VALUE(); \
	WD; \
})
#define	READ_WD_REG() \
({ \
	e2k_wd_t WD; \
	WD.WD_reg = READ_WD_REG_VALUE(); \
	WD; \
})
static	inline	e2k_wd_t
native_read_WD_reg(void)
{
	return NATIVE_READ_WD_REG();
}
static	inline	e2k_wd_t
read_WD_reg(void)
{
	return READ_WD_REG();
}

/*
 * Write double-word Window Descriptor Register (WD) from the structure
 * Register fields filling:		WD.WD_xxx = fff;
 * Register entire filling:		WD.WD_reg = WD_value;
 */
#define	NATIVE_WRITE_WD_REG(WD)		NATIVE_WRITE_WD_REG_VALUE(WD.WD_reg)
#define	WRITE_WD_REG(WD)		WRITE_WD_REG_VALUE(WD.WD_reg)
static inline void
native_write_WD_reg(e2k_wd_t WD)
{
	NATIVE_WRITE_WD_REG(WD);
}
static inline void
write_WD_reg(e2k_wd_t WD)
{
	WRITE_WD_REG(WD);
}

#ifdef	NEED_PARAVIRT_LOOP_REGISTERS

/*
 * Read double-word Loop Status Register (LSR) to the structure
 * Register fields access:		fff = LSR -> LSR_xxx
 * Register entire access:		LSR_entire = LSR -> LSR_reg
 */
#define	READ_LSR_REG() \
({ \
	e2k_lsr_t LSR; \
	LSR.LSR_reg = READ_LSR_REG_VALUE(); \
	LSR; \
})
static	inline	e2k_lsr_t
read_LSR_reg(void)
{
	return READ_LSR_REG();
}

/*
 * Write double-word Loop Status Register (LSR) from the structure
 * Register fields filling:		LSR.LSR_xxx = fff;
 * Register entire filling:		LSR.LSR_reg = LSR_value;
 */
#define	WRITE_LSR_REG(LSR)		WRITE_LSR_REG_VALUE(LSR.LSR_reg)
static inline void
write_LSR_reg(e2k_lsr_t LSR)
{
	WRITE_LSR_REG(LSR);
}

/*
 * Read double-word Initial Loop Counters Register (ILCR) to the structure
 * Register fields access:		fff = ILCR -> ILCR_xxx
 * Register entire access:		ILCR_entire = ILCR -> ILCR_reg
 */
#define	READ_ILCR_REG() \
({ \
	e2k_ilcr_t ILCR; \
	ILCR.ILCR_reg = READ_ILCR_REG_VALUE(); \
	ILCR; \
})
static	inline	e2k_ilcr_t
read_ILCR_reg(void)
{
	return READ_ILCR_REG();
}

/*
 * Write double-word Initial Loop Counters Register (ILCR) from the structure
 * Register fields filling:		ILCR.ILCR_xxx = fff;
 * Register entire filling:		ILCR.ILCR_reg = ILCR_value;
 */
#define	WRITE_ILCR_REG(ILCR)		WRITE_ILCR_REG_VALUE(ILCR.ILCR_reg)
static inline void
write_ILCR_reg(e2k_ilcr_t ILCR)
{
	WRITE_ILCR_REG(ILCR);
}

/*
 * Write double-word LSR/ILCR registers in complex
 */
#define	WRITE_LSR_LSR1_ILCR_ILCR1_REGS(lsr, lsr1, ilcr, ilcr1) \
		WRITE_LSR_ILCR_LSR1_ILCR1_REGS_VALUE(lsr.ILSR_reg, \
			lsr1.LSR1_reg, ilcr.ILCR_reg, ilcr1.ILCR1_reg)
#endif	/* NEED_PARAVIRT_LOOP_REGISTERS */

/*
 * Read/write OS register which point to current process thread info
 * structure (OSR0)
 */
#define	NATIVE_GET_OSR0_REG_VALUE()	NATIVE_NV_READ_OSR0_REG_VALUE()
#define	NATIVE_READ_CURRENT_REG_VALUE()	NATIVE_NV_READ_OSR0_REG_VALUE()
#define	NATIVE_READ_CURRENT_REG() \
({ \
	struct thread_info *TI; \
	TI = (struct thread_info *)NATIVE_READ_CURRENT_REG_VALUE(); \
	TI; \
})
#define	READ_CURRENT_REG() \
({ \
	struct thread_info *TI; \
	TI = (struct thread_info *)READ_CURRENT_REG_VALUE(); \
	TI; \
})
#define	BOOT_READ_CURRENT_REG() \
({ \
	struct thread_info *TI; \
	TI = (struct thread_info *)BOOT_READ_CURRENT_REG_VALUE(); \
	TI; \
})

static	inline	struct thread_info *
read_current_reg(void)
{
	return READ_CURRENT_REG();
}
static	inline	struct thread_info *
boot_read_current_reg(void)
{
	return BOOT_READ_CURRENT_REG();
}

#define	NATIVE_SET_OSR0_REG_VALUE(TI)	\
		NATIVE_NV_WRITE_OSR0_REG_VALUE(TI)
#define	NATIVE_WRITE_CURRENT_REG(TI)		\
		NATIVE_SET_OSR0_REG_VALUE((unsigned long)(TI))
#define	WRITE_CURRENT_REG(TI)			\
		WRITE_CURRENT_REG_VALUE((unsigned long)(TI))
#define	BOOT_WRITE_CURRENT_REG(TI)		\
		BOOT_WRITE_CURRENT_REG_VALUE((unsigned long)(TI))
static inline void
native_write_current_reg(struct thread_info *TI)
{
	NATIVE_WRITE_CURRENT_REG(TI);
}
static inline void
write_current_reg(struct thread_info *TI)
{
	WRITE_CURRENT_REG(TI);
}

/*
 * Read/write OS Entries Mask (OSEM)
 */
#define	READ_OSEM_REG()		READ_OSEM_REG_VALUE()
static	inline	unsigned int
read_OSEM_reg(void)
{
	return READ_OSEM_REG();
}
#define	WRITE_OSEM_REG(OSEM)	WRITE_OSEM_REG_VALUE(OSEM)
static inline void
write_OSEM_reg(unsigned int OSEM)
{
	WRITE_OSEM_REG(OSEM);
}

#define	READ_HCEM_REG()		NATIVE_GET_SREG_CLOSED(hcem)
#define	WRITE_HCEM_REG(value)	NATIVE_SET_SREG_CLOSED_NOEXC(hcem, (value), 5)

#define	READ_HCEB_REG()		NATIVE_GET_DSREG_CLOSED(hceb)
#define	WRITE_HCEB_REG(value)	NATIVE_SET_DSREG_CLOSED_NOEXC(hceb, (value), 5)

/*
 * Read/write word Base Global Register (BGR) to the structure
 * Register fields access:		fff = BGR.xxx
 * Register entire access:		BGR_entire = BGR.BGR_reg
 */
#define	NATIVE_READ_BGR_REG() \
({ \
	e2k_bgr_t BGR; \
	BGR.BGR_reg = NATIVE_READ_BGR_REG_VALUE(); \
	BGR; \
})
#define	READ_BGR_REG() \
({ \
	e2k_bgr_t BGR; \
	BGR.BGR_reg = READ_BGR_REG_VALUE(); \
	BGR; \
})
static	inline	e2k_bgr_t
native_read_BGR_reg(void)
{
	return NATIVE_READ_BGR_REG();
}
static	inline	e2k_bgr_t
read_BGR_reg(void)
{
	return READ_BGR_REG();
}

/*
 * Write word Base Global Register (BGR) from the structure
 * Register fields filling:		BGR.BGR_xxx = fff
 * Register entire filling:		BGR.BGR_reg = BGR_value
 */

#define	NATIVE_WRITE_BGR_REG(BGR)	NATIVE_WRITE_BGR_REG_VALUE(BGR.BGR_reg)
#define	WRITE_BGR_REG(BGR)		WRITE_BGR_REG_VALUE(BGR.BGR_reg)
#define	BOOT_WRITE_BGR_REG(BGR)		BOOT_WRITE_BGR_REG_VALUE(BGR.BGR_reg)

static inline void
native_write_BGR_reg(e2k_bgr_t bgr)
{
	NATIVE_WRITE_BGR_REG(bgr);
}
static inline void
write_BGR_reg(e2k_bgr_t bgr)
{
	WRITE_BGR_REG(bgr);
}

#define	NATIVE_INIT_BGR_REG()	NATIVE_WRITE_BGR_REG(E2K_INITIAL_BGR)
#define	NATIVE_BOOT_INIT_BGR_REG() NATIVE_INIT_BGR_REG()
#define	INIT_BGR_REG()		WRITE_BGR_REG(E2K_INITIAL_BGR)
#define	BOOT_INIT_BGR_REG()	BOOT_WRITE_BGR_REG(E2K_INITIAL_BGR)

static inline void
native_init_BGR_reg(void)
{
	NATIVE_INIT_BGR_REG();
}
static inline void
init_BGR_reg(void)
{
	INIT_BGR_REG();
}
static inline void
native_boot_init_BGR_reg(void)
{
	NATIVE_BOOT_INIT_BGR_REG();
}

/*
 * Read CPU current clock regigister (CLKR)
 */
#define	READ_CLKR_REG()		READ_CLKR_REG_VALUE()

/*
 * Read/Write system clock registers (SCLKM)
 */
#define	READ_SCLKR_REG()	READ_SCLKR_REG_VALUE()
#define	READ_SCLKM1_REG()	((e2k_sclkm1_t) READ_SCLKM1_REG_VALUE())
#define	READ_SCLKM2_REG()	READ_SCLKM2_REG_VALUE()
#define	READ_SCLKM3_REG()	READ_SCLKM3_REG_VALUE()

#define	WRITE_SCLKR_REG(reg_value)	WRITE_SCLKR_REG_VALUE(reg_value)
#define	WRITE_SCLKM1_REG(reg)		WRITE_SCLKM1_REG_VALUE(AW(reg))
#define	WRITE_SCLKM2_REG(reg_value)	WRITE_SCLKM2_REG_VALUE(reg_value)
#define	WRITE_SCLKM3_REG(reg_value)	WRITE_SCLKM3_REG_VALUE(reg_value)

/*
 * Read/Write Control Unit HardWare registers (CU_HW0/CU_HW1)
 */
#define	READ_CU_HW0_REG()	READ_CU_HW0_REG_VALUE()
#define	READ_CU_HW1_REG()	READ_CU_HW1_REG_VALUE()

#define	WRITE_CU_HW0_REG(reg)	WRITE_CU_HW0_REG_VALUE(reg)
#define	WRITE_CU_HW1_REG(reg)	WRITE_CU_HW1_REG_VALUE(reg)

/*
 * Read low/high double-word Recovery point register (RPR)
 */
#define	NATIVE_READ_RPR_LO_REG() \
({ \
	e2k_rpr_lo_t	RPR_lo; \
	RPR_lo.RPR_lo_half = NATIVE_READ_RPR_LO_REG_VALUE(); \
	RPR_lo; \
})
#define	NATIVE_READ_RPR_HI_REG() \
({ \
	e2k_rpr_hi_t	RPR_hi; \
	RPR_hi.RPR_hi_half = NATIVE_READ_RPR_HI_REG_VALUE(); \
	RPR_hi; \
})
#define	NATIVE_CL_READ_RPR_LO_REG() \
({ \
	e2k_rpr_lo_t	RPR_lo; \
	RPR_lo.RPR_lo_half = NATIVE_CL_READ_RPR_LO_REG_VALUE(); \
	RPR_lo; \
})
#define	NATIVE_CL_READ_RPR_HI_REG() \
({ \
	e2k_rpr_hi_t	RPR_hi; \
	RPR_hi.RPR_hi_half = NATIVE_CL_READ_RPR_HI_REG_VALUE(); \
	RPR_hi; \
})
#define	READ_RPR_LO_REG() \
({ \
	e2k_rpr_lo_t	RPR_lo; \
	RPR_lo.RPR_lo_half = READ_RPR_LO_REG_VALUE(); \
	RPR_lo; \
})
#define	READ_RPR_HI_REG() \
({ \
	e2k_rpr_hi_t	RPR_hi; \
	RPR_hi.RPR_hi_half = READ_RPR_HI_REG_VALUE(); \
	RPR_hi; \
})
static	inline	e2k_rpr_lo_t
native_read_RPR_lo_reg(void)
{
	return NATIVE_READ_RPR_LO_REG();
}
static	inline	e2k_rpr_hi_t
native_read_RPR_hi_reg(void)
{
	return NATIVE_READ_RPR_HI_REG();
}
static	inline	e2k_rpr_lo_t
read_RPR_lo_reg(void)
{
	return READ_RPR_LO_REG();
}
static	inline	e2k_rpr_hi_t
read_RPR_hi_reg(void)
{
	return READ_RPR_HI_REG();
}

/*
 * Write low/high double-word Recovery point register (RPR)
 */
#define	NATIVE_WRITE_RPR_LO_REG(RPR_lo) \
		NATIVE_WRITE_RPR_LO_REG_VALUE(RPR_lo.RPR_lo_half)
#define	NATIVE_WRITE_RPR_HI_REG(RPR_hi) \
		NATIVE_WRITE_RPR_HI_REG_VALUE(RPR_hi.RPR_hi_half)
#define	WRITE_RPR_LO_REG(RPR_lo) \
		WRITE_RPR_LO_REG_VALUE(RPR_lo.RPR_lo_half)
#define	WRITE_RPR_HI_REG(RPR_hi) \
		WRITE_RPR_HI_REG_VALUE(RPR_hi.RPR_hi_half)

static inline void
native_write_RPR_lo_reg(e2k_rpr_lo_t RPR_lo)
{
	NATIVE_WRITE_RPR_LO_REG(RPR_lo);
}
static inline void
native_write_RPR_hi_reg(e2k_rpr_hi_t RPR_hi)
{
	NATIVE_WRITE_RPR_HI_REG(RPR_hi);
}
static inline void
write_RPR_lo_reg(e2k_rpr_lo_t RPR_lo)
{
	WRITE_RPR_LO_REG(RPR_lo);
}
static inline void
write_RPR_hi_reg(e2k_rpr_hi_t RPR_hi)
{
	WRITE_RPR_HI_REG(RPR_hi);
}

/*
 * Read CPU current Instruction Pointer register (IP)
 */
#define	READ_IP_REG()		READ_IP_REG_VALUE()
static	inline	unsigned long
read_ip_reg(void)
{
	return READ_IP_REG();
}

/*
 * Read debug and monitors registers
 */
#define	NATIVE_READ_DIBCR_REG() \
({ \
	e2k_dibcr_t	DIBCR; \
	AS_WORD(DIBCR) = NATIVE_READ_DIBCR_REG_VALUE(); \
	DIBCR; \
})
#define	READ_DIBCR_REG() \
({ \
	e2k_dibcr_t	DIBCR; \
	AS_WORD(DIBCR) = READ_DIBCR_REG_VALUE(); \
	DIBCR; \
})
static	inline	e2k_dibcr_t
read_DIBCR_reg(void)
{
	return READ_DIBCR_REG();
}

#define	NATIVE_READ_DIBSR_REG() \
({ \
	e2k_dibsr_t	DIBSR; \
	AS_WORD(DIBSR) = NATIVE_READ_DIBSR_REG_VALUE(); \
	DIBSR; \
})
#define	READ_DIBSR_REG() \
({ \
	e2k_dibsr_t	DIBSR; \
	AS_WORD(DIBSR) = READ_DIBSR_REG_VALUE(); \
	DIBSR; \
})
static	inline	e2k_dibsr_t
read_DIBSR_reg(void)
{
	return READ_DIBSR_REG();
}

#define	NATIVE_READ_DIMCR_REG() \
({ \
	e2k_dimcr_t	DIMCR; \
	AS_WORD(DIMCR) = NATIVE_READ_DIMCR_REG_VALUE(); \
	DIMCR; \
})
#define	READ_DIMCR_REG() \
({ \
	e2k_dimcr_t	DIMCR; \
	AS_WORD(DIMCR) = READ_DIMCR_REG_VALUE(); \
	DIMCR; \
})
static	inline	e2k_dimcr_t
read_DIMCR_reg(void)
{
	return READ_DIMCR_REG();
}

#define	NATIVE_READ_DIBAR0_REG()	NATIVE_READ_DIBAR0_REG_VALUE()
#define	NATIVE_READ_DIBAR1_REG()	NATIVE_READ_DIBAR1_REG_VALUE()
#define	NATIVE_READ_DIBAR2_REG()	NATIVE_READ_DIBAR2_REG_VALUE()
#define	NATIVE_READ_DIBAR3_REG()	NATIVE_READ_DIBAR3_REG_VALUE()
#define	READ_DIBAR0_REG()		READ_DIBAR0_REG_VALUE()
#define	READ_DIBAR1_REG()		READ_DIBAR1_REG_VALUE()
#define	READ_DIBAR2_REG()		READ_DIBAR2_REG_VALUE()
#define	READ_DIBAR3_REG()		READ_DIBAR3_REG_VALUE()
static	inline	unsigned long
read_DIBAR0_reg(void)
{
	return READ_DIBAR0_REG();
}
static	inline	unsigned long
read_DIBAR1_reg(void)
{
	return READ_DIBAR1_REG();
}
static	inline	unsigned long
read_DIBAR2_reg(void)
{
	return READ_DIBAR2_REG();
}
static	inline	unsigned long
read_DIBAR3_reg(void)
{
	return READ_DIBAR3_REG();
}

#define	NATIVE_READ_DIMAR0_REG()	NATIVE_READ_DIMAR0_REG_VALUE()
#define	NATIVE_READ_DIMAR1_REG()	NATIVE_READ_DIMAR1_REG_VALUE()
#define	READ_DIMAR0_REG()		READ_DIMAR0_REG_VALUE()
#define	READ_DIMAR1_REG()		READ_DIMAR1_REG_VALUE()
static	inline	unsigned long
read_DIMAR0_reg(void)
{
	return READ_DIMAR0_REG();
}
static	inline	unsigned long
read_DIMAR1_reg(void)
{
	return READ_DIMAR1_REG();
}

#define	NATIVE_WRITE_DIBCR_REG(DIBCR)	\
		NATIVE_WRITE_DIBCR_REG_VALUE(DIBCR.DIBCR_reg)
#define	WRITE_DIBCR_REG(DIBCR)	WRITE_DIBCR_REG_VALUE(DIBCR.DIBCR_reg)
static inline void
write_DIBCR_reg(e2k_dibcr_t DIBCR)
{
	WRITE_DIBCR_REG(DIBCR);
}
#define	NATIVE_WRITE_DIBSR_REG(DIBSR)	\
		NATIVE_WRITE_DIBSR_REG_VALUE(DIBSR.DIBSR_reg)
#define	WRITE_DIBSR_REG(DIBSR)	WRITE_DIBSR_REG_VALUE(DIBSR.DIBSR_reg)
static inline void
write_DIBSR_reg(e2k_dibsr_t DIBSR)
{
	WRITE_DIBSR_REG(DIBSR);
}
#define	NATIVE_WRITE_DIMCR_REG(DIMCR)	\
		NATIVE_WRITE_DIMCR_REG_VALUE(DIMCR.DIMCR_reg)
#define	WRITE_DIMCR_REG(DIMCR)	WRITE_DIMCR_REG_VALUE(DIMCR.DIMCR_reg)
static inline void
write_DIMCR_reg(e2k_dimcr_t DIMCR)
{
	WRITE_DIMCR_REG(DIMCR);
}
#define	NATIVE_WRITE_DIBAR0_REG(DIBAR0)	NATIVE_WRITE_DIBAR0_REG_VALUE(DIBAR0)
#define	NATIVE_WRITE_DIBAR1_REG(DIBAR1)	NATIVE_WRITE_DIBAR1_REG_VALUE(DIBAR1)
#define	NATIVE_WRITE_DIBAR2_REG(DIBAR2)	NATIVE_WRITE_DIBAR2_REG_VALUE(DIBAR2)
#define	NATIVE_WRITE_DIBAR3_REG(DIBAR3)	NATIVE_WRITE_DIBAR3_REG_VALUE(DIBAR3)
#define	WRITE_DIBAR0_REG(DIBAR0)	WRITE_DIBAR0_REG_VALUE(DIBAR0)
#define	WRITE_DIBAR1_REG(DIBAR1)	WRITE_DIBAR1_REG_VALUE(DIBAR1)
#define	WRITE_DIBAR2_REG(DIBAR2)	WRITE_DIBAR2_REG_VALUE(DIBAR2)
#define	WRITE_DIBAR3_REG(DIBAR3)	WRITE_DIBAR3_REG_VALUE(DIBAR3)
static inline void
write_DIBAR0_reg(unsigned long DIBAR0)
{
	WRITE_DIBAR0_REG(DIBAR0);
}
static inline void
write_DIBAR1_reg(unsigned long DIBAR1)
{
	WRITE_DIBAR1_REG(DIBAR1);
}
static inline void
write_DIBAR2_reg(unsigned long DIBAR2)
{
	WRITE_DIBAR2_REG(DIBAR2);
}
static inline void
write_DIBAR3_reg(unsigned long DIBAR3)
{
	WRITE_DIBAR3_REG(DIBAR3);
}

#define	NATIVE_WRITE_DIMAR0_REG(DIMAR0)	NATIVE_WRITE_DIMAR0_REG_VALUE(DIMAR0)
#define	NATIVE_WRITE_DIMAR1_REG(DIMAR1)	NATIVE_WRITE_DIMAR1_REG_VALUE(DIMAR1)
#define	WRITE_DIMAR0_REG(DIMAR0)	WRITE_DIMAR0_REG_VALUE(DIMAR0)
#define	WRITE_DIMAR1_REG(DIMAR1)	WRITE_DIMAR1_REG_VALUE(DIMAR1)
static inline void
write_DIMAR0_reg(unsigned long DIMAR0)
{
	WRITE_DIMAR0_REG(DIMAR0);
}
static inline void
write_DIMAR1_reg(unsigned long DIMAR1)
{
	WRITE_DIMAR1_REG(DIMAR1);
}

/*
 * Read double-word Compilation Unit Table Register (CUTD) to the structure
 * Register fields access:		fff = CUTD.CUTD_xxx or
 *					fff = CUTD->CUTD_xxx
 * Register entire access:		CUTD_entire = CUTD.CUTD_reg or
 *					CUTD_entire = CUTD->CUTD_reg
 */
#define	NATIVE_NV_READ_CUTD_REG() \
({ \
	e2k_cutd_t CUTD; \
	CUTD.CUTD_reg = NATIVE_NV_READ_CUTD_REG_VALUE(); \
	CUTD; \
})
#define	READ_CUTD_REG() \
({ \
	e2k_cutd_t CUTD; \
	CUTD.CUTD_reg = READ_CUTD_REG_VALUE(); \
	CUTD; \
})
static	inline	e2k_cutd_t
native_nv_read_CUTD_reg(void)
{
	return NATIVE_NV_READ_CUTD_REG();
}
static	inline	e2k_cutd_t
read_CUTD_reg(void)
{
	return READ_CUTD_REG();
}

/*
 * Write double-word Compilation Unit Table Register (CUTD) from the structure
 * Register fields filling:		CUTD.CUTD_xxx = fff or
 *					CUTD->CUTD_xxx = fff
 * Register entire filling:		CUTD.CUTD_reg = CUTD_value or
 *					CUTD->CUTD_reg = CUTD_value
 */
#define	NATIVE_NV_NOIRQ_WRITE_CUTD_REG(CUTD)	\
		NATIVE_NV_NOIRQ_WRITE_CUTD_REG_VALUE(CUTD.CUTD_reg)
#define	WRITE_CUTD_REG(CUTD)	\
		WRITE_CUTD_REG_VALUE(CUTD.CUTD_reg)
static inline void
native_nv_noirq_write_CUTD_reg(e2k_cutd_t CUTD)
{
	NATIVE_NV_NOIRQ_WRITE_CUTD_REG(CUTD);
}
static inline void
write_CUTD_reg(e2k_cutd_t CUTD)
{
	WRITE_CUTD_REG(CUTD);
}

/*
 * Read word Compilation Unit Index Register (CUIR) to the structure
 * Register fields access:		fff = CUIR.CUIR_xxx or
 *					fff = CUIR->CUIR_xxx
 * Register entire access:		CUIR_entire = CUIR.CUIR_reg or
 *					CUIR_entire = CUIR->CUIR_reg
 */
#define	READ_CUIR_REG() \
({ \
	e2k_cuir_t CUIR; \
	CUIR.CUIR_reg = READ_CUIR_REG_VALUE(); \
	CUIR; \
})
static	inline	e2k_cuir_t
read_CUIR_reg(void)
{
	return READ_CUIR_REG();
}

/*
 * Read Core Mode Register (CORE_MODE) to the structure
 * Register fields access:		fff = AS_STRACT(CORE_MODE).xxx
 * Register entire access:		reg_entire = AS_WORD(CORE_MODE)
 */
#define	NATIVE_READ_CORE_MODE_REG() \
({ \
	e2k_core_mode_t CORE_MODE; \
	CORE_MODE.CORE_MODE_reg = NATIVE_READ_CORE_MODE_REG_VALUE(); \
	CORE_MODE; \
})
#define	READ_CORE_MODE_REG() \
({ \
	e2k_core_mode_t CORE_MODE; \
	CORE_MODE.CORE_MODE_reg = READ_CORE_MODE_REG_VALUE(); \
	CORE_MODE; \
})
#define	BOOT_READ_CORE_MODE_REG() \
({ \
	e2k_core_mode_t CORE_MODE; \
	CORE_MODE.CORE_MODE_reg = BOOT_READ_CORE_MODE_REG_VALUE(); \
	CORE_MODE; \
})

/*
 * Write Core Mode Register (CORE_MODE) from the structure
 * Register fields filling:		AS_STRACT(CORE_MODE).xxx = fff
 * Register entire filling:		AS_WORD(CORE_MODE) = CORE_MODE_value
 */
#define	NATIVE_WRITE_CORE_MODE_REG(CORE_MODE)	\
		NATIVE_WRITE_CORE_MODE_REG_VALUE(CORE_MODE.CORE_MODE_reg)
#define	BOOT_NATIVE_WRITE_CORE_MODE_REG(CORE_MODE)	\
		BOOT_NATIVE_WRITE_CORE_MODE_REG_VALUE(CORE_MODE.CORE_MODE_reg)
#define	WRITE_CORE_MODE_REG(CORE_MODE)		\
		WRITE_CORE_MODE_REG_VALUE(CORE_MODE.CORE_MODE_reg)
#define	BOOT_WRITE_CORE_MODE_REG(CORE_MODE)	\
		BOOT_WRITE_CORE_MODE_REG_VALUE(CORE_MODE.CORE_MODE_reg)

/*
 * Read word Processor State Register (PSR) to the structure
 * Register fields access:		fff = AS_STRACT(PSR).xxx
 * Register entire access:		PSR_entire = AS_WORD(PSR)
 */
#define	BOOT_NATIVE_NV_READ_PSR_REG_VALUE()	\
		NATIVE_NV_READ_PSR_REG_VALUE()
#define	NATIVE_NV_READ_PSR_REG() \
({ \
	e2k_psr_t PSR; \
	PSR.PSR_reg = NATIVE_NV_READ_PSR_REG_VALUE(); \
	PSR; \
})
#define	READ_PSR_REG() \
({ \
	e2k_psr_t PSR; \
	PSR.PSR_reg = READ_PSR_REG_VALUE(); \
	PSR; \
})
#define	BOOT_READ_PSR_REG() \
({ \
	e2k_psr_t PSR; \
	PSR.PSR_reg = BOOT_READ_PSR_REG_VALUE(); \
	PSR; \
})

static	inline	e2k_psr_t
read_PSR_reg(void)
{
	return READ_PSR_REG();
}

/*
 * Write word Processor State Register (PSR) from the structure
 * Register fields filling:		AS_STRACT(PSR).xxx = fff
 * Register entire filling:		AS_WORD(PSR) = PSR_value
 */
#define	BOOT_NATIVE_WRITE_PSR_REG_VALUE(PSR_value)	\
		NATIVE_WRITE_PSR_REG_VALUE(PSR_value)
#define	NATIVE_WRITE_PSR_REG(PSR)	NATIVE_WRITE_PSR_REG_VALUE(PSR.PSR_reg)
#define	BOOT_NATIVE_WRITE_PSR_REG(PSR)	\
		BOOT_NATIVE_WRITE_PSR_REG_VALUE(PSR.PSR_reg)
#define	WRITE_PSR_REG(PSR)		WRITE_PSR_REG_VALUE(PSR.PSR_reg)
#define	BOOT_WRITE_PSR_REG(PSR)		BOOT_WRITE_PSR_REG_VALUE(PSR.PSR_reg)

static inline void
write_PSR_reg(e2k_psr_t PSR)
{
	WRITE_PSR_REG(PSR);
}

/*
 * Read word User Processor State Register (UPSR) to the structure
 * Register fields access:		fff = AS_STRACT(UPSR).xxx
 * Register entire access:		UPSR_entire = AS_WORD(UPSR)
 */
#define	BOOT_NATIVE_NV_READ_UPSR_REG_VALUE()	\
		NATIVE_NV_READ_UPSR_REG_VALUE()
#define	NATIVE_NV_READ_UPSR_REG() \
({ \
	e2k_upsr_t UPSR; \
	UPSR.UPSR_reg = NATIVE_NV_READ_UPSR_REG_VALUE(); \
	UPSR; \
})
#define	READ_UPSR_REG() \
({ \
	e2k_upsr_t UPSR; \
	UPSR.UPSR_reg = READ_UPSR_REG_VALUE(); \
	UPSR; \
})

static	inline	e2k_upsr_t
read_UPSR_reg(void)
{
	return READ_UPSR_REG();
}

/*
 * Write word User Processor State Register (UPSR) from the structure
 * Register fields filling:		AS_STRACT(UPSR).xxx = fff
 * Register entire filling:		AS_WORD(UPSR) = UPSR_value
 */
#define	BOOT_NATIVE_WRITE_UPSR_REG_VALUE(UPSR_value)		\
		NATIVE_WRITE_UPSR_REG_VALUE(UPSR_value)
#define	NATIVE_WRITE_UPSR_REG(UPSR)		\
		NATIVE_WRITE_UPSR_REG_VALUE(UPSR.UPSR_reg)
#define	BOOT_NATIVE_WRITE_UPSR_REG(UPSR)		\
		NATIVE_WRITE_UPSR_REG(UPSR)
#define	WRITE_UPSR_REG(UPSR)		\
		WRITE_UPSR_REG_VALUE(UPSR.UPSR_reg)
#define	BOOT_WRITE_UPSR_REG(UPSR)	\
		BOOT_WRITE_UPSR_REG_VALUE(UPSR.UPSR_reg)

static inline void
native_write_UPSR_reg(e2k_upsr_t UPSR)
{
	NATIVE_WRITE_UPSR_REG(UPSR);
}
static inline void
boot_native_write_UPSR_reg(e2k_upsr_t UPSR)
{
	BOOT_NATIVE_WRITE_UPSR_REG(UPSR);
}
static inline void
write_UPSR_reg(e2k_upsr_t UPSR)
{
	WRITE_UPSR_REG(UPSR);
}

/*
 * Read word floating point control registers (PFPFR/FPCR/FPSR) to the structure
 * Register fields access:		fff = PFnnn.yyy
 * Register entire access:		PFnnn_entire = PFnnn_value
 */
#define	NATIVE_NV_READ_PFPFR_REG() \
({ \
	e2k_pfpfr_t PFPFR; \
	PFPFR.PFPFR_reg = NATIVE_NV_READ_PFPFR_REG_VALUE(); \
	PFPFR; \
})
#define	NATIVE_NV_READ_FPCR_REG() \
({ \
	e2k_fpcr_t FPCR; \
	FPCR.FPCR_reg = NATIVE_NV_READ_FPCR_REG_VALUE(); \
	FPCR; \
})
#define	NATIVE_NV_READ_FPSR_REG() \
({ \
	e2k_fpsr_t FPSR; \
	FPSR.FPSR_reg = NATIVE_NV_READ_FPSR_REG_VALUE(); \
	FPSR; \
})
#define	READ_PFPFR_REG() \
({ \
	e2k_pfpfr_t PFPFR; \
	PFPFR.PFPFR_reg = READ_PFPFR_REG_VALUE(); \
	PFPFR; \
})
#define	READ_FPCR_REG() \
({ \
	e2k_fpcr_t FPCR; \
	FPCR.FPCR_reg = READ_FPCR_REG_VALUE(); \
	FPCR; \
})
#define	READ_FPSR_REG() \
({ \
	e2k_fpsr_t FPSR; \
	FPSR.FPSR_reg = READ_FPSR_REG_VALUE(); \
	FPSR; \
})
static	inline	e2k_pfpfr_t
native_nv_read_PFPFR_reg(void)
{
	return NATIVE_NV_READ_PFPFR_REG();
}
static	inline e2k_fpcr_t
native_nv_read_FPCR_reg(void)
{
	return NATIVE_NV_READ_FPCR_REG();
}
static	inline	e2k_fpsr_t
native_nv_read_FPSR_reg(void)
{
	return NATIVE_NV_READ_FPSR_REG();
}
static	inline	e2k_pfpfr_t
read_PFPFR_reg(void)
{
	return READ_PFPFR_REG();
}
static	inline e2k_fpcr_t
read_FPCR_reg(void)
{
	return READ_FPCR_REG();
}
static	inline	e2k_fpsr_t
read_FPSR_reg(void)
{
	return READ_FPSR_REG();
}

/*
 * Write word floating point control registers (PFPFR/FPCR/FPSR)
 * from the structure
 * Register fields filling:		PFnnn.xxx = fff
 * Register entire filling:		PFnnn = PFnnn_value
 */
#define	NATIVE_NV_WRITE_PFPFR_REG(PFPFR)	\
		NATIVE_NV_WRITE_PFPFR_REG_VALUE(PFPFR.PFPFR_reg)
#define	NATIVE_NV_WRITE_FPCR_REG(FPCR)	\
		NATIVE_NV_WRITE_FPCR_REG_VALUE(FPCR.FPCR_reg)
#define	NATIVE_NV_WRITE_FPSR_REG(FPSR)	\
		NATIVE_NV_WRITE_FPSR_REG_VALUE(FPSR.FPSR_reg)
#define	WRITE_PFPFR_REG(PFPFR)	\
		WRITE_PFPFR_REG_VALUE(PFPFR.PFPFR_reg)
#define	WRITE_FPCR_REG(FPCR)		WRITE_FPCR_REG_VALUE(FPCR.FPCR_reg)
#define	WRITE_FPSR_REG(FPSR)		WRITE_FPSR_REG_VALUE(FPSR.FPSR_reg)
static inline void
native_nv_write_PFPFR_reg(e2k_pfpfr_t PFPFR)
{
	NATIVE_NV_WRITE_PFPFR_REG(PFPFR);
}
static inline void
native_nv_write_FPCR_reg(e2k_fpcr_t FPCR)
{
	NATIVE_NV_WRITE_FPCR_REG(FPCR);
}
static inline void
native_nv_write_FPSR_reg(e2k_fpsr_t FPSR)
{
	NATIVE_NV_WRITE_FPSR_REG(FPSR);
}
static inline void
write_PFPFR_reg(e2k_pfpfr_t PFPFR)
{
	WRITE_PFPFR_REG(PFPFR);
}
static inline void
write_FPCR_reg(e2k_fpcr_t FPCR)
{
	WRITE_FPCR_REG(FPCR);
}
static inline void
write_FPSR_reg(e2k_fpsr_t FPSR)
{
	WRITE_FPSR_REG(FPSR);
}

/*
 * Read doubleword Processor Identification Register (IDR) to the structure
 * Register fields access:		fff = AS_STRACT(IDR).xxx or
 *					fff = IDR.IDR_xxx
 * Register entire access:		IDR_entire = AS_WORD(IDR) or
 *					IDR_entire = IDR.IDR_reg
 */
#define	NATIVE_READ_IDR_REG() \
({ \
	e2k_idr_t IDR; \
	AS_WORD(IDR) = NATIVE_READ_IDR_REG_VALUE(); \
	IDR; \
})
#define	BOOT_NATIVE_READ_IDR_REG()	NATIVE_READ_IDR_REG()
static	inline	e2k_idr_t
native_read_IDR_reg(void)
{
	return NATIVE_READ_IDR_REG();
}
static	inline	e2k_idr_t
boot_native_read_IDR_reg(void)
{
	return BOOT_NATIVE_READ_IDR_REG();
}
#define	READ_IDR_REG() \
({ \
	e2k_idr_t IDR; \
	AS_WORD(IDR) = READ_IDR_REG_VALUE(); \
	IDR; \
})
#define	BOOT_READ_IDR_REG() \
({ \
	e2k_idr_t IDR; \
	AS_WORD(IDR) = BOOT_READ_IDR_REG_VALUE(); \
	IDR; \
})
static	inline	e2k_idr_t
read_IDR_reg(void)
{
	return READ_IDR_REG();
}
static	inline	e2k_idr_t
boot_read_IDR_reg(void)
{
	return BOOT_READ_IDR_REG();
}

static inline instr_cs0_t *find_cs0(void *ip)
{
	instr_hs_t *hs;

	hs = (instr_hs_t *) &E2K_GET_INSTR_HS(ip);
	if (!hs->c0)
		return NULL;

	return (instr_cs0_t *) (hs + hs->s + hweight32(hs->al) + 1);
}

static inline instr_cs1_t *find_cs1(void *ip)
{
	instr_hs_t *hs;

	hs = (instr_hs_t *) &E2K_GET_INSTR_HS(ip);
	if (!hs->c1)
		return NULL;

	return (instr_cs1_t *) (hs + hs->mdl);
}

static inline int get_instr_size_by_vaddr(unsigned long addr)
{
	int instr_size;
	instr_syl_t *syl;
	instr_hs_t hs;

	syl = &E2K_GET_INSTR_HS((e2k_addr_t)addr);
	hs.word = *syl;
	instr_size = E2K_GET_INSTR_SIZE(hs);

	return instr_size;
}

#endif /* ! __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif  /* _E2K_CPU_REGS_H_ */
