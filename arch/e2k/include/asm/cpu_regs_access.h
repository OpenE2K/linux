#ifndef	_E2K_CPU_REGS_ACCESS_H_
#define	_E2K_CPU_REGS_ACCESS_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

#include <asm/cpu_regs.h>
#include <asm/e2k_api.h>
#include <linux/thread_info.h>

#define READ_PCSHTP_REG()		E2K_GET_SREG(pcshtp)

#define	WRITE_PCSHTP_REG_SVALUE(PCSHTP_svalue)			\
		E2K_SET_DSREG(pcshtp, PCSHTP_svalue)
#define	STRIP_PCSHTP_WINDOW()	WRITE_PCSHTP_REG_SVALUE(0)

/*
 * Read low double-word OS Compilation Unit Register (OSCUD)
 * from the low word structure
 * Register fields access:		fff = OSCUD_lo.OSCUD_lo_xxx;
 * Register double-word half access:	oscud_lo = OSCUD_lo.OSCUD_lo_half;
 */
#define	READ_OSCUD_LO_REG() \
({ \
	e2k_oscud_lo_t OSCUD_lo; \
	OSCUD_lo.OSCUD_lo_half = READ_OSCUD_LO_REG_VALUE(); \
	OSCUD_lo; \
})
static	inline	e2k_oscud_lo_t
read_OSCUD_lo_reg(void)
{
	return READ_OSCUD_LO_REG();
}

/*
 * Read high double-word OS Compilation Unit Register (OSCUD)
 * from the high word structure
 * Register fields access:		fff = OSCUD_hi.OSCUD_hi_xxx;
 * Register double-word half access:	oscud_lo = OSCUD_hi.OSCUD_hi_half;
 */
#define	READ_OSCUD_HI_REG() \
({ \
	e2k_oscud_hi_t OSCUD_hi; \
	OSCUD_hi.OSCUD_hi_half = READ_OSCUD_HI_REG_VALUE(); \
	OSCUD_hi; \
})
static	inline	e2k_oscud_hi_t
read_OSCUD_hi_reg(void)
{
	return READ_OSCUD_HI_REG();
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

static	inline	void
read_OSCUD_reg(oscud_struct_t *OSCUD)
{
	*OSCUD = READ_OSCUD_REG();
}

/*
 * Write low double-word OS Compilation Unit Register (OSCUD)
 * from the low word structure
 * Register fields filling:		OSCUD_lo.OSCUD_lo_xxx = fff;
 * Register double-word half filling:	OSCUD_lo.OSCUD_lo_half = oscud_lo;
 */
#define	WRITE_OSCUD_LO_REG(OSCUD_lo) \
({ \
	WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo.OSCUD_lo_half); \
})
static	inline	void
write_OSCUD_lo_reg(e2k_oscud_lo_t OSCUD_lo)
{
	WRITE_OSCUD_LO_REG(OSCUD_lo);
}

/*
 * Write high double-word OS Compilation Unit Register (OSCUD)
 * from the high word structure
 * Register fields filling:		OSCUD_hi.OSCUD_hi_xxx = fff;
 * Register double-word half filling:	OSCUD_hi.OSCUD_hi_half = oscud_lo;
 */
#define	WRITE_OSCUD_HI_REG(OSCUD_hi) \
({ \
	WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi.OSCUD_hi_half); \
})
static	inline	void
write_OSCUD_hi_reg(e2k_oscud_hi_t OSCUD_hi)
{
	WRITE_OSCUD_HI_REG(OSCUD_hi);
}

/*
 * Write high & low quad-word OS Compilation Unit Register (OSCUD)
 * from the high & low word structure
 */
#define	WRITE_OSCUD_REG(OSCUD_hi, OSCUD_lo) \
({ \
	WRITE_OSCUD_REG_VALUE(OSCUD_hi.OSCUD_hi_half, OSCUD_lo.OSCUD_lo_half); \
})
static	inline	void
write_OSCUD_hi_lo_reg(e2k_oscud_hi_t OSCUD_hi, e2k_oscud_lo_t OSCUD_lo)
{
	WRITE_OSCUD_REG(OSCUD_hi, OSCUD_lo);
}

/*
 * Write quad-word OS Compilation Unit Register (OSCUD) from the structure
 * Register fields filling:		OSCUD.OSCUD_xxx = fff;
 * Register double-word halfs filling:	OSCUD.OSCUD_lo_reg = OSCUD_lo;
 *					OSCUD.OSCUD_hi_reg = OSCUD_hi;
 */
static	inline	void
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
#define	READ_OSGD_LO_REG() \
({ \
	e2k_osgd_lo_t OSGD_lo; \
	OSGD_lo.OSGD_lo_half = READ_OSGD_LO_REG_VALUE(); \
	OSGD_lo; \
})
static	inline	e2k_osgd_lo_t
read_OSGD_lo_reg(void)
{
	return READ_OSGD_LO_REG();
}

/*
 * Read high double-word OS Globals Register (OSGD)
 * from the high word structure
 * Register fields access:		fff = OSGD_hi.OSGD_hi_xxx;
 * Register double-word half access:	osgd_lo = OSGD_hi.OSGD_hi_half;
 */
#define	READ_OSGD_HI_REG() \
({ \
	e2k_osgd_hi_t OSGD_hi; \
	OSGD_hi.OSGD_hi_half = READ_OSGD_HI_REG_VALUE(); \
	OSGD_hi; \
})
static	inline	e2k_osgd_hi_t
read_OSGD_hi_reg(void)
{
	return READ_OSGD_HI_REG();
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

static	inline	void
read_OSGD_reg(osgd_struct_t *OSGD)
{
	*OSGD = READ_OSGD_REG();
}


/*
 * Write low double-word OS Globals Register (OSGD)
 * from the low word structure
 * Register fields filling:		OSGD_lo.OSGD_lo_xxx = fff;
 * Register double-word half filling:	OSGD_lo.OSGD_lo_half = gd_lo;
 */
#define	WRITE_OSGD_LO_REG(OSGD_lo) \
({ \
	WRITE_OSGD_LO_REG_VALUE(OSGD_lo.OSGD_lo_half); \
})
static	inline	void
write_OSGD_lo_reg(e2k_osgd_lo_t OSGD_lo)
{
	WRITE_OSGD_LO_REG(OSGD_lo);
}

/*
 * Write high double-word OS Globals Register (OSGD)
 * from the high word structure
 * Register fields filling:		OSGD_hi.OSGD_hi_xxx = fff;
 * Register double-word half filling:	OSGD_hi.OSGD_hi_half = gd_lo;
 */
#define	WRITE_OSGD_HI_REG(OSGD_hi) \
({ \
	WRITE_OSGD_HI_REG_VALUE(OSGD_hi.OSGD_hi_half); \
})
static	inline	void
write_OSGD_hi_reg(e2k_osgd_hi_t OSGD_hi)
{
	WRITE_OSGD_HI_REG(OSGD_hi);
}

/*
 * Write high & low quad-word OS Globals Register (OSGD)
 * from the high & low word structure
 */
#define	WRITE_OSGD_REG(OSGD_hi, OSGD_lo) \
({ \
	WRITE_OSGD_REG_VALUE(OSGD_hi.OSGD_hi_half, OSGD_lo.OSGD_lo_half); \
})
static	inline	void
write_OSGD_hi_lo_reg(e2k_osgd_hi_t OSGD_hi, e2k_osgd_lo_t OSGD_lo)
{
	WRITE_OSGD_REG(OSGD_hi, OSGD_lo);
}

/*
 * Write quad-word OS Globals Register (OSGD) from the structure
 * Register fields filling:		OSGD.OSGD_xxx = fff;
 * Register double-word halfs filling:	OSGD.OSGD_lo_reg = OSGD_lo;
 *					OSGD.OSGD_hi_reg = OSGD_hi;
 */
static	inline	void
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
#define	READ_CUD_LO_REG() \
({ \
	e2k_cud_lo_t CUD_lo; \
	CUD_lo.CUD_lo_half = READ_CUD_LO_REG_VALUE(); \
	CUD_lo; \
})
static	inline	e2k_cud_lo_t
read_CUD_lo_reg(void)
{
	return READ_CUD_LO_REG();
}

/*
 * Read high double-word Compilation Unit Register (CUD)
 * from the high word structure
 * Register fields access:		fff = CUD_hi.CUD_hi_xxx;
 * Register double-word half access:	cud_lo = CUD_hi.CUD_hi_half;
 */
#define	READ_CUD_HI_REG() \
({ \
	e2k_cud_hi_t CUD_hi; \
	CUD_hi.CUD_hi_half = READ_CUD_HI_REG_VALUE(); \
	CUD_hi; \
})
static	inline	e2k_cud_hi_t
read_CUD_hi_reg(void)
{
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
static	inline	void
read_CUD_reg(cud_struct_t *CUD)
{
	*CUD = READ_CUD_REG();
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
static	inline	void
write_CUD_lo_reg(e2k_cud_lo_t CUD_lo)
{
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
static	inline	void
write_CUD_hi_reg(e2k_cud_hi_t CUD_hi)
{
	WRITE_CUD_HI_REG(CUD_hi);
}

/*
 * Write high & low quad-word Compilation Unit Register (CUD)
 * from the high & low word structure
 */
#define	WRITE_CUD_REG(CUD_hi, CUD_lo) \
({ \
	WRITE_CUD_REG_VALUE(CUD_hi.CUD_hi_half, CUD_lo.CUD_lo_half); \
})
static	inline	void
write_CUD_hi_lo_reg(e2k_cud_hi_t CUD_hi, e2k_cud_lo_t CUD_lo)
{
	WRITE_CUD_REG(CUD_hi, CUD_lo);
}

/*
 * Write quad-word Compilation Unit Register (CUD) from the structure
 * Register fields filling:		CUD.CUD_xxx = fff;
 * Register double-word halfs filling:	CUD.CUD_lo_reg = CUD_lo;
 *					CUD.CUD_hi_reg = CUD_hi;
 */
static	inline	void
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
static	inline	e2k_gd_lo_t
read_GD_lo_reg(void)
{
	return READ_GD_LO_REG();
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
static	inline	e2k_gd_hi_t
read_GD_hi_reg(void)
{
	return READ_GD_HI_REG();
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
static	inline	void
read_GD_reg(gd_struct_t *GD)
{
	*GD = READ_GD_REG();
}


/*
 * Write low double-word Globals Register (GD)
 * from the low word structure
 * Register fields filling:		GD_lo.GD_lo_xxx = fff;
 * Register double-word half filling:	GD_lo.GD_lo_half = gd_lo;
 */
#define	WRITE_GD_LO_REG(GD_lo) \
({ \
	E2K_SET_DSREG(gd.lo, GD_lo.GD_lo_half); \
})
static	inline	void
write_GD_lo_reg(e2k_gd_lo_t GD_lo)
{
	WRITE_GD_LO_REG(GD_lo);
}

/*
 * Write high double-word Globals Register (GD)
 * from the high word structure
 * Register fields filling:		GD_hi.GD_hi_xxx = fff;
 * Register double-word half filling:	GD_hi.GD_hi_half = gd_lo;
 */
#define	WRITE_GD_HI_REG(GD_hi) \
({ \
	E2K_SET_DSREG(gd.hi, GD_hi.GD_hi_half); \
})
static	inline	void
write_GD_hi_reg(e2k_gd_hi_t GD_hi)
{
	WRITE_GD_HI_REG(GD_hi);
}

/*
 * Write high & low quad-word Globals Register (GD)
 * from the high & low word structure
 */
#define	WRITE_GD_REG(GD_hi, GD_lo) \
({ \
	WRITE_GD_REG_VALUE(GD_hi.GD_hi_half, GD_lo.GD_lo_half); \
})
static	inline	void
write_GD_hi_lo_reg(e2k_gd_hi_t GD_hi, e2k_gd_lo_t GD_lo)
{
	WRITE_GD_REG(GD_hi, GD_lo);
}

/*
 * Write quad-word Globals Register (GD) from the structure
 * Register fields filling:		GD.GD_xxx = fff;
 * Register double-word halfs filling:	GD.GD_lo_reg = GD_lo;
 *					GD.GD_hi_reg = GD_hi;
 */
static	inline	void
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

/*
 * Read low double-word Procedure Stack Pointer Register (PSP)
 * from the low word structure
 * Register fields access:		fff = PSP_lo.PSP_lo_xxx;
 * Register double-word half access:	psp_lo = PSP_lo.PSP_lo_half;
 */
#define	READ_PSP_LO_REG() \
({ \
	e2k_psp_lo_t	PSP_lo; \
	PSP_lo.PSP_lo_half = READ_PSP_LO_REG_VALUE(); \
	PSP_lo; \
})
static	inline	e2k_psp_lo_t
read_PSP_lo_reg(void)
{
	return READ_PSP_LO_REG();
}

/*
 * Read high double-word Procedure Stack Pointer Register (PSP)
 * from the high word structure
 * Register fields access:		fff = PSP_hi.PSP_hi_xxx;
 * Register double-word half access:	psp_lo = PSP_hi.PSP_hi_half;
 */
#define	READ_PSP_HI_REG() \
({ \
	e2k_psp_hi_t	PSP_hi; \
	PSP_hi.PSP_hi_half = READ_PSP_HI_REG_VALUE(); \
	PSP_hi; \
})
static	inline	e2k_psp_hi_t
read_PSP_hi_reg(void)
{
	return READ_PSP_HI_REG();
}

#define	RAW_READ_PSP_HI_REG() \
({ \
	e2k_psp_hi_t	PSP_hi; \
	PSP_hi.PSP_hi_half = RAW_READ_PSP_HI_REG_VALUE(); \
	PSP_hi; \
})

/*
 * Read quad-word Procedure Stack Pointer Register (PSP) to the structure
 * Register fields access:		fff = PSP -> PSP_xxx
 * Register double-word halfs access:	PSP_lo_word = PSP -> PSP_lo_reg
 *					PSP_hi_word = PSP -> PSP_hi_reg
 */
#define	READ_PSP_REG() \
({ \
	psp_struct_t	PSP; \
	PSP.PSP_hi_struct = READ_PSP_HI_REG(); \
	PSP.PSP_lo_struct = READ_PSP_LO_REG(); \
	PSP; \
})

#define	RAW_READ_PSP_REG() \
({ \
	psp_struct_t	PSP; \
	PSP.PSP_hi_struct = RAW_READ_PSP_HI_REG(); \
	PSP.PSP_lo_struct = READ_PSP_LO_REG(); \
	PSP; \
})



/*
 * Write low double-word Procedure Stack Pointer Register (PSP)
 * from the low word structure
 * Register fields filling:		PSP_lo.PSP_lo_xxx = fff;
 * Register double-word half filling:	PSP_lo.PSP_lo_half = psp_lo;
 */
#define	WRITE_PSP_LO_REG(PSP_lo) \
({ \
	WRITE_PSP_LO_REG_VALUE((PSP_lo).PSP_lo_half); \
})
static	inline	void
write_PSP_lo_reg(e2k_psp_lo_t PSP_lo)
{
	WRITE_PSP_LO_REG(PSP_lo);
}

/*
 * Write high double-word Procedure Stack Pointer Register (PSP)
 * from the high word structure
 * Register fields filling:		PSP_hi.PSP_hi_xxx = fff;
 * Register double-word half filling:	PSP_hi.PSP_hi_half = psp_lo;
 */
#define	WRITE_PSP_HI_REG(PSP_hi) \
({ \
	WRITE_PSP_HI_REG_VALUE((PSP_hi).PSP_hi_half); \
})
static	inline	void
write_PSP_hi_reg(e2k_psp_hi_t PSP_hi)
{
	WRITE_PSP_HI_REG(PSP_hi);
}

#define	RAW_WRITE_PSP_HI_REG(PSP_hi) \
({ \
	RAW_WRITE_PSP_HI_REG_VALUE((PSP_hi).PSP_hi_half); \
})

/*
 * Write high & low quad-word Procedure Stack Pointer Register (PSP)
 * from the high & low word structure
 */
#define	WRITE_PSP_REG(PSP_hi, PSP_lo) \
({ \
	WRITE_PSP_HI_REG(PSP_hi); \
	WRITE_PSP_LO_REG(PSP_lo); \
})
static	inline	void
write_PSP_hi_lo_reg(e2k_psp_hi_t PSP_hi, e2k_psp_lo_t PSP_lo)
{
	WRITE_PSP_REG(PSP_hi, PSP_lo);
}

#define	RAW_WRITE_PSP_REG(PSP_hi, PSP_lo) \
({ \
	RAW_WRITE_PSP_HI_REG(PSP_hi); \
	WRITE_PSP_LO_REG(PSP_lo); \
})


/*
 * Read quad-word Procedure Chain Stack Pointer Register (PCSP) to the structure
 * Register fields access:		PCSP_hi = READ_PCSP_HI_REG();
 *					fff = PCSP_hi.PCSP_hi_xxx;
 *					PCSP_lo = READ_PCSP_LO_REG();
 *					fff = PCSP_lo.PCSP_lo_xxx;
 */

/*
 * Read low double-word Procedure Chain Stack Pointer Register (PCSP)
 * from the low word structure
 * Register fields access:		fff = PCSP_lo.PCSP_lo_xxx;
 * Register double-word half access:	pcsp_lo = PCSP_lo.PCSP_lo_half;
 */
#define	READ_PCSP_LO_REG() \
({ \
	e2k_pcsp_lo_t PCSP_lo; \
	PCSP_lo.PCSP_lo_half = READ_PCSP_LO_REG_VALUE(); \
	PCSP_lo; \
})
static	inline	e2k_pcsp_lo_t
read_PCSP_lo_reg(void)
{
	return READ_PCSP_LO_REG();
}

/*
 * Read high double-word Procedure Chain Stack Pointer Register (PCSP)
 * from the high word structure
 * Register fields access:		fff = PCSP_hi.PCSP_hi_xxx;
 * Register double-word half access:	pcsp_lo = PCSP_hi.PCSP_hi_half;
 */
#define	READ_PCSP_HI_REG() \
({ \
	e2k_pcsp_hi_t PCSP_hi; \
	PCSP_hi.PCSP_hi_half = READ_PCSP_HI_REG_VALUE(); \
	PCSP_hi; \
})
static	inline	e2k_pcsp_hi_t
read_PCSP_hi_reg(void)
{
	return READ_PCSP_HI_REG();
}

#define	RAW_READ_PCSP_HI_REG() \
({ \
	e2k_pcsp_hi_t PCSP_hi; \
	PCSP_hi.PCSP_hi_half = RAW_READ_PCSP_HI_REG_VALUE(); \
	PCSP_hi; \
})

/*
 * Read quad-word Procedure Chain Stack Pointer Register (PCSP) to the structure
 * Register fields access:		fff = PCSP -> PCSP_xxx
 * Register double-word halfs access:	PCSP_lo_word = PCSP -> PCSP_lo_reg
 *					PCSP_hi_word = PCSP -> PCSP_hi_reg
 */
#define	READ_PCSP_REG() \
({ \
	pcsp_struct_t	PCSP; \
	PCSP.PCSP_hi_struct = READ_PCSP_HI_REG(); \
	PCSP.PCSP_lo_struct = READ_PCSP_LO_REG(); \
	PCSP; \
})

#define	RAW_READ_PCSP_REG() \
({ \
	pcsp_struct_t	PCSP; \
	PCSP.PCSP_hi_struct = RAW_READ_PCSP_HI_REG(); \
	PCSP.PCSP_lo_struct = READ_PCSP_LO_REG(); \
	PCSP; \
})


/*
 * Write low double-word Procedure Chain Stack Pointer Register (PCSP)
 * from the low word structure
 * Register fields filling:		PCSP_lo.PCSP_lo_xxx = fff;
 * Register double-word half filling:	PCSP_lo.PCSP_lo_half = pcsp_lo;
 */
#define	WRITE_PCSP_LO_REG(PCSP_lo) \
({ \
	WRITE_PCSP_LO_REG_VALUE((PCSP_lo).PCSP_lo_half); \
})
static	inline	void
write_PCSP_lo_reg(e2k_pcsp_lo_t PCSP_lo)
{
	WRITE_PCSP_LO_REG(PCSP_lo);
}

/*
 * Write high double-word Procedure Chain Stack Pointer Register (PCSP)
 * from the high word structure
 * Register fields filling:		PCSP_hi.PCSP_hi_xxx = fff;
 * Register double-word half filling:	PCSP_hi.PCSP_hi_half = pcsp_lo;
 */
#define	WRITE_PCSP_HI_REG(PCSP_hi) \
({ \
	WRITE_PCSP_HI_REG_VALUE((PCSP_hi).PCSP_hi_half); \
})
static	inline	void
write_PCSP_hi_reg(e2k_pcsp_hi_t PCSP_hi)
{
	WRITE_PCSP_HI_REG(PCSP_hi);
}

#define	RAW_WRITE_PCSP_HI_REG(PCSP_hi) \
({ \
	RAW_WRITE_PCSP_HI_REG_VALUE((PCSP_hi).PCSP_hi_half); \
})

/*
 * Write high & low quad-word Procedure Chain Stack Pointer Register (PCSP)
 * from the high & low word structure
 */
#define	WRITE_PCSP_REG(PCSP_hi, PCSP_lo) \
({ \
	WRITE_PCSP_HI_REG_VALUE((PCSP_hi).PCSP_hi_half); \
	WRITE_PCSP_LO_REG_VALUE((PCSP_lo).PCSP_lo_half); \
})
static	inline	void
write_PCSP_hi_lo_reg(e2k_pcsp_hi_t PCSP_hi, e2k_pcsp_lo_t PCSP_lo)
{
	WRITE_PCSP_REG(PCSP_hi, PCSP_lo);
}

#define	RAW_WRITE_PCSP_REG(PCSP_hi, PCSP_lo) \
({ \
	RAW_WRITE_PCSP_HI_REG_VALUE((PCSP_hi).PCSP_hi_half); \
	WRITE_PCSP_LO_REG_VALUE((PCSP_lo).PCSP_lo_half); \
})


/*
 * Read signed word-register Procedure Chain Stack Hardware
 * Top Pointer (PCSHTP)
 */

static	inline	e2k_pcshtp_t
read_PCSHTP_reg(void)
{
	return READ_PCSHTP_REG();
}

/*
 * Write signed word-register Procedure Chain Stack Hardware
 * Top Pointer (PCSHTP)
 */

static	inline	void
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
#define	READ_USD_LO_REG() \
({ \
	e2k_usd_lo_t	USD_lo; \
	USD_lo.USD_lo_half = READ_USD_LO_REG_VALUE(); \
	USD_lo; \
})
static	inline	e2k_usd_lo_t
read_USD_lo_reg(void)
{
	return READ_USD_LO_REG();
}

/*
 * Read high double-word Non-Protected User Stack Descriptor Register (USD)
 * as the high word structure
 * Register fields access:		USD_hi = READ_USD_HI_REG();
 *					fff = USD_hi.USD_hi_xxx;
 */
#define	READ_USD_HI_REG() \
({ \
	e2k_usd_hi_t	USD_hi; \
	USD_hi.USD_hi_half = READ_USD_HI_REG_VALUE(); \
	USD_hi; \
})
static	inline	e2k_usd_hi_t
read_USD_hi_reg(void)
{
	return READ_USD_HI_REG();
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
static	inline	void
read_USD_reg(usd_struct_t *USD)
{
	*USD = READ_USD_REG();
}

/*
 * Write low double-word Non-Protected User Stack Descriptor Register (USD)
 * from the low word structure
 * Register fields filling:		USD_lo.USD_lo_xxx = fff;
 * Register double-word half filling:	USD_lo.USD_lo_half = usd_lo;
 */
#define	WRITE_USD_LO_REG(USD_lo) WRITE_USD_LO_REG_VALUE(USD_lo.USD_lo_half)

static	inline	void
write_USD_lo_reg(e2k_usd_lo_t USD_lo)
{
	WRITE_USD_LO_REG(USD_lo);
}

/*
 * Write high double-word Non-Protected User Stack Descriptor Register (USD)
 * from the high word structure
 * Register fields filling:		USD_hi.USD_hi_xxx = fff;
 * Register double-word half filling:	USD_hi.USD_hi_half = usd_hi;
 */
#define	WRITE_USD_HI_REG(USD_hi) WRITE_USD_HI_REG_VALUE(USD_hi.USD_hi_half)

static	inline	void
write_USD_hi_reg(e2k_usd_hi_t USD_hi)
{
	WRITE_USD_HI_REG(USD_hi);
}

/*
 * Write high & low quad-word Non-Protected User Stack Descriptor Register (USD)
 * from the high & low word structure
 */
#define	WRITE_USD_REG(USD_hi, USD_lo) \
({ \
	WRITE_USD_REG_VALUE(USD_hi.USD_hi_half, USD_lo.USD_lo_half); \
})
static	inline	void
write_USD_hi_lo_reg(e2k_usd_hi_t USD_hi, e2k_usd_lo_t USD_lo)
{
	WRITE_USD_REG(USD_hi, USD_lo);
}

/*
 * Write quad-word Non-Protected User Stack Descriptor Register (USD)
 * from the structure
 * Register fields filling:		USD.USD_xxx = fff;
 * Register double-word halfs filling:	USD.USD_lo_reg = USD_lo;
 *					USD.USD_hi_reg = USD_hi;
 */
static	inline	void
write_USD_reg(usd_struct_t USD)
{
	WRITE_USD_REG(USD.USD_hi_struct, USD.USD_lo_struct);
}

/*
 * Read low double-word Protected User Stack Descriptor Register (PUSD)
 * as the low word structure
 * Register fields access:		PUSD_lo = READ_PUSD_LO_REG();
 *					fff = PUSD_lo.PUSD_lo_xxx;
 */
#define	READ_PUSD_LO_REG() \
({ \
	e2k_pusd_lo_t	PUSD_lo; \
	PUSD_lo.PUSD_lo_half = READ_PUSD_LO_REG_VALUE(); \
	PUSD_lo; \
})
static	inline	e2k_pusd_lo_t
read_PUSD_lo_reg(void)
{
	return READ_PUSD_LO_REG();
}

/*
 * Read high double-word Protected User Stack Descriptor Register (PUSD)
 * as the high word structure
 * Register fields access:		PUSD_hi = READ_PUSD_HI_REG();
 *					fff = PUSD_hi.PUSD_hi_xxx;
 */
#define	READ_PUSD_HI_REG() \
({ \
	e2k_pusd_hi_t	PUSD_hi; \
	PUSD_hi.PUSD_hi_half = READ_PUSD_HI_REG_VALUE(); \
	PUSD_hi; \
})
static	inline	e2k_pusd_hi_t
read_PUSD_hi_reg(void)
{
	return READ_PUSD_HI_REG();
}

/*
 * Read quad-word User Protected Stack Descriptor Register (PUSD)
 * to the structure
 * Register fields access:		fff = PUSD -> PUSD_xxx
 * Register double-word halfs access:	PUSD_lo = PUSD -> PUSD_lo_reg
 *					PUSD_hi = PUSD -> PUSD_hi_reg
 */
#define	READ_PUSD_REG() \
({ \
	pusd_struct_t	PUSD; \
	PUSD.PUSD_hi_struct = READ_PUSD_HI_REG(); \
	PUSD.PUSD_lo_struct = READ_PUSD_LO_REG(); \
	PUSD; \
})
static	inline	void
read_PUSD_reg(pusd_struct_t *PUSD)
{
	*PUSD = READ_PUSD_REG();
}

/*
 * Write low double-word Protected User Stack Descriptor Register (PUSD)
 * from the low word structure
 * Register fields filling:		PUSD_lo.PUSD_lo_xxx = fff;
 * Register double-word half filling:	PUSD_lo.PUSD_lo_half = pusd_lo;
 */
#define	WRITE_PUSD_LO_REG(PUSD_lo) \
		WRITE_PUSD_LO_REG_VALUE(PUSD_lo.PUSD_lo_half)

static	inline	void
write_PUSD_lo_reg(e2k_pusd_lo_t PUSD_lo)
{
	WRITE_PUSD_LO_REG(PUSD_lo);
}

/*
 * Write high double-word Protected User Stack Descriptor Register (PUSD)
 * from the high word structure
 * Register fields filling:		PUSD_hi.PUSD_hi_xxx = fff;
 * Register double-word half filling:	PUSD_hi.PUSD_hi_half = pusd_hi;
 */
#define	WRITE_PUSD_HI_REG(PUSD_hi) \
		WRITE_PUSD_HI_REG_VALUE(PUSD_hi.PUSD_hi_half)

static	inline	void
write_PUSD_hi_reg(e2k_pusd_hi_t PUSD_hi)
{
	WRITE_PUSD_HI_REG(PUSD_hi);
}

/*
 * Write high & low quad-word Protected User Stack Descriptor Register (PUSD)
 * from the high & low word structure
 */
#define	WRITE_PUSD_REG(PUSD_hi, PUSD_lo) \
({ \
	WRITE_PUSD_REG_VALUE(PUSD_hi.PUSD_hi_half, PUSD_lo.PUSD_lo_half); \
})
static	inline	void
write_PUSD_hi_lo_reg(e2k_pusd_hi_t PUSD_hi, e2k_pusd_lo_t PUSD_lo)
{
	WRITE_PUSD_REG(PUSD_hi, PUSD_lo);
}

/*
 * Write quad-word User Protected Stack Descriptor Register (PUSD)
 * from the structure
 * Register fields filling:		PUSD.PUSD_xxx = fff;
 * Register double-word halfs filling:	PUSD.PUSD_lo_reg = PUSD_lo;
 *					PUSD.PUSD_hi_reg = PUSD_hi;
 */
static	inline	void
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
	usbr_struct_t USBR; \
	USBR.USBR_reg = READ_USBR_REG_VALUE(); \
	USBR; \
})
static	inline	usbr_struct_t
read_USBR_reg(void)
{
	return READ_USBR_REG();
}

/*
 * Write double-word User Stacks Base Register (USBR) from the structure
 * Register fields filling:		USBR.USBR_xxx = fff;
 * Register entire filling:		USBR.USBR_reg = USBR_value;
 */
#define	WRITE_USBR_REG(USBR)	WRITE_USBR_REG_VALUE(USBR.USBR_reg)

static	inline	void
write_USBR_reg(usbr_struct_t USBR)
{
	WRITE_USBR_REG(USBR);
}

/*
 * Read double-word Stacks Base Register (SBR) to the structure
 * Register fields access:		fff = SBR -> SBR_xxx
 * Register entire access:		SBR_entire = SBR -> SBR_reg
 */
#define	READ_SBR_REG() \
({ \
	sbr_struct_t SBR; \
	SBR.SBR_reg = READ_SBR_REG_VALUE(); \
	SBR; \
})
static	inline	sbr_struct_t
read_SBR_reg(void)
{
	return READ_SBR_REG();
}

/*
 * Write double-word Stacks Base Register (SBR) from the structure
 * Register fields filling:		SBR.SBR_xxx = fff;
 * Register entire filling:		SBR.SBR_reg = SBR_value;
 */
#define	WRITE_SBR_REG(SBR)		WRITE_SBR_REG_VALUE(SBR.SBR_reg)
static	inline	void
write_SBR_reg(sbr_struct_t SBR)
{
	WRITE_SBR_REG(SBR);
}


#define	READ_PSHTP_REG() \
({ \
	e2k_pshtp_t PSHTP_reg; \
	PSHTP_reg.word = READ_PSHTP_REG_VALUE(); \
	PSHTP_reg; \
})


#define	WRITE_PSHTP_REG(PSHTP_reg) \
({ \
	WRITE_PSHTP_REG_VALUE(AS_WORD(PSHTP_reg)); \
})
#define	STRIP_PSHTP_WINDOW()	WRITE_PSHTP_REG_VALUE(0)


/*
 * Read word Base Global Register (BGR) to the structure
 * Register fields access:		fff = AS_STRACT(BGR).xxx
 * Register entire access:		BGR_entire = AS_WORD(BGR)
 */
#define	READ_BGR_REG() \
({ \
	e2k_bgr_t BGR; \
	AS_WORD(BGR) = READ_BGR_REG_VALUE(); \
	BGR; \
})
static	inline	e2k_bgr_t
read_BGR_reg(void)
{
	return READ_BGR_REG();
}

/*
 * Write word Base Global Register (BGR) from the structure
 * Register fields filling:		AS_STRACT(BGR).xxx = fff
 * Register entire filling:		AS_WORD(BGR) = BGR_value
 */
#define	WRITE_BGR_REG(BGR)		WRITE_BGR_REG_VALUE(AS_WORD(BGR))
static	inline	void
write_BGR_reg(e2k_bgr_t BGR)
{
	WRITE_BGR_REG(BGR);
}

#define	INIT_BGR_REG()	WRITE_BGR_REG(E2K_INITIAL_BGR)
static	inline	void
init_BGR_reg(void)
{
	INIT_BGR_REG();
}


/*
 * Read double-word Compilation Unit Table Register (CUTD) to the structure
 * Register fields access:		fff = CUTD.CUTD_xxx or
 *					fff = CUTD->CUTD_xxx
 * Register entire access:		CUTD_entire = CUTD.CUTD_reg or
 *					CUTD_entire = CUTD->CUTD_reg
 */
#define	READ_CUTD_REG() \
({ \
	e2k_cutd_t CUTD; \
	CUTD.CUTD_reg = READ_CUTD_REG_VALUE(); \
	CUTD; \
})
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
#define	WRITE_CUTD_REG(CUTD)		 WRITE_CUTD_REG_VALUE(CUTD.CUTD_reg)
static	inline	void
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
 * Write word Compilation Unit Index Register (CUIR) from the structure
 * Register fields filling:		CUIR.CUIR_xxx = fff or
 *					CUIR->CUIR_xxx = fff
 * Register entire filling:		CUIR.CUIR_reg = CUIR_value or
 *					CUIR->CUIR_reg = CUIR_value
 */
#define	WRITE_CUIR_REG(CUIR)		 WRITE_CUIR_REG_VALUE(CUIR.CUIR_reg)
static	inline	void
write_CUIR_reg(e2k_cuir_t CUIR)
{
	WRITE_CUIR_REG(CUIR);
}


/*
 * Read word User PRocessor State Register (UPSR) to the structure
 * Register fields access:		fff = AS_STRACT(UPSR).xxx
 * Register entire access:		UPSR_entire = AS_WORD(UPSR)
 */
#define	READ_UPSR_REG() \
({ \
	e2k_upsr_t UPSR; \
	AS_WORD(UPSR) = READ_UPSR_REG_VALUE(); \
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
#define	WRITE_UPSR_REG(UPSR)		WRITE_UPSR_REG_VALUE(AS_WORD(UPSR))
static	inline	void
write_UPSR_reg(e2k_upsr_t UPSR)
{
	WRITE_UPSR_REG(UPSR);
}


/*
 * Read doubleword User Processor Identification Register (IDR) to the structure
 * Register fields access:		fff = AS_STRACT(IDR).xxx or
 *					fff = IDR.IDR_xxx
 * Register entire access:		IDR_entire = AS_WORD(IDR) or
 *					IDR_entire = IDR.IDR_reg
 */
#define	READ_IDR_REG() \
({ \
	e2k_idr_t IDR; \
	AS_WORD(IDR) = READ_IDR_REG_VALUE(); \
	IDR; \
})
static	inline	e2k_idr_t
read_IDR_reg(void)
{
	return READ_IDR_REG();
}

#endif /* ! __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif  /* _E2K_CPU_REGS_ACCESS_H_ */
