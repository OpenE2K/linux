/*
 *
 * Heading of boot-time initialization.
 *
 * Copyright (C) 2011 Salavat Guiliazov <atic@mcst.ru>
 */

#ifndef	_E2K_ASM_PARAVIRT_V2P_H
#define	_E2K_ASM_PARAVIRT_V2P_H

#include <linux/types.h>
#include <asm/p2v/boot_v2p.h>

#ifndef __ASSEMBLY__

/*
 * boot-time virtual to physical conversions hooks.
 */

typedef struct pv_v2p_ops {
	void *(*boot_kernel_va_to_pa)(void *virt_pnt,
					unsigned long kernel_base);
	void *(*boot_func_to_pa)(void *virt_pnt);
	e2k_addr_t (*boot_vpa_to_pa)(e2k_addr_t vpa);
	e2k_addr_t (*boot_pa_to_vpa)(e2k_addr_t pa);
	e2k_addr_t (*vpa_to_pa)(e2k_addr_t vpa);
	e2k_addr_t (*pa_to_vpa)(e2k_addr_t pa);
} pv_v2p_ops_t;

extern pv_v2p_ops_t pv_v2p_ops;
extern pv_v2p_ops_t *cur_pv_v2p_ops;	/* pointer to boot-time tables of OPs */

#define	BOOT_PARAVIRT_GET_BOOT_OPS_FUNC(boot_ops, func_name)		\
({									\
	typeof(boot_ops) ops = boot_native_get_vo_value(boot_ops);	\
	typeof(boot_ops->func_name) func;				\
	func = boot_native_vp_to_pp(ops)->func_name;			\
	func;								\
})

#define	BOOT_PARAVIRT_GET_V2P_FUNC(func_name)				\
		BOOT_PARAVIRT_GET_BOOT_OPS_FUNC(cur_pv_v2p_ops, func_name)

static inline void *
boot_pv_kernel_va_to_pa(void *virt_pnt, unsigned long kernel_base)
{
	return BOOT_PARAVIRT_GET_V2P_FUNC(boot_kernel_va_to_pa)
						(virt_pnt, kernel_base);
}

static inline void *
boot_pv_func_to_pa(void *virt_pnt)
{
	return BOOT_PARAVIRT_GET_V2P_FUNC(boot_func_to_pa)(virt_pnt);
}

static inline e2k_addr_t
boot_pv_vpa_to_pa(e2k_addr_t vpa)
{
	return BOOT_PARAVIRT_GET_V2P_FUNC(boot_vpa_to_pa)(vpa);
}
static	inline	e2k_addr_t
boot_pv_pa_to_vpa(e2k_addr_t pa)
{
	return BOOT_PARAVIRT_GET_V2P_FUNC(boot_pa_to_vpa)(pa);
}

static	inline	void *
boot_pv_va_to_pa(void *virt_pnt)
{
	return boot_pv_kernel_va_to_pa(virt_pnt, -1);
}

static inline e2k_addr_t
pv_vpa_to_pa(e2k_addr_t vpa)
{
	return pv_v2p_ops.vpa_to_pa(vpa);
}
static	inline	e2k_addr_t
pv_pa_to_vpa(e2k_addr_t pa)
{
	return pv_v2p_ops.pa_to_vpa(pa);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
static	inline	void *
boot_kernel_va_to_pa(void *virt_pnt, unsigned long kernel_base)
{
	return boot_pv_kernel_va_to_pa(virt_pnt, kernel_base);
}
static	inline	void *
boot_func_to_pa(void *virt_pnt)
{
	return boot_pv_func_to_pa(virt_pnt);
}

static	inline	void *
boot_va_to_pa(void *virt_pnt)
{
	return boot_pv_va_to_pa(virt_pnt);
}

static	inline	e2k_addr_t
boot_vpa_to_pa(e2k_addr_t vpa)
{
	return boot_pv_vpa_to_pa(vpa);
}
static	inline	e2k_addr_t
boot_pa_to_vpa(e2k_addr_t pa)
{
	return boot_pv_pa_to_vpa(pa);
}

static	inline	e2k_addr_t
vpa_to_pa(e2k_addr_t vpa)
{
	return pv_vpa_to_pa(vpa);
}
static	inline	e2k_addr_t
pa_to_vpa(e2k_addr_t pa)
{
	return pv_pa_to_vpa(pa);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* __ASSEMBLY__ */

#endif /* ! _E2K_ASM_PARAVIRT_V2P_H */
