#ifndef __ASM_PARAVIRT_GUEST_MM_HOOKS_H
#define __ASM_PARAVIRT_GUEST_MM_HOOKS_H

#ifdef __KERNEL__

#ifdef	CONFIG_PARAVIRT_GUEST
static inline void
get_mm_notifier_locked(struct mm_struct *mm)
{
}
#endif /* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */
#endif	/* __ASM_PARAVIRT_GUEST_MM_HOOKS_H */
