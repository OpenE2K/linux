/******************************************************************************
 * Copyright (c) 2012 Salavat Gilyazov
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */


#ifndef __ASM_E2K_KVM_PARAVIRT_H
#define __ASM_E2K_KVM_PARAVIRT_H

#ifdef	CONFIG_PARAVIRT

#ifndef __ASSEMBLY__

#ifdef	PATCHED_REG_ACCESS
extern asmlinkage unsigned int kvm_patched_read_PSR_reg_value(void);
extern asmlinkage void kvm_patched_write_PSR_reg_value(unsigned int reg_value);
extern asmlinkage unsigned int kvm_patched_read_UPSR_reg_value(void);
extern asmlinkage void kvm_patched_write_UPSR_reg_value(unsigned int reg_value);
extern asmlinkage unsigned long kvm_patched_read_PSP_lo_reg_value(void);
extern asmlinkage unsigned long kvm_patched_read_PSP_hi_reg_value(void);
extern asmlinkage void kvm_patched_write_PSP_lo_reg_value(
						unsigned long reg_value);
extern asmlinkage void kvm_patched_write_PSP_hi_reg_value(
						unsigned long reg_value);
extern asmlinkage unsigned long kvm_patched_read_PSHTP_reg_value(void);
extern asmlinkage void kvm_patched_write_PSHTP_reg_value(
						unsigned long reg_value);
extern asmlinkage unsigned long kvm_patched_read_PCSP_lo_reg_value(void);
extern asmlinkage unsigned long kvm_patched_read_PCSP_hi_reg_value(void);
extern asmlinkage void kvm_patched_write_PCSP_lo_reg_value(
						unsigned long reg_value);
extern asmlinkage void kvm_patched_write_PCSP_hi_reg_value(
						unsigned long reg_value);
extern asmlinkage int kvm_patched_read_PCSHTP_reg_svalue(void);
extern asmlinkage void kvm_patched_write_PCSHTP_reg_svalue(int reg_value);
extern asmlinkage unsigned long kvm_patched_read_CR0_lo_reg_value(void);
extern asmlinkage unsigned long kvm_patched_read_CR0_hi_reg_value(void);
extern asmlinkage unsigned long kvm_patched_read_CR1_lo_reg_value(void);
extern asmlinkage unsigned long kvm_patched_read_CR1_hi_reg_value(void);
extern asmlinkage void kvm_patched_write_CR0_lo_reg_value(
						unsigned long reg_value);
extern asmlinkage void kvm_patched_write_CR0_hi_reg_value(
						unsigned long reg_value);
extern asmlinkage void kvm_patched_write_CR1_lo_reg_value(
						unsigned long reg_value);
extern asmlinkage void kvm_patched_write_CR1_hi_reg_value(
						unsigned long reg_value);
extern asmlinkage unsigned long kvm_patched_read_USD_lo_reg_value(void);
extern asmlinkage unsigned long kvm_patched_read_USD_hi_reg_value(void);
extern asmlinkage void kvm_patched_write_USD_lo_reg_value(
						unsigned long reg_value);
extern asmlinkage void kvm_patched_write_USD_hi_reg_value(
						unsigned long reg_value);
extern asmlinkage unsigned long kvm_patched_read_WD_reg_value(void);
extern asmlinkage void kvm_patched_write_WD_reg_value(
						unsigned long reg_value);
extern asmlinkage unsigned int kvm_patched_read_aasr_reg_value(void);
extern asmlinkage void kvm_patched_write_aasr_reg_value(unsigned int reg_value);
extern asmlinkage void kvm_patched_flush_stacks(void);
extern asmlinkage void kvm_patched_flush_regs_stack(void);
extern asmlinkage void kvm_patched_flush_chain_stack(void);
extern asmlinkage void kvm_patched_put_updated_cpu_regs_flags(
							unsigned long flags);
#endif	/* PATCHED_REG_ACCESS */

#endif	/* ! __ASSEMBLY__ */

#endif	/* CONFIG_PARAVIRT */

#endif /* __ASM_E2K_KVM_PARAVIRT_H */
