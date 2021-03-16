#ifndef _ASM_KVM_GUEST_E2K_VIRT_H_
#define _ASM_KVM_GUEST_E2K_VIRT_H_

#include <asm/mas.h>
#include <asm/kvm/guest/boot.h>

#define	E2K_VIRT_CPU_VENDOR	"Elbrus-MCST"
#define	E2K_VIRT_CPU_FAMILY	0xff
#define	E2K_VIRT_CPU_MODEL	IDR_E2K_VIRT_MDL
#define	E2K_VIRT_CPU_REVISION	16	/* 2016 year */
#define	E2K_VIRT_CPU_ISET	07	/* month */

/*
 * Machine (based on e2k virtual processor) topology:
 * It is classical SMP system on common memory, so can have only
 * one node and this node includes all CPUs
 */

#define	E2K_VIRT_NR_NODE_CPUS		KVM_MAX_VCPUS	/* all VCPUs */
#define E2K_VIRT_MAX_NR_NODE_CPUS	E2K_VIRT_NR_NODE_CPUS
#define	e2k_virt_cpu_to_node(cpu)	(0)
#define	e2k_virt_node_to_cpumask(node, main_cpu_mask)	\
		(main_cpu_mask)
#define	e2k_virt_node_to_first_cpu(node, main_cpu_mask)	\
		(0)	/* CPU #0 should be allways */

#define	boot_e2k_virt_cpu_to_node(cpu)	e2k_virt_cpu_to_node(cpu)
#define	boot_e2k_virt_node_to_cpumask(node, boot_main_cpu_mask)		\
					(boot_main_cpu_mask)
#define	boot_e2k_virt_node_to_first_cpu(node, boot_main_cpu_mask)	\
		e2k_virt_node_to_first_cpu(node, boot_main_cpu_mask)

/*
 * Local APIC cluster mode is not used for e2k-virt,
 * so APIC quad is the same as all CPUs combined to single quad #0
 */
#define	E2K_VIRT_NR_APIC_QUAD_CPUS	E2K_VIRT_NR_NODE_CPUS
#define	E2K_VIRT_MAX_APIC_QUADS		1
#define	e2k_virt_apic_quad_to_cpumask(quad, main_cpu_mask)		\
({									\
	main_cpu_mask;							\
})
#define	e2k_virt_cpu_to_apic_quad(cpu)	(0)
#define	e2K_virt_cpu_to_apic_cpu(cpu)	(cpu)

/*
 * IO links and IO controllers topology
 * E2K virtual machines use virtio interface to access to IO devices
 * All other machines use IO links and own chipset and main IO buses controller
 * is IOHUB.
 * Without losing generality, IO controller of e2k-virt can consider
 * as connected through simple IO link too, but it needs do not forget
 * that IO controller is VIRTIO while details are essential
 */
#define	E2K_VIRT_MAX_NUMIOLINKS	1	/* e2k-virt has only one IO */
					/* controller connected through */
					/* North bridge emulated by QEMU */
#define	E2K_VIRT_NODE_IOLINKS	E2K_VIRT_MAX_NUMIOLINKS

#endif /* _ASM_KVM_GUEST_E2K_VIRT_H_ */
