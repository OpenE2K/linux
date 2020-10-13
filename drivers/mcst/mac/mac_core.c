#include <linux/module.h>
#include <linux/mac/mac_kernel.h>

unsigned int mac_test_inode = 0;
EXPORT_SYMBOL(mac_test_inode);

int mac_active = 0;
EXPORT_SYMBOL(mac_active);

int mac_attached = 0;
EXPORT_SYMBOL(mac_attached);

int (*kmac_access_userp)(kmac_subject_id_t, kmac_user_id_t, int);
EXPORT_SYMBOL(kmac_access_userp);

int (*kmac_access_addrp)(kmac_subject_id_t, kmac_addr_t, int);
EXPORT_SYMBOL(kmac_access_addrp);

int (*kmac_access_portp)(kmac_subject_id_t, kmac_port_t, kmac_proto_t, int);
EXPORT_SYMBOL(kmac_access_portp);

int (*sys_macctl_real)(register int request, register void *data,
				  register int size);
EXPORT_SYMBOL(sys_macctl_real);

asmlinkage int sys_macctl(register int request, register void *data,
			  register int size)
{               
	int     result = 0;
	if (mac_attached == 0) {
#ifdef MAC_DEBUG_MOD
		printk("MAC module not attached, return -(ENXIO: %d)\n", ENXIO);
#endif /* MAC_DEBUG_MOD */
		result = -ENXIO;
	} else {
		result = sys_macctl_real(request, data, size);
	}
	
	return (int)result;
}
EXPORT_SYMBOL(sys_macctl);
