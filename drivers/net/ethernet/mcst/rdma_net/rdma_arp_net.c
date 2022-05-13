
#include "rdma_user_intf_net.h"
#include "rdma_reg_net.h"


struct rdma_arp rdma_arp;

int rdma_init_arp()
{
	char *p_options, chr;
	char *rdma_mode_options = NULL;

	printk("rdma_init_arp(%p): START from 0x%08x\n", rdma_init_arp,
	       get_pc_call());
/*
	dbg_arp("rdma_arp:  id_sernum: 0x%x\n", idprom->id_sernum);
	dbg_arp("rdma_arp:  id_ethaddr: %x:%x:%x:%x:%x:%x\n",
		idprom->id_ethaddr[0],
		idprom->id_ethaddr[1],
		idprom->id_ethaddr[2],
		idprom->id_ethaddr[3],
		idprom->id_ethaddr[4],
		idprom->id_ethaddr[5]);
*/
	if (!rdma_mode_options) {
		printk("<1>rdma: SET rdma_mode_options!!!\n");
		printk("<1>USAGE: insmod rdma.o rdma_mode_options=n.a\n");
		printk("<1>where n - number node (0|1|2|3)\n");
		printk("<1>where a - acount nodes [1-4]\n");
		rdma_mode_options = "0.4";
//              return -1;
	}
	p_options = rdma_mode_options;
	sscanf(p_options, "%i%c%i", &rdma_arp.node, &chr, &rdma_arp.nodes);
	printk("rdma_init_arp: node: %i nodes: %i\n", rdma_arp.node,
	       rdma_arp.nodes);
	rdma_arp.ip_init[0][0] = rdma_arp.ip_init[0][1] =
	    rdma_arp.ip_init[0][2] = rdma_arp.ip_init[0][3] = 0;
	rdma_arp.ip_init[1][0] = rdma_arp.ip_init[1][1] =
	    rdma_arp.ip_init[1][2] = rdma_arp.ip_init[1][3] = 0;
	rdma_arp.ttl[0][0] = rdma_arp.ttl[0][1] = rdma_arp.ttl[0][2] =
	    rdma_arp.ttl[0][3] = 0xf;
	rdma_arp.ttl[1][0] = rdma_arp.ttl[1][1] = rdma_arp.ttl[1][2] =
	    rdma_arp.ttl[1][3] = 0xf;

	return 0;
}
