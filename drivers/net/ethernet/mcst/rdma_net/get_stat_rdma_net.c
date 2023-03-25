#include "rdma_user_intf_net.h"

#ifdef __KERNEL__

#include "rdma_reg_net.h"
#include "rdma_error_net.h"

#define printf printk

#else

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>

struct stat_rdma *stat_rdma[2];

int dev_open(char *name)
{
	int fd;


	errno = 0;
	fd = open(name, O_RDWR);
	if (fd < 0) {
		printf("dev_open fail for dev: %s, err=%u: %s\n",
		       name, errno, strerror(errno));
		exit(1);
	}
	return (fd);
}
void my_close(int fd)
{
	int ret = 0;

	errno = 0;
	ret = close(fd);
	return;
}

int time_sleep = 2;

int main(int argc, char **argv)
{
	int fd, ret;

	stat_rdma[0] =
	    (struct stat_rdma *) malloc(sizeof(struct stat_rdma) << 1);
	if (!stat_rdma[0]) {
		printf("RDMA_GET_STAT: memory alloc: %s\n",
		       strerror(errno));
		return 1;
	}
	stat_rdma[1] =
	    (struct stat_rdma *) ((char *) stat_rdma[0] +
				  sizeof(struct stat_rdma));
	fd = dev_open(argv[1]);
	if (argc == 3) {
		ret = ioctl(fd, RDMA_SET_STAT, stat_rdma[0]);
		printf("RDMA_SET_STAT: %d %s\n", ret, strerror(errno));
	}
	while (1) {
		ret = ioctl(fd, RDMA_GET_STAT, stat_rdma[0]);
		if (ret < 0) {
			printf("RDMA_GET_STAT: %d: %s\n", ret,
			       strerror(errno));
			return 1;
		}
		get_stat_rdma();
		sleep(time_sleep);
		system("clear");
	}
	return 0;
}
#endif

int time_out = 0, cur_clock = 0;
int rdm0 = 0, rdm1 = 0;
int rdckb0 = 0, rdckb1 = 0;
int rdckbsr = 0;
int countkbsr = 0;
int countintr0 = 0;
int countintr1 = 0;

int get_stat_rdma(void)
{

#ifdef __KERNEL__
	printf("rdma_intr\t\t: %8x\t\t%8x\n",
	       stat_rdma[0]->rdma_intr, stat_rdma[1]->rdma_intr);
#else
	int rdmps0, rdmps1, rdckbs0, rdckbs1;

	if (stat_rdma[0]->cur_clock > cur_clock) {
		time_out = (stat_rdma[0]->cur_clock - cur_clock);
	} else {
		time_out =
		    (stat_rdma[0]->cur_clock + (0xffffffff - cur_clock));
	}
	if (time_out == 0)
		time_out = 1;
	cur_clock = stat_rdma[0]->cur_clock;
	countkbsr++;
	printf("rdma_intr\t\t: %8x\t%d\t%8x\t%d\n",
	       stat_rdma[0]->rdma_intr,
	       100 * (stat_rdma[0]->rdma_intr - countintr0) / time_out,
	       stat_rdma[1]->rdma_intr,
	       100 * (stat_rdma[1]->rdma_intr - countintr1) / time_out);
	countintr0 = stat_rdma[0]->rdma_intr;
	countintr1 = stat_rdma[1]->rdma_intr;

	rdmps0 = 100 * (stat_rdma[0]->rdm - rdm0) / time_out;
	rdmps1 = 100 * (stat_rdma[1]->rdm - rdm1) / time_out;
	printf("rdm_per_sec\t\t: %x\t%x\t%x\n",
	       rdmps0, rdmps1, rdmps0 + rdmps1);
	rdm0 = stat_rdma[0]->rdm;
	rdm1 = stat_rdma[1]->rdm;
	rdckbs0 = 100 * (stat_rdma[0]->rdc_kbyte - rdckb0) / time_out;
	rdckbs1 = 100 * (stat_rdma[1]->rdc_kbyte - rdckb1) / time_out;
	rdckbsr += rdckbs0 + rdckbs1;
	printf("rdckb_sec\t\t: %x\t%x\t%x\t%x\n",
	       rdckbs0, rdckbs1, rdckbs0 + rdckbs1, rdckbsr / countkbsr);
	rdckb0 = stat_rdma[0]->rdc_kbyte;
	rdckb1 = stat_rdma[1]->rdc_kbyte;
#endif
	printf("rdc_kbyte\t\t: %x\t%x\n",
	       stat_rdma[0]->rdc_kbyte, stat_rdma[1]->rdc_kbyte);
	printf("sm_rdm\t\t\t: %8x %8x\t%8x %8x\n",
	       stat_rdma[0]->es_sm, stat_rdma[0]->rdm, stat_rdma[1]->es_sm,
	       stat_rdma[1]->rdm);
	printf("es_msf\t\t\t: %8x\t%8x\n", stat_rdma[0]->es_msf,
	       stat_rdma[1]->es_msf);
	printf("rdm_SUM\t\t\t: %8x\t%8x\n",
	       stat_rdma[0]->TRWD_UNXP + stat_rdma[0]->rdm_UNXP +
	       stat_rdma[0]->rdm_EXP,
	       stat_rdma[1]->TRWD_UNXP + stat_rdma[1]->rdm_UNXP +
	       stat_rdma[1]->rdm_EXP);
	printf("nr sz    \t\t: %x %x\t%x %x\n", stat_rdma[0]->nr_in_steck,
	       stat_rdma[0]->sz_in_steck >> 10, stat_rdma[1]->nr_in_steck,
	       stat_rdma[1]->sz_in_steck >> 10);
	printf("try_RDMA\t\t: %8x\t%8x\n", stat_rdma[0]->try_RDMA,
	       stat_rdma[1]->try_RDMA);
	printf("try_TDMA\t\t: %x %x %x %x %x %x\t\t%x %x %x %x %x %x\n",
	       stat_rdma[0]->try_TDMA, stat_rdma[0]->try_TDMA_1,
	       stat_rdma[0]->try_TDMA_2, stat_rdma[0]->try_TDMA_3,
	       stat_rdma[0]->try_TDMA_4, stat_rdma[0]->try_TDMA_5,
	       stat_rdma[1]->try_TDMA, stat_rdma[1]->try_TDMA_1,
	       stat_rdma[1]->try_TDMA_2, stat_rdma[1]->try_TDMA_3,
	       stat_rdma[1]->try_TDMA_4, stat_rdma[1]->try_TDMA_5);
	printf("es_rdc\t\t\t: %8x\t%8x\n", stat_rdma[0]->es_rdc,
	       stat_rdma[1]->es_rdc);
	printf("tx avail\t\t\t: %x\t%x\n", stat_rdma[0]->tx_avail,
	       stat_rdma[1]->tx_avail);
	printf("rx avail\t\t\t: %x\t%x\n", stat_rdma[0]->rx_avail,
	       stat_rdma[1]->rx_avail);
	printf("bc avail\t\t\t: %x\t%x\n", stat_rdma[0]->bc_avail,
	       stat_rdma[1]->bc_avail);
	printf("tr avail\t\t\t: %x\t%x\n", stat_rdma[0]->tr_avail,
	       stat_rdma[1]->tr_avail);
	printf("tdc+dsf_tdc\t\t: %8x\t%8x\n",
	       stat_rdma[0]->es_dsf_tdc + stat_rdma[0]->es_tdc,
	       stat_rdma[1]->es_dsf_tdc + stat_rdma[1]->es_tdc);
	printf("es_tdc\t\t\t: %8x\t%8x\n", stat_rdma[0]->es_tdc,
	       stat_rdma[1]->es_tdc);
	printf("timeout\t\t\t: %x\t\t%x\n", stat_rdma[0]->tx_timeout,
	       stat_rdma[1]->tx_timeout);
	printf("es_dsf\t\t\t: %8x\t%8x\tes_cmie\t: %8x\t%8x\n",
	       stat_rdma[0]->es_dsf, stat_rdma[1]->es_dsf,
	       stat_rdma[0]->es_cmie, stat_rdma[1]->es_cmie);
	printf("dma_tcs_dps_err\t\t: %8x\t%8x\n",
	       stat_rdma[0]->dma_tcs_dps_err,
	       stat_rdma[1]->dma_tcs_dps_err);
	printf("dma_tcs_dpcrc_err\t: %8x\t%8x\n",
	       stat_rdma[0]->dma_tcs_dpcrc_err,
	       stat_rdma[1]->dma_tcs_dpcrc_err);
	printf("dma_tcs_dpto_err\t: %8x\t%8x\n",
	       stat_rdma[0]->dma_tcs_dpto_err,
	       stat_rdma[1]->dma_tcs_dpto_err);
	printf("dma_tcs_dpid_err\t: %8x\t%8x\n",
	       stat_rdma[0]->dma_tcs_dpid_err,
	       stat_rdma[1]->dma_tcs_dpid_err);
	printf("tdc_err\t\t\t: %8x\t%8x\tcs_sie\t: %8x\t%8x\n",
	       stat_rdma[0]->dma_tcs_dps_err +
	       stat_rdma[0]->dma_tcs_dpcrc_err +
	       stat_rdma[0]->dma_tcs_dpto_err +
	       stat_rdma[0]->dma_tcs_dpid_err,
	       stat_rdma[1]->dma_tcs_dps_err +
	       stat_rdma[1]->dma_tcs_dpcrc_err +
	       stat_rdma[1]->dma_tcs_dpto_err +
	       stat_rdma[1]->dma_tcs_dpid_err, stat_rdma[0]->cs_sie,
	       stat_rdma[1]->cs_sie);
	printf("spin_dead\t\t: %x %x %x %x\t %x %x %x %x\n",
	       stat_rdma[0]->spin_lvnet_tx_rdma_intr,
	       stat_rdma[0]->spin_lvnet_tx_lvnet_tx,
	       stat_rdma[0]->spin_rdma_intr_lvnet_tx,
	       stat_rdma[0]->spin_rdma_intr_rdma_intr,
	       stat_rdma[1]->spin_lvnet_tx_rdma_intr,
	       stat_rdma[1]->spin_lvnet_tx_lvnet_tx,
	       stat_rdma[1]->spin_rdma_intr_lvnet_tx,
	       stat_rdma[1]->spin_rdma_intr_rdma_intr);
	printf("stop_wake_queue\t\t: %d\t%x\t %x\n",
	       stat_rdma[0]->stop_wake_queue, stat_rdma[0]->stop_queue,
	       stat_rdma[0]->wake_queue);
	printf
	    ("rep tx_bc bc_bc tx_rt tr_rt tx_tr\t: %x %x %x %x %x\t%x %x %x %x %x\n",
	     stat_rdma[0]->rec_trwd_tx_bc, stat_rdma[0]->rec_trwd_bc_bc,
	     stat_rdma[0]->rec_trwd_tx_rt, stat_rdma[0]->rec_trwd_tr_rt,
	     stat_rdma[0]->rec_trwd_tx_tr, stat_rdma[1]->rec_trwd_tx_bc,
	     stat_rdma[1]->rec_trwd_bc_bc, stat_rdma[1]->rec_trwd_tx_rt,
	     stat_rdma[1]->rec_trwd_tr_rt, stat_rdma[1]->rec_trwd_tx_tr);

	printf("lance stop wake\t\t: %x %x %x %x %x\t %x %x %x %x\n",
	       stat_rdma[0]->lance_stop_1,
	       stat_rdma[0]->lance_stop_2,
	       stat_rdma[0]->lance_stop_3,
	       stat_rdma[0]->lance_stop_4,
	       stat_rdma[0]->lance_stop_5,
	       stat_rdma[0]->lance_wake_1,
	       stat_rdma[0]->lance_wake_2,
	       stat_rdma[0]->lance_wake_3, stat_rdma[0]->lance_wake_4);
	printf("rdc_waste\t\t: %x\t%x\n",
	       stat_rdma[0]->rdc_waste, stat_rdma[1]->rdc_waste);

	printf
	    ("fail_ snd_ready lvnet_tx: %x %x %x %x %x\t %x %x %x %x %x\n",
	     stat_rdma[0]->fail_snd_ready_rt,
	     stat_rdma[0]->fail_snd_ready_tr,
	     stat_rdma[0]->fail_snd_ready_bc,
	     stat_rdma[0]->fail_snd_ready_def, stat_rdma[0]->fail_lvnet_tx,
	     stat_rdma[1]->fail_snd_ready_rt,
	     stat_rdma[1]->fail_snd_ready_tr,
	     stat_rdma[1]->fail_snd_ready_bc,
	     stat_rdma[1]->fail_snd_ready_def,
	     stat_rdma[1]->fail_lvnet_tx);
	printf("nfor_rec_trwd_rt tr bc  : %x %x %x %x\t %x %x %x %x\n",
	       stat_rdma[0]->nfor_rec_trwd_rt,
	       stat_rdma[0]->nfor_rec_trwd_tr,
	       stat_rdma[0]->nfor_rec_trwd_bc,
	       stat_rdma[0]->nfor_rec_trwd_def,
	       stat_rdma[1]->nfor_rec_trwd_rt,
	       stat_rdma[1]->nfor_rec_trwd_tr,
	       stat_rdma[1]->nfor_rec_trwd_bc,
	       stat_rdma[1]->nfor_rec_trwd_def);
	printf("nfor_snd_trwd_tx tr bc  : %x %x %x %x\t %x %x %x %x\n",
	       stat_rdma[0]->nfor_snd_trwd_tx,
	       stat_rdma[0]->nfor_snd_trwd_tr,
	       stat_rdma[0]->nfor_snd_trwd_bc,
	       stat_rdma[0]->nfor_snd_trwd_def,
	       stat_rdma[1]->nfor_snd_trwd_tx,
	       stat_rdma[1]->nfor_snd_trwd_tr,
	       stat_rdma[1]->nfor_snd_trwd_bc,
	       stat_rdma[1]->nfor_snd_trwd_def);

	printf("LOW MOD HIGH DROP\t: %x %x %x %x\t %x %x %x %x\n",
	       stat_rdma[0]->net_rx_cn_low,
	       stat_rdma[0]->net_rx_cn_mod,
	       stat_rdma[0]->net_rx_cn_high,
	       stat_rdma[0]->net_rx_cn_drop,
	       stat_rdma[1]->net_rx_cn_low,
	       stat_rdma[1]->net_rx_cn_mod,
	       stat_rdma[1]->net_rx_cn_high, stat_rdma[1]->net_rx_cn_drop);
	printf("send_skb_err_1 _2 _3 _4\t: %x %x %x %x\t %x %x %x %x\n",
	       stat_rdma[0]->send_skb_pio_err_1,
	       stat_rdma[0]->send_skb_pio_err_2,
	       stat_rdma[0]->send_skb_pio_err_3,
	       stat_rdma[0]->send_skb_pio_err_4,
	       stat_rdma[1]->send_skb_pio_err_1,
	       stat_rdma[1]->send_skb_pio_err_2,
	       stat_rdma[1]->send_skb_pio_err_3,
	       stat_rdma[1]->send_skb_pio_err_4);
	printf("rec tr st br brst\t: %x %x %x %x %x\t %x %x %x %x %x\n",
	       stat_rdma[0]->rec_transmit, stat_rdma[0]->rec_in_steck,
	       stat_rdma[0]->rec_broad, stat_rdma[0]->rec_broad_steck,
	       stat_rdma[0]->rec_transmit + stat_rdma[0]->rec_in_steck +
	       stat_rdma[0]->rec_broad + stat_rdma[0]->rec_broad_steck,
	       stat_rdma[1]->rec_transmit, stat_rdma[1]->rec_in_steck,
	       stat_rdma[1]->rec_broad, stat_rdma[1]->rec_broad_steck,
	       stat_rdma[1]->rec_transmit + stat_rdma[1]->rec_in_steck +
	       stat_rdma[1]->rec_broad + stat_rdma[1]->rec_broad_steck);

	printf
	    ("***********************************************************\n");
	return 0;
}
