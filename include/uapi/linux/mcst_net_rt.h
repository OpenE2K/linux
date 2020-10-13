#ifndef _UAPI_LINUX_MCST_NET_RT_H
#define _UAPI_LINUX_MCST_NET_RT_H

#include <linux/sockios.h>
#include <linux/if_ether.h>

#define RESET_IOCTL               (SIOCDEVPRIVATE + 0)
#define CHANEL_OFFLINE1_IOCTL     (SIOCDEVPRIVATE + 1)
#define CHANEL_OFFLINE2_IOCTL     (SIOCDEVPRIVATE + 7)
#define CHANEL_ONLINE1_IOCTL      (SIOCDEVPRIVATE + 3)
#define CHANEL_ONLINE2_IOCTL      (SIOCDEVPRIVATE + 4)
#define POLL_STATUS1_IOCTL        (SIOCDEVPRIVATE + 5)
#define POLL_STATUS2_IOCTL        (SIOCDEVPRIVATE + 6)


/* Here is RT net device sunlance interface */
#define SIOCDEV_SET_LANCE_RATE    SIOCDEVPRIVATE + 9

#define SIOCDEV_DUMP_DEV	SIOCDEVPRIVATE + 10
#define SIOCDEV_GET_LB_TIME	SIOCDEVPRIVATE + 11

#define SIOCDEV_RTND_OPEN       SIOCDEVPRIVATE + 12
#define SIOCDEV_RTND_CLOSE      SIOCDEVPRIVATE + 13
#define SIOCDEV_RTND_READ       SIOCDEVPRIVATE + 14
#define SIOCDEV_RTND_WRITE      SIOCDEVPRIVATE + 15


typedef struct el_netdev_udata {
        int proto;
        int rx_len;
        int skipped;
        int timeout;
        char * rx_buf;
        int tx_len;
        char *tx_buf;
        unsigned char src_mac[ETH_ALEN];
        unsigned char dst_mac[ETH_ALEN];
} el_netdev_udata_t;

#ifdef CONFIG_COMPAT
typedef struct el_netdev_udata_compat {
        int proto;
        int rx_len;
        int skipped;
        int timeout;
        u32 rx_buf;
        int tx_len;
        u32 tx_buf;
        unsigned char src_mac[ETH_ALEN];
        unsigned char dst_mac[ETH_ALEN];
} el_netdev_udata_compat_t;
#endif

#endif   /* _UAPI_LINUX_MCST_NET_RT_H */

