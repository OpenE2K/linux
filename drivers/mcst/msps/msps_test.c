
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/mcst/msps_io.h>
#include <linux/mcst/mcst_selftest.h>

#include <sys/time.h>

#define myprintf(fmt, args...) printf("* msps_test:\t" fmt, ## args)

#define DEV_NAME	"/dev/msps0"

u_long	*dma[2];
char	dev_name[1024] = DEV_NAME;
int	instance = 0;
int	selftest_flag = 0;
int	active_work = 0;
int	data_size = 64; /* bytes */
int	write_flag = 0;
int	testmode_flag = 0; /* plug at PLIS 1 -> 0, 3 -> 2, 5 -> 4 */
int	nothing_flag = 0;

static  time_t test_time = 60;
static  time_t print_time = 5;

void print_first_dma()
{
	myprintf("first  dma bytes: 0x%lx 0x%lx\n",
		 *(dma[0] + 0), *(dma[1] + 0));
	myprintf("second dma bytes: 0x%lx 0x%lx\n",
		 *(dma[0] + 1), *(dma[1] + 1));
}


static void
test_opt(int ac, char **av)
{
	int     i;
	while ((i = getopt(ac, av, "?hnTi:t:Ss:p:aA:")) != EOF) {
		switch (i) {
		case 'i':
			instance = atol(optarg);
			if (instance == 1 || instance == 3 || instance == 5)
				write_flag = 1;
			sprintf(dev_name, "/dev/msps%d", instance);
			break;
		case 'a':
			active_work = 1;
			break;
		case 'A':
			active_work = atol(optarg);
			if (active_work < 0)
				active_work = 0;
			break;
		case 'd': /* temporary off */
			sprintf(dev_name, "%s", optarg);
			break;
		case 't':
			test_time = atol(optarg);
			if (test_time < 0)
				test_time = 0;
			break;
		case 'T':
			testmode_flag = 1;
			break;
		case 'S':
			selftest_flag = 1;
			break;
		case 's':
			data_size = atol(optarg);
			if (data_size <= 0)
				data_size = 1;
			break;
		case 'p':
			print_time = atol(optarg);
			break;
		case 'n':
			nothing_flag = 1;
			break;
		case '?':
		case 'h':
			printf("Parameters:\n"
			       "\t[-d path to device (temporary off)]\n"
			       "\t[-i instance number/dev/msps?]\n"
			       "\t[-t test time]\n"
			       "\t[-s size data]\n"
			       "\t[-S run internal test]\n"
			       "\t[-p period output print]\n"
			       "\t[-T test exchange mode]\n"
			       "\t[-n do nothing, only open/close (-S working)]\n"
			       "\t[-a active wait on cpu (not interrupt) 10 microsec]\n"
			       "\t[-A active wait on cpu - arg - time waiting]\n");
			exit(0);
			break;
		}
	}
}

int main(int ac, char **av)
{

	int	fd, res;
	msps_status_t status;
	msps_setup_a_t activetask;
	msps_setup_t *task = &activetask.s;
	int i;
	u_long mask = 0;

	test_opt(ac, av);

	fd = open(dev_name, O_RDWR);
	if (fd == -1) {
		myprintf("Cant open device (%s): %s\n",
			  dev_name, strerror(errno));
		return -1;
	}

	if (selftest_flag) {
		selftest_t test;

		res = ioctl(fd, MCST_SELFTEST_MAGIC, &test);
		if (res < 0) {
			myprintf("selfttest ioctl get error\n");
		} else {

			printf("selftest: %d %d (0x%x 0x%x 0x%x) [%d %d] (0x%x 0x%x 0x%x) \"%s\"\n",
			       test.bus_type,
			       test.error,
			       test.info.pci.vendor,
			       test.info.pci.device,
			       test.info.pci.class,
			       test.info.pci.major,
			       test.info.pci.minor,
			       test.info.pci.bus,
			       test.info.pci.slot,
			       test.info.pci.func,
			       test.info.pci.name
				);
		}
	}

	if (nothing_flag)
		goto end;

	dma[0] = (u_long *)mmap(0, MSPS_DMA_SIZE, PROT_READ | PROT_WRITE,
				  MAP_SHARED, fd,
				  MSPS_DMA_MMAP_0);
	if (dma[0] == (u_long *)-1) {
		myprintf("Error mmap dma[0]: %s\n", strerror(errno));
		return -1;
	}

	dma[1] = (u_long *)mmap(0, MSPS_DMA_SIZE, PROT_READ | PROT_WRITE,
				  MAP_SHARED, fd,
				  MSPS_DMA_MMAP_1);
	if (dma[1] == (u_long *)-1) {
		myprintf("Error mmap dma[1]: %s\n", strerror(errno));
		return -1;
	}
	myprintf("mmap - ok\n");

	for (i = 0; i < (data_size/sizeof(u_long)); i++) {
		(*(dma[0] + i)) = 0x0;
		(*(dma[1] + i)) = 0x0;
	}

	print_first_dma();
/*
htonll(*dma[3])
*/

	if (testmode_flag) {
		printf("Device test mode - are on\n");
		ioctl(fd, MSPS_TEST_MODE_ON, NULL);
	}

	res = ioctl(fd, MSPS_GET_STATUS, &status);
	if (res < 0) {
		myprintf("ioctl get status error\n");
		return -1;
	}

	task->size = data_size;
	activetask.time = active_work * 1000; /* mili or micro seconds!?   0_o   */

	if (write_flag)
		mask = 0x55555555;

	for (i = 0; i < (data_size/sizeof(u_long)); i++) {
		(*(dma[0] + i)) = mask;
		(*(dma[1] + i)) = mask;
	}

	printf("%s with msps %s (%s):\n",
		write_flag ? "Write" : "Read",
		dev_name,
		active_work ? "active" : "interrupt");

	if (active_work)
		res = ioctl(fd, MSPS_EXCH_DATA_ACTIVE, &activetask);
	else
		res = ioctl(fd, MSPS_EXCH_DATA, task);

	if (res < 0) {
		myprintf("ioctl exch_data error\n");
	} else {
		myprintf("%d -> state: 0x%x, size: %d, buf: %d\n",
			 task->size,
			 task->status.state,
			 task->status.size,
			 task->status.buffer
			);
	}

	print_first_dma();

/*

  typedef struct msps_status {
  msps_exch_stat_t	input;
  msps_exch_stat_t	output;
  } msps_status_t;

  typedef struct msps_exch_stat {
  u_int		state;	// if == 0 - then finished
  u_int		size;	// size of last exchange
  u_int		buffer;	// which buffer used for last exchange
  } msps_exch_stat_t;

*/

	myprintf("status:\n\tstate\t0x%x\n\tsize\t0x%x\n\tbuffer\t0x%x\n\n",
		 status.state,
		 status.size,
		 status.buffer);

	if (testmode_flag) {
		printf("Device test mode - are off\n");
		ioctl(fd, MSPS_TEST_MODE_OFF, NULL);
	}

	munmap(dma[0], MSPS_DMA_SIZE);
	munmap(dma[1], MSPS_DMA_SIZE);
end:
	close(fd);

	return 0;
}
