#include <linux/of.h>

/* Offsets for I2S controller configuring */
#define CONTROL_STATUS                      0x0
#define SPKER_BUF1_ADDR                     0x4
#define SPKER_BUF2_ADDR                     0x8
#define SPKER_BUF_SIZE                      0xC
#define SPKER_DWORDS_TO_READ                0x10
#define SPKER_DWORDS_READED                 0x14
#define SPKER_BUF_PTR                       0x18
#define MIC_BUF1_ADDR                       0x1C
#define MIC_BUF2_ADDR                       0x20
#define MIC_BUF_SIZE                        0x24
#define MIC_BUF_PTR                         0x28
#define INTSTS                              0x2c
#define INT_EN_MASK                         0x30

/* I2S controller manage flags */
#define START_PLAYBACK                      (1 << 0)
#define STOP_PLAYBACK                       (1 << 1)
#define START_CAPTURE                       (1 << 3)

/* I2S controller status flags*/
#define SPKER_BUF1_ACTIVE                   (1 << 19)
#define SPKER_BUF2_ACTIVE                   (1 << 20)
#define MIC_BUF1_ACTIVE                     (1 << 21)
#define MIC_BUF2_ACTIVE                     (1 << 22)

/* Interrupt flags */
#define INTSTS_SB1E                         (1 << 0)	/* Int Spker buf1 is empty */
#define INTSTS_SB2E                         (1 << 1)	/* Int Spker buf2 is empty */
#define INTSTS_MB1F                         (1 << 2)	/* Int Mic buf1 is full */
#define INTSTS_MB2F                         (1 << 3)	/* Int Mic buf2 is full */
#define INTSTS_DMA_SDOD                     (1 << 5)	/* Int DMA Spker data out done */
#define INTSTS_DMA_MDD                      (1 << 6)	/* Int DMA Mic data done */

#define L_I2S_BUFFER_MAX_SIZE               65472       /* Max buffer size in bytes */