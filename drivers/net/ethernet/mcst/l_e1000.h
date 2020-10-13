/* Init Block bits */
#define DRX 		(1 << 0)  /* Receiver disable */
#define DTX		(1 << 1)  /* Transmitter disable */
#define LOOP		(1 << 2)  /* loopback */
#define DTCR		(1 << 3)  /* disable transmit crc */
#define COLL		(1 << 4)  /* force collision; actual only in
				   * "internal loopback" mode */
#define DRTY		(1 << 5)  /* disable retry */	
#define INTL		(1 << 6)  /* Internal loopback */
#define	EMBA		(1 << 7)  /* enable modified back-off algorithm */
#define EJMF		(1 << 8)  /* enable jambo frame */
#define EPSF		(1 << 9)  /* enable pause frame */
#define FULL		(1 << 10)  /* full packet mode */
#define PROM		(1 << 15) /* promiscuous mode */ 

/* Register Map */
#define E_CSR		0x00 /* Ethernet 	Control/Status Register */
#define	MGIO_CSR	0x04 /* MGIO 		Control/Status Register */
#define MGIO_DATA	0x08 /* MGIO 		Data Register */
#define E_BASE_ADDR	0x0c /* Ethernet	Base Address Register */
#define	DMA_BASE_ADDR	0x10 /* DMA		Base Address Register */
#define PSF_CSR		0x14 /* Pause Frame	Control/Status Register */
#define PSF_DATA	0x18 /* Pause Frame	Data Register */
#define	INT_DELAY	0x1c /* Interrupt Delay Register */


/* E_CSR register bits */
/* 31:21 unused, readed as 0 */
#define	ATME		(1 << 24) /* RW, Add Timer Enable */
#define	TMCE		(1 << 23) /* RW, Timer Clear Enable */
#define DRIN		(1 << 22) /* RW, Disable RX Interrupt */
#define	DTIN		(1 << 21) /* RW, Disable TX Interrupt */
#define ESLE		(1 << 20) /* RW, Enable Slave Error */
#define SLVE		(1 << 19) /* RW1c, Slave Error */
#define PSFI		(1 << 18) /* RW1c, Pause Frame Interrupt */
/* 17 unused, readed as 0  */
#define SINT		(1 << 16) /* R, Status Interrupt */
#define ERR		(1 << 15) /* R, Error */
#define BABL		(1 << 14) /* RW1c, Babble */
#define CERR		(1 << 13) /* RW1c, Collision Error */
#define MISS		(1 << 12) /* RW1c, Missed Packet */
#define MERR		(1 << 11) /* RW1c, Memory Error */
#define RINT		(1 << 10) /* RW1c, Receiver Interrupt */
#define TINT		(1 << 9)  /* RW1c, Transmiter Interrupt */
#define IDON		(1 << 8)  /* RW1c, Initialization Done */
#define INTR		(1 << 7)  /* R, Interrupt Flag */
#define INEA		(1 << 6)  /* RW, Interrupt Enable */
#define RXON		(1 << 5)  /* R, Receiver On */
#define TXON		(1 << 4)  /* R, Transmiter On */
#define TDMD		(1 << 3)  /* RW1, Transmit Demand */
#define STOP		(1 << 2)  /* RW1, Stop */
#define STRT		(1 << 1)  /* RW1, Start */
#define INIT		(1 << 0)  /* RW1, Initialize */		

/* RX Descriptor status bits */
#define RD_OWN		(1 << 15) 
#define RD_ERR		(1 << 14)
#define RD_FRAM		(1 << 13)
#define RD_OFLO		(1 << 12)
#define RD_CRC		(1 << 11)
#define RD_BUFF		(1 << 10)
#define RD_STP		(1 << 9)
#define RD_ENP		(1 << 8)
#define RD_PAM		(1 << 6)
#define RD_LAFM		(1 << 4)
#define RD_BAM		(1 << 3)

/* TX Descriptor status bits */
#define TD_OWN		(1 << 15) 
#define TD_ERR		(1 << 14)
#define TD_AFCS		(1 << 13)
#define	TD_NOINTR	(1 << 13)
#define TD_MORE		(1 << 12)
#define TD_ONE		(1 << 11)
#define TD_DEF		(1 << 10)
#define TD_STP		(1 << 9)
#define TD_ENP		(1 << 8)

/* TX Descriptor misc bits */
#define TD_RTRY		(1 << 26)
#define TD_LCAR		(1 << 27)
#define TD_LCOL		(1 << 28)
#define TD_UFLO		(1 << 30)
#define TD_BUFF		(1 << 31)

/* MGIO_CSR regiter bits */
#define FDPL            (1 << 23)  /* rw*** FULL DUPLEX POLARITY */
#define FEPL            (1 << 22)  /* rw*** FAST ETHERNET POLARITY */
#define GEPL            (1 << 21)  /* rw*** GIGABIT ETHERNET POLARITY */
#define SLSP            (1 << 20)  /* rw*** LINK STATUS POLARITY */
#define SLST            (1 << 19)  /* rw*** SOFT LINK STATUS */
#define SLSE            (1 << 18)  /* rw*** SOFT LINK STATUS ENABLE */
#define FDUP		(1 << 17)  /* RW/R* FULL DUPLEX */
#define FETH		(1 << 16)  /* RW/R* FAST ETHERNET */
#define GETH		(1 << 15)  /* RW/R* GIGABIT ETHERNET */
#define HARD		(1 << 14)  /* RW HARD/SOFT Selector */
#define RRDY		(1 << 13)  /* RC RESULT READY */
#define CST1		(1 << 12)  /* RC CHANGED LINK STATUS 1 */
#define LST1		(1 << 11)  /* R LINK STATUS 1 */
#define CST0		(1 << 10)  /* RC CHANGED LINK STATUS 0 */
#define LST0		(1 << 9)   /* R LINK STATUS 0 */
#define OUT1		(1 << 8)   /* RW OUTPUT PORT 1 */
#define OUT0		(1 << 7)   /* RW OUTPUT PORT 0 */
#define RSTP(polarity)	((polarity) << 6)   /* RW RESET POLARITY */
#define ERDY		(1 << 5)   /* RW ENABLE INT ON RRDY  */
#define EST1		(1 << 4)   /* RW ENABLE INT ON CST1 */
#define EST0		(1 << 3)   /* RW ENABLE INT ON CST0 */
#define SRST		(1 << 2)   /* RW PHY SOFTWARE RESET */
#define LSTS		(1 << 1)   /* RW LINK STATUS SELECT */
#define MGIO_SINT	(1 << 0)   /* STATUS INTERRUPT - combines (RRDY ||
				    * CST1 || CST0) if (ERDY || EST1 || EST0) 
				    * selected. Has its own copy in E_CSR  */

#define	E1000_RSET_POLARITY	RSTP(0)	/* polarity is 0 for E1000 */

/* "*" - if HARD == 1 then "RW", and "R" in other case. In the "HARD == 0" 
* case e1000 working mode is specified by PHY  */

/* Some of PHY (DP83865) registers */
#define PHY_AUX_CTRL	0x12	   /* Auxiliary Control Register */
#define PHY_LED_CTRL	0x13	   /* LED Control Register */
#define PHY_BIST_CFG2	0x1a	   /* BIST configuration Register 2 */

/* Some of PHY_AUX_CTRL's fields */
#define RGMII_EN_1	(1 << 13)
#define RGMII_EN_0	(1 << 12)
/* This two fields enable either RGMII or GMII/MII */
	/* 1:1 - RGMII 3com mode 
	 * 1:0 - RGMII Hp mode 
	 * 0:1 - GMII/MII mode
	 * 0:0 - GMII/MII mode 
	 */

/* Some of PHY_LED_CTRL's fields */
#define RED_LEN_EN	(1 << 5) /* Reduced LED enable */
	
/* Some of PHY_BIST_CFG2's fields */
#define LINK_SEL	(1 << 0) /* Link/Link-ACT selector */
/* When RED_LEN_EN bit is enabled:
*	LINK_SEL = 1 - 10M Link LED displays 10/100/1000 Link 
*	LINK_SEL = 0 - 10M Link LED displays 10/100/1000 Link
*			and ACT 
*/


/* PSF_CSR Register */
#define	PSF_PSEX		(1 << 4) /* RC,  Pause Expired */
#define PSF_EPSX		(1 << 3) /* RW, PSEX Enable   */
#define	PSF_PSFR		(1 << 2) /* RC, Pause Frame Recieved */
#define PSF_EPSF		(1 << 1) /* RW, PSFR Enable */
#define	PSF_PSFI		(1 << 0) /* R,  Pause Frame Interrupt */

/* PSF_DATA Register, R */
#define RCNT_SHIFT	0
#define	RCNT_MASK	0xFFFF
#define	RCNT_CUR_SHIFT	16
#define RCNT_CUR_mask	0xFFFF

/* INT_DELAY Register */
#define RXINT_DELAY_SHIFT	0
#define	RXINT_DELAY_MASK	0xFFFF
#define	TXINT_DELAY_SHIFT	16
#define TXINT_DELAY_MAsk	0xFFFF








#define	L_ETH1000_IRQ_DEFAULT	10	/* default IRQ # for Elbrus ethernet */
					/* controller (see IOHUB docs) */

/* Bits for MGIO_DATA registers */
#define		MGIO_DATA_OFF		0
#define		MGIO_CS_OFF		16
#define		MGIO_REG_AD_OFF		18
#define		MGIO_PHY_AD_OFF		23
#define		MGIO_OP_CODE_OFF	28
#define		MGIO_ST_OF_F_OFF	30

// RX STATUS fields
#define    RX_ST_OWN	(1<<15)
#define    RX_ST_ERR	(1<<14)
#define    RX_ST_FRAM	(1<<13)
#define    RX_ST_OFLO	(1<<12)
#define    RX_ST_CRC	(1<<11)
#define    RX_ST_BUFF	(1<<10)
#define    RX_ST_STP	(1<<9)
#define    RX_ST_ENP	(1<<8)
#define    RX_ST_PAM	(1<<6)
#define    RX_ST_LAFM	(1<<5)
#define    RX_ST_BAM	(1<<4)



// TX STATUS fields
#define    TX_ST_OWN	(1<<15)
#define    TX_ST_ERR	(1<<14)
#define    TX_ST_AFCS	(1<<13)
#define    TX_ST_NOINTR (1<<13)
#define    TX_ST_MORE	(1<<12)
#define    TX_ST_ONE	(1<<11)
#define    TX_ST_DEF	(1<<10)
#define    TX_ST_STP	(1<<9)
#define    TX_ST_ENP	(1<<8)

// MISC fields
#define    MISC_BUFF	(1<<31)
#define    MISC_UFLO	(1<<30)
#define    MISC_UNUSED	(1<<29)
#define    MISC_LCOL	(1<<28)
#define    MISC_LCAR	(1<<27)
#define    MISC_RTRY	(1<<26)

typedef struct init_block {
	u16	mode;
	u8	paddr[6];
	u64	laddrf;
	u32	rdra; /* 31:4 = addr of recieving desc ring (16 bytes align) + 
		       * 3:0  = number of descriptors (the power of two) 
		       * 0x09 is max value (desc number = 512 if [3:0] >= 0x09)
		       */
	u32	tdra; /* 31:4 = addr of transm desc ring (16 bytes align) + 
		       * 3:0  = number of descriptors (the power of two) 
		       * 0x09 is max value (desc number = 512 if [3:0] >= 0x09)
		       */
} __attribute__((packed)) init_block_t; /* Must be 24 bytes exactly; E1000 works in LE mode, so  
		 			* initialization must be in acordance with that */


#define	L_E1000_NOMSI	0
#define	L_E1000_MSI	1
#define	L_E1000_MSIX	2

extern int e1000_rt_probe1(unsigned long ioaddr, unsigned char *base_ioaddr,
                int shared, struct pci_dev *pdev, struct resource *res,
		int bar, struct msix_entry *msix_entries, int msi_status);
extern void e1000_rt_remove(struct pci_dev *pdev);


#define	CAN_DISABLE_TXINT(ep)			\
	(!(ep->pci_dev->vendor == PCI_VENDOR_ID_INTEL && ep->revision < 2))
#define SUPPORT_COALESCE(ep)			\
	((ep->pci_dev->vendor == PCI_VENDOR_ID_MCST_TMP) && \
		(ep->pci_dev->device == 0x8022))
