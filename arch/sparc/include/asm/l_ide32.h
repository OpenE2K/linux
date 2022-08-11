#ifndef _E90_L_IDE_H_
#define _E90_L_IDE_H_

#define TRACE_E90_IDE_FLAG		0	
#define TRACE_E90_IDE_FLAG_ADDR		0


#define TRACE_E90_IDE	if (TRACE_E90_IDE_FLAG) printk
#define TRACE_E90_IDE_ADDR	if (TRACE_E90_IDE_FLAG_ADDR && !TRACE_E90_IDE_FLAG) printk

static inline u8 e90_inb(unsigned long port)
{
	return readb_asi(port, ASI_M_PCI);
}

static inline u16 e90_inw (unsigned long port)
{
	return le16_to_cpu(readw_asi(port, ASI_M_PCI));
}

static inline void e90_insw(unsigned long port, void *dst, u32 count)
{
	u16 *ps = dst;
	u32 *pi;

	if(((unsigned long)ps) & 0x2) {
		*ps++ = readw_asi(port, ASI_M_PCI);
		count--;
	}
	pi = (u32 *)ps;
	while(count >= 2) {
		u32 w;
		w  = readw_asi(port, ASI_M_PCI) << 16;
		w |= readw_asi(port, ASI_M_PCI);
		*pi++ = w;
		count -= 2;
	}
	ps = (u16 *)pi;
	if(count)
		*ps++ = readw_asi(port, ASI_M_PCI);

}


static inline void e90_outb(u8 val, unsigned long port)
{
	writeb_asi(val, port, ASI_M_PCI);
}

static inline void e90_outw (u16 val, unsigned long port)
{
	writew_asi(cpu_to_le16(val), port, ASI_M_PCI);
}

static inline void e90_outsw(unsigned long port, void *src, u32 count)
{
	const u16 *ps = src;
	const u32 *pi;

	if(((unsigned long)src) & 0x2) {
		writew_asi(*ps++, port, ASI_M_PCI);
		count--;
	}
	pi = (const u32 *)ps;
	while(count >= 2) {
		u32 w = *pi++;
		writew_asi(w >> 16, port, ASI_M_PCI);
		writew_asi(w, port, ASI_M_PCI);
		count -= 2;
	}
	ps = (const u16 *)pi;
	if(count)
		writew_asi(*ps, port, ASI_M_PCI);
}

static inline void e90_outl(u32 val, unsigned long port)
{
        writel_asi(cpu_to_le32(val), port, ASI_M_PCI);
}


static void e90_ide_exec_command(ide_hwif_t *hwif, u8 cmd)
{
	TRACE_E90_IDE("%s: e90_ide_exec_command 0x%x; ", hwif->cur_dev->name, cmd);
        e90_outb(cmd, hwif->io_ports.command_addr);
	TRACE_E90_IDE("Done\n");
}

static u8 e90_ide_read_status(ide_hwif_t *hwif)
{
        u8 r;
	TRACE_E90_IDE("%s: e90_ide_read_status:  ", hwif->cur_dev->name);
        r = e90_inb(hwif->io_ports.status_addr);
	TRACE_E90_IDE("   Done = 0x%x\n", r);
        return r;
}

static u8 e90_ide_read_altstatus(ide_hwif_t *hwif)
{
        u8 r;
        TRACE_E90_IDE("%s: e90_ide_read_alt_status:  ", hwif->cur_dev->name);
        r = e90_inb(hwif->io_ports.ctl_addr);
        TRACE_E90_IDE("   Done = 0x%x\n", r);
        return r;
}

static void e90_ide_write_devctl(ide_hwif_t *hwif, u8 ctl)
{
	TRACE_E90_IDE("%s: e90_ide_write_devctl 0x%x   ", hwif->cur_dev->name, ctl);
        e90_outb(ctl, hwif->io_ports.ctl_addr);
	TRACE_E90_IDE("Done\n");
}


static void e90_ide_dev_select(ide_drive_t *drive)
{
        ide_hwif_t *hwif = drive->hwif;
        u8 select = drive->select | ATA_DEVICE_OBS;
	TRACE_E90_IDE("%s: e90_ide_dev_select 0x%x  ", hwif->cur_dev->name, select);
        e90_outb(select, hwif->io_ports.device_addr);
	TRACE_E90_IDE("Done\n");
}


static void e90_ide_tf_load(ide_drive_t *drive, struct ide_taskfile *tf, u8 valid)
{
        ide_hwif_t *hwif = drive->hwif;
        struct ide_io_ports *io_ports = &hwif->io_ports;

	TRACE_E90_IDE("%s: e90_ide_tf_load: valid=0x%x; feature=0x%02x, nsect=0x%02x,"
		" lbal=0x%02x, lbam=0x%02x, lbah=0x%02x, dev=0x%02x   ", hwif->cur_dev->name,
		valid, tf->feature, tf->nsect, tf->lbal,
		tf->lbam, tf->lbah, tf->device);
        TRACE_E90_IDE_ADDR("%s: e90_ide_tf_load: valid=0x%x; feature=0x%02x, nsect=0x%02x,"
                " lbal=0x%02x, lbam=0x%02x, lbah=0x%02x, dev=0x%02x\n", hwif->cur_dev->name,
                valid, tf->feature, tf->nsect, tf->lbal,
                tf->lbam, tf->lbah, tf->device);
        if (valid & IDE_VALID_FEATURE)
                e90_outb(tf->feature, io_ports->feature_addr);
        if (valid & IDE_VALID_NSECT)
                e90_outb(tf->nsect, io_ports->nsect_addr);
        if (valid & IDE_VALID_LBAL)
                e90_outb(tf->lbal, io_ports->lbal_addr);
        if (valid & IDE_VALID_LBAM)
                e90_outb(tf->lbam, io_ports->lbam_addr);
        if (valid & IDE_VALID_LBAH)
                e90_outb(tf->lbah, io_ports->lbah_addr);
        if (valid & IDE_VALID_DEVICE)
                e90_outb(tf->device, io_ports->device_addr);
	TRACE_E90_IDE("Done\n");
}


static void e90_ide_tf_read(ide_drive_t *drive, struct ide_taskfile *tf, u8 valid)
{
        ide_hwif_t *hwif = drive->hwif;
        struct ide_io_ports *io_ports = &hwif->io_ports;

	TRACE_E90_IDE("%s: e90_ide_tf_read  ", hwif->cur_dev->name);
        if (valid & IDE_VALID_ERROR)
                tf->error  = e90_inb(io_ports->feature_addr);
        if (valid & IDE_VALID_NSECT)
                tf->nsect  = e90_inb(io_ports->nsect_addr);
        if (valid & IDE_VALID_LBAL)
                tf->lbal   = e90_inb(io_ports->lbal_addr);
        if (valid & IDE_VALID_LBAM)
                tf->lbam   = e90_inb(io_ports->lbam_addr);
        if (valid & IDE_VALID_LBAH)
                tf->lbah   = e90_inb(io_ports->lbah_addr);
        if (valid & IDE_VALID_DEVICE)
                tf->device = e90_inb(io_ports->device_addr);
	TRACE_E90_IDE("Done: valid=0x%x; feature=0x%02x, nsect=0x%02x," 
                " lbal=0x%02x, lbam=0x%02x, lbah=0x%02x, dev=0x%02x\n",
                valid, tf->feature, tf->nsect, tf->lbal,
                tf->lbam, tf->lbah, tf->device);
}

static void e90_ide_input_data(ide_drive_t *drive, struct ide_cmd *cmd, void *buf,
                    unsigned int len)
{
        ide_hwif_t *hwif = drive->hwif;
        struct ide_io_ports *io_ports = &hwif->io_ports;
        unsigned long data_addr = io_ports->data_addr;
        unsigned int words = (len + 1) >> 1;

	TRACE_E90_IDE("%s: e90_ide_input_data: len = 0x%x   ", hwif->cur_dev->name, len);
        e90_insw(data_addr, buf, words);
	TRACE_E90_IDE("Done\n");
}

static void e90_ide_output_data(ide_drive_t *drive, struct ide_cmd *cmd, void *buf,
                     unsigned int len)
{
        ide_hwif_t *hwif = drive->hwif;
        struct ide_io_ports *io_ports = &hwif->io_ports;
        unsigned long data_addr = io_ports->data_addr;
        unsigned int words = (len + 1) >> 1;

        TRACE_E90_IDE("%s: e90_ide_output_data: len = 0x%x   ", hwif->cur_dev->name, len);
        e90_outsw(data_addr, buf, words);
	TRACE_E90_IDE("Done\n");
}


const struct ide_tp_ops e90_tp_ops = {
        .exec_command           = e90_ide_exec_command,
        .read_status            = e90_ide_read_status,
        .read_altstatus         = e90_ide_read_altstatus,
        .write_devctl           = e90_ide_write_devctl,

        .dev_select             = e90_ide_dev_select,
        .tf_load                = e90_ide_tf_load,
        .tf_read                = e90_ide_tf_read,

        .input_data             = e90_ide_input_data,
        .output_data            = e90_ide_output_data,
};

static void l_init_iops (ide_hwif_t *hwif)
{
	hwif->tp_ops = &e90_tp_ops;
}



	/*   DMA handling interface   */

static u8 e90_ide_dma_sff_read_status(ide_hwif_t *hwif)
{
	u8 r;
	TRACE_E90_IDE("%s: e90_ide_dma_sff_read_status  ", hwif->cur_dev->name);
	r = e90_inb(hwif->dma_base + ATA_DMA_STATUS);
	TRACE_E90_IDE("Done = 0x%02x\n", r);
	return r; 
}

static void e90_ide_dma_sff_write_status(ide_hwif_t *hwif, u8 val)
{
        TRACE_E90_IDE("%s: e90_ide_dma_sff_write_status  0x%02x   ", hwif->cur_dev->name, val);
        e90_outb(val, hwif->dma_base + ATA_DMA_STATUS);
	TRACE_E90_IDE("    Done\n");
}

/**
 *      ide_dma_host_set        -       Enable/disable DMA on a host
 *      @drive: drive to control
 *
 *      Enable/disable DMA on an IDE controller following generic
 *      bus-mastering IDE controller behaviour.
 */

static void e90_ide_dma_host_set(ide_drive_t *drive, int on)
{
        ide_hwif_t *hwif = drive->hwif;
        u8 unit = drive->dn & 1;
        u8 dma_stat = e90_ide_dma_sff_read_status(hwif);

	TRACE_E90_IDE("%s: e90_ide_dma_host_set\n", drive->name);
        if (on)
                dma_stat |= (1 << (5 + unit));
        else
                dma_stat &= ~(1 << (5 + unit));

        e90_ide_dma_sff_write_status(hwif, dma_stat);
}

int e90_ide_dma_setup(ide_drive_t *drive, struct ide_cmd *cmd)
{
        ide_hwif_t *hwif = drive->hwif;
        u8 rw = (cmd->tf_flags & IDE_TFLAG_WRITE) ? 0 : ATA_DMA_WR;
        u8 dma_stat;

        /* fall back to pio! */
	TRACE_E90_IDE("%s: e90_ide_dma_setup   ", drive->name);
        if (ide_build_dmatable(drive, cmd) == 0) {
                ide_map_sg(drive, cmd);
		TRACE_E90_IDE(" ide_build_dmatable failed\n");
                return 1;
        }

        /* PRD table */
        e90_outl(hwif->dmatable_dma, hwif->dma_base + ATA_DMA_TABLE_OFS);
	TRACE_E90_IDE("PRD table = 0x%08x;  ", hwif->dmatable_dma);
        /* specify r/w */
        e90_outb(rw, hwif->dma_base + ATA_DMA_CMD);
	TRACE_E90_IDE("   rw = 0x%02x\n", rw);
        /* read DMA status for INTR & ERROR flags */
        dma_stat = e90_ide_dma_sff_read_status(hwif);

        /* clear INTR & ERROR flags */
        e90_ide_dma_sff_write_status(hwif, dma_stat | ATA_DMA_ERR | ATA_DMA_INTR);

        return 0;
}

void e90_ide_dma_start(ide_drive_t *drive)
{
        ide_hwif_t *hwif = drive->hwif;
        u8 dma_cmd;

        /* Note that this is done *after* the cmd has
         * been issued to the drive, as per the BM-IDE spec.
         * The Promise Ultra33 doesn't work correctly when
         * we do this part before issuing the drive cmd.
         */
	TRACE_E90_IDE("%s: e90_ide_dma_start  ", drive->name);
         dma_cmd = e90_inb(hwif->dma_base + ATA_DMA_CMD);
	TRACE_E90_IDE(" read dma_cmd = 0x%02x;   ", dma_cmd);
         e90_outb(dma_cmd | ATA_DMA_START, hwif->dma_base + ATA_DMA_CMD);
	TRACE_E90_IDE(" write dma_cmd = 0x%02x.  Done\n", dma_cmd | ATA_DMA_START);
}

/* returns 1 on error, 0 otherwise */
int e90_ide_dma_end(ide_drive_t *drive)
{
        ide_hwif_t *hwif = drive->hwif;
        u8 dma_stat = 0, dma_cmd = 0;

        /* stop DMA */
	TRACE_E90_IDE("%s: e90_ide_dma_end   ", drive->name);
        dma_cmd = e90_inb(hwif->dma_base + ATA_DMA_CMD);
        TRACE_E90_IDE(" read dma_cmd = 0x%02x;   ", dma_cmd);
        e90_outb(dma_cmd & ~ATA_DMA_START, hwif->dma_base + ATA_DMA_CMD);
        TRACE_E90_IDE(" write dma_cmd = 0x%02x.\n", dma_cmd | ATA_DMA_START);

        /* get DMA status */
        dma_stat = e90_ide_dma_sff_read_status(hwif);

        /* clear INTR & ERROR bits */
        e90_ide_dma_sff_write_status(hwif, dma_stat | ATA_DMA_ERR | ATA_DMA_INTR);

#define CHECK_DMA_MASK (ATA_DMA_ACTIVE | ATA_DMA_ERR | ATA_DMA_INTR)
	TRACE_E90_IDE("Done e90_ide_dma_end\n");
        /* verify good DMA status */
        if ((dma_stat & CHECK_DMA_MASK) != ATA_DMA_INTR)
                return 0x10 | dma_stat;
        return 0;
}

const struct ide_dma_ops e90_dma_ops = {
        .dma_host_set           = e90_ide_dma_host_set,
        .dma_setup              = e90_ide_dma_setup,
        .dma_start              = e90_ide_dma_start,
        .dma_end                = e90_ide_dma_end,
        .dma_test_irq           = ide_dma_test_irq,
        .dma_lost_irq           = ide_dma_lost_irq,
        .dma_timer_expiry       = ide_dma_sff_timer_expiry,
        .dma_sff_read_status    = e90_ide_dma_sff_read_status,
};

#define	L_FORCE_NATIVE_MODE	1
#define	L_DEAULT_IDE_DMA_MODE	0

#endif /*_E90_L_IDE_H_*/
