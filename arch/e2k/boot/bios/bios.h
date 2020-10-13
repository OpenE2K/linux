
void rom_printk(char const *fmt, ...);

extern void sb_enable_itself(void);
#ifndef CONFIG_E2K_SIC
extern void sb_enable_ioapic(void);
#endif
#ifdef CONFIG_E2K_SIC
extern void configure_apic_system(void);
extern void configure_system_timer(void);
#endif
extern void sb_enable_rtc(void);
extern void sb_enable_ide(void);
extern void enable_serial_ports(void);
extern void enable_parallel_port(void);
extern void enable_mouse(void);
extern void enable_keyboard(void);
extern void enable_rtc(void);
extern void enable_floppy(void);
extern void enable_mga(void);
extern void vga_init(void);
#ifdef	CONFIG_E2K_LEGACY_SIC
extern void enable_embeded_graphic(void);
#endif	/* CONFIG_E2K_LEGACY_SIC */

extern void init_kbd(void);
extern unsigned char inb(unsigned long port);
extern void outb(unsigned char byte, unsigned long port);

struct bios_hardware {
	unsigned char serial	:1;
	unsigned char parallel	:1;
	unsigned char rtc	:1;
	unsigned char keyboard	:1;
	unsigned char mouse	:1;
	unsigned char floppy	:1;
	unsigned char video	:1;
	unsigned char dbgport	:1;
};

typedef struct bios_hardware bios_hardware_t;

extern bios_hardware_t hardware;
