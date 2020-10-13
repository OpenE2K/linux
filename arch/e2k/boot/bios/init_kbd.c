#include <asm/head.h>
#include "init_kbd.h"
#include <asm/e2k_debug.h>
#include <asm/io.h>

#undef	DEBUG_KBD_MODE
#undef	DebugKBD
#define DEBUG_KBD_MODE		0	/* keyboard debug */
#define DebugKBD		if (DEBUG_KBD_MODE) rom_printk

void wait_kbd_write(void)
{
	unsigned char in = inb(KBD_STATUS_REG);
	while (in & KBD_STAT_IBF) {
		in = inb(KBD_STATUS_REG);
	}
}

void wait_kbd_read(void)
{
	unsigned char in = inb(KBD_STATUS_REG);
	DebugKBD("wait_kbd_read() status 0x%x\n", in);
	while ((~in) & KBD_STAT_OBF) {
		in = inb(KBD_STATUS_REG);
		DebugKBD("wait_kbd_read() while status 0x%x\n", in);
	}
}

void send_kbd_cmd(unsigned int cmd)
{
	wait_kbd_write();
	DebugKBD("send_kbd_cmd() cmd 0x%x\n", cmd);
	outb(cmd, KBD_CNTL_REG);
}

void send_kbd_data(unsigned int data)
{
	wait_kbd_write();
	DebugKBD("send_kbd_data() data out 0x%x\n", data);
	outb(data, KBD_DATA_REG);;
}

unsigned int recv_kbd_data(void)
{
	unsigned int in;
	wait_kbd_read();
	in = (unsigned int)inb(KBD_DATA_REG);
	DebugKBD("recv_kbd_data() data in 0x%x\n", in);
	return in;
}

void init_kbd(void)
{
	int check = 0;
	rom_printk("kbd init ...\n");
// init KBC
	send_kbd_cmd(KBD_CCMD_KBD_DISABLE);
	check = 1;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_cmd(KBD_CCMD_SELF_TEST);
	if (recv_kbd_data() != 0x55) goto failed;
	check = 2;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_cmd(KBD_CCMD_GET_VERSION);
	recv_kbd_data();
	check = 3;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_cmd(KBD_CCMD_KBD_TEST);
	if (recv_kbd_data() != 0x00) goto failed;
	check = 4;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_cmd(KBD_CCMD_KBD_ENABLE);
//
	check = 5;
	DebugKBD("init_kbd() check #%d\n", check);
#if 1
	send_kbd_data(KBD_CMD_RESET);
	if (recv_kbd_data() != KBD_REPLY_ACK) goto failed;
	if (recv_kbd_data() != KBD_REPLY_POR) goto failed;
	check = 6;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_data(KBD_CMD_DISABLE);
	if (recv_kbd_data() != KBD_REPLY_ACK) goto failed;
	check = 7;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_data(KBD_CMD_SET_LEDS);
	if (recv_kbd_data() != KBD_REPLY_ACK) goto failed;
	check = 8;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_data(0x07);
	if (recv_kbd_data() != KBD_REPLY_ACK) goto failed;
	check = 9;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_data(KBD_CMD_ECHO);
	if (recv_kbd_data() != 0xee) goto failed;
	check = 10;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_data(KBD_CMD_READ_ID);
	if (recv_kbd_data() != KBD_REPLY_ACK) goto failed;
	check = 11;
	DebugKBD("init_kbd() check #%d\n", check);
	recv_kbd_data();
	recv_kbd_data();
	check = 12;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_data(KBD_CMD_SET_RATE);
	if (recv_kbd_data() != KBD_REPLY_ACK) goto failed;
	check = 13;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_data(0x0);
//	if (recv_kbd_data() != KBD_REPLY_ACK) goto failed;
	check = 14;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_data(KBD_CMD_SET_LEDS);
	if (recv_kbd_data() != KBD_REPLY_ACK) goto failed;
	check = 15;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_data(0x0);
	if (recv_kbd_data() != KBD_REPLY_ACK) goto failed;
	check = 16;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_data(KBD_CMD_ENABLE);
	if (recv_kbd_data() != KBD_REPLY_ACK) goto failed;
	check = 17;
	DebugKBD("init_kbd() check #%d\n", check);
	send_kbd_cmd(KBD_CCMD_WRITE_MODE);
	send_kbd_data(KBD_MODE_KBD_INT | KBD_MODE_SYS | KBD_MODE_KCC);
#endif	
	rom_printk("kbd init passed ...\n");
	return;
failed:
	rom_printk("kbd init faled... check %d\n", check);
	return;
}
