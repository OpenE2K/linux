
#include <linux/vmalloc.h>
#include <asm/e2k_debug.h>
#include <asm/e2k.h>


static void error(char *x)
{
	rom_puts("\n\n");
	rom_puts(x);
	rom_puts("\n\n -- System halted");

        E2K_LMS_HALT_ERROR(0xdead); /* Halt */
}

e2k_addr_t free_mem_ptr;	/* zip.c wants it visible */
e2k_addr_t free_mem_end_ptr;

void bios_mem_init(long membase, long memsize)
{
	free_mem_ptr = membase;
	free_mem_end_ptr = membase + memsize;
}


void inline *malloc_aligned(int size, int alignment)
{
	void *p;
	int mask;

	if (alignment == 0) alignment = 8;

	mask = alignment - 1;

	if (size <0) error("Malloc error");
	if (free_mem_ptr <= 0) error("Memory error");

	free_mem_ptr = (free_mem_ptr + mask) & ~mask;	/* Align */

	p = (void *)free_mem_ptr;
	free_mem_ptr += size;

	if (free_mem_ptr >= free_mem_end_ptr)
		error("Out of memory");

	return p;
}

inline void *malloc(int size)
{
	void *p;

	p = malloc_aligned(size, 8);

	return p;
}

void inline free(void *where)
{	/* Don't care */
}
e2k_addr_t
get_busy_memory_end(void)
{
	return free_mem_ptr;
}
