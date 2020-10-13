#include <asm/iset.h>
#include <asm/e2k_api.h>

void e2s_flushts(void)
{
	E2K_FLUSHTS;
}

struct iset iset_e2s = {
	.flushts = e2s_flushts
};
