#ifndef _L_UNCACHED_H
#define _L_UNCACHED_H

void *l_alloc_uncached(struct device *dev, size_t size,
		phys_addr_t *phys_addr, gfp_t gfp);
void l_free_uncached(struct device *dev, size_t size, void *cpu_addr);

int l_init_uncached_pool(void);
void l_destroy_uncached_pool(void);

#endif /* !(_L_UNCACHED_H) */
