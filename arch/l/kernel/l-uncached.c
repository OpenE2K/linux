#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/genalloc.h>
#include <linux/device.h>

#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/cacheflush.h>


static struct gen_pool *l_uncached_pool;
#define L_POOL_ORDER	(MAX_ORDER - 1)

static void *l_vmap_wc(phys_addr_t start, size_t size)
{
	pgprot_t prot = pgprot_writecombine(PAGE_KERNEL);
	struct page **pages;
	phys_addr_t page_start;
	unsigned int page_count;
	unsigned int i;
	void *vaddr;

	page_start = start - offset_in_page(start);
	page_count = DIV_ROUND_UP(size + offset_in_page(start), PAGE_SIZE);


	pages = kmalloc_array(page_count, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return NULL;

	for (i = 0; i < page_count; i++) {
		phys_addr_t addr = page_start + i * PAGE_SIZE;
		pages[i] = pfn_to_page(addr >> PAGE_SHIFT);
	}
	vaddr = vmap(pages, page_count, VM_MAP, prot);
	kfree(pages);

	return vaddr;
}

/*
 * Add a new chunk of uncached memory pages to the specified pool.
 *
 * @pool: pool to add new chunk of uncached memory to
 * @nid: node id of node to allocate memory from, or -1
 *
 * This is accomplished by first allocating a granule of cached memory pages
 * and then converting them to uncached memory pages.
 */
static int l_uncached_add_chunk(struct gen_pool *uc_pool, int nid)
{
	int ret;
	void *va;
	unsigned long pa;
	size_t sz = PAGE_SIZE << L_POOL_ORDER;
	struct page *page = __alloc_pages_node(nid, GFP_KERNEL | __GFP_THISNODE,
							L_POOL_ORDER);
	if (!page)
		return -1;
	split_page(page, L_POOL_ORDER);

	pa = page_to_phys(page);
	va = l_vmap_wc(pa, sz);
	if (!va)
		goto failed;
	ret = gen_pool_add_virt(uc_pool, (unsigned long)va, pa, sz, nid);
	if (ret)
		goto failed;
	/*FIXME: NUMA */
#ifdef CONFIG_E90S
	e90s_flush_l2_cache();
#elif defined(CONFIG_E2K)
	write_back_cache_all();
#else
	WARN("FIXME: add flush cache\n");
#endif
	return 0;
failed:
	iounmap(va);
	__free_pages(page, L_POOL_ORDER);
	return -1;
}

/*
 * l_uncached_alloc_page
 *
 * @nid: node id, or -1
 * @n_pages: number of contiguous pages to allocate
 *
 * Allocate the specified number of contiguous uncached pages on the
 * the requested node.
 */
static unsigned long l_uncached_alloc_page(int nid, int n_pages,
						phys_addr_t *phys_addr)
{
	unsigned long uc_addr;
	struct gen_pool *uc_pool = l_uncached_pool;

	do {
		uc_addr = gen_pool_alloc(uc_pool, n_pages * PAGE_SIZE);
		if (uc_addr != 0) {
			*phys_addr = gen_pool_virt_to_phys(uc_pool, uc_addr);
			return uc_addr;
		}
	} while (l_uncached_add_chunk(uc_pool, nid) == 0);

	return 0;
}

/*
 * uncached_free_page
 *
 * @uc_addr: uncached address of first page to free
 * @n_pages: number of contiguous pages to free
 *
 * Free the specified number of uncached pages.
 */
static void l_uncached_free_page(unsigned long uc_addr, int n_pages)
{
	struct gen_pool *pool = l_uncached_pool;
	gen_pool_free(pool, uc_addr, n_pages * PAGE_SIZE);
}

void *l_alloc_uncached(struct device *dev, size_t size,
		phys_addr_t *phys_addr, gfp_t gfp)
{
	int pages = PAGE_ALIGN(size) / PAGE_SIZE;
	void *v = (void *)l_uncached_alloc_page(dev_to_node(dev), pages,
							phys_addr);
	if (!v)
		return v;
	return v;
}

void l_free_uncached(struct device *dev, size_t size, void *cpu_addr)
{
	int pages = PAGE_ALIGN(size) / PAGE_SIZE;
	l_uncached_free_page((unsigned long)cpu_addr, pages);
}

static void l_free_chunk(struct gen_pool *pool,
			      struct gen_pool_chunk *chunk, void *data)
{
	vunmap((void *)chunk->start_addr);
	free_pages(chunk->phys_addr, L_POOL_ORDER);
}

static void l_pool_destroy(struct gen_pool *pool, struct device *dev)
{
	if (!pool)
		return;
	/* this is quite ugly but no better idea */
	gen_pool_for_each_chunk(pool, l_free_chunk, dev);
	gen_pool_destroy(pool);
}

void l_destroy_uncached_pool(void)
{
	l_pool_destroy(l_uncached_pool, NULL);
}

int l_init_uncached_pool(void)
{
	struct gen_pool *p;
	int ret = 0;

	p = gen_pool_create(PAGE_SHIFT, 0);
	if (!p) {
		ret = -ENOMEM;
		goto error;
	}
	l_uncached_pool = p;
	gen_pool_set_algo(p, gen_pool_first_fit_order_align, NULL);

error:
	return ret;
}
