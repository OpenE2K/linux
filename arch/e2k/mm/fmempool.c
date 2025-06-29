#include <asm/fmempool.h>

typedef struct {
	fmempool_t *parent;
	void *arg;
} fmempool_callarg_t;

static void *my_fmempool_alloc(gfp_t gfp_mask, void *pool_data)
{
	fmempool_callarg_t *ca = pool_data;
	fmempool_t *pool = ca->parent;

	if (!pool)
		return NULL;

	if (!pool->initialized)
		return NULL;

	smp_rmb(); /* Paired with write barrier in fmempool_create function */

	return pool->user_alloc_fn(gfp_mask, ca->arg);
}

static void my_fmempool_free(void *element, void *pool_data)
{
	fmempool_callarg_t *ca = pool_data;
	fmempool_t *pool = ca->parent;

	if (!pool)
		return;

	if (!pool->initialized)
		return;

	smp_rmb(); /* Paired with write barrier in fmempool_create function */

	pool->user_free_fn(element, ca->arg);
}

static fmempool_callarg_t *create_callarg(fmempool_t *pool, void *pool_data)
{

	fmempool_callarg_t *ca = kmalloc(sizeof(fmempool_callarg_t), GFP_KERNEL);
	if (unlikely(!ca))
		return NULL;

	ca->parent = pool;
	ca->arg = pool_data;

	return ca;
}

fmempool_t *fmempool_create(int capacity, mempool_alloc_t *alloc_fn,
	mempool_free_t *free_fn, void *pool_data)
{

	fmempool_t *pool = kzalloc(sizeof(fmempool_t), GFP_KERNEL);
	if (unlikely(!pool))
		return NULL;

	pool->private = create_callarg(pool, pool_data);
	if (unlikely(!pool->private)) {
		fmempool_destroy(pool);
		return NULL;
	}

	pool->user_alloc_fn = alloc_fn;
	pool->user_free_fn = free_fn;
	pool->capacity = capacity;
	pool->size = 0;

	pool->mem = mempool_create(capacity, my_fmempool_alloc,
		my_fmempool_free, pool->private);
	if (unlikely(!pool->mem)) {
		fmempool_destroy(pool);
		return NULL;
	}

	smp_wmb(); /* Paired with read barriers in my_fmempool_alloc/free functions */

	pool->initialized = true;

	return pool;
}

void fmempool_destroy(fmempool_t *pool)
{
	if (likely(pool)) {
		if (likely(pool->mem))
			mempool_destroy(pool->mem);

		kfree(pool->private);
	}

	kfree(pool);
}

void *fmempool_alloc(fmempool_t *pool, gfp_t gfp_mask)
{
	void *mem = NULL;

	if (!pool || !pool->initialized)
		return NULL;

	if (likely(pool->size < pool->capacity))
		mem = mempool_alloc(pool->mem, gfp_mask);

	if (likely(mem))
		pool->size++;

	return mem;
}

void fmempool_free(void *element, fmempool_t *pool)
{
	if (pool && pool->initialized) {
		mempool_free(element, pool->mem);

		if (likely(pool->size > 0))
			pool->size--;
	}
}