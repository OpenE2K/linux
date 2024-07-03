/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/interval_tree.h>
#include <linux/types.h>
#include <linux/mman.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/rwsem.h>
#include <linux/sched/signal.h>
#include <linux/semaphore.h>
#include <linux/uaccess.h>
#include <linux/pagewalk.h>
#include <linux/hugetlb.h>

#include <asm/umalloc.h>
#include <asm/e2k_ptypes.h>
#include <asm/process.h>
#include <asm/mmu_context.h>
#include <asm/e2k_debug.h>

#define DEBUG_GC_TRACE          0
#define Dbg_gc_trace            if (DEBUG_GC_TRACE) printk

#define DEBUG_CL_DESC		0
#define Dbg_cl_desc(...)	DebugPrint(DEBUG_CL_DESC, ##__VA_ARGS__)

static void stop_all_children_and_parent(void)
{
	struct task_struct *t;
        
        Dbg_gc_trace(" stop_all_children_and_parent \n");
        
        if (thread_group_empty(current))
		return;

	rcu_read_lock();
	for_each_thread(current, t) { 
		if (t != current)
			send_sig_info(SIGSTOP, SEND_SIG_PRIV, t);
        }
	rcu_read_unlock();
}

static void wakeup_all_children_and_parent(void)
{
	struct task_struct *t;
 
        Dbg_gc_trace(" wakeup_all_children_and_parent begin \n");

        if (thread_group_empty(current))
		return;

	rcu_read_lock();
	for_each_thread(current, t) { 
		if (t != current)
			send_sig_info(SIGCONT, SEND_SIG_PRIV, t);
        }
	rcu_read_unlock();
}
 
/*
 * Fill 'ptr' with 'dw' double words
 */
int mem_set_empty_tagged_dw(void __user *ptr, s64 size, u64 dw)
{
	void __user *ptr_aligned;
	s64 size_aligned, size_head, size_tail;

	if (size < 8)
		if (clear_user((void __user *) ptr, size))
			return -EFAULT;

	ptr_aligned = PTR_ALIGN(ptr, 8);
	size_head = (s64 __force) (ptr_aligned - ptr);
	size_aligned = round_down(size - size_head, 8);
	size_tail = size - size_head - size_aligned;

	if (fill_user(ptr, size_head, 0xff) ||
		fill_user_with_tags(ptr, size_aligned, ETAGEWD, dw) ||
		fill_user(ptr_aligned + size_aligned, size_tail, 0xff))
		return -EFAULT;

	return 0;
}

__always_inline /* To optimize based on 'kernel_stack' value */
static int find_data_in_list(struct rb_root_cached *areas, e2k_ptr_t data,
		void __user *ptr, unsigned long offset, bool kernel_stack,
		void __user **fault_addr)
{
	unsigned long start, last;
	struct interval_tree_node *it;

	if (!kernel_stack)
		might_fault();

	Dbg_cl_desc("data.lo = 0x%llx data.hi = 0x%llx ptr = 0x%lx\n",
			data.lo, data.hi, ptr);

	start = data.base;
	last = start + data.size - 1;
	if (!data.size)
		return 0;

	/* We know that there is no intersection between passed areas
	 * so there is no need to go over *all* intervals intersecting
	 * this particular descriptor: if the first one was not big enough
	 * then all others also won't be. */
	it = interval_tree_iter_first(areas, start, last);
	if (it && it->start <= start && it->last >= last) {
		/*
		 * If we find descriptor in readonly page, we would
		 * catch a reasonable PFAULT on store operation.
		 */
		if (kernel_stack) {
			__NATIVE_STORE_TAGGED_QWORD(ptr, data.lo,
					data.hi, ETAGNVD, ETAGNVD, offset);
		} else {
			if (put_user_tagged_8(data.lo, ETAGNVD,
						(u64 __user *) ptr) ||
					put_user_tagged_8(data.hi, ETAGNVD,
						(u64 __user *) (ptr + offset))) {
				*fault_addr = ptr;
				return -EFAULT;
			}
		}
	}

	return 0;
}

__always_inline /* To optimize based on 'kernel_stack' value */
static int clean_descriptors_in_psp(struct rb_root_cached *areas,
		unsigned long start, unsigned long end, void __user **fault_addr,
		bool kernel_stack)
{
	void __user *ptr;
	int ret;

	if (machine.native_iset_ver < E2K_ISET_V5) {
		for (ptr = (void __user *) start; ptr < (void __user *) end; ptr += 64) {
			u64 val0_lo, val0_hi, val1_lo, val1_hi;
			u32 tag0, tag1;

			if (kernel_stack) {
				u32 tag0_lo, tag0_hi, tag1_lo, tag1_hi;
				NATIVE_LOAD_VAL_AND_TAGD(ptr, val0_lo, tag0_lo);
				NATIVE_LOAD_VAL_AND_TAGD(ptr + 8, val0_hi, tag0_hi);
				NATIVE_LOAD_VAL_AND_TAGD(ptr + 32, val1_lo, tag1_lo);
				NATIVE_LOAD_VAL_AND_TAGD(ptr + 40, val1_hi, tag1_hi);
				tag0 = (tag0_hi << 4) | tag0_lo;
				tag1 = (tag1_hi << 4) | tag1_lo;
			} else {
				if (__get_user_tagged_16(val0_lo, val0_hi, tag0, ptr) ||
				    __get_user_tagged_16(val1_lo, val1_hi, tag1, ptr + 32)) {
					*fault_addr = ptr;
					return -EFAULT;
				}
			}

			if (unlikely(tag0 == ETAGAPQ)) {
				e2k_ptr_t data;
				data.lo = val0_lo;
				data.hi = val0_hi;
				ret = find_data_in_list(areas, data, ptr, 8,
							kernel_stack, fault_addr);
				if (ret)
					return ret;
			}
			if (unlikely(tag1 == ETAGAPQ)) {
				e2k_ptr_t data;
				data.lo = val1_lo;
				data.hi = val1_hi;
				ret = find_data_in_list(areas, data, ptr + 32, 8,
							kernel_stack, fault_addr);
				if (ret)
					return ret;
			}
		}
	} else {
		for (ptr = (void __user *) start; ptr < (void __user *) end; ptr += 32) {
			u64 val0_lo, val0_hi, val1_lo, val1_hi;
			u32 tag0, tag1;

			if (kernel_stack) {
				u32 tag0_lo, tag0_hi, tag1_lo, tag1_hi;
				NATIVE_LOAD_VAL_AND_TAGD(ptr, val0_lo, tag0_lo);
				NATIVE_LOAD_VAL_AND_TAGD(ptr + 16, val0_hi, tag0_hi);
				NATIVE_LOAD_VAL_AND_TAGD(ptr + 8, val1_lo, tag1_lo);
				NATIVE_LOAD_VAL_AND_TAGD(ptr + 24, val1_hi, tag1_hi);
				tag0 = (tag0_hi << 4) | tag0_lo;
				tag1 = (tag1_hi << 4) | tag1_lo;
			} else if (__get_user_tagged_16_offset(val0_lo, val0_hi,
							       tag0, ptr, 16ul) ||
					__get_user_tagged_16_offset(val1_lo, val1_hi,
							tag1, ptr + 8ul, 16ul)) {
				*fault_addr = ptr;
				return -EFAULT;
			}

			if (unlikely(tag0 == ETAGAPQ)) {
				e2k_ptr_t data;
				data.lo = val0_lo;
				data.hi = val0_hi;
				ret = find_data_in_list(areas, data, ptr, 16,
							kernel_stack, fault_addr);
				if (ret)
					return ret;
			}
			if (unlikely(tag1 == ETAGAPQ)) {
				e2k_ptr_t data;
				data.lo = val1_lo;
				data.hi = val1_hi;
				ret = find_data_in_list(areas, data, ptr + 8, 16,
							kernel_stack, fault_addr);
				if (ret)
					return ret;
			}
		}
	}

	return 0;
}

static int clean_descriptors_normal(struct rb_root_cached *areas,
		unsigned long start, unsigned long end, void __user **fault_addr)
{
	void __user *ptr;
	int ret;

#pragma loop count (100000)
	for (ptr = (void __user *) start; ptr < (void __user *) end; ptr += 32) {
		u64 val0_lo, val0_hi, val1_lo, val1_hi;
		u32 tag0, tag1;

		if (__get_user_tagged_16(val0_lo, val0_hi, tag0, ptr) ||
		    __get_user_tagged_16(val1_lo, val1_hi, tag1, ptr + 16)) {
			*fault_addr = ptr;
			return -EFAULT;
		}

		if (unlikely(tag0 == ETAGAPQ)) {
			e2k_ptr_t data;
			data.lo = val0_lo;
			data.hi = val0_hi;
			ret = find_data_in_list(areas, data, ptr, 8, false, fault_addr);
			if (ret)
				return ret;
		}
		if (unlikely(tag1 == ETAGAPQ)) {
			e2k_ptr_t data;
			data.lo = val1_lo;
			data.hi = val1_hi;
			ret = find_data_in_list(areas, data, ptr + 16, 8, false, fault_addr);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int clean_descriptors_range_user(struct rb_root_cached *areas,
		unsigned long start, unsigned long end,
		const struct vm_area_struct *vma, void __user **fault_addr)
{
	bool privileged = !!(vma->vm_flags & VM_PRIVILEGED);
	int ret;

	if (privileged) {
		bool proc_stack = !!(vma->vm_flags & VM_HW_STACK_PS);

		unsigned long ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		if (proc_stack) {
			ret = clean_descriptors_in_psp(areas, start, end, fault_addr, false);
		} else {
			ret = clean_descriptors_normal(areas, start, end, fault_addr);
		}
		clear_ts_flag(ts_flag);
	} else {
		ret = clean_descriptors_normal(areas, start, end, fault_addr);
	}

	return ret;
}

static int clean_descriptors_test_walk(unsigned long start, unsigned long end,
				struct mm_walk *walk)
{
	unsigned long vm_flags = walk->vma->vm_flags;

	/* Do not check VM_WRITE: user could have write protected an area with
	 * descriptor in which case we should indicate an error (-EFAULT). */
	if ((vm_flags & VM_PFNMAP) || !(vm_flags & VM_READ) ||
			(vm_flags & VM_PRIVILEGED) &&
			!(vm_flags & (VM_SIGNAL_STACK|VM_HW_STACK_PS)))
		return 1;

	return 0;
}

struct clean_args {
	struct rb_root_cached *areas;
	void __user *fault_addr;
};

static int clean_descriptors_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, struct mm_walk *walk)
{
	struct clean_args *args = walk->private;
	struct rb_root_cached *areas = args->areas;
	void __user **fault_addr = &args->fault_addr;
	int ret = 0;

	if (pmd_none(*pmd))
		goto out;

	if (pmd_trans_unstable(pmd)) {
		ret = clean_descriptors_range_user(areas, addr, end, walk->vma, fault_addr);
		goto out;
	}

	for (; addr != end; addr += PAGE_SIZE) {
		const pte_t *pte = pte_offset_map(pmd, addr);
		if (!pte_none(*pte)) {
			ret = clean_descriptors_range_user(areas, addr,
					addr + PAGE_SIZE, walk->vma, fault_addr);
			if (ret)
				goto out;
		}
		pte_unmap(pte);
	}

out:
	cond_resched();
	return ret;
}

#ifdef CONFIG_HUGETLB_PAGE
/* This function walks within one hugetlb entry in the single call */
static int clean_descriptors_hugetlb_range(pte_t *ptep, unsigned long hmask,
				 unsigned long addr, unsigned long end,
				 struct mm_walk *walk)
{
	struct clean_args *args = walk->private;
	struct rb_root_cached *areas = args->areas;
	void __user **fault_addr = &args->fault_addr;
	pte_t pte;
	int ret = 0;

	pte = huge_ptep_get(ptep);
	if (!pte_none(pte))
		ret = clean_descriptors_range_user(areas, addr, end, walk->vma, fault_addr);

	cond_resched();

	return ret;
}
#endif /* HUGETLB_PAGE */

static int clean_descriptors_copies(struct rb_root_cached *areas)
{
	struct mm_struct *mm = current->mm;
	struct pt_regs *regs = current_pt_regs();
	u64 pshtp_size;
	int ret;
	struct clean_args args = {
		.areas = areas,
		.fault_addr = NULL,
	};
	struct mm_walk_ops clean_descriptors_walk = {
		.test_walk = clean_descriptors_test_walk,
		.pmd_entry = clean_descriptors_pte_range,
#ifdef CONFIG_HUGETLB_PAGE
		.hugetlb_entry = clean_descriptors_hugetlb_range,
#endif
	};

	/*
	 * Parse part of user stack spilled to kernel
	 */
	pshtp_size = GET_PSHTP_MEM_INDEX(regs->stacks.pshtp);
	if (pshtp_size) {
		unsigned long ptr, end, flags;

		ptr = AS(current_thread_info()->k_psp_lo).base;
		end = ptr + pshtp_size;

		raw_all_irq_save(flags);
		NATIVE_FLUSHCPU;
		clean_descriptors_in_psp(areas, ptr, end, &args.fault_addr, true);
		raw_all_irq_restore(flags);

		if (WARN_ON_ONCE(args.fault_addr))
			args.fault_addr = NULL;
	}

	stop_all_children_and_parent();

	unsigned long cursor = 0;
	do {
		mmap_read_lock(current->mm);

		pagefault_disable();
		ret = walk_page_range(mm, cursor, mm->highest_vm_end,
				      &clean_descriptors_walk, &args);
		pagefault_enable();

		if (!args.fault_addr) {
			mmap_read_unlock(current->mm);
			break;
		}

		WARN_ON_ONCE(ret != -EFAULT);
		cursor = (unsigned long) args.fault_addr;
		args.fault_addr = NULL;

		ret = fixup_user_fault(mm, cursor, FAULT_FLAG_WRITE, NULL);
		mmap_read_unlock(current->mm);
	} while (ret >= 0);

	wakeup_all_children_and_parent();

	return ret;
}

/*
 * Clean freed user memory and destroy freed descriptors in memory.
 */
int clean_single_descriptor(e2k_ptr_t descriptor)
{
	unsigned long ptr, size;
	struct interval_tree_node it_entry;
	struct rb_root_cached areas = RB_ROOT_CACHED;

	ptr = descriptor.base;
	size = descriptor.size;

	/* Make a copy of a list */
	if (!size)
		return 0;

	it_entry.start = ptr;
	it_entry.last = ptr + size - 1;
	interval_tree_insert(&it_entry, &areas);

	/* Clean all descriptor copies from user memory */
	return clean_descriptors_copies(&areas);
}
/*
 * Clean freed user memory and destroy freed descriptors in memory.
 */
int clean_descriptors(void __user *list_descriptors, unsigned long list_size)
{
	int i, res;
	void __user *addr;
	e2k_ptr_t descriptor;
	u32 tag;
	unsigned long ptr, size;
	struct interval_tree_node *it_array;
	struct rb_root_cached areas = RB_ROOT_CACHED;

	/* We need a copy of a list, because user memory whould be cleaned */
	it_array = kmalloc_array(list_size, sizeof(it_array[0]), GFP_KERNEL);
	if (!it_array)
		return -ENOMEM;

	for (i = 0, addr = list_descriptors; i < list_size; i++, addr += 16) {
		res = get_user_tagged_16(descriptor.lo,
				descriptor.hi, tag, addr);
		if (res)
			goto free_list;

		if (unlikely(tag != ETAGAPQ)) {
			pr_info_ratelimited("%s: bad descriptor extag 0x%x hiw=0x%llx low=0x%llx ind=%d\n",
					__func__, tag,
					descriptor.hi, descriptor.lo, i);
			pr_info_ratelimited("%s: list_descriptors: 0x%lx / list_size=%ld\n",
					__func__, list_descriptors, list_size);
			res = -EFAULT;
			goto free_list;
		}

		ptr = descriptor.base;
		size = descriptor.size;
		if (!size)
			continue;

		/* Set memory to empty values */
		res = mem_set_empty_tagged_dw((void __user *) ptr, size,
					0x0baddead0baddead); /*freed mem mark*/
		if (res)
			goto free_list;

		/* Make a copy of a list. Here we check that
		 * there are no intersections between areas -
		 * this fact is used in find_data_in_list() */
		if (unlikely(interval_tree_iter_first(&areas, ptr,
				ptr + size - 1))) {
			pr_info_once("sys_clean_descriptors: intersection between passed areas found\n");
			res = -EINVAL;
			goto free_list;
		}

		it_array[i].start = ptr;
		it_array[i].last = ptr + size - 1;
		interval_tree_insert(&it_array[i], &areas);
	}
	/* Clean all descriptor copies from user memory */
	res = clean_descriptors_copies(&areas);

free_list:
	kfree(it_array);
	return res;
}
