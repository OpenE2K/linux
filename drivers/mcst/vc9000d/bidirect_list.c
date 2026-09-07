/*
 * Copyright (c) 2015, Verisilicon Inc. - All Rights Reserved
 *
 * This software is dual licensed, either GPL-2.0 or BSD-3-Clause, at your
 * option.
 *
 ********************************************************************************
 *
 * GPL-2.0
 *
 ********************************************************************************
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 ********************************************************************************
 *
 * Alternatively, This software may be distributed under the terms of
 * BSD-3-Clause, in which case the following provisions apply instead of the ones
 * mentioned above :
 *
 ********************************************************************************
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
/* needed for __init,__exit directives */
#include <linux/init.h>
/* needed for remap_page_range
 *  SetPageReserved
 *  ClearPageReserved
 */
#include <linux/mm.h>
/* obviously, for kmalloc */
#include <linux/slab.h>
/* for struct file_operations, register_chrdev() */
#include <linux/fs.h>
/* standard error codes */
#include <linux/errno.h>

#include <linux/moduleparam.h>
/* request_irq(), free_irq() */
#include <linux/interrupt.h>
#include <linux/sched.h>

#include <linux/semaphore.h>
#include <linux/spinlock.h>
/* needed for virt_to_phys() */
#include <asm/io.h>
#ifdef PCIE_EN
#include <linux/pci.h>
#endif
#include <asm/uaccess.h>
#include <linux/ioport.h>

#include <asm/irq.h>

#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/timer.h>

#include "bidirect_list.h"

void init_bi_list(bi_list *list)
{
	list->head = NULL;
	list->tail = NULL;
}

bi_list_node *bi_list_create_node(void)
{
	bi_list_node *node = NULL;

	node = vmalloc(sizeof(bi_list_node));
	if (!node) {
		PDEBUG("%s\n", "vmalloc for node fail!");
		return node;
	}
	memset(node, 0, sizeof(bi_list_node));
	return node;
}
void bi_list_free_node(bi_list_node *node)
{
	//free current node
	vfree(node);
}

void bi_list_insert_node_tail(bi_list *list, bi_list_node *current_node)
{
	if (!current_node) {
		PDEBUG("%s\n", "insert node tail  NULL");
		return;
	}
	if (list->tail) {
		current_node->prev = list->tail;
		list->tail->next = current_node;
		list->tail = current_node;
		list->tail->next = NULL;
	} else {
		list->head = current_node;
		list->tail = current_node;
		current_node->next = NULL;
		current_node->prev = NULL;
	}
}

void bi_list_insert_node_before(bi_list *list, bi_list_node *base_node,
				bi_list_node *new_node)
{
	bi_list_node *prev = NULL;

	if (!new_node) {
		PDEBUG("%s\n", "insert node before new node NULL");
		return;
	}
	if (base_node) {
		if (base_node->prev) {
			//at middle position
			prev = base_node->prev;
			prev->next = new_node;
			new_node->next = base_node;
			base_node->prev = new_node;
			new_node->prev = prev;
		} else {
			//at head
			base_node->prev = new_node;
			new_node->next = base_node;
			list->head = new_node;
			new_node->prev = NULL;
		}
	} else {
		//at tail
		bi_list_insert_node_tail(list, new_node);
	}
}

void bi_list_remove_node(bi_list *list, bi_list_node *node)
{
	bi_list_node *prev = NULL;
	bi_list_node *next = NULL;

	if (!node) {
		PDEBUG("%s\n", "remove node NULL");
		return;
	}
	next = node->next;
	prev = node->prev;

	if (!next && !prev) {
		//there is only one node.
		list->head = NULL;
		list->tail = NULL;
	} else if (!next) {
		//at tail
		list->tail = prev;
		prev->next = NULL;
	} else if (!prev) {
		//at head
		list->head = next;
		next->prev = NULL;
	} else {
		//at middle position
		prev->next = next;
		next->prev = prev;
	}
}
