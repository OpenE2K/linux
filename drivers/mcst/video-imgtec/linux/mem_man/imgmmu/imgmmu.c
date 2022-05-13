/*!
 *****************************************************************************
 *
 * @File       imgmmu.c
 * @Description    Implementation of the MMU functions
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 *
 * The contents of this file are subject to the MIT license as set out below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above.
 *
 * If you wish to allow use of your version of this file only under the terms
 * of GPL, and not to allow others to use your version of this file under the
 * terms of the MIT license, indicate your decision by deleting the provisions
 * above and replace them with the notice and other provisions required by GPL
 * as set out in the file called "GPLHEADER" included in this distribution. If
 * you do not delete the provisions above, a recipient may use your version of
 * this file under the terms of either the MIT license or GPL.
 *
 * This License is also included in this distribution in the file called
 * "MIT_COPYING".
 *
 *****************************************************************************/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/scatterlist.h>

#include <img_types.h>
#include <img_defs.h>
#include <img_errors.h>

#include "mmulib/mmu.h"
#include "mmulib/heap.h"	/* for struct MMUHeapAlloc */

/**
 * @ingroup IMGMMU_lib
 *
 * @name Internal declarations
 * @{
 */
/*-----------------------------------------------------------------------------
 * Following elements are in the IMGMMU_lib_int module
 *---------------------------------------------------------------------------*/

#include "mmu_defs.h"		/* access to MMU info and error printing function */

#include <asm/page.h>

/** @brief Directory entry in the MMU - contains several page mapping */
struct MMUDirectory {
	/** @brief Physical page used for the directory entries */
	struct MMUPage *pDirectoryPage;
	/** @brief All the page table structures in a static array of pointers */
	struct MMUPageTable **ppPageMap;

	/**
	 * @brief Functions to use to manage pages allocation, liberation and writing
	 */
	IMGMMU_Info sConfiguration;

	/** @brief number of mapping using this directory */
	IMG_UINT32 ui32NMapping;
};

/** @brief Mapping a virtual address and some entries in a directory */
struct MMUMapping {
	/** @brief associated directory */
	struct MMUDirectory *pDirectory;
	/**
	 * @brief device virtual address root associated with this mapping - not
	 * owned by the mapping
	 */
	IMGMMU_HeapAlloc sDevVirtAddr;

	/** @brief flag used when allocating */
	unsigned int uiUsedFlag;
	/** @brief number of entries mapped */
	IMG_UINT32 ui32NEntries;
};

/** @brief One page Table of the directory */
struct MMUPageTable {
	/** @brief associated directory */
	struct MMUDirectory *pDirectory;
	/** @brief page used to store this mapping in the MMU */
	struct MMUPage *pPage;

	/** @brief number of valid entries in this page */
	IMG_UINT32 ui32ValidEntries;
};

/*
 * local functions
 */

#define MMU_LOG_TMP 256

/**
 * @brief Write to stderr (or KRN_ERR if in kernel module)
 */
void _MMU_Log(int err, const char *function, IMG_UINT32 line,
	      const char *format, ...)
{
	char _message_[MMU_LOG_TMP];
	va_list args;

	va_start(args, format);

	vsprintf(_message_, format, args);

	va_end(args);

	if (err) {
		printk(KERN_ERR "ERROR: %s:%u %s", function, line, _message_);
	} else {
		/* info, debug, ... */
		printk(KERN_INFO "%s:%u %s", function, line, _message_);
	}
}

/**
 * @brief Destruction of a PageTable (does not follow the pChild pointer)
 *
 * @warning Does not verify if pages are still valid or not
 */
static void mmu_PageTableDestroy(struct MMUPageTable *pPageTable)
{
	IMG_UINT32 i;
	/* the page table should belong to a directory */
	IMG_ASSERT(pPageTable->pDirectory != NULL);
	/* the function should be configured */
	IMG_ASSERT(pPageTable->pDirectory->sConfiguration.pfnPageFree != NULL);
	/* the physical page should still be here */
	IMG_ASSERT(pPageTable->pPage != NULL);

	/* invalidate all pages just for sanity before giving back the memory to the system */
	for (i = 0; i < IMGMMU_N_PAGE; i++) {
		pPageTable->pDirectory->sConfiguration.pfnPageWrite(pPageTable->pPage, i, 0,
							MMU_FLAG_INVALID);
	}
	/* when non-UMA need to update the device memory after setting it to 0 */
	if (pPageTable->pDirectory->sConfiguration.pfnPageUpdate != NULL) {
		pPageTable->pDirectory->sConfiguration.pfnPageUpdate(pPageTable->pPage);
	}
	MMU_LogDebug("Destroy page table (phys addr 0x%" IMG_I64PR "x)\n",
		     pPageTable->pPage->uiPhysAddr);
	pPageTable->pDirectory->sConfiguration.pfnPageFree(pPageTable->pPage);
	pPageTable->pPage = NULL;

	IMG_FREE(pPageTable);
}

/**
 * @brief Extact the directory index from a virtual address
 */
static unsigned int mmu_DirectoryEntry(IMG_UINTPTR uiVirtAddress)
{
	return (unsigned)((uiVirtAddress & VIRT_DIR_IDX_MASK) >>
			  IMGMMU_DIR_SHIFT);
}

/**
 * @brief Extract the page table index from a virtual address
 */
static unsigned int mmu_PageEntry(IMG_UINTPTR uiVirtAddress)
{
	return (unsigned)((uiVirtAddress & VIRT_PAGE_TBL_MASK)
			  >> IMGMMU_PAGE_SHIFT);
}

/**
 * @brief Default function used when a MMUInfo structure has an empty
 * pfnPageWrite pointer
 */
static void mmu_PageWrite(IMGMMU_Page *pWriteTo, unsigned int offset,
			  IMG_UINT64 uiToWrite, unsigned int eMMUFlag)
{
	IMG_UINT32 *pDirMemory = NULL;
	IMG_UINT64 uiCurrPhysAddr = uiToWrite;

	IMG_ASSERT(pWriteTo != NULL);

	pDirMemory = (IMG_UINT32 *) pWriteTo->uiCpuVirtAddr;
	/* uiCurrPhysAddr = pDirectory->ppPageMap[dirOffset]->pPage->uiPhysAddr
	   & (~pDirectory->uiPageOffsetMask); */
	/* assumes that the MMU HW has the extra-bits enabled (this default
	   function has no way of knowing) */
	if ((IMGMMU_PHYS_SIZE - IMGMMU_VIRT_SIZE) > 0) {
		uiCurrPhysAddr >>= (IMGMMU_PHYS_SIZE - IMGMMU_VIRT_SIZE);
	}
	/* the IMGMMU_PAGE_SHIFT bottom bits should be masked because page
	   allocation */
	/* IMGMMU_PAGE_SHIFT-(IMGMMU_PHYS_SIZE-IMGMMU_VIRT_SIZE) are used for
	   flags so it's ok */
	pDirMemory[offset] = (IMG_UINT32) uiCurrPhysAddr | (eMMUFlag);
}

/**
 * @brief Default function used when a MMUInfo structure has an empty
 * pfnPageWrite pointer (associated read)
 */
static IMG_UINT32 mmu_PageRead(struct MMUPage *pReadFrom, unsigned int offset)
{
	IMG_UINT32 *pDirMemory = NULL;

	IMG_ASSERT(pReadFrom != NULL);

	pDirMemory = (IMG_UINT32 *) pReadFrom->uiCpuVirtAddr;
	return pDirMemory[offset];
}

/**
 * @brief Create a page table
 *
 * @return A pointer to the new page table structure and IMG_SUCCESS in pResult
 * @return NULL in case of error and a value in pResult
 * @li IMG_ERROR_MALLOC_FAILED if internal structure allocation failed
 * @li IMG_ERROR_FATAL if physical page allocation failed
 */
static struct MMUPageTable *mmu_PageTableCreate(struct MMUDirectory *pDirectory,
						IMG_RESULT *pResult)
{
	struct MMUPageTable *pNeo = NULL;
	IMG_UINT32 i;

	IMG_ASSERT(pResult != NULL);
	IMG_ASSERT(pDirectory != NULL);
	IMG_ASSERT(pDirectory->sConfiguration.pfnPageAlloc != NULL);
	IMG_ASSERT(pDirectory->sConfiguration.pfnPageWrite != NULL);

	pNeo =
	    (struct MMUPageTable *)IMG_CALLOC(1, sizeof(struct MMUPageTable));
	if (pNeo == NULL) {
		MMU_LogError("failed to allocate %" IMG_SIZEPR
			     "u bytes for internal" " page table structure\n",
			     sizeof(struct MMUPageTable));
		*pResult = IMG_ERROR_MALLOC_FAILED;
		return NULL;
	}

	pNeo->pDirectory = pDirectory;

	pNeo->pPage =
	    pDirectory->sConfiguration.pfnPageAlloc(pDirectory->sConfiguration.
						    allocCtx);
	if (pNeo->pPage == NULL) {
		MMU_LogError("failed to allocate Page Table physical page using"
			     " directory's PageAlloc function\n");
		IMG_FREE(pNeo);
		*pResult = IMG_ERROR_FATAL;
		return NULL;
	}
	MMU_LogDebug("Create page table (phys addr 0x%" IMG_I64PR
		     "x CPU Virt 0x%" IMG_PTRDPR "x)\n",
		     pNeo->pPage->uiPhysAddr, pNeo->pPage->uiCpuVirtAddr);

	/* invalidate all pages */
	for (i = 0; i < IMGMMU_N_PAGE; i++) {
		pDirectory->sConfiguration.pfnPageWrite(pNeo->pPage, i, 0,
							MMU_FLAG_INVALID);
	}

	/* when non-UMA need to update the device memory after setting it to 0 */
	if (pDirectory->sConfiguration.pfnPageUpdate != NULL) {
		pDirectory->sConfiguration.pfnPageUpdate(pNeo->pPage);
	}

	*pResult = IMG_SUCCESS;
	return pNeo;
}

/**
 * @}
 */
/*-----------------------------------------------------------------------------
 * End of the IMGMMU_lib_int module
 *---------------------------------------------------------------------------*/

/*
 * public functions already have a group in mmu.h
 */

IMG_SIZE IMGMMU_GetPageSize(void)
{
	return IMGMMU_PAGE_SIZE;
}

IMG_SIZE IMGMMU_GetPhysicalSize(void)
{
	return IMGMMU_PHYS_SIZE;
}

IMG_SIZE IMGMMU_GetVirtualSize(void)
{
	return IMGMMU_VIRT_SIZE;
}

static IMG_SIZE g_cpupagesize = PAGE_SIZE;

IMG_SIZE IMGMMU_GetCPUPageSize(void)
{
	return g_cpupagesize;
}

IMG_RESULT IMGMMU_SetCPUPageSize(IMG_SIZE pagesize)
{
	if (pagesize != PAGE_SIZE) {
		MMU_LogError("trying to change CPU page size from %lu"
			     " to %" IMG_SIZEPR
			     "u not possible when compiling in kernel module\n",
			     PAGE_SIZE, pagesize);
		return IMG_ERROR_FATAL;
	}
	return IMG_SUCCESS;
}

struct MMUDirectory *IMGMMU_DirectoryCreate(const IMGMMU_Info *pMMUConfig,
					    IMG_RESULT *pResult)
{
	struct MMUDirectory *pNeo = NULL;
	IMG_UINT32 i;

	IMG_ASSERT(pResult != NULL);

	/* invalid information in the directory config:
	   - invalid page allocator and dealloc (page write can be NULL)
	   - invalid virtual address representation
	   - invalid page size
	   - invalid MMU size */
	if (pMMUConfig == NULL || pMMUConfig->pfnPageAlloc == NULL ||
	    pMMUConfig->pfnPageFree == NULL) {
		MMU_LogError("invalid MMU configuration\n");
		*pResult = IMG_ERROR_INVALID_PARAMETERS;
		return NULL;
	}

	pNeo =
	    (struct MMUDirectory *)IMG_CALLOC(1, sizeof(struct MMUDirectory));
	if (pNeo == NULL) {
		MMU_LogError("failed to allocate %" IMG_SIZEPR
			     "u bytes for directory" " internal structure\n",
			     sizeof(struct MMUDirectory));
		*pResult = IMG_ERROR_MALLOC_FAILED;
		return NULL;
	}

	pNeo->ppPageMap = (struct MMUPageTable **)IMG_CALLOC(IMGMMU_N_TABLE,
							     sizeof(struct
								    MMUPageTable
								    *));
	if (pNeo->ppPageMap == NULL) {
		IMG_FREE(pNeo);
		MMU_LogError("failed to allocate %" IMG_SIZEPR
			     "u bytes for directory" " internal structure\n",
			     IMGMMU_N_TABLE * sizeof(struct MMUPageTable *));
		*pResult = IMG_ERROR_MALLOC_FAILED;
		return NULL;
	}

	IMG_MEMCPY(&pNeo->sConfiguration, pMMUConfig, sizeof(IMGMMU_Info));
	if (pMMUConfig->pfnPageWrite == NULL) {
		MMU_LogDebug("using default MMU write\n");
		/* use internal function */
		pNeo->sConfiguration.pfnPageWrite = &mmu_PageWrite;
	}
	if (pMMUConfig->pfnPageRead == NULL) {
		MMU_LogDebug("using default MMU read\n");
		/* use read internal function only if write is also NULL */
		pNeo->sConfiguration.pfnPageRead = &mmu_PageRead;
	}

	pNeo->pDirectoryPage = pMMUConfig->pfnPageAlloc(pMMUConfig->allocCtx);
	if (pNeo->pDirectoryPage == NULL) {
		MMU_LogError("failed to allocate directory physical page using"
			     " PageAlloc function\n");
		IMG_FREE(pNeo);
		*pResult = IMG_ERROR_FATAL;
		return NULL;
	}

	MMU_LogDebug("create MMU directory (phys page 0x%" IMG_I64PR
		     "x; CPU virt" " 0x%" IMG_PTRDPR "x)\n",
		     pNeo->pDirectoryPage->uiPhysAddr,
		     pNeo->pDirectoryPage->uiCpuVirtAddr);
	/* now we have a valid MMUDirectory structure */

	/* invalidate all entries */
	for (i = 0; i < IMGMMU_N_TABLE; i++) {
		pNeo->sConfiguration.pfnPageWrite(pNeo->pDirectoryPage, i, 0,
						  MMU_FLAG_INVALID);
	}

	/* when non-UMA need to update the device memory */
	if (pNeo->sConfiguration.pfnPageUpdate != NULL) {
		pNeo->sConfiguration.pfnPageUpdate(pNeo->pDirectoryPage);
	}

	*pResult = IMG_SUCCESS;
	return pNeo;
}

IMG_RESULT IMGMMU_DirectoryDestroy(struct MMUDirectory *pDirectory)
{
	IMG_UINT32 i;

	if (pDirectory == NULL)	{
		/* could be an assert */
		MMU_LogError("pDirectory is NULL\n");
		return IMG_ERROR_INVALID_PARAMETERS;
	}
	if (pDirectory->ui32NMapping > 0) {
		/* mappings should have been destroyed! */
		MMU_LogError("directory still has %u mapping attached to it\n",
			     pDirectory->ui32NMapping);
		/*return IMG_ERROR_FATAL; */
		/* not exiting because clearing the page table map is more important
		   than loosing a few structures */
	}

	IMG_ASSERT(pDirectory->sConfiguration.pfnPageFree != NULL);
	IMG_ASSERT(pDirectory->ppPageMap != NULL);

	MMU_LogDebug("destroy MMU dir (phys page 0x%" IMG_I64PR "x)\n",
		     pDirectory->pDirectoryPage->uiPhysAddr);

	/* destroy every mapping that still exists */
	for (i = 0; i < IMGMMU_N_TABLE; i++) {
		if (pDirectory->ppPageMap[i] != NULL) {
			/* invalidate all pages just for sanity before
			 * giving back the memory to the system */
			pDirectory->sConfiguration.pfnPageWrite(
				pDirectory->pDirectoryPage,
				i, 0,
				MMU_FLAG_INVALID);
			mmu_PageTableDestroy(pDirectory->ppPageMap[i]);
			pDirectory->ppPageMap[i] = NULL;
		}
	}

	if (pDirectory->sConfiguration.pfnPageUpdate != NULL) {
		pDirectory->sConfiguration.pfnPageUpdate(
			pDirectory->pDirectoryPage);
	}

	/* finally destroy the directory entry */
	pDirectory->sConfiguration.pfnPageFree(pDirectory->pDirectoryPage);
	pDirectory->pDirectoryPage = NULL;

	IMG_FREE(pDirectory->ppPageMap);
	IMG_FREE(pDirectory);
	return IMG_SUCCESS;
}

IMGMMU_Page *IMGMMU_DirectoryGetPage(struct MMUDirectory *pDirectory)
{
	IMG_ASSERT(pDirectory != NULL);

	return pDirectory->pDirectoryPage;
}

IMG_UINT32 IMGMMU_DirectoryGetDirectoryEntry(struct MMUDirectory *pDirectory,
					     IMG_UINTPTR uiVirtualAddress)
{
	IMG_UINT32 uiDirEntry = 0;
	IMG_ASSERT(pDirectory != NULL);

	if (pDirectory->sConfiguration.pfnPageRead == NULL) {
		return (IMG_UINT32)-1;
	}

	uiDirEntry = mmu_DirectoryEntry(uiVirtualAddress);
	return pDirectory->sConfiguration.pfnPageRead(pDirectory->
						      pDirectoryPage,
						      uiDirEntry);
}

IMG_UINT32 IMGMMU_DirectoryGetPageTableEntry(struct MMUDirectory *pDirectory,
					     IMG_UINTPTR uiVirtualAddress)
{
	IMG_UINT32 uiDirEntry = 0;
	IMG_UINT32 uiTableEntry = 0;
	IMG_ASSERT(pDirectory != NULL);

	if (pDirectory->sConfiguration.pfnPageRead == NULL) {
		return (IMG_UINT32) -1;
	}

	uiDirEntry = mmu_DirectoryEntry(uiVirtualAddress);
	uiTableEntry = mmu_PageEntry(uiVirtualAddress);

	if (pDirectory->ppPageMap[uiDirEntry] == NULL) {
		return (IMG_UINT32) -1;
	}
	return pDirectory->sConfiguration.pfnPageRead(
		pDirectory->ppPageMap[uiDirEntry]->pPage, uiTableEntry);
}

static struct MMUMapping *IMGMMU_DirectoryMap(struct MMUDirectory *pDirectory,
					      const struct MMUHeapAlloc
					      *pDevVirtAddr,
					      unsigned int uiMapFlags,
					      IMG_RESULT(*phys_iter_next) (void
									   *arg,
									   IMG_UINT64 *next),
					      void *phys_iter_arg,
					      IMG_RESULT *pResult)
{
	unsigned int firstDir = 0, firstPage = 0;
	unsigned int dirOffset = 0, pageOffset = 0;
	IMG_UINT32 ui32NEntries = 0;
	IMG_UINT32 i, d;
	const IMG_UINT32 duplicate =
	    IMGMMU_GetCPUPageSize() / IMGMMU_GetPageSize();
	IMG_RESULT res = IMG_SUCCESS;
	struct MMUMapping *pNeo = NULL;

	/* in non UMA updates on pages needs to be done - store index of directory
	   entry pages to update */
	IMG_UINT32 *pToUpdate;
	/* number of pages in pToUpdate (will be at least 1 for the firstPage to
	   update) */
	IMG_UINT32 ui32NPagesToUpdate = 0;
	/* to know if we also need to update the directory page (creation of new
	   page) */
	IMG_BOOL8 bModifiedDirectory = IMG_FALSE;

	IMG_ASSERT(pResult != NULL);
	IMG_ASSERT(pDirectory != NULL);
	IMG_ASSERT(pDevVirtAddr != NULL);
	/* otherwise PAGE_SIZE and MMU page size are not set properly! */
	IMG_ASSERT(duplicate >= 1);

	ui32NEntries = pDevVirtAddr->uiAllocSize / IMGMMU_GetCPUPageSize();
	if (pDevVirtAddr->uiAllocSize % MMU_PAGE_SIZE != 0 || ui32NEntries == 0) {
		MMU_LogError("invalid allocation size\n");
		*pResult = IMG_ERROR_INVALID_PARAMETERS;
		return NULL;
	}

	if ((uiMapFlags & MMU_FLAG_VALID) != 0) {
		MMU_LogError("valid flag (0x%x) is set in the falgs 0x%x\n",
			     MMU_FLAG_VALID, uiMapFlags);
		*pResult = IMG_ERROR_INVALID_PARAMETERS;
		return NULL;
	}

	/* has to be dynamically allocated because it is bigger than 1k (max stack
	   in the kernel) */
	/* IMGMMU_N_TABLE is 1024 for 4096B pages, that's a 4k allocation (1 page)
	   - if it gets bigger may IMG_BIGALLOC should be used */
	pToUpdate =
	    (IMG_UINT32 *) IMG_CALLOC(IMGMMU_N_TABLE, sizeof(IMG_UINT32));
	if (pToUpdate == NULL) {
		MMU_LogError("Failed to allocate the update index table (%"
			     IMG_SIZEPR "u Bytes)\n",
			     IMGMMU_N_TABLE * sizeof(IMG_UINT32));
		*pResult = IMG_ERROR_MALLOC_FAILED;
		return NULL;
	}

	/* manage multiple page table mapping */

	firstDir = mmu_DirectoryEntry(pDevVirtAddr->uiVirtualAddress);
	firstPage = mmu_PageEntry(pDevVirtAddr->uiVirtualAddress);

	IMG_ASSERT(firstDir < IMGMMU_N_TABLE);
	IMG_ASSERT(firstPage < IMGMMU_N_PAGE);

	/* verify that the pages that should be used are available */
	dirOffset = firstDir;
	pageOffset = firstPage;

	/* loop over the number of entries given by CPU allocator but CPU page size
	   can be > than MMU page size therefore it may need to "duplicate" entries
	   by creating a fake physical address */
	for (i = 0; i < ui32NEntries * duplicate; i++) {
		if (pageOffset >= IMGMMU_N_PAGE) {
			IMG_ASSERT(dirOffset < IMGMMU_N_TABLE);
			dirOffset++;	/* move to next directory */
			IMG_ASSERT(dirOffset < IMGMMU_N_TABLE);
			pageOffset = 0;	/* using its first page */
		}

		/* if pDirectory->ppPageMap[dirOffset] == NULL not yet allocated it
		   means all entries are available */
		if (pDirectory->ppPageMap[dirOffset] != NULL) {
			/* inside a pagetable - verify that the required offset is
			   invalid */
			IMG_UINT32 *pPageMem = (IMG_UINT32 *)
			    pDirectory->ppPageMap[dirOffset]->pPage->
			    uiCpuVirtAddr;

			if ((pPageMem[pageOffset] & MMU_FLAG_VALID) != 0) {
				MMU_LogError
				    ("one of the required page is currently in"
				     " use (vaddr:%lx)\n", pDevVirtAddr->uiVirtualAddress);
				res = IMG_ERROR_MEMORY_IN_USE;
				break;
			}
		}
		/* PageTable struct exists */
		pageOffset++;
	}			/* for all needed entries */

	/* it means one entry was not invalid or not enough page were given */
	if (res != IMG_SUCCESS) {
		/* message already printed */
		/* IMG_ERROR_MEMORY_IN_USE when an entry is not invalid */
		/* IMG_ERROR_INVALID_PARAMETERS when not enough pages are given
		   (or too much) */
		*pResult = res;
		IMG_FREE(pToUpdate);
		return NULL;
	}

	pNeo = (struct MMUMapping *)IMG_CALLOC(1, sizeof(struct MMUMapping));
	if (pNeo == NULL) {
		MMU_LogError("failed to allocate %" IMG_SIZEPR "u bytes for the"
			     " mapping structure\n", sizeof(struct MMUMapping));
		*pResult = IMG_ERROR_MALLOC_FAILED;
		IMG_FREE(pToUpdate);
		return NULL;
	}
	pNeo->pDirectory = pDirectory;
	pNeo->sDevVirtAddr = *pDevVirtAddr;
	IMG_MEMCPY(&(pNeo->sDevVirtAddr), pDevVirtAddr,
		   sizeof(IMGMMU_HeapAlloc));
	pNeo->uiUsedFlag = uiMapFlags;

	/* we now know that all pages are available */
	dirOffset = firstDir;
	pageOffset = firstPage;

	pToUpdate[ui32NPagesToUpdate] = firstDir;
	ui32NPagesToUpdate++;

	for (i = 0; i < ui32NEntries; i++) {
		IMG_UINT64 curPhysAddr;

		if (phys_iter_next(phys_iter_arg, &curPhysAddr) != IMG_SUCCESS) {
			MMU_LogError
			    ("not enough entries in physical address array\n");
			IMG_FREE(pNeo);
			IMG_FREE(pToUpdate);
			*pResult = IMG_ERROR_FATAL;
			return NULL;
		}
		for (d = 0; d < duplicate; d++) {
			if (pageOffset >= IMGMMU_N_PAGE) {
				dirOffset++;	/* move to next directory */
				pageOffset = 0;	/* using its first page */

				pToUpdate[ui32NPagesToUpdate] = dirOffset;
				ui32NPagesToUpdate++;
			}

			/* this page table object does not exists, create it */
			if (pDirectory->ppPageMap[dirOffset] == NULL) {
				pDirectory->ppPageMap[dirOffset] =
				    mmu_PageTableCreate(pDirectory, pResult);
				if (pDirectory->ppPageMap[dirOffset] == NULL) {
					MMU_LogError
					    ("failed to create a non-existing page table\n");

					/* invalidate all already mapped pages - do not destroy the
					   created pages */
					while (i > 1) {
						if (d == 0) {
							i--;
							d = duplicate;
						}
						d--;

						if (pageOffset == 0) {
							/* -1 is done just after */
							pageOffset = IMGMMU_N_PAGE;
							IMG_ASSERT(dirOffset > 0);
							dirOffset--;
						}

						pageOffset--;

						/* it should have been used before */
						IMG_ASSERT(pDirectory->ppPageMap[dirOffset] != NULL);
						pDirectory->sConfiguration.pfnPageWrite(
							pDirectory->ppPageMap[dirOffset]->pPage,
							pageOffset, 0,
							MMU_FLAG_INVALID);
						pDirectory->ppPageMap[dirOffset]->ui32ValidEntries--;
					}

					IMG_FREE(pNeo);
					IMG_FREE(pToUpdate);
					*pResult = IMG_ERROR_FATAL;
					return NULL;
				}

				/* make this page table valid */
				/* should be dirOffset */
				pDirectory->sConfiguration.pfnPageWrite(
					pDirectory->pDirectoryPage,
					dirOffset,
					pDirectory->ppPageMap[dirOffset]->pPage->uiPhysAddr,
					MMU_FLAG_VALID);
				bModifiedDirectory = IMG_TRUE;
			}

			/* map this particular page in the page table */
			/* use d*(MMU page size) to add additional entries from the given
			   physical address with the correct offset for the MMU */
			pDirectory->sConfiguration.pfnPageWrite(
				pDirectory->ppPageMap[dirOffset]->pPage,
				pageOffset,
				curPhysAddr + d * IMGMMU_GetPageSize(),
				pNeo->uiUsedFlag | MMU_FLAG_VALID);
			pDirectory->ppPageMap[dirOffset]->ui32ValidEntries++;

			pageOffset++;
		}		/* for duplicate */
	}			/* for entries */

	pNeo->ui32NEntries = ui32NEntries * duplicate;
	/* one more mapping is related to this directory */
	pDirectory->ui32NMapping++;

	/* if non UMA we need to update device memory */
	if (pDirectory->sConfiguration.pfnPageUpdate != NULL) {
		while (ui32NPagesToUpdate > 0) {
			pDirectory->sConfiguration.pfnPageUpdate(
				pDirectory->ppPageMap[
					pToUpdate[
						ui32NPagesToUpdate - 1]]->pPage);
			ui32NPagesToUpdate--;
		}
		if (bModifiedDirectory == IMG_TRUE) {
			pDirectory->sConfiguration.pfnPageUpdate(
				pDirectory->pDirectoryPage);
		}
	}

	*pResult = IMG_SUCCESS;
	IMG_FREE(pToUpdate);
	return pNeo;
}

/*
 * with physical address array
 */

struct linear_phys_iter {
	IMG_UINT64 *array;
	int idx;
};

static IMG_RESULT linear_phys_iter_next(void *arg, IMG_UINT64 *next)
{
	struct linear_phys_iter *iter = arg;

	*next = iter->array[iter->idx++];	/* boundary check? */
	return IMG_SUCCESS;
}

struct MMUMapping *IMGMMU_DirectoryMapArr(struct MMUDirectory *pDirectory,
					  IMG_UINT64 *aPhysPageList,
					  const struct MMUHeapAlloc *pDevVirtAddr,
					  unsigned int uiMapFlags,
					  IMG_RESULT *pResult)
{
	struct linear_phys_iter arg = { aPhysPageList, 0 };
	return IMGMMU_DirectoryMap(pDirectory, pDevVirtAddr, uiMapFlags,
				   linear_phys_iter_next, &arg, pResult);
}

/*
 * with sg
 */
struct sg_phys_iter {
	struct scatterlist *sgl;
	unsigned int offset;
};

static IMG_RESULT sg_phys_iter_next(void *arg, IMG_UINT64 *next)
{
	struct sg_phys_iter *iter = arg;

	if (!iter->sgl)
		return IMG_ERROR_FATAL;
#ifdef CONFIG_MCST
	*next = sg_dma_address(iter->sgl) + iter->offset;
	iter->offset += PAGE_SIZE;

	if (iter->offset == sg_dma_len(iter->sgl)) {
		iter->sgl = sg_next(iter->sgl);
		iter->offset = 0;
	}
#else
	*next = sg_phys(iter->sgl) + iter->offset;	/* phys_addr to dma_addr? */
	iter->offset += PAGE_SIZE;

	if (iter->offset == iter->sgl->length) {
		iter->sgl = sg_next(iter->sgl);
		iter->offset = 0;
	}
#endif

	return IMG_SUCCESS;
}

struct MMUMapping *IMGMMU_DirectoryMapSG(
	struct MMUDirectory *pDirectory,
	struct scatterlist *pPhysPageSG,
	const struct MMUHeapAlloc *pDevVirtAddr,
	unsigned int uiMapFlags,
	IMG_RESULT *pResult)
{
	struct sg_phys_iter arg = { pPhysPageSG };
	return IMGMMU_DirectoryMap(pDirectory, pDevVirtAddr, uiMapFlags,
				   sg_phys_iter_next, &arg, pResult);
}

IMG_RESULT IMGMMU_DirectoryUnMap(struct MMUMapping *pMapping)
{
	unsigned int firstDir = 0, firstPage = 0;
	unsigned int dirOffset = 0, pageOffset = 0;
	IMG_UINT32 i;
	struct MMUDirectory *pDirectory = NULL;

	/* in non UMA updates on pages needs to be done - store index of directory
	   entry pages to update */
	IMG_UINT32 *pToUpdate;
	IMG_UINT32 ui32NPagesToUpdate = 0;

	IMG_ASSERT(pMapping != NULL);
	IMG_ASSERT(pMapping->ui32NEntries > 0);
	IMG_ASSERT(pMapping->pDirectory != NULL);

	pDirectory = pMapping->pDirectory;

	/* has to be dynamically allocated because it is bigger than 1k (max stack
	   in the kernel) */
	pToUpdate =
	    (IMG_UINT32 *) IMG_CALLOC(IMGMMU_N_TABLE, sizeof(IMG_UINT32));
	if (pToUpdate == NULL) {
		MMU_LogError("Failed to allocate the update index table (%"
			     IMG_SIZEPR "u Bytes)\n",
			     IMGMMU_N_TABLE * sizeof(IMG_UINT32));
		return IMG_ERROR_MALLOC_FAILED;
	}

	firstDir = mmu_DirectoryEntry(pMapping->sDevVirtAddr.uiVirtualAddress);
	firstPage = mmu_PageEntry(pMapping->sDevVirtAddr.uiVirtualAddress);

	/* verify that the pages that should be used are available */
	dirOffset = firstDir;
	pageOffset = firstPage;

	pToUpdate[ui32NPagesToUpdate] = firstDir;
	ui32NPagesToUpdate++;

	for (i = 0; i < pMapping->ui32NEntries; i++) {
		if (pageOffset >= IMGMMU_N_PAGE) {
			dirOffset++;	/* move to next directory */
			pageOffset = 0;	/* using its first page */

			pToUpdate[ui32NPagesToUpdate] = dirOffset;
			ui32NPagesToUpdate++;
		}

		/* this page table object does not exists something destroyed it while
		   the mapping was supposed to use it */
		IMG_ASSERT(pDirectory->ppPageMap[dirOffset] != NULL);

		pDirectory->sConfiguration.pfnPageWrite(
			pDirectory->ppPageMap[dirOffset]->pPage,
			pageOffset, 0,
			MMU_FLAG_INVALID);
		pDirectory->ppPageMap[dirOffset]->ui32ValidEntries--;

		pageOffset++;
	}

	pDirectory->ui32NMapping--;

	if (pDirectory->sConfiguration.pfnPageUpdate != NULL) {
		while (ui32NPagesToUpdate > 0) {
			pDirectory->sConfiguration.pfnPageUpdate(
				pDirectory->ppPageMap[
					pToUpdate[ui32NPagesToUpdate - 1]]->pPage);
			ui32NPagesToUpdate--;
		}
	}

	/* mapping does not own the given virtual address */
	IMG_FREE(pMapping);
	IMG_FREE(pToUpdate);
	return IMG_SUCCESS;
}

IMG_UINT32 IMGMMU_DirectoryClean(struct MMUDirectory *pDirectory)
{
	IMG_UINT32 i, removed = 0;

	IMG_ASSERT(pDirectory != NULL);
	IMG_ASSERT(pDirectory->sConfiguration.pfnPageWrite);

	for (i = 0; i < IMGMMU_N_TABLE; i++) {
		if (pDirectory->ppPageMap[i] != NULL &&
		    pDirectory->ppPageMap[i]->ui32ValidEntries == 0) {
			pDirectory->sConfiguration.pfnPageWrite(
				pDirectory->pDirectoryPage,
				i, 0,
				MMU_FLAG_INVALID);

			mmu_PageTableDestroy(pDirectory->ppPageMap[i]);
			pDirectory->ppPageMap[i] = NULL;
			removed++;
		}
	}

	if (pDirectory->sConfiguration.pfnPageUpdate != NULL) {
		pDirectory->sConfiguration.pfnPageUpdate(
			pDirectory->pDirectoryPage);
	}

	return removed;
}
