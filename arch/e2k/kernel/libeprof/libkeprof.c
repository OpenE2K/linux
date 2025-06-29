/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/atomic.h>

/*****************************************************************************/
/********************************* prof_defs.h *******************************/
/*****************************************************************************/

#define PROF_SAVE_FILE  __BUILTIN_ecomp_prof_SaveFile

#ifdef ECOMP_SUPPORT_INTERNAL_CHECK
#define PROF_CHECK
#endif /* ECOMP_SUPPORT_INTERNAL_CHECK */

#define PROF_FILE_IDEN_LEN (5 + 1) /* Profile identification sign length */

#define PROF_FILE_IDEN_STR_C "VER.C"

#define PROF_BYTES_IN_UINT   4   /* prof_UInt_t type size */
#define PROF_BYTES_IN_UINT64 8   /* prof_UInt64_t type size */
#define PROF_BITS_IN_BYTE    8   /* Bits in byte */

/********************************* prof_defs.h *******************************/


#define PROFILE_FILENAME "kernel_profile"

const int prof_BuffSize = 20 * 1024 * 1024;

/**
 * Buffer for profile content
 * Allocation of 20 Mb
 */
static char prof_ProfileBuff[prof_BuffSize] = {0};

/* Flag is enabled if saving to buffer launched at first time */
static bool save_first_time = true;

/* Number of times the profile dump proc is called */
static int profile_counters_num = 1;

/**
 * The increment value. While preparing dumps we set it to zero so that
 * our counters should not be broken
 */
unsigned long ecomp_ProfileIncrement = 0;

/*****************************************************************************/
/******************************** prof_types.h *******************************/
/*****************************************************************************/

typedef unsigned int prof_UInt_t;

typedef unsigned long long prof_UInt64_t;

/**
 * Profile mode
 */
typedef enum {
PROF_FUNC_ATTR_EDGES        = 0x2,  /* Edges */
PROF_FUNC_ATTR_LOOPS        = 0x4,  /* Loop profile */
PROF_FUNC_ATTR_VALUE_PROF   = 0x40, /* Value profiling */
PROF_FUNC_ATTR_LOOPSOUTER   = 0x100 /* Outer loop profile */
} prof_FuncAttr_t;

/******************************** prof_types.h *******************************/

/*****************************************************************************/
/******************************** prof_utils.h *******************************/
/*****************************************************************************/

#define PROF_ERROR_MSG_LENGTH 1024

#define prof_IsStrStartEQ(str1, str2) \
(\
strncmp(str1, str2, strlen(str2)) == 0 \
)

#ifdef ECOMP_SUPPORT_INTERNAL_CHECK

#define PROF_ASSERT(cond) \
do { if (!(cond)) panic("assertion failed"); } while (0)

#else /* ECOMP_SUPPORT_INTERNAL_CHECK */

#define PROF_ASSERT(cond)

#endif /* ECOMP_SUPPORT_INTERNAL_CHECK */

/**
 * Custom bool
 */
typedef enum {
PROF_FALSE  = 0,
PROF_TRUE   = 1
} prof_Bool_t;

/******************************** prof_utils.h *******************************/

/*****************************************************************************/
/******************************** prof_utils.c *******************************/
/*****************************************************************************/

/**
 * Memory allocation
 *
 * Returns: Pointer to allocated memory
 */
static void *
prof_Malloc(size_t size) /* Size of allocation */
{
	void *ptr;

	ptr = kmalloc(size, GFP_KERNEL);

	if (ptr == NULL) {
		/* Break if can't allocate memory */
		panic("Not enough memory for profiling\n");
	}

	return ptr;
} /* prof_Malloc */

/**
 * Memory allocation and initialization
 *
 * Returns: Pointer to allocated memory
 */
static void *
prof_Calloc(size_t len,  /* Number of elements */
			size_t size) /* Element size */
{
	void *ptr;

	ptr = kcalloc(len, size, GFP_KERNEL);

	if (ptr == NULL) {
		/* Break if can't allocate memory */
		panic("Not enough memory for profiling\n");
	}

	return ptr;
} /* prof_Calloc */

/**
 * Free allocated memory
 */
static void
prof_Free(void *ptr) /* Allocated memory */
{
	; /* do nothing */
} /* prof_Free */

/******************************** prof_utils.c *******************************/



/*****************************************************************************/
/******************************** prof_hashrt.h ******************************/
/*****************************************************************************/

#define PROF_HASH_ALL_ENTRIES(entry, table) \
(entry) = prof_HashGetFirstEntry((table)); \
(entry) != NULL; \
(entry) = prof_HashGetNextEntry((entry))

/*******************************************************************************
 ************************************ Types ************************************
 ******************************************************************************/

/**
 * Key and value types for hash table
 */
typedef enum {
	PROF_HASH_VOID_PTR_TYPE,
	PROF_HASH_STRING_TYPE,
	PROF_HASH_UINT64_TYPE
} prof_HashType_t;

/**
 * Hash table entry
 */
typedef struct prof_HashEntry_r {
	union {
		const char *s_key; /* String key value */
		prof_UInt64_t uint64_key; /* Integer key value */
	};

	struct prof_HashEntry_r *next; /* Next entry with current index */
	struct prof_HashEntry_r *prev; /* Previous entry with current index */
	struct prof_HashEntry_r *next_in_table; /* Next index in table */
	struct prof_HashEntry_r *prev_in_table; /* Previous index in table */

	union {
		void *v_value; /* User type value in hash */
		char *s_value; /* String value in hash */
		prof_UInt64_t uint64_value; /* Integer value in hash */
	};
} prof_HashEntry_t;

/**
 * Hash table
 */
typedef struct {
	prof_HashEntry_t **hash_table;      /* Hash element array */
	prof_UInt_t        table_dimension; /* Array size for hash */
	prof_UInt_t        size;            /* Entry number */
	prof_HashEntry_t  *first;           /* First entry in hash */
	prof_HashEntry_t  *last;            /* Last entry in hash */
	prof_HashType_t    key_type;        /* Key type */
	prof_HashType_t    val_type;        /* Value type */
} prof_HashTable_t;

/******************************** prof_hashrt.h ******************************/



/*****************************************************************************/
/******************************** prof_hashrt.c ******************************/
/*****************************************************************************/

/*******************************************************************************
 *********************************** Macross ***********************************
 ******************************************************************************/

#define PROF_HASH_ARRAY_SIZE_LN 10

#define PROF_HASH_ARRAY_SIZE	(1 << PROF_HASH_ARRAY_SIZE_LN)

#define PROF_HASH_MASK (PROF_HASH_ARRAY_SIZE - 1)

#define PROF_HASH_DOWN_SHIFT (sizeof(prof_UInt_t) * 8 - PROF_HASH_ARRAY_SIZE_LN)

/* hash function */
#define PROF_HASH_RANDOM_INDEX(i) \
(\
(((((prof_UInt_t) (i))*1103515245) >> PROF_HASH_DOWN_SHIFT) & \
((unsigned int)PROF_HASH_MASK))\
)

/*********************************** Macross **********************************/

/*******************************************************************************
 ************************ Work with type prof_HashTable_t **********************
 ******************************************************************************/

/**
 * Create new table
 *
 * Returns Created table or NULL
 */
prof_HashTable_t *
prof_HashCreate(prof_HashType_t key_type,   /* Key type */
				prof_HashType_t value_type) /* Record type */
{
	prof_HashTable_t *self;

	self = (prof_HashTable_t *) prof_Malloc(sizeof(prof_HashTable_t));

	if (self == NULL)
		return NULL;

	memset(self, 0, sizeof(prof_HashTable_t));

	self->table_dimension = PROF_HASH_ARRAY_SIZE;
	self->hash_table = (prof_HashEntry_t **)
	prof_Calloc(PROF_HASH_ARRAY_SIZE, sizeof(prof_HashEntry_t *));
	self->key_type = key_type;
	self->val_type = value_type;

	if (self->hash_table == NULL) {
		prof_Free(self);
		return NULL;
	}

	return self;
} /* prof_HashCreate */

/**
 * Delete table with records (dat ain records should be deleted separately)
 */
void
prof_HashDestroy(prof_HashTable_t *table) /* Deleting table */
{
	prof_Free(table->hash_table);
	prof_Free(table);
} /* prof_HashDestroy */

/**
 * Create new record
 */
static prof_HashEntry_t *
prof_HashCreateEntryByString(
	const char *key,
	void *value)
{
	prof_HashEntry_t *self;

	self = (prof_HashEntry_t *) prof_Malloc(sizeof(prof_HashEntry_t));

	if (!self)
		return NULL;

	memset(self, 0, sizeof(prof_HashEntry_t));
	self->s_key	 = key;
	self->v_value   = value;

	return self;
} /* prof_HashCreateEntryByString */

/**
 * Create new record
 */
static prof_HashEntry_t *
prof_HashCreateVoidPtrEntryByUInt64(
	prof_UInt64_t key,
	void *value)
{
	prof_HashEntry_t *self;

	self = (prof_HashEntry_t *) prof_Malloc(sizeof(prof_HashEntry_t));

	if (!self)
		return NULL;

	memset(self, 0, sizeof(prof_HashEntry_t));
	self->uint64_key	= key;
	self->v_value	   = value;

	return self;
} /* prof_HashCreateVoidPtrEntryByUInt64 */

/**
 * Create new record
 */
static prof_HashEntry_t *
prof_HashCreateUInt64EntryByUInt64(
	prof_UInt64_t key,
	prof_UInt64_t value)
{
	prof_HashEntry_t *self;

	self = (prof_HashEntry_t *) prof_Malloc(sizeof(prof_HashEntry_t));

	if (!self)
		return NULL;

	memset(self, 0, sizeof(prof_HashEntry_t));
	self->uint64_key	= key;
	self->uint64_value  = value;

	return self;
} /* prof_HashCreateUInt64EntryByUInt64 */

/**
 * Generate hash value by key (string)
 */
static prof_UInt_t
prof_HashStringFunc(const char *key)
{
	int	i;
	prof_UInt_t  table_index, summ, length;

	summ  = 0;
	length  = strlen(key);

	for (i = 0; i < length; i++)
		summ += (unsigned char)key[i];

	table_index = PROF_HASH_RANDOM_INDEX(summ);

	return table_index;
} /* prof_HashStringFunc */

/**
 * Generate hash value by key (string)
 */
static prof_UInt_t
prof_HashUint64Func(prof_UInt64_t key)
{
	prof_UInt_t  table_index;

	table_index = PROF_HASH_RANDOM_INDEX(key);
	return table_index;
} /* prof_HashUint64Func */

prof_UInt64_t
prof_HashGetEntryUInt64Key(const prof_HashEntry_t *entry)
{
	return entry->uint64_key;
} /* prof_HashGetEntryUInt64Key */

void *
prof_HashGetEntryVoidPtrVal(const prof_HashEntry_t *entry)
{
	return entry->v_value;
} /* prof_HashGetEntryVal */

char *
prof_HashGetEntryStringVal(const prof_HashEntry_t *entry)
{
	return entry->s_value;
} /* prof_HashGetEntryStringVal */

prof_UInt64_t
prof_HashGetEntryUInt64Val(const prof_HashEntry_t *entry)
{
	return entry->uint64_value;
} /* prof_HashGetEntryUInt64Val */

void
prof_HashSetEntryUInt64Val(
	prof_HashEntry_t *entry,
	prof_UInt64_t val)
{
	entry->uint64_value = val;
} /* prof_HashGetEntryUInt64Val */

static prof_HashEntry_t *
prof_HashFindByString(
	const prof_HashTable_t *self,
	const char *key)
{
	prof_UInt_t	index;
	prof_HashEntry_t *entry;

	PROF_ASSERT(self->key_type == PROF_HASH_STRING_TYPE);
	index = prof_HashStringFunc(key);
	entry = self->hash_table[index];

	while (entry != NULL) {
		if (strcmp(entry->s_key, key) == 0)
			return entry;

		entry = entry->next;
	}

	return NULL;
} /* prof_HashFindByString */

void *
prof_HashFindByStringAndGetVoidPtrValue(
	const prof_HashTable_t *self,
	const char *key)
{
	prof_HashEntry_t *entry;

	PROF_ASSERT(self->key_type == PROF_HASH_STRING_TYPE);
	PROF_ASSERT(self->val_type == PROF_HASH_VOID_PTR_TYPE);
	entry = prof_HashFindByString(self, key);

	if (entry == NULL)
		return NULL;

	return prof_HashGetEntryVoidPtrVal(entry);
} /* prof_HashFindByStringAndGetVoidPtrValue */

prof_HashEntry_t *
prof_HashFindByUInt64(
	const prof_HashTable_t *self,
	prof_UInt64_t key)
{
	prof_UInt_t index;
	prof_HashEntry_t *entry;

	PROF_ASSERT(self->key_type == PROF_HASH_UINT64_TYPE);
	index = prof_HashUint64Func(key);
	entry = self->hash_table[index];

	while (entry != NULL) {
		if (entry->uint64_key == key)
			return entry;

		entry = entry->next;
	}

	return NULL;
} /* prof_HashFindByUInt64 */

char *
prof_HashFindByUInt64AndGetCharValue(
	const prof_HashTable_t *self,
	prof_UInt64_t key)
{
	prof_HashEntry_t *entry;

	PROF_ASSERT(self->key_type == PROF_HASH_UINT64_TYPE);
	entry = prof_HashFindByUInt64(self, key);

	if (entry == NULL)
		return NULL;

	return prof_HashGetEntryVoidPtrVal(entry);
} /* prof_HashFindByUInt64AndGetCharValue */

static void
prof_AddEntryByIndex(
	prof_HashTable_t *self,
	prof_UInt_t index,
	prof_HashEntry_t *new_entry)
{
	prof_HashEntry_t *place;

	place = self->hash_table[index];
	self->size++;

	if (place != NULL) {
		while (place->next != NULL)
			place = place->next;

		place->next	 = new_entry;
		new_entry->prev = place;
	} else {
		self->hash_table[index] = new_entry;
	}

	if (self->first == NULL) {
		self->first = new_entry;
		self->last  = new_entry;
	} else {
		new_entry->prev_in_table = self->last;
		self->last->next_in_table = new_entry;
		self->last = new_entry;
	}
} /* prof_AddEntryByIndex */

/**
 * Add entry to the table with given key
 *
 * NOTE If an element with given key exist, a function does nothing
 * WARNING Key should be in a heap because it is not copied
 */
void
prof_HashAddVoidPtrValueByString(
	prof_HashTable_t *self,
	const char *key,
	void *value)
{
	prof_UInt_t index;
	prof_HashEntry_t *new_entry;

	PROF_ASSERT(self->key_type == PROF_HASH_STRING_TYPE);
	PROF_ASSERT(self->val_type == PROF_HASH_VOID_PTR_TYPE);

	if (prof_HashFindByStringAndGetVoidPtrValue(self, key) != NULL)
		return;

	index = prof_HashStringFunc(key);
	new_entry = prof_HashCreateEntryByString(key, value);
	prof_AddEntryByIndex(self, index, new_entry);
} /* prof_HashAddVoidPtrValueByString */

/**
 * Add entry to the table with given key
 *
 * NOTE If an element with given key exist, a function does nothing
 * WARNING Key should be in a heap because it is not copied
 */
void
prof_HashAddStringValueByUInt64(
	prof_HashTable_t *self,
	prof_UInt64_t	 key,
	char		 *value)
{
	prof_UInt_t index;
	prof_HashEntry_t *new_entry;

	PROF_ASSERT(self->key_type == PROF_HASH_UINT64_TYPE);
	PROF_ASSERT(self->val_type == PROF_HASH_STRING_TYPE);

	if (prof_HashFindByUInt64AndGetCharValue(self, key) != NULL)
		return;

	index = prof_HashUint64Func(key);
	new_entry = prof_HashCreateVoidPtrEntryByUInt64(key, value);
	prof_AddEntryByIndex(self, index, new_entry);
} /* prof_HashAddStringValueByUInt64 */

/**
 * Add entry to the table with given key
 *
 * NOTE If an element with given key exist, a function does nothing
 * WARNING Key should be in a heap because it is not copied
 */
void
prof_HashAddUInt64ValueByUInt64(
	prof_HashTable_t *self,
	prof_UInt64_t key,
	prof_UInt64_t value)
{
	prof_UInt_t index;
	prof_HashEntry_t *new_entry;

	PROF_ASSERT(self->key_type == PROF_HASH_UINT64_TYPE);
	PROF_ASSERT(self->val_type == PROF_HASH_UINT64_TYPE);

	if (prof_HashFindByUInt64AndGetCharValue(self, key) != NULL)
		return;

	index = prof_HashUint64Func(key);
	new_entry = prof_HashCreateUInt64EntryByUInt64(key, value);
	prof_AddEntryByIndex(self, index, new_entry);
} /* prof_HashAddStringValueByUInt64 */

void
prof_HashDeleteEntryByString(
	prof_HashTable_t  *self,
	const char *key)
{
	prof_HashEntry_t *entry;
	int index;

	PROF_ASSERT(self->key_type == PROF_HASH_STRING_TYPE);
	entry = prof_HashFindByString(self, key);

	if (entry == NULL)
		return;

	if (self->first == entry)
		self->first = entry->next_in_table;

	if (self->last == entry)
		self->last = entry->prev_in_table;

	if (entry->prev != NULL)
		entry->prev->next = entry->next;

	if (entry->next != NULL)
		entry->next->prev = entry->prev;

	if (entry->prev_in_table != NULL)
		entry->prev_in_table->next_in_table = entry->next_in_table;

	if (entry->next_in_table != NULL)
		entry->next_in_table->prev_in_table = entry->prev_in_table;

	index = prof_HashStringFunc(key);

	if (self->hash_table[index] == entry) {
		if (entry->next != NULL)
			self->hash_table[index] = entry->next;
		else
			self->hash_table[index] = NULL;
	}

	prof_Free(entry);
} /* prof_HashDeleteEntryByString */

void
prof_HashForEachEntry(
	prof_HashTable_t *self_p,
	void (*user_func)(void *))
{
	int cur_entry_num;

	PROF_ASSERT(self_p->hash_table != NULL);

	for (cur_entry_num = 0;
		cur_entry_num < self_p->table_dimension;
		cur_entry_num++) {
		prof_HashEntry_t *cur_entry;

		cur_entry = self_p->hash_table[cur_entry_num];

		while (cur_entry != NULL) {
			user_func((void *)cur_entry->v_value);
			cur_entry = cur_entry->next;
		}
	}
} /* prof_HashForEachEntry */

prof_HashEntry_t *
prof_HashGetFirstEntry(const prof_HashTable_t *table)
{
	return table->first;
} /* prof_HashGetFirstEntry */

prof_HashEntry_t *
prof_HashGetNextEntry(const prof_HashEntry_t *entry)
{
	return entry->next_in_table;
} /* prof_HashGetFirstEntry */

prof_UInt_t
prof_HashGetElementNum(const prof_HashTable_t *self)
{
	return self->size;
} /* prof_HashGetElementNum */

/****************************** prof_HashTable_t *****************************/

/******************************** prof_hashrt.c ******************************/




/*****************************************************************************/
/******************************* prof_profilert.h ****************************/
/*****************************************************************************/

/**
 * Container with procedure profile data
 */
typedef struct {
	/* General data */
	char *name; /* Procedure name */
	prof_FuncAttr_t attr; /* Options of profile dumps */
	prof_UInt_t	cfg_checksum; /* Procedure checksum */
	prof_Bool_t is_excluded;

	/* Edge profile */
	prof_UInt64_t *edge_counters; /* Edge counter array */
	prof_UInt_t num_edges; /* Number of edges inside procedure */

	off_t edges_in_file; /* Offset for edges array in file */
	/* Number of effectively dumped edge counters */
	prof_UInt_t dumped_edges_number;
} prof_Func_t;

/**
 * Module profile
 */
typedef struct {
	char *name; /* Module name */
    /* Table with procedures of module */
	prof_HashTable_t *procedures;
	/* Offset for module info in file */
	off_t module_offset;
} prof_Module_t;

/**
 * Program modules table entry.
 *  Key is modules name, value is pointer to an object
 */
typedef prof_HashEntry_t prof_ModulesEntry_t;

/* Program modules table */
typedef prof_HashTable_t prof_ModulesTable_t;

typedef enum {
	PROF_COUNT_OFFSETS = 0, /* Only count offsets. No write to buffer */
	PROF_WRITE_OFFSETS	  /* Only write to buffer. no offset count */
} prof_FileWriteMode_t;

/**
 * Program profile
 */
typedef struct {
	prof_ModulesTable_t *modules; /* Table with modules */

	char *prof_buff; /* Buffer to dump profile info */
	prof_UInt_t cur_buf_pos; /* Current position in file */
	/* Offset of data as if it has been writen in file */
	prof_UInt_t	offset;
	prof_FileWriteMode_t write_mode; /* Current file write mode */
} prof_Program_t;

/******************************* prof_profilert.h ****************************/



/*****************************************************************************/
/******************************* prof_profilert.c ****************************/
/*****************************************************************************/

/*******************************************************************************
 ******************************* prof_Func_t ***********************************
 ******************************************************************************/

void
prof_FuncSetAttr(
	prof_Func_t *func,
	prof_FuncAttr_t attr)
{
	func->attr = attr;
} /* prof_FuncSetAttr */

/**
 * Create object for function profile
 */
static prof_Func_t *
prof_FuncCreate(
	const char	 *name,
	prof_FuncAttr_t attr)
{
	prof_Func_t *func;

	func = (prof_Func_t *) prof_Malloc(sizeof(prof_Func_t));
	memset(func, 0, sizeof(prof_Func_t));
	func->name = kstrdup(name, GFP_KERNEL);
	prof_FuncSetAttr(func, attr);

	return func;
} /* prof_FuncCreate */

const char *
prof_FuncGetName(const prof_Func_t *func)
{
	return func->name;
} /* prof_FuncGetName */

prof_FuncAttr_t
prof_FuncGetAttr(const prof_Func_t *func)
{
	return func->attr;
} /* prof_FuncGetAttr */

static void
prof_FuncSetEdgesNum(
	prof_Func_t *func,
	unsigned int num_edges,
	prof_Bool_t create_arrays)
{
	func->num_edges = num_edges;

	if (create_arrays) {
		func->edge_counters = (prof_UInt64_t *)
			prof_Malloc(sizeof(prof_UInt64_t) * num_edges);
		memset(func->edge_counters, -1,
			   sizeof(prof_UInt64_t) * num_edges);
	}
} /* prof_FuncSetEdgesNum */

prof_UInt_t
prof_FuncGetNumEdges(const prof_Func_t *func)
{
	return func->num_edges;
} /* prof_FuncGetNumEdges */

prof_UInt64_t
prof_FuncGetEdgeCounter(
	const prof_Func_t *func,
	prof_UInt_t	edge_num)
{
	return func->edge_counters[edge_num];
} /* prof_FuncGetEdgeCounter */

void
prof_FuncSetEdgeCounter(
	const prof_Func_t *func,
	prof_UInt_t	edge_num,
	prof_UInt64_t counter)
{
	func->edge_counters[edge_num] = counter;
} /* prof_FuncSetEdgeCounter */

prof_UInt_t
prof_FuncGetDumpedEdgesNum(const prof_Func_t *func)
{
	return func->dumped_edges_number;
} /* prof_FuncGetDumpedEdgesNum */

void
prof_FuncSetDumpedEdgesNum(
	prof_Func_t *func,
	prof_UInt_t number)
{
	func->dumped_edges_number = number;
} /* prof_FuncSetDumpedEdgesNum */

void
prof_FuncIncrDumpedEdges(prof_Func_t *func)
{
	func->dumped_edges_number++;
} /* prof_FuncIncrDumpedEdges */

prof_UInt_t
prof_FuncGetChecksum(const prof_Func_t *func)
{
	return func->cfg_checksum;
} /* prof_FuncGetChecksum */

void
prof_FuncSetChecksum(
	prof_Func_t *func,
	prof_UInt_t sum)
{
	func->cfg_checksum = sum;
} /* prof_FuncGetChecksum */

static void
prof_FuncDestroy(prof_Func_t *func)
{
	if (prof_FuncGetNumEdges(func) != 0)
		prof_Free(func->edge_counters);

	prof_Free(func->name);
	prof_Free(func);
} /* prof_FuncDestroy */

/********************************** prof_Func_t *******************************/

/*******************************************************************************
 ********************************** prof_Module_t ******************************
 ******************************************************************************/

/**
 * Create object with module profile
 */
static prof_Module_t *
prof_ModuleCreate(const char *name)
{
	prof_Module_t  *module;

	module = (prof_Module_t *) prof_Malloc(sizeof(prof_Module_t));
	memset(module, 0, sizeof(prof_Module_t));
	module->procedures = prof_HashCreate(PROF_HASH_STRING_TYPE,
		PROF_HASH_VOID_PTR_TYPE);
	module->name = kstrdup(name, GFP_KERNEL);

	return module;
} /* prof_ModuleCreate */

static void
prof_ModuleDestroy(prof_Module_t *module)
{
	prof_HashForEachEntry(module->procedures,
		(void (*)(void *)) prof_FuncDestroy);
	prof_HashDestroy(module->procedures);
	prof_Free(module->name);

	prof_Free(module);
} /* prof_ModuleDestroy */

void
prof_ModuleRemoveFunction(
	prof_Module_t *module,
	const char *func_name)
{
	prof_HashDeleteEntryByString(module->procedures, func_name);
} /* prof_ModuleRemoveFunction*/

prof_Func_t *
prof_ModuleFindFunction(
	prof_Module_t *module,
	const char *function_name)
{
	prof_Func_t *function;

	function = prof_HashFindByStringAndGetVoidPtrValue(module->procedures,
		function_name);

	return function;
} /* prof_ModuleFindFunction */

prof_HashTable_t *
prof_ModuleFunctions(prof_Module_t  *module)
{
	return module->procedures;
} /* prof_ModuleFunctions */

/**
 * Find or create procedure inside module
 */
prof_Func_t *
prof_ModuleFindOrCreateFunction(
	prof_Module_t *module,
	const char *function_name,
	prof_FuncAttr_t	func_attr,
	unsigned int edge_max_num,
	unsigned int loop_max_num,
	unsigned int loop_outer_max_num,
	unsigned int loop_outer_outer_max_num,
	unsigned int crc,
	prof_UInt_t vprof_opers)
{
	prof_Func_t *function;

	function = prof_HashFindByStringAndGetVoidPtrValue(module->procedures,
		function_name);

	if (function == NULL) {
		function = prof_FuncCreate(function_name, func_attr);
		prof_FuncSetEdgesNum(function, edge_max_num, PROF_FALSE);
		PROF_ASSERT(crc != 0);
		prof_HashAddVoidPtrValueByString(module->procedures,
			 function_name,
			 function);
	}

	return function;
} /* prof_ModuleFindOrCreateFunction */

char *
prof_ModuleGetName(const prof_Module_t *module)
{
	return module->name;
} /* prof_ModuleGetName */

prof_UInt_t
prof_ModuleGetNumFunctions(const prof_Module_t *module)
{
	return prof_HashGetElementNum(module->procedures);
} /* prof_ModuleGetNumFunctions */

off_t
prof_ModuleGetOffset(const prof_Module_t *module)
{
	return module->module_offset;
} /* prof_ModuleGetOffset */

void
prof_ModuleSetOffset(
	prof_Module_t *module,
	off_t offset)
{
	module->module_offset = offset;
} /* prof_ModuleSetOffset */

/********************************* prof_Module_t ******************************/

/*******************************************************************************
 ********************************* prof_Program_t ******************************
 ******************************************************************************/

prof_Program_t *
prof_ProgCreate(prof_Bool_t is_vprof)
{
	prof_Program_t *profile;

	profile = (prof_Program_t *) prof_Malloc(sizeof(prof_Program_t));
	memset(profile, 0, sizeof(prof_Program_t));
	profile->modules = prof_HashCreate(PROF_HASH_STRING_TYPE,
		PROF_HASH_VOID_PTR_TYPE);
	profile->prof_buff = (char *)&prof_ProfileBuff;
	profile->offset = 0;
	profile->write_mode = PROF_COUNT_OFFSETS;
	profile->cur_buf_pos = 0;

	return profile;
} /* prof_ProgCreate */

prof_ModulesTable_t *
prof_ProgGetModules(const prof_Program_t *profile)
{
	return profile->modules;
} /* prof_ProgGetModules */

void
prof_ProgDestroy(prof_Program_t *profile)
{
	prof_HashForEachEntry(prof_ProgGetModules(profile),
		(void (*)(void *)) prof_ModuleDestroy);
	prof_HashDestroy(prof_ProgGetModules(profile));
	prof_Free(profile);
} /* prof_ProgDestroy */

prof_Module_t *
prof_ProgFindModule(
	const prof_Program_t *profile,
	const char *module_name)
{
	prof_Module_t *module;

	module = prof_HashFindByStringAndGetVoidPtrValue(
		prof_ProgGetModules(profile),
		module_name);

	return module;
} /* prof_ProgFindModule */

prof_Module_t *
prof_ProgFindOrCreateModule(
	prof_Program_t *profile,
	const char *module_name)
{
	prof_Module_t *module;

	module = prof_ProgFindModule(profile, module_name);

	if (module == NULL) {
		module = prof_ModuleCreate(module_name);
		prof_HashAddVoidPtrValueByString(prof_ProgGetModules(profile),
			prof_ModuleGetName(module),
			module);
	}

	return module;
} /* prof_ProgFindOrCreateModule */

prof_UInt_t
prof_ProgGetNumModules(const prof_Program_t *profile)
{
	return prof_HashGetElementNum(profile->modules);
} /* prof_ProgGetNumModules */


/*********************************** prof_Program_t **************************/

/******************************* prof_profilert.c ****************************/


/*****************************************************************************/
/********************************* prof_librt.c ******************************/
/*****************************************************************************/

#ifdef ECOMP_SUPPORT_INTERNAL_CHECK
#define PROF_DEBUG
#endif /* ECOMP_SUPPORT_INTERNAL_CHECK */

static prof_Program_t *prof_ProgramProfile = NULL;


/* #define PROF_DEBUG */

#ifdef PROF_DEBUG

static prof_Bool_t prof_IsDebugSave = PROF_FALSE;

static prof_Bool_t prof_IsDebugRuntime = PROF_FALSE;

#define prof_DebugRuntime(actions) \
{ \
	if (prof_IsDebugRuntime) { \
		actions; \
	} \
} /* prof_DebugRuntime */

#define prof_DebugSave(actions) \
{ \
	if (prof_IsDebugSave) { \
		actions; \
	} \
} /* prof_DebugSave */

#else /* PROF_DEBUG */
#define prof_DebugSave(action)
#define prof_DebugRuntime(actions)
#endif /* PROF_DEBUG */

static void
prof_IncrOffset(prof_UInt_t off)
{
	prof_ProgramProfile->offset += off;
} /* prof_IncrOffset */

static prof_UInt_t
prof_GetCurrentOffset(void)
{
	return prof_ProgramProfile->offset;
} /* prof_GetCurrentOffset */

static void
prof_IncrCurBufPos(void)
{
	prof_ProgramProfile->cur_buf_pos++;
} /* prof_IncrCurBufPos */

static prof_UInt_t
prof_GetCurrentBufPos(void)
{
	return prof_ProgramProfile->cur_buf_pos;
} /* prof_GetCurrentBufPos */

static void
prof_Write(
	const char *buf,
	size_t nbyte)
{
	int i;

	for (i = 0; i < nbyte; i++) {
		prof_ProgramProfile->prof_buff[prof_GetCurrentBufPos()] =
			buf[i];
		prof_IncrCurBufPos();
	}
} /* prof_Write */

static void
prof_DumpUInt(
	int file_descr,
	prof_UInt_t val)
{
	if (prof_ProgramProfile->write_mode == PROF_WRITE_OFFSETS) {
		prof_UInt_t	temp;
		unsigned char uint_arr[PROF_BYTES_IN_UINT];
		int i;

		temp = val;
		for (i = 0; i < PROF_BYTES_IN_UINT; i++) {
			val >>= PROF_BITS_IN_BYTE;
			uint_arr[i] = temp - (val << PROF_BITS_IN_BYTE);
			temp = val;
		}

		prof_Write((char *)uint_arr, PROF_BYTES_IN_UINT);
	} else {
		prof_IncrOffset(PROF_BYTES_IN_UINT);

	}
} /* prof_DumpUInt */

static void
prof_DumpUInt64(
	int file_descr,
	prof_UInt64_t val)
{
	if (prof_ProgramProfile->write_mode == PROF_WRITE_OFFSETS) {
		prof_UInt64_t temp;
		unsigned char uint64_arr[PROF_BYTES_IN_UINT64];
		int i;

		temp = val;
		for (i = 0; i < PROF_BYTES_IN_UINT64; i++) {
			val = val >> PROF_BITS_IN_BYTE;
			uint64_arr[i] = temp - (val << PROF_BITS_IN_BYTE);
			temp = val;
		}

		prof_Write((char *)uint64_arr, PROF_BYTES_IN_UINT64);
	} else {
		prof_IncrOffset(PROF_BYTES_IN_UINT64);
	}
} /* prof_DumpUInt64 */

static void
prof_DumpString(
	int	file_descr,
	const char *out_string,
	size_t size)
{
	if (prof_ProgramProfile->write_mode == PROF_WRITE_OFFSETS)
		prof_Write(out_string, size);
	else
		prof_IncrOffset(size);
} /* prof_DumpString */

static void
prof_DumpProgramHeader(
	prof_Program_t *program_profile,
	int file_descript)
{
	prof_DumpString(file_descript,
		PROF_FILE_IDEN_STR_C,
		PROF_FILE_IDEN_LEN);
	prof_DumpUInt(file_descript, prof_ProgGetNumModules(program_profile));
	prof_DumpUInt(file_descript, 0);
	prof_DumpUInt(file_descript, 0);
} /* prof_DumpProgramHeader */

static void
prof_DumpModuleHeader(
	prof_Module_t *module_p,
	int fd)
{
	int name_len;

	name_len = strlen(prof_ModuleGetName(module_p)) + 1;
	prof_DumpUInt(fd, name_len);
	prof_DumpString(fd, prof_ModuleGetName(module_p), name_len);
	prof_DumpUInt(fd, prof_ModuleGetNumFunctions(module_p));
	prof_DumpUInt(fd, (prof_UInt_t)prof_ModuleGetOffset(module_p));
} /* prof_DumpModuleHeader */

static void
prof_DumpFuncHeader(
	prof_Func_t	*func_p,
	int fd)
{
	prof_FuncAttr_t attr;
	int name_len;

	prof_DebugSave(
		pr_info("prof_debug_save: Start writing proc '%s' header:\n",
		prof_FuncGetName(func_p)));

	name_len = strlen(prof_FuncGetName(func_p)) + 1;
	prof_DebugSave(
		pr_info("prof_debug_save: Saving name len: %d\n",
		name_len));
	prof_DumpUInt(fd, name_len);
	prof_DumpString(fd, prof_FuncGetName(func_p), name_len);

	attr = prof_FuncGetAttr(func_p);
	prof_DebugSave(
		pr_info("prof_debug_save: Saving attr:");
		pr_info("%s", (attr & PROF_FUNC_ATTR_EDGES) ?
				" PROF_FUNC_ATTR_EDGES" : "");
		pr_info("%s", (attr & PROF_FUNC_ATTR_LOOPS) ?
				" PROF_FUNC_ATTR_LOOPS" : "");
		pr_info("%s", (attr & PROF_FUNC_ATTR_VALUE_PROF) ?
				" PROF_FUNC_ATTR_VALUE_PROF" : "");
		pr_info("%s", (attr & PROF_FUNC_ATTR_LOOPSOUTER) ?
				" PROF_FUNC_ATTR_LOOPSOUTER" : "");
		pr_info("\n"));
	prof_DumpUInt(fd, attr);

	prof_DebugSave(
		pr_info("prof_debug_save: Saving edges_in_file: %ld\n",
		(long)func_p->edges_in_file));
	prof_DumpUInt(fd, func_p->edges_in_file);

	/* out max number of edges */
	prof_DebugSave(
		pr_info("prof_debug_save: Saving num_edges: %u\n",
		prof_FuncGetNumEdges(func_p)));
	prof_DumpUInt(fd, prof_FuncGetNumEdges(func_p));

	/* out real number of edges */
	prof_DebugSave(
		pr_info("prof_debug_save: Saving out_num_edges: %u\n",
		prof_FuncGetDumpedEdgesNum(func_p)));
	prof_DumpUInt(fd, prof_FuncGetDumpedEdgesNum(func_p));

	prof_DumpUInt(fd, 0); /* stub for loops profile */

	/* out max number of loops */
	prof_DumpUInt(fd, 0); /* stub for loop profile */

	prof_DumpUInt(fd, 0);
	prof_DumpUInt(fd, 0);

	prof_DumpUInt(fd, 0);
	prof_DumpUInt(fd, 0);

	prof_DebugSave(
		pr_info("prof_debug_save: Saving cfg_checksum: %u\n",
		prof_FuncGetChecksum(func_p)));
	prof_DumpUInt(fd, prof_FuncGetChecksum(func_p));

	prof_DebugSave(
		pr_info("prof_debug_save: Saving is_excluded: %u\n",
		func_p->is_excluded));
	prof_DumpUInt(fd, func_p->is_excluded);
	prof_DumpUInt(fd, 0);

	prof_DumpUInt(fd, 0);
	prof_DumpUInt(fd, 0);
	prof_DumpUInt(fd, 0);

	prof_DebugSave(
		pr_info("prof_debug_save: Finish writing proc '%s' header:\n\n\n",
			func_p->name));
} /* prof_DumpFuncHeader */

static void
prof_DumpEdgeProfile(
	prof_Func_t *func_p,
	int fd)
{
	prof_UInt_t edge_number, index;

	prof_FuncSetDumpedEdgesNum(func_p, 0);
	edge_number = prof_FuncGetNumEdges(func_p);

	for (index = 0; index < edge_number; index++) {
		prof_UInt64_t	   counter;

		counter = prof_FuncGetEdgeCounter(func_p, index);

		if (counter == 0 ||
			counter == -1) {
			continue;
		}

		prof_DebugSave(
			pr_info("prof_debug_save: Saving edge %d counter %llu\n",
				index, counter));

		prof_DumpUInt(fd, index);
		prof_DumpUInt64(fd, counter);
		prof_FuncIncrDumpedEdges(func_p);
	}

PROF_ASSERT(prof_FuncGetNumEdges(func_p) >= prof_FuncGetDumpedEdgesNum(func_p));
} /* prof_DumpEdgeProfile */

static void
prof_DumpFuncProfile(
	prof_Func_t *func_p,
	int fd)
{
	prof_FuncAttr_t func_attr = prof_FuncGetAttr(func_p);

	prof_DebugSave(
		pr_info("\n\nprof_debug_save: Start writing proc '%s' profile:\n",
			prof_FuncGetName(func_p)));

	func_p->edges_in_file = prof_GetCurrentOffset();

	if (func_attr & PROF_FUNC_ATTR_EDGES) {
		prof_DebugSave(
			pr_info("prof_debug_save: Saving edge counters\n"));

		prof_DumpEdgeProfile(func_p, fd);
	}

	prof_DebugSave(
		pr_info("prof_debug_save: Finish writing proc '%s' profile\n\n",
			prof_FuncGetName(func_p)));
} /* prof_DumpFuncProfile */

static void
prof_DumpModuleProfile(
	prof_Module_t *module_p,
	int fd)
{
	prof_HashTable_t *tbl;
	prof_HashEntry_t *proc_entry;
	void *func_p;

	prof_ModuleSetOffset(module_p, prof_GetCurrentOffset());
	PROF_ASSERT(module_p->procedures != 0);
	tbl = prof_ModuleFunctions(module_p);

	for (PROF_HASH_ALL_ENTRIES(proc_entry, tbl)) {
		func_p = prof_HashGetEntryVoidPtrVal(proc_entry);
		prof_DumpFuncHeader(func_p, fd);
	}

	for (PROF_HASH_ALL_ENTRIES(proc_entry, tbl)) {
		func_p = prof_HashGetEntryVoidPtrVal(proc_entry);
		prof_DumpFuncProfile(func_p, fd);
	}

} /* prof_DumpModuleProfile */

/**
 * Set counter increment to 0
 */
static void
prof_MakeIncrStepZero(void)
{
	ecomp_ProfileIncrement = 0;
} /* prof_MakeIncrStepZero */

/**
 * Set counter increment to 1
 */
void
prof_MakeIncrStepOne(void)
{
	ecomp_ProfileIncrement = 1;
} /* prof_MakeIncrStepOne */

/**
 * Clear buffer and variables for profile repeated dump
 */
static void
prof_ClearBuffer(void)
{
	int i;

	save_first_time = true;

	prof_ProgramProfile->offset = 0;
	prof_ProgramProfile->write_mode = PROF_COUNT_OFFSETS;
	prof_ProgramProfile->cur_buf_pos = 0;

	for (i = 0; i < prof_BuffSize; i++)
		prof_ProfileBuff[i] = 0;
} /* prof_ClearBuffer */

void
PROF_SAVE_FILE(prof_Program_t *program_profile)
{
	int fd = 0;
	prof_ModulesTable_t *tbl;
	prof_ModulesEntry_t *entry;

	if (!save_first_time) {
		/**
		 * Fixed disagreeable effect of multiple entrer in this
		 * function. It should be entered only once
		 */
		return;
	}

	save_first_time = false;
	prof_MakeIncrStepZero();
	prof_ProgramProfile->offset = 0;
	prof_ProgramProfile->write_mode = PROF_COUNT_OFFSETS;
	prof_ProgramProfile->cur_buf_pos = 0;
	prof_ClearBuffer();

	prof_DebugSave(
		pr_info("prof_debug_save: Start saving program header\n"));
	prof_DumpProgramHeader(program_profile, fd);
	prof_DebugSave(
		pr_info("prof_debug_save: Finish saving program header\n"));
	tbl = prof_ProgGetModules(program_profile);

	for (PROF_HASH_ALL_ENTRIES(entry, tbl))
		prof_DumpModuleHeader(prof_HashGetEntryVoidPtrVal(entry), fd);

	for (PROF_HASH_ALL_ENTRIES(entry, tbl))
		prof_DumpModuleProfile(prof_HashGetEntryVoidPtrVal(entry), fd);

	prof_ProgramProfile->write_mode = PROF_WRITE_OFFSETS;

	prof_DebugSave(
		pr_info("prof_debug_save: Start saving program header\n"));
	prof_DumpProgramHeader(program_profile, fd);
	prof_DebugSave(
		pr_info("prof_debug_save: Finish saving program header\n"));

	prof_DebugSave(
		pr_info("prof_debug_save: Start saving module headers\n"));
	for (PROF_HASH_ALL_ENTRIES(entry, tbl))
		prof_DumpModuleHeader(prof_HashGetEntryVoidPtrVal(entry), fd);
	prof_DebugSave(
		pr_info("prof_debug_save: Finish saving module headers\n"));

	prof_DebugSave(
		pr_info("prof_debug_save: Start saving counters\n"));
	/* TODO save pointers in file for functions */
	for (PROF_HASH_ALL_ENTRIES(entry, tbl))
		prof_DumpModuleProfile(prof_HashGetEntryVoidPtrVal(entry), fd);
	prof_DebugSave(
		pr_info("prof_debug_save: Finish saving counters\n"));
} /* PROF_SAVE_FILE */

/**
 * Dump of buffer into file
 */
static void
prof_DumpFile(struct seq_file *s) /* File descriptor */
{
	seq_write(s, prof_ProgramProfile->prof_buff, prof_GetCurrentBufPos());
} /* prof_DumpFile */

void
__BUILTIN_ecomp_prof_RegProcSTDN(
	const char	  *module_name,
	const char	  *proc_name,
	prof_FuncAttr_t func_attr,
	prof_UInt_t	   cfg_checksum,
	prof_UInt_t	   edges,
	prof_UInt_t	   edges_comdat,
	prof_UInt64_t *edge_counters,
	prof_UInt_t	   loops,
	prof_UInt_t	   outer_loops,
	prof_UInt_t	   outer_outer_loops,
	prof_UInt64_t **loop_numbers,
	prof_UInt64_t **loop_counters,
	void		  *loop_outer_counters,
	void		  *loop_outer_outer_counters,
	prof_UInt_t	   prof_opers_num,
	void		  *vprof_counters,
	prof_Bool_t	   is_excluded)
{
	prof_Module_t *module_p;
	prof_Func_t	*func_p;

	prof_DebugRuntime(
		pr_info("\n\nprof_IsDebugRuntime: ");
		pr_info("Start proc '%s' from module '%s' registration\n",
			proc_name, module_name));

	/* Disable profiling of weak/comdat functions, that were dropped at link time and
	 * have different body compared to winner function (bug 138595) */
	if (!is_excluded && edges_comdat != edges)
		is_excluded = PROF_TRUE;

	module_p = prof_ProgFindOrCreateModule(prof_ProgramProfile,
		module_name);
	func_p = prof_HashFindByStringAndGetVoidPtrValue(module_p->procedures,
		proc_name);
	if (func_p != NULL) {
		/* There are two functions with equal names, equal code and equal module name.
		 * Profiler cannot distinguish them, so we simply disable profiling */
		func_p->is_excluded = PROF_TRUE;
		return;
	}

	prof_DebugRuntime(
		pr_info("prof_IsDebugRuntime: Creating new object for proc '%s' with checksum %u\n",
			proc_name, cfg_checksum);
		pr_info("prof_IsDebugRuntime: Proc attr");
		pr_info("%s", (func_attr & PROF_FUNC_ATTR_EDGES) ?
				" PROF_FUNC_ATTR_EDGES" : "");
		pr_info("%s", (func_attr & PROF_FUNC_ATTR_LOOPS) ?
				" PROF_FUNC_ATTR_LOOPS" : "");
		pr_info("%s", (func_attr & PROF_FUNC_ATTR_VALUE_PROF) ?
				" PROF_FUNC_ATTR_VALUE_PROF" : "");
		pr_info("%s", (func_attr & PROF_FUNC_ATTR_LOOPSOUTER) ?
				" PROF_FUNC_ATTR_LOOPSOUTER" : "");
		pr_info("\n"));

	func_p = prof_ModuleFindOrCreateFunction(module_p, proc_name,
			func_attr, edges, loops, outer_loops,
			outer_outer_loops, cfg_checksum,
			prof_opers_num);

	func_p->edge_counters = (prof_UInt64_t *) edge_counters;
	func_p->is_excluded = is_excluded;
	prof_FuncSetChecksum(func_p, cfg_checksum);

	prof_DebugRuntime(
		pr_info("\nprof_IsDebugRuntime: Finish proc '%s' from module '%s' registration\n\n",
			proc_name, module_name));
} /* __BUILTIN_ecomp_prof_RegProcSTDN_lib */
EXPORT_SYMBOL(__BUILTIN_ecomp_prof_RegProcSTDN);

void
__BUILTIN_ecomp_prof_CreateProfileObj(
	prof_Bool_t	is_vprof,
	prof_Bool_t	is_parallel, /* STUB */
	const char *path)
{
	if (prof_ProgramProfile != NULL)
		return;

	prof_DebugRuntime(
		pr_info("prof_IsDebugRuntime: Using value profile: %s\n",
			(is_vprof) ? "YES" : "NO"));

	prof_ProgramProfile = prof_ProgCreate(is_vprof);
} /* __BUILTIN_ecomp_prof_CreateProfileObj */
EXPORT_SYMBOL(__BUILTIN_ecomp_prof_CreateProfileObj);

void
__BUILTIN_prof_PrintModuleInited(const char *module_name)
{
	prof_DebugRuntime(pr_info(" .	 Module inited %s!!!\n", module_name));
} /* __BUILTIN_prof_PrintModuleInited */

void
__BUILTIN_ecomp_prof_AtomicAdd64(prof_UInt64_t *res)
{
	atomic64_add(ecomp_ProfileIncrement, (atomic64_t *)res);
} /* __BUILTIN_ecomp_prof_AtomicAdd64 */
EXPORT_SYMBOL(__BUILTIN_ecomp_prof_AtomicAdd64);

/********************************* prof_librt.c ******************************/


static int profile_seq_show(struct seq_file *s, void *v)
{
	int num = *((loff_t *) v);

	if (num >= profile_counters_num)
		return 0;

	prof_DumpFile(s);

	return 0;
}

static void *profile_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= profile_counters_num)
		return 0;

	PROF_SAVE_FILE(prof_ProgramProfile);

	return (void *) pos;
}

static void *profile_seq_next(
	struct seq_file *s,
	void *v,
	loff_t *pos)
{
	if ((*pos)++ >= profile_counters_num)
		return 0;
	return (void *) pos;
}

static void profile_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations profile_seq_ops = {
	.start = profile_seq_start,
	.next = profile_seq_next,
	.stop = profile_seq_stop,
	.show = profile_seq_show
};

static int profile_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &profile_seq_ops);
}

static ssize_t profile_write(
	struct file *file,
	const char __user *buf,
	size_t count,
	loff_t *data)
{
	prof_ClearBuffer();

	return count;
}

static const struct proc_ops profile_proc_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_open = profile_proc_open,
	.proc_write = profile_write,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release
};

static int __init kernel_profile_init(void)
{
	proc_create(PROFILE_FILENAME, S_IRUGO | S_IWUSR,
			NULL, &profile_proc_fops);
	return 0;
}

module_init(kernel_profile_init);

