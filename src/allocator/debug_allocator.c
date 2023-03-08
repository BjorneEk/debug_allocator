/*==========================================================*
 *
 * @author Gustaf Franzén :: https://github.com/BjorneEk;
 *
 * memory leak debugger
 *
 *==========================================================*/
#include "debug_allocator.h"
#include "types.h"
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#define LIB_NAME "Debug Allocator"


typedef void	*(*malloc_f)(size_t);
typedef void	*(*calloc_f)(size_t, size_t);
typedef void	*(*realloc_f)(void*, size_t);
typedef void	(*free_f)(void*);

typedef u64_t	(*hash_f)(u64_t);


struct bucket {
	u64_t hash;

	/* dereferenced pointer */
	u64_t key;

	/* size allocated on pointer */
	size_t value;

	struct bucket *next;
};

typedef struct memmap {

	struct bucket *buckets;

	u64_t len;

	u64_t n_buckets;

} memmap_t;

u64_t 			HASH_fnv_1a(u64_t ptr);
static memmap_t 	*new_map(u64_t len);
static bool 		map_contins_key(memmap_t *m, u64_t key);
static void 		map_remove(memmap_t *m, u64_t key);
static u64_t 		map_get(memmap_t *m, u64_t key);
static void		map_add(memmap_t *m, u64_t key, u64_t value);
static void		map_free(memmap_t **m);
static void		print_map(memmap_t *m);
static struct bucket	*get_bucket(memmap_t *m, u64_t key);

#define COLOR_BRIGHT_BLACK	"\033[30;1;4m"
#define COLOR_BRIGHT_RED	"\033[31;1;4m"
#define COLOR_BRIGHT_GREEN	"\033[32;1;4m"
#define COLOR_BRIGHT_YELLOW	"\033[33;1;4m"
#define COLOR_BRIGHT_BLUE	"\033[34;1;4m"

#define COLOR_BLACK		"\033[30m"
#define COLOR_RED		"\033[31m"
#define COLOR_GREEN		"\033[32m"
#define COLOR_YELLOW		"\033[33m"
#define COLOR_BLUE		"\033[34m"
#define COLOR_NONE		"\033[0m"

static hash_f hash_function = HASH_fnv_1a;

static struct {
	memmap_t *memmap;
	u64_t allocated_bytes;
	u64_t deallocated_bytes;
	u64_t max_allocations;
	u64_t total_allocations;
} ctx;


static inline void fprint_color(FILE *file, const char *restrict str, const char *clr)
{
	fprintf(file, "%s%s" COLOR_NONE, clr, str);
}

static void warn(const char * restrict fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	fprint_color(stdout, LIB_NAME, COLOR_BLUE);
	printf(":\n");
	printf("[");
	fprint_color(stdout, "Warning", COLOR_BRIGHT_YELLOW);
	printf("]");
	printf(": ");
	vprintf(fmt, args);
	printf("\n");
}

static void error(const char * restrict fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	fprint_color(stderr, LIB_NAME, COLOR_BLUE);
	fprintf(stderr, ":\n");
	fprintf(stderr, "[");
	fprint_color(stderr, "Error", COLOR_BRIGHT_RED);
	fprintf(stderr, "]");
	fprintf(stderr, ": ");
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
}

#define SYSTEM_FUNC_DECL(_func)				\
static inline						\
const _func##_f SYSTEM_##_func()			\
{							\
	return (_func##_f) dlsym(RTLD_NEXT, #_func);	\
}

SYSTEM_FUNC_DECL(malloc)
SYSTEM_FUNC_DECL(calloc)
SYSTEM_FUNC_DECL(free)
SYSTEM_FUNC_DECL(realloc)

void debug_alloc_use_hash(hash_f hf)
{
	hash_function = hf;
}

void debug_alloc_init_size(u64_t size)
{
#ifndef DEBUG
	warn("\"DEBUG\" not defined, %s will not work", LIB_NAME);
#else
	ctx.memmap = new_map(size);
	ctx.allocated_bytes = 0;
	ctx.deallocated_bytes = 0;
	ctx.total_allocations = 0;
	ctx.max_allocations = 0;
	printf("\n%s%s%s: Initialized, optimized for < %i active pointers\n\n",
	COLOR_BRIGHT_BLUE, LIB_NAME, COLOR_NONE, DEFAULT_MAP_LEN);
#endif /*DEBUG*/
}

void debug_alloc_init()
{
	debug_alloc_init_size(DEFAULT_MAP_LEN);
}

void debug_alloc_finnish(bool print_ptrs)
{
#ifndef DEBUG
	warn("\"DEBUG\" not defined, no output generated");
#else
	if(ctx.allocated_bytes != ctx.deallocated_bytes && print_ptrs) {
		printf("	---%s%s%s---\n\n", COLOR_BRIGHT_BLUE, LIB_NAME, COLOR_NONE);
		printf("%sStill allocated%s: %llu pointers, total %llu bytes\n", COLOR_BRIGHT_RED,
			COLOR_NONE, ctx.memmap->n_buckets, ctx.allocated_bytes - ctx.deallocated_bytes);
		printf("\e[1m|Address		|Bytes	|\e[m\n");
		print_map(ctx.memmap);
		printf("\n");
	}
	printf("%sTotal allocations%s:	%llu\n", COLOR_BRIGHT_YELLOW, COLOR_NONE, ctx.total_allocations);
	printf("%sMax allocations%s:	%llu	(max number of heap allocated pointers active at a single moment. "
		"init size should be larger that this number for optimal performance)\n\n",
		COLOR_BRIGHT_YELLOW, COLOR_NONE, ctx.max_allocations);
	if(ctx.allocated_bytes != ctx.deallocated_bytes) {
		printf("	---%sSummary%s---\n\n", COLOR_BRIGHT_BLUE, COLOR_NONE);
		printf("%sBytes allocated%s:	%lli\n", COLOR_BRIGHT_YELLOW, COLOR_NONE, ctx.allocated_bytes);
		printf("%sBytes deallocated%s:	%s%lli%s\n\n", COLOR_BRIGHT_YELLOW, COLOR_NONE,
		COLOR_BRIGHT_RED, ctx.deallocated_bytes, COLOR_NONE);
		printf("%sMemory leak%s:	%llu bytes\n\n", COLOR_BRIGHT_RED, COLOR_NONE,
		ctx.allocated_bytes - ctx.deallocated_bytes);
	} else {
		printf("	---%sSummary%s---\n\n", COLOR_BRIGHT_BLUE, COLOR_NONE);
		printf("%sBytes allocated%s:	%lli\n", COLOR_BRIGHT_YELLOW, COLOR_NONE, ctx.allocated_bytes);
		printf("%sBytes deallocated%s:	%s%lli%s\n\n", COLOR_BRIGHT_YELLOW, COLOR_NONE,
			COLOR_BRIGHT_GREEN, ctx.deallocated_bytes, COLOR_NONE);
		printf("%sNo memory leaks!%s\n\n", COLOR_GREEN, COLOR_NONE);
	}

	map_free(&ctx.memmap);
#endif /* DEBUG */
}

#ifdef DEBUG


void	*malloc(size_t size)
{
	void *res;

	res = SYSTEM_malloc()(size);
	ctx.allocated_bytes += size;

	map_add(ctx.memmap, *((u64_t*)&res), size);
	//printf("malloc(%zu) -> 0x%llx\n", size, *((u64_t*)&res));
	++ctx.total_allocations;
	if (ctx.memmap->n_buckets > ctx.max_allocations)
		ctx.max_allocations = ctx.memmap->n_buckets;
	return res;
}

void	*calloc(size_t num, size_t size)
{
	void *res;

	res = SYSTEM_calloc()(num, size);

	map_add(ctx.memmap, *((u64_t*)&res), (u64_t)size * (u64_t)num);
	//printf("calloc(%zu %zu) -> 0x%llx\n", num, size, *((u64_t*)&res));
	++ctx.total_allocations;
	if (ctx.memmap->n_buckets > ctx.max_allocations)
		ctx.max_allocations = ctx.memmap->n_buckets;
	return res;
}

void	free (void* ptr)
{
	if (map_contins_key(ctx.memmap, *((u64_t*)&ptr))) {
		ctx.deallocated_bytes += map_get(ctx.memmap, *((u64_t*)&ptr));
		map_remove(ctx.memmap, *((u64_t*)&ptr));
		//printf("free(0x%llx)\n",*((u64_t*)&ptr));
		SYSTEM_free()(ptr);
	} else {
		error("Pointer being freed was not allocated 0x%llx", *((u64_t*)&ptr));
	}
}

void	*realloc(void* ptr, size_t size)
{
	void *res;
	u64_t org;
	struct bucket *b;

	org = *((u64_t*)&ptr);
	b = ptr ? get_bucket(ctx.memmap, org) : NULL;

	res = SYSTEM_realloc()(ptr, size);

	//printf("realloc(0x%llx, %zu) -> 0x%llx\n",*((u64_t*)&ptr), size, *((u64_t*)&res));

	if (b && *((u64_t*)&res) == org) {
		if(size > b->value)
			ctx.allocated_bytes += size - b->value;
		else
			ctx.deallocated_bytes += b->value - size;
		b->value = size;
	} else if (b) {
		ctx.deallocated_bytes += b->value;
		ctx.allocated_bytes += size;
		map_remove(ctx.memmap, org);
		map_add(ctx.memmap, *((u64_t*)&res), size);
	} else {
		ctx.allocated_bytes += size;
		map_add(ctx.memmap, *((u64_t*)&res), size);
	}
	++ctx.total_allocations;
	if (ctx.memmap->n_buckets > ctx.max_allocations)
		ctx.max_allocations = ctx.memmap->n_buckets;
	return res;
}


#endif /*DEBUG*/

static void print_bucket(struct bucket *b)
{
	printf("\e[1m|%s0x%016llx%s	\e[1m|%s%zu%s	\e[1m|%s\n",COLOR_GREEN,
	b->key, COLOR_NONE, COLOR_YELLOW, b->value, COLOR_NONE, COLOR_NONE);
}

static void print_map(memmap_t *m)
{
	i32_t i;
	struct bucket *b;

	for(i = 0; i < m->len; i++) {
		b = &m->buckets[i];
		if(b->hash != 0 && b->value != 0) {
			do {
				print_bucket(b);
				b = b->next;
			} while (b != NULL);
		}
	}
}

static memmap_t *new_map(u64_t len)
{
	memmap_t *res;

	res = SYSTEM_malloc()(sizeof(memmap_t));
	res->buckets = SYSTEM_calloc()(len, sizeof(struct bucket));
	res->n_buckets = 0;
	res->len = len;

	return res;
}

static u64_t hash_idx(memmap_t *m, u64_t key)
{
	return hash_function(key) % m->len;
}

static inline bool bucket_equals(u64_t hash, u64_t key, const struct bucket *b)
{
	return (hash == b->hash && b->key == key);
}

static struct bucket *get_bucket(memmap_t *m, u64_t key)
{
	struct bucket *b;
	u64_t hash;
	u64_t idx;


	hash = hash_function(key);
	idx = hash % m->len;
	b = &m->buckets[idx];

	do {
		if (bucket_equals(hash, key, b))
			return b;
	} while((b = b->next) != NULL);
	return NULL;
}

static bool map_contins_key(memmap_t *m, u64_t key)
{
	return get_bucket(m, key) != NULL;
}

static void map_remove(memmap_t *m, u64_t key)
{
	struct bucket *b, *tmp;
	u64_t hash;
	u64_t idx;


	hash = hash_function(key);
	idx = hash % m->len;
	b = &m->buckets[idx];
	--m->n_buckets;

	if(b->next == NULL && bucket_equals(hash, key, b)) {
		memset(b, 0, sizeof(struct bucket));
		return;
	} else if (bucket_equals(hash, key, b)) {
		tmp = b->next;
		memcpy(b, tmp, sizeof(struct bucket));
		SYSTEM_free()(tmp);
		return;
	}

	while (b->next != NULL) {

		if (bucket_equals(hash, key, b->next)) {
			tmp = b->next;
			b->next = b->next->next;
			SYSTEM_free()(tmp);
			return;
		}
		b = b->next;
	}
}

static u64_t map_get(memmap_t *m, u64_t key)
{
	struct bucket *entry;

	entry = get_bucket(m, key);

	if(entry == NULL)
		return 0;

	return entry->value;
}

static struct bucket new_bucket(memmap_t *m, u64_t key, u64_t value)
{
	struct bucket res;

	res.value	= value;
	res.key		= key;

	res.hash	= hash_function(key);
	res.next	= NULL;
	return res;
}

static struct bucket *new_bucket_ptr(memmap_t *m, u64_t key, u64_t value)
{
	struct bucket *res;

	res = SYSTEM_malloc()(sizeof(struct bucket));
	res->value	= value;
	res->key	= key;

	res->hash	= hash_function(key);
	res->next	= NULL;
	return res;
}

static void	map_add(memmap_t *m, u64_t key, u64_t value)
{
	u64_t i;
	struct bucket *b;

	++m->n_buckets;
	i = hash_idx(m, key);

	if(m->buckets[i].key == 0 && m->buckets[i].value == 0) {
		m->buckets[i] = new_bucket(m, key, value);
	} else {
		for(b = &m->buckets[i]; b->next != NULL; b = b->next)
			;
		b->next = new_bucket_ptr(m, key, value);
	}
}

static void free_bucket(struct bucket b)
{
	struct bucket *next, *tmp;

	next = b.next;

	while(next != NULL) {
		tmp = next;
		next = next->next;
		SYSTEM_free()(tmp);
	}
}

static void	map_free(memmap_t **m)
{
	u64_t i;

	for(i = 0; i < (*m)->len; i++)
		free_bucket((*m)->buckets[i]);
	SYSTEM_free()(*m);
}

u64_t HASH_fnv_1a(u64_t ptr)
{
	i64_t	i;
	u64_t	hash;
	u64_t	last;
	u8_t	data[8];

	hash	= 2166136261u;
	memcpy(data, &ptr, 8);

	hash ^=	(u64_t)data[0] << 0  | (u64_t)data[1] << 8  |
		(u64_t)data[2] << 16 | (u64_t)data[3] << 24 |
		(u64_t)data[4] << 32 | (u64_t)data[5] << 40 |
		(u64_t)data[6] << 48 | (u64_t)data[7] << 56;
	hash *= 0xbf58476d1ce4e5b9; /* FNV PRIME */

	last = sizeof(u64_t) & 0xff;

	last |= (u64_t)data[0] << 8;
		hash ^= last;
		hash *= 0xd6e8feb86659fd93; /* FNV PRIME */

	return hash ^ hash >> 32;
}
