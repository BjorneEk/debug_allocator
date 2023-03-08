/*==========================================================*
 *
 * @author Gustaf Franzén :: https://github.com/BjorneEk;
 *
 * memory leak debugger
 *
 *==========================================================*/

#ifndef _DEBUG_ALLOC_H_
#define _DEBUG_ALLOC_H_

#include "types.h"
#include "debug_enable.h"
#include <stdlib.h>
#include <stdbool.h>


#define DEFAULT_MAP_LEN 0xFFF

void debug_alloc_init_size(u64_t size);

void debug_alloc_init();

void debug_alloc_use_hash(u64_t (*hf)(u64_t));

void debug_alloc_finnish(bool print_ptrs);

#ifdef DEBUG
void	*malloc(size_t size);
void	*calloc(size_t num, size_t size);
void	free (void* ptr);
void	*realloc (void* ptr, size_t size);
#endif /*DEBUG*/

#endif /* _DEBUG_ALLOC_H_ */