/*==========================================================*
 *
 * @author Gustaf Franzén :: https://github.com/BjorneEk;
 *
 *==========================================================*/
#include <stdio.h>
#include <stdlib.h>
#define DEBUG
#include "allocator/debug_allocator.h"



int main(int argc, char const *argv[])
{
	int *arr;
	int i;
	debug_alloc_init();

	arr = malloc(20 * sizeof(int));

	for(i = 0; i < 20; i++)
		arr[i] = i*2;
	printf("\n");
	for(i = 0; i < 20; i++)
		printf("%i, ", arr[i]);
	printf("\n");

	arr = realloc(arr, 10 * sizeof(int));

	printf("\n");
	for(i = 0; i < 10; i++)
		printf("%i, ", arr[i]);
	printf("\n");
	//free(arr);
	debug_alloc_finnish(true);
}
