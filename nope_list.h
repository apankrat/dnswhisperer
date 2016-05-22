/*
 *	The code is distributed under terms of the BSD license.
 *	Copyright (c) 2016 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/bsd-license
 */

#ifndef _NOPE_LIST_H_
#define _NOPE_LIST_H_

#include <stddef.h>
#include "byte_range.h"

typedef struct nope_list
{
	byte_range   raw;   /* .txt as is */
	size_t       size;
	byte_range * items; /* an array of (size) */

} nope_list;

/*
 *
 */
nope_list  * load_nope_list(const char * filename, size_t max_size);
void free_nope_list(nope_list * nl);

byte_range * match_nope_list(nope_list * nl, const char * what);

#endif

