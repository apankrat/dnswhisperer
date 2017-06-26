/*
 *	The code is distributed under terms of the BSD license.
 *	Copyright (c) 2016 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/bsd-license
 */

#ifndef _BYTE_RANGE_H_
#define _BYTE_RANGE_H_

#include <stdint.h>

typedef struct byte_range
{
	uint8_t * ptr;
	uint8_t * end;

} byte_range;

/*
 *
 */
void br_get_line(byte_range * buf, byte_range * line);
void br_trim(byte_range * line);
void br_to_lower(byte_range * blob);

/*
 *
 */
uint8_t br_front(const byte_range * br);
uint8_t br_back(const byte_range * br);

int br_compare(const byte_range * a, const byte_range * b);
const uint8_t * br_search(const byte_range * haystack, const byte_range * needle);

#endif

