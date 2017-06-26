/*
 *	The code is distributed under terms of the BSD license.
 *	Copyright (c) 2016 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/bsd-license
 */

#include "byte_range.h"

#include <ctype.h>
#include <stddef.h>

void br_get_line(byte_range * buf, byte_range * line)
{
	uint8_t * p;

	line->ptr = buf->ptr;

	for (p = line->ptr; p < buf->end; p++)
		if (*p == '\r' || *p == '\n')
			break;

	line->end = p;

	if (p+1 < buf->end && p[0] == '\r' && p[1] == '\n') /* \r\n */
		buf->ptr = p+2;
	else
	if (p < buf->end)
		buf->ptr = p+1;
	else
		buf->ptr = p;
}

void br_trim(byte_range * line)
{
	for ( ; line->ptr < line->end; line->ptr++)
		if (! isspace(line->ptr[0]))
			break;

	for ( ; line->ptr < line->end; line->end--)
		if (! isspace(line->end[-1]))
			break;
}

void br_to_lower(byte_range * blob)
{
	uint8_t * p;

	for (p = blob->ptr; p < blob->end; p++)
		*p = tolower(*p);
}

/*
 *
 */
uint8_t br_front(const byte_range * br)
{
	return (br->ptr < br->end) ? br->ptr[0] : 0;
}

uint8_t br_back(const byte_range * br)
{
	return (br->ptr < br->end) ? br->end[-1] : 0;
}

int br_compare(const byte_range * a, const byte_range * b)
{
	int r = (a->end - a->ptr) - (b->end - b->ptr);
	return r ? r : memcmp(a->ptr, b->ptr, a->end - a->ptr);
}

const uint8_t * br_search(const byte_range * haystack, const byte_range * needle)
{
	size_t haystack_len = haystack->end - haystack->ptr;
	size_t needle_len = needle->end - needle->ptr;
	size_t i, n;

	if (haystack_len < needle_len)
		return NULL;

	for (i=0, n=haystack_len-needle_len+1; i<n; i++)
		if (memcmp(haystack->ptr+i, needle->ptr, needle_len) == 0)
			return haystack->ptr+i;

	return NULL;
}

