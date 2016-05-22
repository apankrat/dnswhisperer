/*
 *	The code is distributed under terms of the BSD license.
 *	Copyright (c) 2016 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/bsd-license
 */

#include "nope_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

static
void * zalloc(size_t bytes)
{
	void * ptr = calloc(1, bytes);
	if (! ptr)
		printf("calloc(%u) failed\n", bytes);
	return ptr;
}

nope_list * load_nope_list(const char * filename, size_t max_size)
{
	nope_list * nl = NULL;
	const char * func;
	struct stat st;
	int fd = -1;
	int r;
	byte_range temp;
	size_t i;
	
	if (stat(filename, &st) < 0)
	{
		printf("stat(%s) failed with %d\n", filename, errno);
		goto err;
	}

	if (st.st_size > max_size)
	{
		printf("%s is too big\n", filename);
		goto err;
	}
	
	fd = open(filename, O_RDONLY);
	if (fd < 0)
	{
		printf("open(%s) failed with %d\n", filename, errno);
		goto err;
	}

	nl = zalloc(sizeof(*nl));
	if (! nl)
		goto err;

	nl->raw.ptr = zalloc(st.st_size);
	if (! nl->raw.ptr)
		goto err;

	r = read(fd, (void*)nl->raw.ptr, st.st_size);
	if (r != st.st_size)
	{
		printf("read(%s) returned %d, wanted %d\n", filename, r, st.st_size);
		goto err;
	}
	nl->raw.end = nl->raw.ptr + st.st_size;

	close(fd);
	fd = -1;

	/*
	 *
	 */
	for (temp = nl->raw; temp.ptr < temp.end; )
	{
		byte_range line;

		br_get_line(&temp, &line);
		if (line.ptr == line.end || line.ptr[0] == '#')
			continue;

		br_trim(&line);
		if (line.ptr == line.end)
			continue;

		nl->size++;
	}

	if (! nl->size)
	{
		printf("%s has no usable entries\n", filename);
		goto err;
	}

	nl->items = zalloc(sizeof(*nl->items) * nl->size);
	if (! nl->items)
		goto err;

	for (i = 0, temp = nl->raw; temp.ptr < temp.end; )
	{
		byte_range line;

		br_get_line(&temp, &line);
		if (line.ptr == line.end || line.ptr[0] == '#')
			continue;

		br_trim(&line);
		if (line.ptr == line.end)
			continue;

		nl->items[i++] = line;
	}

	return nl;

err:
	free_nope_list(nl);

	if (fd != -1)
		close(fd);

	return NULL;
}

void free_nope_list(nope_list * nl)
{
	if (! nl)
		return;

	free(nl->raw.ptr);
	free(nl->items);
	free(nl);
}

byte_range * match_nope_list(nope_list * nl, const char * _what)
{
	byte_range what;
	size_t i;

	what.ptr = (uint8_t*)_what;
	what.end = (uint8_t*)_what + strlen(_what);

	for (i=0; i<nl->size; i++)
		if (br_search(&what, nl->items+i))
			return nl->items+i;

	return NULL;
}
