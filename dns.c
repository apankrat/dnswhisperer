/*
 *	The code is distributed under terms of the BSD license.
 *	Copyright (c) 2016 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/bsd-license
 */

#include "dns.h"

#include "byte_range.h"
#include <stdlib.h>

static
int parse_question(byte_range * buf, dns_question * q)
{
	byte_range name;
	uint8_t * name_org;
	uint8_t len;

	memset(q, 0, sizeof(*q));
	
	name_org = (uint8_t*)q->name;
	name.ptr = name_org;
	name.end = name_org + sizeof(q->name);

	for (;;)
	{
		if (buf->ptr == buf->end)
			return -1;

		len = *buf->ptr++;
		if (len == 0)
			break;

		if (buf->ptr + len > buf->end)
			return -1;

		if (name.ptr + len + 2 > name.end) /* +2 is for \0 and . */
			return -1;

		if (name.ptr > name_org)
			*name.ptr++ = '.';

		memcpy(name.ptr, buf->ptr, len);
		name.ptr += len;
		buf->ptr += len;
	}
	*name.ptr = 0;

	/*
	 *
	 */
	name.end = name.ptr;
	name.ptr = name_org;
	br_to_lower(&name);

	/*
	 *
	 */
	if (buf->ptr + 4 > buf->end)
		return -1;

	q->qt = htons( *(uint16_t*)buf->ptr );
	q->qc = htons( *(uint16_t*)(buf->ptr+2) );

	buf->ptr += 4;
	return 0;
}

int dns_get_question(const dns_header * hdr, size_t len, size_t q_index, dns_question * q)
{
	byte_range buf;

	if (q_index >= hdr->qcount || len < sizeof(*hdr))
		return -1;

	buf.ptr = (uint8_t *)hdr;
	buf.end = buf.ptr + len;

	buf.ptr += sizeof(*hdr);
	do
	{
		if (parse_question(&buf, q) < 0)
			return -1;
	}
	while (q_index--);

	return 0;
}

