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
int parse_name(byte_range * buf, byte_range * name)
{
	uint8_t * name_org;
	uint8_t len;

	name_org = name->ptr;

	for (;;)
	{
		if (buf->ptr == buf->end)
			return -1;

		len = *buf->ptr++;
		if (len == 0)
			break;

		if ((len & 0xC0) == 0xC0)
		{
			if (buf->ptr + 1 > buf->end)
				return -1;

			buf->ptr++;
			break;
		}

		/*
		 *
		 */
		if (buf->ptr + len > buf->end)
			return -1;

		if (name->ptr + len + 2 > name->end) /* +2 is for \0 and . */
			return -1;

		if (name->ptr > name_org)
			*(name->ptr++) = '.';

		memcpy(name->ptr, buf->ptr, len);
		name->ptr += len;
		buf->ptr += len;
	}
	*(name->ptr) = 0;

	/*
	 *
	 */
	name->end = name->ptr;
	name->ptr = name_org;
	br_to_lower(name);

	return 0;
}

static
int parse_question(byte_range * buf, dns_question * q)
{
	byte_range name;

	memset(q, 0, sizeof(*q));

	/*
	 *
	 */
	name.ptr = q->name;
	name.end = q->name + sizeof(q->name);

	if (parse_name(buf, &name) < 0)
		return -1;

	/*
	 *
	 */
	if (buf->ptr + 4 > buf->end)
		return -1;

	q->type   = htons( *(uint16_t*)buf->ptr );
	q->class_ = htons( *(uint16_t*)(buf->ptr+2) );

	buf->ptr += 4;

	return 0;
}

static
int parse_rr(byte_range * buf, dns_rr * rr)
{
	byte_range name;

	memset(rr, 0, sizeof(*rr));

	/*
	 *
	 */
	name.ptr = rr->name;
	name.end = rr->name + sizeof(rr->name);

	if (parse_name(buf, &name) < 0)
		return -1;

	/*
	 *
	 */
	if (buf->ptr + 10 > buf->end)
		return -1;

	rr->type   = htons( *(uint16_t*)buf->ptr );
	rr->class_ = htons( *(uint16_t*)(buf->ptr+2) );
	rr->ttl    = htonl( *(uint32_t*)(buf->ptr+4) );
	rr->len    = htons( *(uint16_t*)(buf->ptr+8) );
	rr->data   = buf->ptr + 10;

	if (buf->ptr + 10 + rr->len > buf->end)
		return -1;

	buf->ptr += 10 + rr->len;
	return 0;
}

/*
 *
 */
int dns_get_question(const dns_header * hdr, size_t len, size_t q_index, dns_question * q)
{
	byte_range buf;
	size_t q_count;

	q_count = htons(hdr->qcount);

	if (q_index >= q_count || len < sizeof(*hdr))
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

int dns_get_answer(const dns_header * hdr, size_t len, size_t a_index, dns_rr * a)
{
	byte_range buf;
	dns_question foo;
	size_t i, q_count, a_count;;

	q_count = htons(hdr->qcount);
	a_count = htons(hdr->acount);

	if (a_index >= a_count || len < sizeof(*hdr))
		return -1;

	buf.ptr = (uint8_t *)hdr;
	buf.end = buf.ptr + len;

	buf.ptr += sizeof(*hdr);

	for (i = 0; i < q_count; i++)
		if (parse_question(&buf, &foo) < 0)
			return -1;

	do
	{
		if (parse_rr(&buf, a) < 0)
			return -1;
	}
	while (a_index--);

	return 0;
}

#if 0
void dump_dns_response(const dns_header * hdr, size_t len)
{
	size_t i, q_count, a_count;

	q_count = htons(hdr->qcount);
	a_count = htons(hdr->acount);

	printf("\n");
	for (i=0; i<len; i++)
	{
		printf("%02x ", 0xff & *(i + (char*)hdr));
		if ((i & 0xf) == 0xf)
			printf("\n");
	}

	printf("\n");

	printf("ID        0x%04hx\n", htons(hdr->id));
	printf("flags     0x%04hx\n", htons(hdr->flags));
	printf("q_count   %u\n", q_count);
	printf("a_count   %u\n", a_count);
	printf("ns_count  %hu\n", htons(hdr->nscount));
	printf("ar_count  %hu\n", htons(hdr->arcount));

	for (i=0; i < q_count; i++)
	{
		dns_question q;
		if (dns_get_question(hdr, len, i, &q) < 0)
		{
			printf("Failed to parse Q[%u]\n", i);
			return;
		}

		printf("\n   Q%u\n", i+1);
		printf("   Name   [%s]\n", q.name);
		printf("   Type   0x%04x\n", q.type);
		printf("   Class  0x%04x\n", q.class_);
	}

	for (i=0; i < a_count; i++)
	{
		dns_rr a;
		if (dns_get_answer(hdr, len, i, &a) < 0)
		{
			printf("Failed to parse A[%u]\n", i);
			return;
		}

		printf("\n   A%u\n", i+1);
		printf("   Name   [%s]\n", a.name);
		printf("   Type   0x%04x\n", a.type);
		printf("   Class  0x%04x\n", a.class_);
		printf("   TTL    %lu\n", a.ttl);
		printf("   Bytes  %hu\n", a.len);
	}
}
#endif

