/*
 *	The code is distributed under terms of the BSD license.
 *	Copyright (c) 2016 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/bsd-license
 */

#ifndef _DNS_H_
#define _DNS_H_

#include <stdint.h>
#include <string.h>
#include <stdio.h>

/*
 *	Raw DNS packet header
 */
#pragma pack(push, 1)

typedef struct dns_header
{
	uint16_t  id;
	uint16_t  flags;
	uint16_t  qcount;
	uint16_t  acount;
	uint16_t  nscount;
	uint16_t  arcount;

} dns_header;

#pragma pack(pop)

#define DNS_GET_QR(hdr)     ( (htons((hdr)->flags) >> 15) & 0x01 )
#define DNS_GET_OPCODE(hdr) ( (htons((hdr)->flags) >> 11) & 0x0F )
#define DNS_GET_RCODE(hdr)  ( htons((hdr)->flags) & 0x0F )

/*
 *	Parsed sections
 */
typedef struct dns_question
{
	char      name[256]; /* xyz.com */
	uint16_t  type;
	uint16_t  class_;
} dns_question;


typedef struct dns_rr
{
	char      name[256]; /* xyz.com */
	uint16_t  type;
	uint16_t  class_;
	uint32_t  ttl;
	uint16_t  len;
	char    * data;
} dns_rr;

/*
 *
 */
int dns_get_question(const dns_header * hdr, size_t len, size_t q_index, dns_question * q);
int dns_get_answer(const dns_header * hdr, size_t len, size_t a_index, dns_rr * a);

void dump_dns_response(const dns_header * hdr, size_t len);

#endif

