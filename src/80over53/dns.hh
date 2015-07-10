#pragma once

/*
 * DNS size limits (in octets)
 *
 * labels       < 64   (6 bits)
 * names        < 256  (8 bits)
 * TTL          < 2^31 (31 bits)
 * UDP messages <= 512 (9 bits)
 *
 */

#define DNS_LABEL_MAX_SZ ((1<<6)-1)
#define DNS_NAME_MAX_SZ  ((1<<8)-1)
#define DNS_TTL_MAX_SZ   ((1<<31)-1)

enum struct dns_type : uint16_t {
	A = 1,
	AAAA = 28,
	AFSDB = 18,
	APL = 42,
	CAA = 257,
	CDNSKEY = 60,
	CDS = 59,
	CERT = 37,
	CNAME = 5,
	DHCID = 49,
	DLV = 32769,
	DNAME = 39,
	DNSKEY = 48,
	DS = 43,
	HIP = 55,
	IPSECKEY = 45,
	KEY = 25,
	LOC = 29,
	MX = 15,
	NAPTR = 35,
	NS = 2,
	NSEC = 47,
	NSEC3 = 50,
	NSEC3PARAM = 51,
	PTR = 12,
	RRSIG = 46,
	RP = 17,
	SIG = 24,
	SOA = 6,
	SRV = 33,
	SSHFP = 44,
	TA = 32768,
	TKEY = 249,
	TLSA = 52,
	TSIG = 250,
	TXT = 16
};

enum struct dns_class : uint16_t {
	IN = 1,
	CH = 3,
	HS = 4,
	NONE = 254,
	ANY = 255
};

struct dns_question {

	char qname[DNS_NAME_MAX_SZ + 1] = "";
	dns_type qtype = dns_type::A;
	dns_class qclass = dns_class::IN;
};

#pragma pack(push, 1)

struct dns_header {

	uint16_t id;

	uint8_t qr:1,
			opcode:4,
			aa:1,
			tc:1,
			rd:1;

	uint8_t  ra:1,
			 z:3,
			 rcode:4;

	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;

	int sprint(char *, size_t);
};

#pragma pack(pop)
