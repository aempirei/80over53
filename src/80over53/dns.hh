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
#define DNS_MSG_MAX_SZ   (1<<9)

enum struct dns_type : uint16_t {
	ANY = 0,
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

	char qname[DNS_NAME_MAX_SZ + 1];

	size_t qname_sz = 0;

	dns_type qtype = dns_type::A;
	dns_class qclass = dns_class::IN;

	virtual ssize_t parse(size_t, const void *, size_t);

	virtual int sprint(char *, size_t);
};

struct dns_rr : dns_question {

	uint16_t ttl = 0;

	uint8_t rdata[DNS_MSG_MAX_SZ];

	size_t rdata_sz = 0;

	virtual ssize_t parse(size_t, const void *, size_t);

	virtual int sprint(char *, size_t);
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

	ssize_t parse(const void *, size_t);

	int sprint(char *, size_t);
};

#pragma pack(pop)

const char *dns_type_str(dns_type);
const char *dns_class_str(dns_class);

#define DNS_NAME_FORMAT_LABEL		0x00
#define DNS_NAME_FORMAT_POINTER		0xc0
#define DNS_NAME_FORMAT_MASK		0xc0
#define DNS_LABEL_SZ_MASK			0x3f
#define DNS_POINTER_MASK			0x3fff

ssize_t expand_label(size_t, const void *, size_t, char *, size_t *);
ssize_t expand_name(size_t, const void *, size_t, char *, size_t *);

size_t get_label_sz(size_t, const void *);
size_t get_pointer_offset(size_t, const void *);

size_t get_name_format(size_t, const void *);

bool is_empty_label(size_t, const void *);

bool is_name_label(size_t, const void *);
bool is_name_pointer(size_t, const void *);
