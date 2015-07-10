#include <cstdio>
#include <cstring>
#include <arpa/inet.h>

#include <80over53/dns.hh>

const char *dns_type_str(dns_type x) {
	switch(x) {

		case dns_type::A: return "A";
		case dns_type::AAAA: return "AAAA";
		case dns_type::AFSDB: return "AFSDB";
		case dns_type::APL: return "APL";
		case dns_type::CAA: return "CAA";
		case dns_type::CDNSKEY: return "CDNSKEY";
		case dns_type::CDS: return "CDS";
		case dns_type::CERT: return "CERT";
		case dns_type::CNAME: return "CNAME";
		case dns_type::DHCID: return "DHCID";
		case dns_type::DLV: return "DLV";
		case dns_type::DNAME: return "DNAME";
		case dns_type::DNSKEY: return "DNSKEY";
		case dns_type::DS: return "DS";
		case dns_type::HIP: return "HIP";
		case dns_type::IPSECKEY: return "IPSECKEY";
		case dns_type::KEY: return "KEY";
		case dns_type::LOC: return "LOC";
		case dns_type::MX: return "MX";
		case dns_type::NAPTR: return "NAPTR";
		case dns_type::NS: return "NS";
		case dns_type::NSEC: return "NSEC";
		case dns_type::NSEC3: return "NSEC3";
		case dns_type::NSEC3PARAM: return "NSEC3PARAM";
		case dns_type::PTR: return "PTR";
		case dns_type::RRSIG: return "RRSIG";
		case dns_type::RP: return "RP";
		case dns_type::SIG: return "SIG";
		case dns_type::SOA: return "SOA";
		case dns_type::SRV: return "SRV";
		case dns_type::SSHFP: return "SSHFP";
		case dns_type::TA: return "TA";
		case dns_type::TKEY: return "TKEY";
		case dns_type::TLSA: return "TLSA";
		case dns_type::TSIG: return "TSIG";
		case dns_type::TXT: return "TXT";

		default: return nullptr;
	}
}
const char *dns_class_str(dns_class x) {

	switch(x) {

		case dns_class::IN: return "IN";
		case dns_class::CH: return "CH";
		case dns_class::HS: return "HS";
		case dns_class::NONE: return "NONE";
		case dns_class::ANY: return "ANY";

		default: return nullptr;
	}
}

ssize_t dns_question::parse(size_t offset, const void *data, size_t data_sz) {
	ssize_t n = expand_name(offset, data, data_sz, qname);
	return -1;
}

int dns_question::sprint(char *s, size_t sz) {
	return snprintf(s, sz, "%s %s %s", dns_type_str(qtype), dns_class_str(qclass), qname);
}

int dns_header::sprint(char *s, size_t sz) {
	return snprintf(s, sz, "id=%d %s %s%s%s%s%s z=%d %s QD(%d) AN(%d) NS(%d) AR(%d)",
			ntohs(id),
			qr == 0 ? "QUERY" : "RESPONSE",
			opcode == 0 ? "QUERY" : opcode == 1 ? "IQUERY" : opcode == 2 ? "STATUS" : "RESERVED",
			aa ? " AUTHORITATIVE" : "",
			tc ? " TRUNCATED" :  "",
			rd ? " RD" : "",
			ra ? " RA" : "",
			z,
			rcode == 0 ? "OK" :
			rcode == 1 ? "FORMAT ERROR" :
			rcode == 2 ? "SERVER FAILURE" :
			rcode == 3 ? "NAME ERROR" :
			rcode == 4 ? "NOT IMPLEMENTED" :
			rcode == 5 ? "REFUSED" : "RESERVED",
			ntohs(qdcount),
			ntohs(ancount),
			ntohs(nscount),
			ntohs(arcount));
}

ssize_t expand_name(size_t offset, const void *data, size_t data_sz, char *name) {

	ssize_t label_sz;

	size_t used = 0;

	do {

		label_sz = expand_label(offset + used, data, data_sz, name + used);

		if(label_sz == -1)
			return -1;

		used += label_sz;

		name[used++] = (label_sz == 0) ? '\0' : '.';

	} while(label_sz > 0 && offset + used < data_sz);

	return used - 1;
}


ssize_t expand_label(size_t offset, const void *data, size_t data_sz, char *label) {

	if(is_label(offset, data)) {

		ssize_t label_sz = get_label_sz(offset, data);
		const char *label_offset = (const char *)data + offset + 1;

		memcpy(label, (const void *)label_offset, label_sz);

		return label_sz;

	} else if(is_pointer(offset, data)) {

		size_t pointer_offset = get_pointer_offset(offset, data);

		return expand_label(pointer_offset, data, data_sz, label);

	} else {

		return -1;
	}
}

size_t get_label_sz(size_t offset, const void *data) {
	return *(const uint8_t *)data & 0x3f;
}

size_t get_pointer_offset(size_t offset, const void *data) {
	const uint8_t *p = (const uint8_t *)data;
	return ( (size_t)256 * p[0] + p[1] ) & (size_t)0x3fff;
}
int is_label(size_t offset, const void *data) {
	return ( *(const uint8_t *)data & 0xc0 ) == 0x00;
}

int is_pointer(size_t offset, const void *data) {
	return ( *(const uint8_t *)data & 0xc0 ) == 0xc0;
}
