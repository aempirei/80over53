#include <cstdio>
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

ssize_t dns_question::parse(const void *data, size_t sz) {
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
