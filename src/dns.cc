#include <cstdio>
#include <arpa/inet.h>

#include <80over53/dns.hh>

int dns_header::sprint(char *s, size_t sz) {
	return snprintf(s,
			sz,
			"id=%d %s %s%s%s%s%s z=%d %s QD(%d) AN(%d) NS(%d) AR(%d)",
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
