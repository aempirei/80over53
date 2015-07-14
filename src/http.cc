#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <80over53/http.hh>

#define dfprintf(...)

http_request::http_request() : method(http_method::GET), host("localhost"), path("/index.html"), port(80) {
}

sockaddr *http_request::get_sockaddr(sockaddr *sa, socklen_t sa_sz) const {

	hostent *record = gethostbyname(host.c_str());
	if(record == nullptr)
		return nullptr;

	memset(sa, 0, sa_sz);

	if(record->h_addrtype == AF_INET) {

		sockaddr_in *sin = (sockaddr_in *)sa;

		if(sa_sz != sizeof(sockaddr_in)) {
			errno = EINVAL;
			return nullptr;
		}

		sin->sin_addr = *(in_addr *)record->h_addr;
		sin->sin_family = record->h_addrtype;
		sin->sin_port = htons(port);

	} else if(record->h_addrtype == AF_INET6) {

		sockaddr_in6 *sin6 = (sockaddr_in6 *)sa;

		if(sa_sz != sizeof(sockaddr_in6)) {
			errno = EINVAL;
			return nullptr;
		}

		sin6->sin6_addr = *(in6_addr *)record->h_addr;
		sin6->sin6_family = record->h_addrtype;
		sin6->sin6_port = htons(port);
	}

	return sa;
}
