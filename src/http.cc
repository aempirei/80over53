#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <string>
#include <sstream>

#include <80over53/http.hh>

#define dfprintf(...)

http_request::http_request() : http_request(http_method::GET, "localhost", "/index.html", 80) {
}

http_request::http_request(http_method my_method, const std::string& my_host, const std::string& my_path, uint16_t my_port)
: method(my_method), host(my_host), path(my_path), port(my_port)
{
}

::http_request defaults::http_request = ::http_request();

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

const char *http_method_str(http_method x) {
	switch(x) {
		case http_method::GET:     return "GET";
		case http_method::HEAD:    return "HEAD";
		case http_method::POST:    return "POST";
		case http_method::PUT:     return "PUT";
		case http_method::DELETE:  return "DELETE";
		case http_method::TRACE:   return "TRACE";
		case http_method::CONNECT: return "CONNECT";
	}

	return nullptr;
}

std::string http_request::to_s() const {
	std::stringstream ss;

	ss << http_method_str(method) << ' ' << "http://" << host;

	if(port != defaults::http_request.port)
		ss << ':' << std::dec << port;

	ss << path << std::endl;

	if(not headers.empty()) {
		for(const auto& header : headers)
			ss << header << std::endl;
	}

	if(not form.empty()) {
		ss << std::endl;
		for(auto iter = form.begin(); iter != form.end(); iter++) {
			ss << iter->first << '=' << iter->second;
			if(std::next(iter) == form.end())
				ss << std::endl;
			else
				ss << '&';
		}
	}

	return ss.str();
}
