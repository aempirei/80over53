#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <string>
#include <sstream>

#include <80over53/http.hh>

#define dfprintf(...)

http_request::http_request() : http_request(http_method::GET, "localhost", "/index.html", false) {
}

http_request::http_request(http_method my_method, const char *my_host, const char *my_path, bool my_ssl)
: http_request(my_method, my_host, my_path, my_ssl, my_ssl ? 443 : 80)
{
}

http_request::http_request(http_method my_method, const char *my_host, const char *my_path, bool my_ssl, uint16_t my_port)
: method(my_method), host(my_host), path(my_path), ssl(my_ssl), port(my_port)
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

std::string http_request::form_string() const {

	std::stringstream ss;

	for(auto iter = form.begin(); iter != form.end(); iter++) {
		ss << iter->first << '=' << iter->second;
		if(std::next(iter) != form.end())
			ss << '&';
	}

	return ss.str();
}

std::string http_request::headers_string() const {

	std::stringstream ss;

	for(const auto& header : headers)
		ss << header.first << ": " << header.second << "\r\n";

	return ss.str();
}

std::string http_request::content() const {

	switch(method) {

		case http_method::POST:

			return form_string();

		case http_method::GET:
		case http_method::HEAD:
		case http_method::PUT:
		case http_method::DELETE:
		case http_method::TRACE:
		case http_method::CONNECT:

		default:

			return "";
	}
}

std::string http_request::url() const {

	std::stringstream ss;

	ss << "http" << (ssl ? "s" : "" ) << "://" << host;

	if((ssl and port == 443) or (not ssl and port == 80))
		ss << ':' << std::dec << port;

	ss << path;
	
	if(method == http_method::GET and not form.empty())
		ss << '?' << form_string();

	return ss.str();
}

std::string http_request::to_s() {

	std::stringstream ss;

	ss << http_method_str(method) << ' ' << path;

	if(method == http_method::GET and not form.empty())
		ss << '?' << form_string();

	ss << " HTTP/1.1\r\n";

	if(headers.find("Host") == headers.end())
		headers["Host"] = host;

	if(method == http_method::POST) {

		headers["Content-Length"] = std::to_string(content().size());

		if(headers.find("Content-Type") == headers.end())
		headers["Content-Type"] = "application/x-www-form-urlencoded";
	}

	ss << headers_string() << "\r\n";

	if(method == http_method::POST)
		ss << content();

	return ss.str();
}

int http_request::parse(const dns_question& question, const char *domain) {

	if(question.qtype != dns_type::TXT or question.qclass != dns_class::IN)
		return -1;

	return 0;
}
