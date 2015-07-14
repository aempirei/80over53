#include <sys/types.h>
#include <sys/socket.h>

#include <map>
#include <list>
#include <string>

#pragma once

enum struct http_method { GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT };

const char *http_method_str(http_method);

#define HTTP_PATH_MAX_SZ 512

using http_form = std::map<std::string,std::string>;
using http_headers = std::list<std::string>;

struct http_request {

	http_method method;
	std::string host;
	std::string path;
	uint16_t port;
	http_headers headers;
	http_form form;

	http_request();
	http_request(http_method, const std::string&, const std::string&, uint16_t);

	sockaddr *get_sockaddr(sockaddr *, socklen_t) const;

	std::string to_s() const;
};

namespace defaults {
	extern ::http_request http_request;
}
