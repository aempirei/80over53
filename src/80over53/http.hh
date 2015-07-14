#include <sys/types.h>
#include <sys/socket.h>

#include <map>
#include <list>

#pragma once

enum struct http_method { GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT };

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

	sockaddr *get_sockaddr(sockaddr *, socklen_t) const;
};
