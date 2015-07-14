#include <sys/types.h>
#include <sys/socket.h>

#include <map>
#include <list>
#include <string>

#include <80over53/dns.hh>

#pragma once

enum struct http_method { GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT };

const char *http_method_str(http_method);

#define HTTP_PATH_MAX_SZ 512

using http_form = std::map<std::string, std::string>;
using http_headers = std::map<std::string, std::string>;

struct http_request {

	http_method method;
	std::string host;
	std::string path;
	bool ssl;
	uint16_t port;
	http_headers headers;
	http_form form;

	http_request();
	http_request(http_method, const char *, const char *,  bool, uint16_t);
	http_request(http_method, const char *, const char *,  bool);

	sockaddr *get_sockaddr(sockaddr *, socklen_t) const;

	int parse(const dns_question&, const char *);

	std::string url() const;
	std::string content() const;

	std::string form_string() const;
	std::string headers_string() const;

	std::string to_s();
};

namespace defaults {
	extern ::http_request http_request;
}

