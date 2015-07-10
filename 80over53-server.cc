/*
 * 80over53-server - HTTP-over-DNS Server
 * 
 * Copyright(c) 2015 256 LLC
 * Written by Christopher Abad
 * 20 GOTO 10
 * 
 */

#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstdint>
// #include <stdatomic.h>

#include <cstring>
#include <cerrno>
#include <ctime>
#include <climits>

#include <clocale>
#include <cwchar>
#include <cwctype>

#include <csignal>

#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

/*
 * 80over53-server program logic
 * =============================
 *
 * register signal handlers
 *    TERM,INT,QUIT : stop
 *    HUP,USR1      : reload configuration
 *    USR2          : report status
 *    
 *
 * register atexit handler
 *    no-op
 *
 * dns-fd : socket-open-udp -> bind-port-53
 *
 * insert dns-fd into rfd-set
 *
 * while select on rfd-set and not stop
 *
 *    if dns-fd ready in rfd-set
 *       request : read-dns-fd -> transform -> send-http-fd
 *       insert http-fd into rfd-set
 *
 *    while http-fd ready in rfd-set
 *       response : read-http-fd -> transform -> send-dns-fd
 *       delete http-fd from rfd-set
 *       close http-fd
 *
 * foreach fd in rfd-set
 *    delete fd from rfd-set
 *    close fd
 *
 * exit
 *
 */

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

void eprintf(int, const char *, ...);

struct configuration {
	int verbose;
    const char *locale;
	uint32_t address;
	uint16_t port;
	FILE *fp;

	configuration() : verbose(0), locale(""), address(INADDR_ANY), port(53), fp(stdout) {
	}
};

configuration default_config = configuration();

struct dns_header {

	uint16_t id;

	uint8_t qr:1,
			 opcode:4,
			 aa:1,
			 tc:1,
			 rd:1;

	uint8_t	 ra:1,
			 z:3,
			 rcode:4;

	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;

	dns_header() : id(0), qr(0), opcode(0), aa(0), tc(0), rd(0), ra(0), z(0), rcode(0), qdcount(0), ancount(0), nscount(0), arcount(0)
	{
	}

	int sprint(char *s, size_t sz) {
		return snprintf(s, sz, "id=%d %s %s%s%s%s%s z=%d %s QD(%d) AN(%d) NS(%d) AR(%d)",
				ntohs(id),
				qr == 0 ? "QUERY" : "RESPONSE",
				opcode == 0 ? "QUERY" :
				opcode == 1 ? "IQUERY" :
				opcode == 2 ? "STATUS" :
				"RESERVED",
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
				rcode == 5 ? "REFUSED" :
				"RESERVED",
				ntohs(qdcount),
				ntohs(ancount),
				ntohs(nscount),
				ntohs(arcount));
	}
} __attribute__ ((__packed__));

ssize_t expand_label(size_t offset, const void *data, size_t data_sz, char *label);
ssize_t expand_name(size_t offset, const void *data, size_t data_sz, char *name);

size_t get_label_sz(size_t offset, const void *data);
size_t get_pointer_offset(size_t offset, const void *data);

int is_label(size_t offset, const void *data);
int is_pointer(size_t offset, const void *data);

ssize_t expand_name(size_t offset, const void *data, size_t data_sz, char *name) {
 
	/* TODO: improve the memory management of the dns name block */

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

const char *default_action(int default_value) {
    return default_value ? "disable" : "enable";
}

void usage_print(const char *option_str, const char *action, const char *option_desc) {

    const int option_width = -11;

    fprintf(stderr, "\t%*s%s %s\n", option_width, option_str, action, option_desc);
}

void usage(const char *arg0) {

    fprintf(stderr, "\nusage: %s [options] [file]...\n\n", arg0);

	char ip_string[20];
	char port_string[20];

	if(inet_ntop(AF_INET, &default_config.address, ip_string, sizeof(ip_string)) == NULL) {
		perror("inet_ntop()");
		exit(EXIT_FAILURE);
	}

	snprintf(port_string, sizeof(port_string), "%d", default_config.port);

    usage_print("-h", "show", "this help");
    usage_print("-v", default_action(default_config.verbose), "verbose output");
	usage_print("-4 ip", "IPv4 bind address, default:", ip_string);
	usage_print("-p port", "UDP bind port, default:", port_string);
    usage_print("-l locale", "use", "specified locale string");

    fputc('\n', stderr);
}

int cliconfig(configuration * config, int argc, char **argv) {

    int opt;

    *config = default_config;

    opterr = 0;

	struct in_addr addr;
	unsigned long port;

	while ((opt = getopt(argc, argv, "hv4:p:l:")) != -1) {

		switch (opt) {

			case 'v':

				config->verbose = !default_config.verbose;
				break;

			case '4':

				if(inet_pton(AF_INET, optarg, &addr) == -1) {
					perror("inet_pton()");
					exit(EXIT_FAILURE);
				}
				config->address = addr.s_addr;
				break;

			case 'p':

				port = strtoul(optarg, NULL, 0);
				if(port == ULONG_MAX && errno == ERANGE) {
					perror("strtoul()");
					exit(EXIT_FAILURE);
				}
				config->port = port;
				break;

			case 'l':

				config->locale = optarg;
				break;

			case 'h':

				usage(argv[0]);
				exit(EXIT_SUCCESS);

			case '?':

				fprintf(stderr, "unknown option: -%c\n", optopt);
				usage(argv[0]);
				exit(EXIT_FAILURE);

			default:

				fprintf(stderr, "unimplemented option: -%c\n", opt);
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	return optind;
}

sig_atomic_t stop = 0;

void sighandler_stop(int signo) {
	signal(signo, SIG_IGN);
	stop = signo;
	fprintf(stderr, "caught signal #%d (%s), stopping server...\n", signo, strsignal(signo));
}

sig_atomic_t report = 0;

void sighandler_report(int signo) {
	signal(signo, SIG_IGN);
	report = signo;
	fprintf(stderr, "caught signal #%d (%s), reporting status...\n", signo, strsignal(signo));
}

sig_atomic_t reload = 0;

void sighandler_reload(int signo) {
	signal(signo, SIG_IGN);
	reload = signo;
	fprintf(stderr, "caught signal #%d (%s), reloading configuration...\n", signo, strsignal(signo));
}

#define HTTPFD_SZ 16
#define DATA_SZ 2048

ssize_t recvfrom_fd_data(configuration * config, int fd, void *data, size_t data_sz, struct sockaddr_in *p_sin) {


	socklen_t addrlen;
	ssize_t n;

	addrlen = sizeof(*p_sin);

	n = recvfrom(fd, data, data_sz, 0, (struct sockaddr *)p_sin, &addrlen);
	if(n == -1)
		return -1;

	if(config->verbose) {

		char buf[20];

		if(inet_ntop(AF_INET, &(p_sin->sin_addr), buf, sizeof(buf)) == NULL) {
			perror("inet_ntop()");
			exit(EXIT_FAILURE);
		}

		fprintf(config->fp, "fd #%d data ready : read %ld bytes from %s:%d\n", fd, (long)n, buf, ntohs(p_sin->sin_port));
	}

	return n;
}

int int_array_delete(int *xs, size_t *xs_n, size_t n) {

	int x = xs[n];

	while(++n < *xs_n)
		xs[n - 1] = xs[n];

	(*xs_n)--;
	return x;
}

int int_array_pop(int *xs, size_t *xs_n) {
	return int_array_delete(xs, xs_n, *xs_n - 1);
}

int int_array_shift(int *xs, size_t *xs_n) {
	return int_array_delete(xs, xs_n, 0);
}

enum struct http_method { GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT };

void generate_http_request(configuration *config, void *data, ssize_t data_sz, int *httpfd, size_t *p_httpfd_n) {

	constexpr uint16_t http_port = 80;
	constexpr http_method method = http_method::GET;

	struct sockaddr_in sin_to;

	int fd;
	size_t content_length;

	char content[8192];
	char abs_path[2048];
	char ip_string[20];

	ssize_t left;
	ssize_t done;

	dns_header header;

	left = data_sz;
	done = 0;

	if((signed)sizeof(dns_header) <= left) {
		memcpy(&header, (uint8_t *)data + done, sizeof(dns_header));
		left -= sizeof(dns_header);
		done += sizeof(dns_header);
	}

	if(config->verbose) {
		char header_string[256];
		header.sprint(header_string, sizeof(header_string));
		fprintf(config->fp, "dns header :: %s\n", header_string);
	}

	memset(&sin_to, 0, sizeof(sin_to));
	sin_to.sin_family = AF_INET;
	sin_to.sin_port = htons(http_port);
	if(inet_pton(AF_INET, ip_string, &sin_to.sin_addr) == -1) {
		perror("inet_pton()");
		exit(EXIT_FAILURE);
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if(*p_httpfd_n == HTTPFD_SZ) {

		fprintf(stderr, "too many http connections open, closing oldest...");

		close(int_array_shift(httpfd, p_httpfd_n));
	}

	httpfd[*p_httpfd_n] = fd;

	(*p_httpfd_n)++;
}

void http_over_dns(configuration * config) {

	struct sockaddr_in sin;

	size_t httpfd_n = 0;

	int httpfd[HTTPFD_SZ];
	int dnsfd = -1;
	int maxfd;

	const int nsecs = 15;

	fd_set rfds;

	struct timeval tv;

	unsigned char data[DATA_SZ];

	if (setlocale(LC_CTYPE, config->locale) == NULL) {
		fprintf(stderr, "failed to set locale LC_CTYPE=\"%s\"\n", config->locale);
		exit(EXIT_FAILURE);
	}

	if(config->verbose) {

		char buf[20];

		if(config->address == INADDR_ANY) {
			strcpy(buf, "*");
		} else if(inet_ntop(AF_INET, &config->address, buf, sizeof(buf)) == NULL) {
			perror("inet_ntop()");
			exit(EXIT_FAILURE);
		}

		fprintf(config->fp, "address: %s:%d\n", buf, config->port);
		fprintf(config->fp, "verbose: %s\n", config->verbose ? "true" : "false");
		fprintf(config->fp, " locale: \"%s\"\n", config->locale);
	}

	if(setuid(0) == -1) {
		perror("setuid()");
		exit(EXIT_FAILURE);
	}

	auto configure_signal = [config](int signo, sighandler_t handler) {
		if(config->verbose) 
			fprintf(config->fp, "configuring signal #%d (%s)\n", signo, strsignal(signo));
		if(signal(signo, handler) == SIG_ERR) {
			perror("signal()");
			exit(EXIT_FAILURE);
		}
	};

	configure_signal(SIGQUIT, sighandler_stop  );
	configure_signal(SIGTERM, sighandler_stop  );
	configure_signal(SIGINT , sighandler_stop  );
	configure_signal(SIGHUP , sighandler_reload);
	configure_signal(SIGUSR1, sighandler_reload);
	configure_signal(SIGUSR2, sighandler_report);

	dnsfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(dnsfd == -1) {
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(config->port);
	sin.sin_addr.s_addr = config->address;

	if(bind(dnsfd, (const struct sockaddr *)&sin, sizeof(sin)) == -1) {
		perror("bind()");
		exit(EXIT_FAILURE);
	}

	while(stop == 0) {

		if(report != 0) {
			configure_signal(report, sighandler_report);
			report = 0;
		}

		if(reload != 0) {
			configure_signal(reload, sighandler_reload);
			reload = 0;
		}

		struct sockaddr_in sin_from;
		ssize_t sz;

		FD_ZERO(&rfds);

		FD_SET(dnsfd, &rfds);
		maxfd = dnsfd;

		for(size_t n = 0; n < httpfd_n; n++) {
			FD_SET(httpfd[n], &rfds);
			if(httpfd[n] > maxfd)
				maxfd = httpfd[n];
		}

		tv.tv_sec = nsecs;
		tv.tv_usec = 0;

		int left = select(maxfd + 1, &rfds, NULL, NULL, &tv);

		if(left == -1) {

			if(errno == EINTR)
				continue;

			perror("select()");
			exit(EXIT_FAILURE);
		}
		
		if(left == 0) {
			fprintf(config->fp, "%dsec timeout...\n", nsecs);
			continue;
		}

		if(left > 0 && FD_ISSET(dnsfd, &rfds)) {

			sz = recvfrom_fd_data(config, dnsfd, data, DATA_SZ, &sin_from);
			if(sz == -1) {
				if(errno != EAGAIN) {
					perror("recvfrom()");
					exit(EXIT_FAILURE);
				}
			} else {

				generate_http_request(config, data, sz, httpfd, &httpfd_n);

				FD_CLR(dnsfd, &rfds);
				left--;
			}
		}

		for(size_t n = 0; n < httpfd_n; n++) {

			if(left > 0 && FD_ISSET(httpfd[n], &rfds)) {

				int fd = httpfd[n];

				sz = recvfrom_fd_data(config, fd, data, DATA_SZ, &sin_from);

				if(sz == -1) {

					if(errno != EAGAIN) {
						eprintf(errno, "recvfrom() failed, removing http-fd #%d", fd);
						close(int_array_delete(httpfd, &httpfd_n, n));
					}

				} else if(sz == 0) {

					if(config->verbose)
						fprintf(config->fp, "http connection closed, removing http-fd #%d", fd);
					close(int_array_delete(httpfd, &httpfd_n, n));

				} else {
				}

				FD_CLR(fd, &rfds);
				left--;
			}
		}

		if(config->verbose)
			fprintf(config->fp, "%ld http-fds\n", httpfd_n);
	}

	fprintf(config->fp, "cleaning up...\n");

	if(dnsfd != -1) {
		close(dnsfd);
		dnsfd = -1;
	}

	for(size_t n = 0; n < httpfd_n; n++)
		close(httpfd_n);

	httpfd_n = 0;

	fprintf(config->fp, "goodbye!\n");

	fclose(config->fp);
}

void eprintf(int errnum, const char *format, ...) {

    va_list ap;
    char eb[256];
    char s[256];

    va_start(ap, format);
    vsnprintf(s, sizeof(s), format, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s\n", s, strerror_r(errnum, eb, sizeof(eb)));
}

int main(int argc, char **argv) {

	configuration config;

	int lastopt = cliconfig(&config, argc, argv);

	if (lastopt != argc) {
		fprintf(stderr, "too many arguments\n");
		exit(EXIT_FAILURE);
	}

	http_over_dns(&config);

	exit(EXIT_SUCCESS);
}
