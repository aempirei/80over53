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

#include <set>

#include <80over53/dns.hh>
#include <80over53/http.hh>

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

void eprintf(int, const char *, ...);

struct configuration {
	bool verbose = false;
    const char *locale = "";
	uint32_t address = INADDR_ANY;
	const char *domain = "$.256.bz";
	uint16_t port = 53;
	FILE *fp = stdout;
};

configuration default_config = configuration();

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

	if(inet_ntop(AF_INET, &default_config.address, ip_string, sizeof(ip_string)) == nullptr) {
		perror("inet_ntop()");
		exit(EXIT_FAILURE);
	}

	snprintf(port_string, sizeof(port_string), "%d", default_config.port);

    usage_print("-h", "show", "this help");
    usage_print("-v", default_action(default_config.verbose), "verbose output");
	usage_print("-4 ip", "IPv4 bind address, default:", ip_string);
	usage_print("-p port", "UDP bind port, default:", port_string);
    usage_print("-l locale", "use", "specified locale string");
    usage_print("-d domain", "domain name, default:", default_config.domain);

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

				port = strtoul(optarg, nullptr, 0);
				if(port == ULONG_MAX && errno == ERANGE) {
					perror("strtoul()");
					exit(EXIT_FAILURE);
				}
				config->port = port;
				break;

			case 'l':

				config->locale = optarg;
				break;

			case 'd':
				
				config->domain = optarg;
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

		if(inet_ntop(AF_INET, &(p_sin->sin_addr), buf, sizeof(buf)) == nullptr) {
			perror("inet_ntop()");
			exit(EXIT_FAILURE);
		}

		fprintf(config->fp, "fd #%d data ready : read %ld bytes from %s:%d\n", fd, (long)n, buf, ntohs(p_sin->sin_port));
	}

	return n;
}

ssize_t process_question(configuration *config, size_t offset, const void * data, size_t data_sz, std::set<int>& fds) {

	struct sockaddr_in sin_to;

	dns_question question;
	http_request request;

	int fd;

	ssize_t n = question.parse(offset, data, data_sz);
	if(n == -1)
		return -1;

	offset = n;

	if(config->verbose) {
		char q_str[DNS_NAME_MAX_SZ * 2];
		question.sprint(q_str, sizeof(q_str));
		fprintf(config->fp, "DNS QUESTION :: %s\n", q_str);
	}

	if(request.parse(question, config->domain) == -1)
		return -1;

	if(request.get_sockaddr((sockaddr *)&sin_to, sizeof(sin_to)) == nullptr) {
		perror("http_request::get_sockaddr()");
		return -1;
	}

	request.method = http_method::POST;

	request.form["id"] = "16";
	request.form["username"] = "christopher";
	request.form["domain"] = "256.bz";

	if(config->verbose) {
		fprintf(config->fp, "url: %s\n", request.url().c_str());
		fprintf(config->fp, "[request]\n%s\n", request.to_s().c_str());
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if(connect(fd, (sockaddr *)&sin_to, sizeof(sin_to)) == -1) {
		perror("connect()");
		close(fd);
		return offset;
	}

	fds.insert(fd);

	return offset;
}

ssize_t
process_rr_section(configuration *config, size_t offset, const void * data, size_t data_sz, size_t count, const char *section_name)
{

	for(size_t q_n = 1; q_n <= count; q_n++) {

		dns_rr rr;
		char rr_string[DNS_NAME_MAX_SZ * 2];

		ssize_t n = rr.parse(offset, data, data_sz);
		if(n == -1) {
			fprintf(stderr, "dns %s #%d parse failed...\n", section_name, (int)q_n);
			return -1;
		}

		offset = n;

		if(config->verbose) {
			rr.sprint(rr_string, sizeof(rr_string));
			fprintf(config->fp, "dns %s #%d :: %s\n", section_name, (int)q_n, rr_string);
		}
	}

	return offset;
}

void process_dns_packet(configuration *config, void *data, ssize_t data_sz, std::set<int>& fds) {

	size_t content_length;

	char content[8192];
	char abs_path[2048];

	ssize_t offset;
	ssize_t n;

	int fd;

	dns_question question;

	dns_header header;

	n = header.parse(data, data_sz);
	if(n == -1) {
		fprintf(stderr, "dns header parse failed...\n");
		return;
	}

	offset = n;

	if(config->verbose) {
		char header_string[256];
		header.sprint(header_string, sizeof(header_string));
		fprintf(config->fp, "DNS HEADER :: %s\n", header_string);
	}

	if(header.is_response()) {
		fprintf(stderr, "ignoring DNS RESPONSE\n");
		return;
	}

	if((dns_opcode)header.opcode != dns_opcode::QUERY) {
		fprintf(stderr, "ignoring DNS OPCODE #%d (%s)\n", header.opcode, dns_opcode_str((dns_opcode)header.opcode));
		return;
	}

	for(size_t q_n = 1; q_n <= header.qdcount; q_n++) {
		n = process_question(config, offset, data, data_sz, fds);
		if(n == -1) {
			fprintf(stderr, "couldn't process DNS QUESTION #%d\n", (int)q_n);
			return;
		}

		offset = n;
	}

	if((offset = process_rr_section(config, offset, data, data_sz, header.ancount, "answer")) == -1)
		return;

	if((offset = process_rr_section(config, offset, data, data_sz, header.nscount, "nameservers")) == -1)
		return;

	if((offset = process_rr_section(config, offset, data, data_sz, header.arcount, "additional")) == -1)
		return;

	while(fds.size() >= FD_SETSIZE) {

		fd = *fds.begin();

		fprintf(stderr, "too many http connections open, closing fd #%d...", fd);

		close(fd);

		fds.erase(fd);
	}
}

void http_over_dns(configuration * config) {

	struct sockaddr_in sin;

	std::set<int> httpfdset;

	int dnsfd = -1;
	int maxfd;

	const int nsecs = 15;

	fd_set rfds;

	struct timeval tv;

	unsigned char data[DATA_SZ];

	if (setlocale(LC_CTYPE, config->locale) == nullptr) {
		fprintf(stderr, "failed to set locale LC_CTYPE=\"%s\"\n", config->locale);
		exit(EXIT_FAILURE);
	}

	if(config->verbose) {

		char buf[20];

		if(config->address == INADDR_ANY) {
			strcpy(buf, "*");
		} else if(inet_ntop(AF_INET, &config->address, buf, sizeof(buf)) == nullptr) {
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

	while(not stop) {

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

		for(int fd : httpfdset) {
			FD_SET(fd, &rfds);
			if(fd > maxfd)
				maxfd = fd;
		}

		tv.tv_sec = nsecs;
		tv.tv_usec = 0;

		if(config->verbose) {
			fprintf(config->fp, "waiting %ds for any files ready for reading (%d/%d descriptors)\n",
					nsecs,
					(int)httpfdset.size() + 1,
					(int)FD_SETSIZE + 1);
		}

		int left = select(maxfd + 1, &rfds, nullptr, nullptr, &tv);

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

				process_dns_packet(config, data, sz, httpfdset);

				FD_CLR(dnsfd, &rfds);
				left--;
			}
		}

		for(int fd : httpfdset) {

			if(left > 0 && FD_ISSET(fd, &rfds)) {

				sz = recvfrom_fd_data(config, fd, data, DATA_SZ, &sin_from);

				if(sz == -1) {

					if(errno != EAGAIN) {

						eprintf(errno, "recvfrom() failed, removing http-fd #%d", fd);

						close(fd);
						httpfdset.erase(fd);
					}

				} else if(sz == 0) {

					if(config->verbose)
						fprintf(config->fp, "http connection closed, removing http-fd #%d", fd);

					close(fd);
					httpfdset.erase(fd);

				} else {

					//
					// process the data
					//
				}

				FD_CLR(fd, &rfds);
				left--;
			}
		}
	}

	fprintf(config->fp, "cleaning up...\n");

	if(dnsfd != -1) {
		close(dnsfd);
		dnsfd = -1;
	}

	for(int fd : httpfdset)
		close(fd);

	httpfdset.clear();

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
