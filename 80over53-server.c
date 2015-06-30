/*
 * 80over53-server - HTTP-over-DNS Server
 * 
 * Copyright(c) 2015 256 LLC
 * Written by Christopher Abad
 * 20 GOTO 10
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdatomic.h>

#include <string.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

#include <locale.h>
#include <wchar.h>
#include <wctype.h>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

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
 *    TERM,INT,QUIT : done := true
 *    HUP,USR1 : report status
 *
 * register atexit handler
 *    no-op
 *
 * dns-fd : socket-open-udp -> bind-port-53
 *
 * insert dns-fd into rfd-set
 *
 * while select on rfd-set and not done
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

typedef struct configuration {
	int verbose;
    const char *locale;
	uint32_t address;
	uint16_t port;
} configuration_t;

const configuration_t default_config = {
	.verbose = 0,
    .locale = "",
	.address = INADDR_ANY,
	.port = 53
};

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

int cliconfig(configuration_t * config, int argc, char **argv) {

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

sig_atomic_t done = 0;

void sighandler(int signo) {
	signal(signo, SIG_IGN);
	done = 1;
	fprintf(stderr, "caught signal %d...\n", signo);
}

#define HTTPFD_SZ 16

void http_over_dns(configuration_t * config, FILE * fpout) {

	struct sockaddr_in sin;

	int httpfd[HTTPFD_SZ];
	int dnsfd = -1;
	size_t httpfd_n = 0;
	int maxfd;

	const int nsecs = 1;

	fd_set rfds;

    if (setlocale(LC_CTYPE, config->locale) == NULL) {
        fprintf(stderr, "failed to set locale LC_CTYPE=\"%s\"\n", config->locale);
        exit(EXIT_FAILURE);
    }

	if(config->verbose) {

		char ip_string[20];

		if(config->address == INADDR_ANY) {
			strcpy(ip_string, "*");
		} else if(inet_ntop(AF_INET, &config->address, ip_string, sizeof(ip_string)) == NULL) {
			perror("inet_ntop()");
			exit(EXIT_FAILURE);
		}

		fprintf(fpout, "address: %s:%d\n", ip_string, config->port);
		fprintf(fpout, "verbose: %s\n", config->verbose ? "true" : "false");
		fprintf(fpout, " locale: \"%s\"\n", config->locale);
	}

	if(setuid(0) == -1) {
		perror("setuid()");
		exit(EXIT_FAILURE);
	}

	if(signal(SIGQUIT, sighandler) == SIG_ERR) {
		perror("signal()");
		exit(EXIT_FAILURE);
	}

	if(signal(SIGTERM, sighandler) == SIG_ERR) {
		perror("signal()");
		exit(EXIT_FAILURE);
	}

	if(signal(SIGINT, sighandler) == SIG_ERR) {
		perror("signal()");
		exit(EXIT_FAILURE);
	}

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

	FD_ZERO(&rfds);

	FD_SET(dnsfd, &rfds);
	maxfd = dnsfd;

	for(size_t n = 0; n < httpfd_n; n++) {
		FD_SET(httpfd[n], &rfds);
		if(httpfd[n] > maxfd)
			maxfd = httpfd[n];
	}

	while(!done) {
		fprintf(fpout, "sleeping %d seconds...\n", nsecs);
		sleep(nsecs);
    }

	fprintf(fpout, "cleaning up...\n");

	fclose(fpout);

	if(dnsfd != -1) {
		close(dnsfd);
		dnsfd = -1;
	}

	for(size_t n = 0; n < httpfd_n; n++)
		close(httpfd_n);

	httpfd_n = 0;

	fprintf(fpout, "goodbye!\n");

}

void eprintf(int errnum, const char *format, ...) {

    va_list ap;
    char eb[256];
    char s[256];

    if (strerror_r(errnum, eb, sizeof(eb)) == -1) {
        perror("strerror_r()");
        return;
    }

    va_start(ap, format);
    vsnprintf(s, sizeof(s), format, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s\n", s, eb);
}

int main(int argc, char **argv) {

	configuration_t config;

	int lastopt = cliconfig(&config, argc, argv);

	if (lastopt != argc) {
		fprintf(stderr, "too many arguments\n");
		exit(EXIT_FAILURE);
	}

	http_over_dns(&config, stdout);

	exit(EXIT_SUCCESS);
}
