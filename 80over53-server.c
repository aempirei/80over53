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

#include <string.h>
#include <errno.h>
#include <time.h>

#include <locale.h>
#include <wchar.h>
#include <wctype.h>

#include <unistd.h>
#include <fcntl.h>

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
    int numeric_markup;
    int alpha_markup;
    int wide_markup;
    int dynamic_mode;
    int compression_mode;
    const char *locale;
} configuration_t;

const configuration_t default_config = {
    .numeric_markup = 1,
    .alpha_markup = 0,
    .wide_markup = 0,
    .dynamic_mode = 0,
    .compression_mode = 0,
    .locale = ""
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

    usage_print("-h", "show", "this help");
    usage_print("-n", default_action(default_config.numeric_markup), "numeric markup");
    usage_print("-a", default_action(default_config.alpha_markup), "alpha markup");
    usage_print("-w", default_action(default_config.wide_markup), "wide markup");
    usage_print("-d", default_action(default_config.dynamic_mode), "dynamic mode");
    usage_print("-c", default_action(default_config.compression_mode), "compression mode");
    usage_print("-l locale", "use", "specified locale string");

    fputc('\n', stderr);
}

int cliconfig(configuration_t * config, int argc, char **argv) {

    int opt;

    *config = default_config;

    opterr = 0;

    while ((opt = getopt(argc, argv, "hdcnawvl:")) != -1) {
        switch (opt) {
            /*
               case 'd':
               config->dynamic_mode = !default_config.dynamic_mode;
               break;
               case 'c':
               config->compression_mode = !default_config.compression_mode;
               break;
             */
        case 'n':
            config->numeric_markup = !default_config.numeric_markup;
            break;
        case 'a':
            config->alpha_markup = !default_config.alpha_markup;
            break;
        case 'w':
            config->wide_markup = !default_config.wide_markup;
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

int print_eilseq(int ch, FILE * fp) {
    return fwprintf(fp, L"\33[46;31m\\x%02x\33[0m", ch);
}

int print_wide(int ch, FILE * fp) {
    return fwprintf(fp, L"\33[1;31m%lc\33[0m", ch);
}

int print_numeric(wint_t ch, FILE * fp) {
    int value = ch - L'0';
    const int codea[] = { 30, 37, 36, 31, 34, 33, 32, 35, 34, 31 };
    const int codeb[] = { 01, 01, 01, 00, 01, 01, 00, 00, 00, 01 };
    return fwprintf(fp, L"\33[%d;%dm%lc\33[0m", codeb[value], codea[value], ch);
}

int print_alpha(wint_t ch, FILE * fp) {
    wint_t value = towlower(ch) - L'a';

    return fwprintf(fp, L"\33[%d;%dm%lc\33[0m", (value / 6) & 1, 31 + (value % 6), ch);
}

void synescat(configuration_t * config, FILE * fpin, FILE * fpout) {

    wint_t wch;
    int ch;

    if (setlocale(LC_CTYPE, config->locale) == NULL) {
        fprintf(stderr, "failed to set locale LC_CTYPE=\"%s\"\n", config->locale);
        exit(EXIT_FAILURE);
    }

    for (;;) {

        wch = fgetwc(fpin);

        if (wch == WEOF) {
            if (feof(fpin)) {
                break;
            } else if (errno == EILSEQ) {
                if ((ch = fgetc(fpin)) == EOF) {
                    if (feof(fpin)) {
                        break;
                    } else {
                        perror("fgetc()");
                        exit(EXIT_FAILURE);
                    }
                }
                print_eilseq(ch, fpout);
            } else {
                perror("fgetwc()");
                exit(EXIT_FAILURE);
            }
        } else {

            if (config->numeric_markup && iswdigit(wch)) {
                print_numeric(wch, fpout);
            } else if (config->alpha_markup && iswalpha(wch)) {
                print_alpha(wch, fpout);
            } else if (config->wide_markup && wch > 255) {
                print_wide(wch, fpout);
            } else if (fputwc(wch, fpout) == WEOF) {
                fprintf(stderr, "fputwc(0x%02x,...)", wch);
                perror("");
                exit(EXIT_FAILURE);
            }
        }
    }

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

    const char fopen_mode[] = "r";

    configuration_t config;
    FILE *fp;

    int files_index = cliconfig(&config, argc, argv);

    if (files_index == argc) {
        synescat(&config, stdin, stdout);
    } else {
        for (int i = files_index; i < argc; i++) {
            if ((fp = fopen(argv[i], fopen_mode)) == NULL) {
                eprintf(errno, "fopen(\"%s\",\"%s\")", argv[i], fopen_mode);
            } else {
                synescat(&config, fp, stdout);
                fclose(fp);
            }
        }
    }

    exit(EXIT_SUCCESS);
}
