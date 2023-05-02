/* mini_httpd - small HTTP server
**
** Copyright � 1999,2000 by Jef Poskanzer <jef@mail.acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/

#include "version.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

// include for d3trustedhttpd
#include <stdint.h>
#include <linux/net.h>
#include <sys/un.h>
#include <crypt.h>
// defind for d3trustedhttpd
#define MAX_USERNAME_LEN 128
#define MIN_PASSWORD_LEN 6
#define MAX_PASSWORD_LEN 128
#define MAX_SESSION_LEN 128
#define SHA256_DIGEST_LENGTH 32
#define HTTP_SESSION_LEN (SHA256_DIGEST_LENGTH*2)
#define MAX_CONTENT_LENGTH 0x4000
typedef double vec_float;
typedef struct UserInfoOut user_info_out_t;
struct UserInfoOut{
	// public regions
	uint32_t magic;
	uint32_t uid;
	uint32_t type;
	uint32_t face_id;
	char username[MAX_USERNAME_LEN+8];
};
enum {
	USER_TYPE_ADMIN,
	USER_TYPE_USER,
	USER_TYPE_GUEST,
	USER_TYPE_COUNT
};
enum {
	ACTION_PERMISSON_PASSWD,
	ACTION_PERMISSON_ENABLE,
	ACTION_PERMISSON_DISABLE,
	ACTION_PERMISSON_KICOOUT,
	ACTION_PERMISSON_RESET,
	ACTION_PERMISSON_SET_MSG,
	ACTION_PERMISSON_GET_MSG,
	ACTION_COUNT
};
#define USER_MAGIC_NORMAL 0x72657375 // "user"
#define USER_MAGIC_DISABLED 0xffffffff //

//#define USE_SSL
#define HAVE_SCANDIR

#define MAX_FILE_NAME 128
//#define MAX_FILE_DATA 1024
#define MAX_FILE_DATA 4096
#define SEC_FILE_STATUS_NORMAL 0xaabb
#define SEC_FILE_STATUS_DEL 0xffffffff
#define MAX_FILE_COUNT 128
#define MAX_FILE_ID MAX_FILE_COUNT
#define SEC_FILE_MAGIC 0x73656366 // "secf"
#define FILE_NODE_EMPTY 0x1
#define FILE_NODE_DIR 0x2
#define FILE_NODE_FILE 0x4
#define FILE_NODE_DEL 0xff

typedef struct SecFile sec_file_t;
#pragma pack(push, 4)
struct SecFile{
	uint32_t magic;
	char hash[SHA256_DIGEST_LENGTH];
	char filename[MAX_FILE_NAME];
	uint32_t status;
	char data[0];
};
#pragma pack(pop)

typedef struct FileInfo file_info_t;
//#pragma pack(push, 4)
struct FileInfo{
	uint32_t magic;
	uint32_t node_type;
	uint32_t parent_id;
	uint32_t ext_id;
	uint32_t owner;
	uint32_t file_size;
	char filename[MAX_FILE_NAME];
	char hash[SHA256_DIGEST_LENGTH*2];
};
//#pragma pack(pop)

typedef struct DirInfo dir_info_t;
//#pragma pack(push, 4)
struct DirInfo{
	uint32_t magic; // "dir" 0x726964
	uint32_t node_type;
	uint32_t parent_id;
	uint32_t ext_id;
	uint32_t owner;
	char dir_name[MAX_FILE_NAME];
	uint8_t sub_items[MAX_FILE_COUNT];
};
//#pragma pack(pop)

#include "match.h"
#include "port.h"
#include "tdate_parse.h"

#ifdef HAVE_SENDFILE
#ifdef HAVE_LINUX_SENDFILE
#include <sys/sendfile.h>
#else /* HAVE_LINUX_SENDFILE */
#include <sys/uio.h>
#endif /* HAVE_LINUX_SENDFILE */
#endif /* HAVE_SENDFILE */

#if defined(TCP_CORK) && !defined(TCP_NOPUSH)
#define TCP_NOPUSH TCP_CORK
/* (Linux's TCP_CORK is basically the same as BSD's TCP_NOPUSH.) */
#endif

#ifdef USE_SSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif /* USE_SSL */

#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
#define USE_IPV6
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

#ifndef SIZE_T_MAX
#define SIZE_T_MAX 2147483647L
#endif

#define HAVE_INT64T
#ifndef HAVE_INT64T
typedef long long int64_t;
#endif

#ifdef __CYGWIN__
#define timezone _timezone
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* Do overlapping strcpy safely, by using memmove. */
#define ol_strcpy(dst, src) memmove(dst, src, strlen(src) + 1)

#ifndef ERR_DIR
#define ERR_DIR "errors"
#endif /* ERR_DIR */
#ifndef DEFAULT_HTTP_PORT
#define DEFAULT_HTTP_PORT 80
#endif /* DEFAULT_HTTP_PORT */
#ifdef USE_SSL
#ifndef DEFAULT_HTTPS_PORT
#define DEFAULT_HTTPS_PORT 443
#endif /* DEFAULT_HTTPS_PORT */
#ifndef DEFAULT_CERTFILE
#define DEFAULT_CERTFILE "mini_httpd.pem"
#endif /* DEFAULT_CERTFILE */
#endif /* USE_SSL */
#ifndef DEFAULT_USER
#define DEFAULT_USER "nobody"
#endif /* DEFAULT_USER */
#ifndef CGI_NICE
#define CGI_NICE 10
#endif /* CGI_NICE */
#ifndef CGI_PATH
#define CGI_PATH "/usr/local/bin:/usr/ucb:/bin:/usr/bin"
#endif /* CGI_PATH */
#ifndef CGI_LD_LIBRARY_PATH
#define CGI_LD_LIBRARY_PATH "/usr/local/lib:/usr/lib"
#endif /* CGI_LD_LIBRARY_PATH */
#ifndef AUTH_FILE
#define AUTH_FILE ".htpasswd"
#endif /* AUTH_FILE */
#ifndef READ_TIMEOUT
#define READ_TIMEOUT 60
#endif /* READ_TIMEOUT */
#ifndef WRITE_TIMEOUT
#define WRITE_TIMEOUT 300
#endif /* WRITE_TIMEOUT */
#ifndef DEFAULT_CHARSET
#define DEFAULT_CHARSET "UTF-8"
#endif /* DEFAULT_CHARSET */
#ifndef MAX_SEND_BUFFER_SIZE
#define MAX_SEND_BUFFER_SIZE 1048576
#endif /* MAX_SEND_BUFFER_SIZE */

#define METHOD_UNKNOWN 0
#define METHOD_GET 1
#define METHOD_HEAD 2
#define METHOD_POST 3
#define METHOD_PUT 4
#define METHOD_DELETE 5
#define METHOD_TRACE 6

/* A multi-family sockaddr. */
typedef union {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
#ifdef USE_IPV6
    struct sockaddr_in6 sa_in6;
    struct sockaddr_storage sa_stor;
#endif /* USE_IPV6 */
} usockaddr;

static char* argv0 = NULL;
static int debug;
static unsigned short port;
static char* dir = NULL;
static char* data_dir = NULL;
static int do_chroot;
static int vhost;
static char* user = NULL;
static char* cgi_pattern = NULL;
static char* url_pattern = NULL;
static int no_empty_referrers;
static char* local_pattern = NULL;
static char* hostname = NULL;
static char hostname_buf[500] = {'\0'};
static char* logfile = NULL;
static char* pidfile = NULL;
static char* charset = NULL;
static char* p3p = NULL;
static int max_age;
static FILE* logfp;
static int listen4_fd, listen6_fd;
static int do_ssl;
#ifdef USE_SSL
static char* certfile = NULL;
static char* cipher = NULL;
static SSL_CTX* ssl_ctx = NULL;
#endif /* USE_SSL */
static char cwd[MAXPATHLEN];
static int got_hup;

/* Request variables. */
static int conn_fd;
#ifdef USE_SSL
static SSL* ssl;
#endif /* USE_SSL */
static usockaddr client_addr;
static char* request = NULL;
static size_t request_size, request_len, request_idx;
static int method;
static char* path = NULL;
static char* file = NULL;
static char* pathinfo = NULL;
struct stat sb;
static char* query = NULL;
static char* protocol = NULL;
static int status;
static off_t bytes = 0;
static char* req_hostname = NULL;

static char* authorization = NULL;
static size_t content_length = 0;
static char* content_type = NULL;
static char* cookie = NULL;
static char* host = NULL;
static time_t if_modified_since;
static char* referrer = NULL;
static char* useragent = NULL;

static char* remoteuser = NULL;

/* Forwards. */
static void usage(void);
static void read_config(char* filename);
static void value_required(char* name, char* value);
static void no_value_required(char* name, char* value);
static int initialize_listen_socket(usockaddr* usaP);
static void handle_request(void) __attribute__((noreturn));
static void finish_request(int exitstatus) __attribute__((noreturn));
static void de_dotdot(char* f);
static int get_pathinfo(void);
static void do_file(void);
static void do_dir(void);
#ifdef HAVE_SCANDIR
static char* file_details(const char* d, const char* name);
static void strencode(char* to, size_t tosize, const char* from);
#endif /* HAVE_SCANDIR */
static void do_cgi(void);
static void cgi_interpose_input(int wfd);
static void post_post_garbage_hack(void);
static void cgi_interpose_output(int rfd, int parse_headers);
static char** make_argp(void);
static char** make_envp(void);
static char* build_env(char* fmt, char* arg);
static void auth_check(char* dirname);
static void send_authenticate(char* realm);
static char* virtual_file(char* f);
static void send_error(int s, char* title, char* extra_header, char* text);
static void send_error_body(int s, char* title, char* text);
static int send_error_file(char* filename);
static void send_error_tail(void);
static void add_headers(int s, char* title, char* extra_header, char* me, char* mt, off_t b, time_t mod);
static void start_request(void);
static void add_to_request(char* str, size_t len);
static char* get_request_line(void);
static void start_response(void);
static void add_to_response(char* str);
static void send_response(void);
static void send_via_write(int fd, off_t size);
static void send_via_sendfile(int fd, int s, off_t size);
static ssize_t my_read(char* buf, size_t size);
static ssize_t my_write(void* buf, size_t size);
#ifdef HAVE_SENDFILE
static ssize_t my_sendfile(int fd, int s, off_t offset, size_t nbytes);
#endif /* HAVE_SENDFILE */
static void add_str(char** bufP, size_t* bufsizeP, size_t* buflenP, char* str);
static void add_data(char** bufP, size_t* bufsizeP, size_t* buflenP, char* str, size_t len);
static void make_log_entry(void);
static void check_referrer(void);
static int really_check_referrer(void);
static char* get_method_str(int m);
static void init_mime(void);
static const char* figure_mime(char* name, char* me, size_t me_size);
static void handle_sigterm(int sig);
static void handle_sighup(int sig);
static void handle_sigchld(int sig);
static void re_open_logfile(void);
static void handle_read_timeout(int sig);
static void handle_write_timeout(int sig);
static void lookup_hostname(usockaddr* usa4P, size_t sa4_len, int* gotv4P, usockaddr* usa6P, size_t sa6_len, int* gotv6P);
static char* ntoa(usockaddr* usaP);
static int sockaddr_check(usockaddr* usaP);
static size_t sockaddr_len(usockaddr* usaP);
static void strdecode(char* to, char* from);
static uint32_t urldecode(char *to, const char *from);
static int hexit(char c);
static int b64_decode(const char* str, unsigned char* space, int size);
static void set_ndelay(int fd);
static void clear_ndelay(int fd);
static void* e_malloc(size_t size);
static void* e_realloc(void* optr, size_t size);
static char* e_strdup(char* ostr);
#ifdef NO_SNPRINTF
static int snprintf(char* str, size_t size, const char* format, ...);
#endif /* NO_SNPRINTF */

int main(int argc, char** argv) {
    int argn;
    struct passwd* pwd;
    uid_t uid = 32767;
    gid_t gid = 32767;
    usockaddr host_addr4;
    usockaddr host_addr6;
    int gotv4, gotv6;
    fd_set lfdset;
    int maxfd;
    usockaddr usa;
    socklen_t sz;
    int r;
    char* cp;

    /* Parse args. */
    argv0 = argv[0];
    debug = 0;
    port = 0;
    dir = (char*)0;
    data_dir = (char*)0;
    do_chroot = 0;
    vhost = 0;
    cgi_pattern = (char*)0;
    url_pattern = (char*)0;
    no_empty_referrers = 0;
    local_pattern = (char*)0;
    charset = DEFAULT_CHARSET;
    p3p = (char*)0;
    max_age = -1;
    user = DEFAULT_USER;
    hostname = (char*)0;
    logfile = (char*)0;
    pidfile = (char*)0;
    logfp = (FILE*)0;
    do_ssl = 0;
#ifdef USE_SSL
    certfile = DEFAULT_CERTFILE;
    cipher = (char*)0;
#endif /* USE_SSL */
    argn = 1;
    while (argn < argc && argv[argn][0] == '-') {
        if (strcmp(argv[argn], "-V") == 0) {
            (void)printf("%s\n", SERVER_SOFTWARE);
            exit(0);
        } else if (strcmp(argv[argn], "-C") == 0 && argn + 1 < argc) {
            ++argn;
            read_config(argv[argn]);
        } else if (strcmp(argv[argn], "-D") == 0)
            debug = 1;
#ifdef USE_SSL
        else if (strcmp(argv[argn], "-S") == 0)
            do_ssl = 1;
        else if (strcmp(argv[argn], "-E") == 0 && argn + 1 < argc) {
            ++argn;
            certfile = argv[argn];
        } else if (strcmp(argv[argn], "-Y") == 0 && argn + 1 < argc) {
            ++argn;
            cipher = argv[argn];
        }
#endif /* USE_SSL */
        else if (strcmp(argv[argn], "-p") == 0 && argn + 1 < argc) {
            ++argn;
            port = (unsigned short)atoi(argv[argn]);
        } else if (strcmp(argv[argn], "-d") == 0 && argn + 1 < argc) {
            ++argn;
            dir = argv[argn];
        } else if (strcmp(argv[argn], "-dd") == 0 && argn + 1 < argc) {
            ++argn;
            data_dir = argv[argn];
        } else if (strcmp(argv[argn], "-c") == 0 && argn + 1 < argc) {
            ++argn;
            cgi_pattern = argv[argn];
        } else if (strcmp(argv[argn], "-u") == 0 && argn + 1 < argc) {
            ++argn;
            user = argv[argn];
        } else if (strcmp(argv[argn], "-h") == 0 && argn + 1 < argc) {
            ++argn;
            hostname = argv[argn];
        } else if (strcmp(argv[argn], "-r") == 0)
            do_chroot = 1;
        else if (strcmp(argv[argn], "-v") == 0)
            vhost = 1;
        else if (strcmp(argv[argn], "-l") == 0 && argn + 1 < argc) {
            ++argn;
            logfile = argv[argn];
        } else if (strcmp(argv[argn], "-i") == 0 && argn + 1 < argc) {
            ++argn;
            pidfile = argv[argn];
        } else if (strcmp(argv[argn], "-T") == 0 && argn + 1 < argc) {
            ++argn;
            charset = argv[argn];
        } else if (strcmp(argv[argn], "-P") == 0 && argn + 1 < argc) {
            ++argn;
            p3p = argv[argn];
        } else if (strcmp(argv[argn], "-M") == 0 && argn + 1 < argc) {
            ++argn;
            max_age = atoi(argv[argn]);
        } else
            usage();
        ++argn;
    }
    if (argn != argc)
        usage();

    cp = strrchr(argv0, '/');
    if (cp != (char*)0)
        ++cp;
    else
        cp = argv0;
    openlog(cp, LOG_NDELAY | LOG_PID, LOG_DAEMON);

    if (port == 0) {
#ifdef USE_SSL
        if (do_ssl)
            port = DEFAULT_HTTPS_PORT;
        else
            port = DEFAULT_HTTP_PORT;
#else  /* USE_SSL */
        port = DEFAULT_HTTP_PORT;
#endif /* USE_SSL */
    }

    /* If we're root and we're going to become another user, get the uid/gid
    ** now.
    */
    if (getuid() == 0) {
        pwd = getpwnam(user);
        if (pwd == (struct passwd*)0) {
            syslog(LOG_CRIT, "unknown user - '%s'", user);
            (void)fprintf(stderr, "%s: unknown user - '%s'\n", argv0, user);
            exit(1);
        }
        uid = pwd->pw_uid;
        gid = pwd->pw_gid;
    }

    /* Log file. */
    if (logfile != (char*)0) {
        logfp = fopen(logfile, "a");
        if (logfp == (FILE*)0) {
            syslog(LOG_CRIT, "%s - %m", logfile);
            perror(logfile);
            exit(1);
        }
        if (logfile[0] != '/') {
            syslog(LOG_WARNING, "logfile is not an absolute path, you may not be able to re-open it");
            (void)fprintf(stderr, "%s: logfile is not an absolute path, you may not be able to re-open it\n", argv0);
        }
        if (getuid() == 0) {
            /* If we are root then we chown the log file to the user we'll
            ** be switching to.
            */
            if (fchown(fileno(logfp), uid, gid) < 0) {
                syslog(LOG_WARNING, "fchown logfile - %m");
                perror("fchown logfile");
            }
        }
    }

    /* Look up hostname. */
    lookup_hostname(
        &host_addr4, sizeof(host_addr4), &gotv4,
        &host_addr6, sizeof(host_addr6), &gotv6);
    if (hostname == (char*)0) {
        (void)gethostname(hostname_buf, sizeof(hostname_buf));
        hostname = hostname_buf;
    }
    if (!(gotv4 || gotv6)) {
        syslog(LOG_CRIT, "can't find any valid address");
        (void)fprintf(stderr, "%s: can't find any valid address\n", argv0);
        exit(1);
    }

    /* Initialize listen sockets.  Try v6 first because of a Linux peculiarity;
    ** like some other systems, it has magical v6 sockets that also listen for
    ** v4, but in Linux if you bind a v4 socket first then the v6 bind fails.
    */
    if (gotv6)
        listen6_fd = initialize_listen_socket(&host_addr6);
    else
        listen6_fd = -1;
    if (gotv4)
        listen4_fd = initialize_listen_socket(&host_addr4);
    else
        listen4_fd = -1;
    /* If we didn't get any valid sockets, fail. */
    if (listen4_fd == -1 && listen6_fd == -1) {
        syslog(LOG_CRIT, "can't bind to any address");
        (void)fprintf(stderr, "%s: can't bind to any address\n", argv0);
        exit(1);
    }

#ifdef USE_SSL
    if (do_ssl) {
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();
        ssl_ctx = SSL_CTX_new(SSLv23_server_method());
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        if (certfile[0] != '\0')
            if (SSL_CTX_use_certificate_file(ssl_ctx, certfile, SSL_FILETYPE_PEM) == 0 ||
                SSL_CTX_use_certificate_chain_file(ssl_ctx, certfile) == 0 ||
                SSL_CTX_use_PrivateKey_file(ssl_ctx, certfile, SSL_FILETYPE_PEM) == 0 ||
                SSL_CTX_check_private_key(ssl_ctx) == 0) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
        if (cipher != (char*)0) {
            if (SSL_CTX_set_cipher_list(ssl_ctx, cipher) == 0) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
        }
    }
#endif /* USE_SSL */

    if (!debug) {
        /* Make ourselves a daemon. */
#ifdef HAVE_DAEMON
        if (daemon(1, 1) < 0) {
            syslog(LOG_CRIT, "daemon - %m");
            perror("daemon");
            exit(1);
        }
#else
        switch (fork()) {
            case 0:
                break;
            case -1:
                syslog(LOG_CRIT, "fork - %m");
                perror("fork");
                exit(1);
            default:
                exit(0);
        }
#ifdef HAVE_SETSID
        (void)setsid();
#endif
#endif
    } else {
        /* Even if we don't daemonize, we still want to disown our parent
        ** process.
        */
#ifdef HAVE_SETSID
        (void)setsid();
#endif /* HAVE_SETSID */
    }

    if (pidfile != (char*)0) {
        /* Write the PID file. */
        FILE* pidfp = fopen(pidfile, "w");
        if (pidfp == (FILE*)0) {
            syslog(LOG_CRIT, "%s - %m", pidfile);
            perror(pidfile);
            exit(1);
        }
        (void)fprintf(pidfp, "%d\n", (int)getpid());
        (void)fclose(pidfp);
    }

    /* Read zone info now, in case we chroot(). */
    tzset();

    /* If we're root, start becoming someone else. */
    if (getuid() == 0) {
        /* Set aux groups to null. */
        if (setgroups(0, (gid_t*)0) < 0) {
            syslog(LOG_CRIT, "setgroups - %m");
            perror("setgroups");
            exit(1);
        }
        /* Set primary group. */
        if (setgid(gid) < 0) {
            syslog(LOG_CRIT, "setgid - %m");
            perror("setgid");
            exit(1);
        }
        /* Try setting aux groups correctly - not critical if this fails. */
        if (initgroups(user, gid) < 0) {
            syslog(LOG_ERR, "initgroups - %m");
            perror("initgroups");
        }
#ifdef HAVE_SETLOGIN
        /* Set login name. */
        (void)setlogin(user);
#endif /* HAVE_SETLOGIN */
    }

    /* Switch directories if requested. */
    if (dir != (char*)0) {
        if (chdir(dir) < 0) {
            syslog(LOG_CRIT, "chdir - %m");
            perror("chdir");
            exit(1);
        }
    }

    /* Get current directory. */
    (void)getcwd(cwd, sizeof(cwd) - 1);
    if (cwd[strlen(cwd) - 1] != '/')
        (void)strcat(cwd, "/");

    /* Chroot if requested. */
    if (do_chroot) {
        if (chroot(cwd) < 0) {
            syslog(LOG_CRIT, "chroot - %m");
            perror("chroot");
            exit(1);
        }
        /* If we're logging and the logfile's pathname begins with the
        ** chroot tree's pathname, then elide the chroot pathname so
        ** that the logfile pathname still works from inside the chroot
        ** tree.
        */
        if (logfile != (char*)0) {
            if (strncmp(logfile, cwd, strlen(cwd)) == 0) {
                (void)ol_strcpy(logfile, &logfile[strlen(cwd) - 1]);
                /* (We already guaranteed that cwd ends with a slash, so leaving
                ** that slash in logfile makes it an absolute pathname within
                ** the chroot tree.)
                */
            } else {
                syslog(LOG_WARNING, "logfile is not within the chroot tree, you will not be able to re-open it");
                (void)fprintf(stderr, "%s: logfile is not within the chroot tree, you will not be able to re-open it\n", argv0);
            }
        }
        (void)strcpy(cwd, "/");
        /* Always chdir to / after a chroot. */
        if (chdir(cwd) < 0) {
            syslog(LOG_CRIT, "chroot chdir - %m");
            perror("chroot chdir");
            exit(1);
        }
    }

    /* Switch directories again if requested. */
    if (data_dir != (char*)0) {
        if (chdir(data_dir) < 0) {
            syslog(LOG_CRIT, "data_dir chdir - %m");
            perror("data_dir chdir");
            exit(1);
        }
    }

    /* If we're root, become someone else. */
    if (getuid() == 0) {
        /* Set uid. */
        if (setuid(uid) < 0) {
            syslog(LOG_CRIT, "setuid - %m");
            perror("setuid");
            exit(1);
        }
        /* Check for unnecessary security exposure. */
        if (!do_chroot) {
            syslog(LOG_WARNING,
                   "started as root without requesting chroot(), warning only");
            (void)fprintf(stderr,
                          "%s: started as root without requesting chroot(), warning only\n", argv0);
        }
    }

    /* Catch various signals. */
#ifdef HAVE_SIGSET
    (void)sigset(SIGTERM, handle_sigterm);
    (void)sigset(SIGINT, handle_sigterm);
    (void)sigset(SIGUSR1, handle_sigterm);
    (void)sigset(SIGHUP, handle_sighup);
    (void)sigset(SIGCHLD, handle_sigchld);
    (void)sigset(SIGPIPE, SIG_IGN);
#else  /* HAVE_SIGSET */
    (void)signal(SIGTERM, handle_sigterm);
    (void)signal(SIGINT, handle_sigterm);
    (void)signal(SIGUSR1, handle_sigterm);
    (void)signal(SIGHUP, handle_sighup);
    (void)signal(SIGCHLD, handle_sigchld);
    (void)signal(SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGSET */
    got_hup = 0;

    init_mime();

    if (hostname == (char*)0)
        syslog(
            LOG_NOTICE, "%.80s starting on port %d", SERVER_SOFTWARE,
            (int)port);
    else
        syslog(
            LOG_NOTICE, "%.80s starting on %.80s, port %d", SERVER_SOFTWARE,
            hostname, (int)port);

    /* Main loop. */
    for (;;) {
        /* Do we need to re-open the log file? */
        if (got_hup) {
            re_open_logfile();
            got_hup = 0;
        }

        /* Do a select() on at least one and possibly two listen fds.
        ** If there's only one listen fd then we could skip the select
        ** and just do the (blocking) accept(), saving one system call;
        ** that's what happened up through version 1.18.  However there
        ** is one slight drawback to that method: the blocking accept()
        ** is not interrupted by a signal call.  Since we definitely want
        ** signals to interrupt a waiting server, we use select() even
        ** if there's only one fd.
        */
        FD_ZERO(&lfdset);
        maxfd = -1;
        if (listen4_fd != -1) {
            FD_SET(listen4_fd, &lfdset);
            if (listen4_fd > maxfd)
                maxfd = listen4_fd;
        }
        if (listen6_fd != -1) {
            FD_SET(listen6_fd, &lfdset);
            if (listen6_fd > maxfd)
                maxfd = listen6_fd;
        }
        if (select(maxfd + 1, &lfdset, (fd_set*)0, (fd_set*)0, (struct timeval*)0) < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue; /* try again */
            syslog(LOG_CRIT, "select - %m");
            perror("select");
            exit(1);
        }

        /* Accept the new connection. */
        sz = sizeof(usa);
        if (listen4_fd != -1 && FD_ISSET(listen4_fd, &lfdset))
            conn_fd = accept(listen4_fd, &usa.sa, &sz);
        else if (listen6_fd != -1 && FD_ISSET(listen6_fd, &lfdset))
            conn_fd = accept(listen6_fd, &usa.sa, &sz);
        else {
            syslog(LOG_CRIT, "select failure");
            (void)fprintf(stderr, "%s: select failure\n", argv0);
            exit(1);
        }
        if (conn_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED)
                continue; /* try again */
#ifdef EPROTO
            if (errno == EPROTO)
                continue; /* try again */
#endif                    /* EPROTO */
            syslog(LOG_CRIT, "accept - %m");
            perror("accept");
            exit(1);
        }

        /* Fork a sub-process to handle the connection. */
        r = fork();
        if (r < 0) {
            syslog(LOG_CRIT, "fork - %m");
            perror("fork");
            exit(1);
        }
        if (r == 0) {
            /* Child process. */
            client_addr = usa;
            if (listen4_fd != -1)
                (void)close(listen4_fd);
            if (listen6_fd != -1)
                (void)close(listen6_fd);
            handle_request();
        }
        (void)close(conn_fd);
    }
}

static void
usage(void) {
#ifdef USE_SSL
    (void)fprintf(stderr, "usage:  %s [-C configfile] [-D] [-S] [-E certfile] [-Y cipher] [-p port] [-d dir] [-dd data_dir] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile] [-T charset] [-P P3P] [-M maxage]\n", argv0);
#else  /* USE_SSL */
    (void)fprintf(stderr, "usage:  %s [-C configfile] [-D] [-p port] [-d dir] [-dd data_dir] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile] [-T charset] [-P P3P] [-M maxage]\n", argv0);
#endif /* USE_SSL */
    exit(1);
}

static void
read_config(char* filename) {
    FILE* fp;
    char line[10000];
    char* cp;
    char* cp2;
    char* name;
    char* value;

    fp = fopen(filename, "r");
    if (fp == (FILE*)0) {
        syslog(LOG_CRIT, "%s - %m", filename);
        perror(filename);
        exit(1);
    }

    while (fgets(line, sizeof(line), fp) != (char*)0) {
        /* Trim comments. */
        if ((cp = strchr(line, '#')) != (char*)0)
            *cp = '\0';

        /* Skip leading whitespace. */
        cp = line;
        cp += strspn(cp, " \t\012\015");

        /* Split line into words. */
        while (*cp != '\0') {
            /* Find next whitespace. */
            cp2 = cp + strcspn(cp, " \t\012\015");
            /* Insert EOS and advance next-word pointer. */
            while (*cp2 == ' ' || *cp2 == '\t' || *cp2 == '\012' || *cp2 == '\015')
                *cp2++ = '\0';
            /* Split into name and value. */
            name = cp;
            value = strchr(name, '=');
            if (value != (char*)0)
                *value++ = '\0';
            /* Interpret. */
            if (strcasecmp(name, "debug") == 0) {
                no_value_required(name, value);
                debug = 1;
            } else if (strcasecmp(name, "port") == 0) {
                value_required(name, value);
                port = (unsigned short)atoi(value);
            } else if (strcasecmp(name, "dir") == 0) {
                value_required(name, value);
                dir = e_strdup(value);
            } else if (strcasecmp(name, "data_dir") == 0) {
                value_required(name, value);
                data_dir = e_strdup(value);
            } else if (strcasecmp(name, "chroot") == 0) {
                no_value_required(name, value);
                do_chroot = 1;
            } else if (strcasecmp(name, "nochroot") == 0) {
                no_value_required(name, value);
                do_chroot = 0;
            } else if (strcasecmp(name, "user") == 0) {
                value_required(name, value);
                user = e_strdup(value);
            } else if (strcasecmp(name, "cgipat") == 0) {
                value_required(name, value);
                cgi_pattern = e_strdup(value);
            } else if (strcasecmp(name, "urlpat") == 0) {
                value_required(name, value);
                url_pattern = e_strdup(value);
            } else if (strcasecmp(name, "noemptyreferers") == 0 ||
                       strcasecmp(name, "noemptyreferrers") == 0) {
                value_required(name, value);
                no_empty_referrers = 1;
            } else if (strcasecmp(name, "localpat") == 0) {
                value_required(name, value);
                local_pattern = e_strdup(value);
            } else if (strcasecmp(name, "host") == 0) {
                value_required(name, value);
                hostname = e_strdup(value);
            } else if (strcasecmp(name, "logfile") == 0) {
                value_required(name, value);
                logfile = e_strdup(value);
            } else if (strcasecmp(name, "vhost") == 0) {
                no_value_required(name, value);
                vhost = 1;
            } else if (strcasecmp(name, "pidfile") == 0) {
                value_required(name, value);
                pidfile = e_strdup(value);
            } else if (strcasecmp(name, "charset") == 0) {
                value_required(name, value);
                charset = e_strdup(value);
            } else if (strcasecmp(name, "p3p") == 0) {
                value_required(name, value);
                p3p = e_strdup(value);
            } else if (strcasecmp(name, "max_age") == 0) {
                value_required(name, value);
                max_age = atoi(value);
            }
#ifdef USE_SSL
            else if (strcasecmp(name, "ssl") == 0) {
                no_value_required(name, value);
                do_ssl = 1;
            } else if (strcasecmp(name, "certfile") == 0) {
                value_required(name, value);
                certfile = e_strdup(value);
            } else if (strcasecmp(name, "cipher") == 0) {
                value_required(name, value);
                cipher = e_strdup(value);
            }
#endif /* USE_SSL */
            else {
                (void)fprintf(
                    stderr, "%s: unknown config option '%s'\n", argv0, name);
                exit(1);
            }

            /* Advance to next word. */
            cp = cp2;
            cp += strspn(cp, " \t\012\015");
        }
    }

    (void)fclose(fp);
}

static void
value_required(char* name, char* value) {
    if (value == (char*)0) {
        (void)fprintf(
            stderr, "%s: value required for %s option\n", argv0, name);
        exit(1);
    }
}

static void
no_value_required(char* name, char* value) {
    if (value != (char*)0) {
        (void)fprintf(
            stderr, "%s: no value required for %s option\n",
            argv0, name);
        exit(1);
    }
}

static int
initialize_listen_socket(usockaddr* usaP) {
    int listen_fd;
    int i;

    /* Check sockaddr. */
    if (!sockaddr_check(usaP)) {
        syslog(
            LOG_ERR, "unknown sockaddr family on listen socket - %d",
            usaP->sa.sa_family);
        (void)fprintf(
            stderr, "%s: unknown sockaddr family on listen socket - %d\n",
            argv0, usaP->sa.sa_family);
        return -1;
    }

    listen_fd = socket(usaP->sa.sa_family, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        syslog(LOG_CRIT, "socket %.80s - %m", ntoa(usaP));
        perror("socket");
        return -1;
    }

    (void)fcntl(listen_fd, F_SETFD, 1);

    i = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*)&i, sizeof(i)) < 0) {
        syslog(LOG_CRIT, "setsockopt SO_REUSEADDR - %m");
        perror("setsockopt SO_REUSEADDR");
        return -1;
    }

    if (bind(listen_fd, &usaP->sa, sockaddr_len(usaP)) < 0) {
        syslog(LOG_CRIT, "bind %.80s - %m", ntoa(usaP));
        perror("bind");
        return -1;
    }

    if (listen(listen_fd, 1024) < 0) {
        syslog(LOG_CRIT, "listen - %m");
        perror("listen");
        return -1;
    }

#ifdef HAVE_ACCEPT_FILTERS
    {
        struct accept_filter_arg af;
        (void)bzero(&af, sizeof(af));
        (void)strcpy(af.af_name, ACCEPT_FILTER_NAME);
        (void)setsockopt(listen_fd, SOL_SOCKET, SO_ACCEPTFILTER, (char*)&af, sizeof(af));
    }
#endif /* HAVE_ACCEPT_FILTERS */

    return listen_fd;
}

static int conn_d3_trusted_core() {
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sock < 0){
		return -1;
	}
	struct sockaddr_un sock_addr;
	sock_addr.sun_family = AF_UNIX;
	strncpy(sock_addr.sun_path, "/var/run/d3_trusted_core.sock", sizeof(sock_addr.sun_path) - 1);
	if(connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0){
		return -1;
	}	
    int enable = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &enable, sizeof(enable)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
	return sock;
}

static int do_check_session_format(const char *session_id){
    if (!session_id) {
        return 1;
    }
    if (!(strlen(session_id)>0 && strlen(session_id) <= HTTP_SESSION_LEN)) {
        return 1;
    }
    for (int i = 0; i < HTTP_SESSION_LEN; i++) {
        if (!isxdigit(session_id[i])) {
            return 1;
        }
    }
    return 0;
}

static void do_login_passwd(const char *username, const char *password){
	int login_result = 0;
	char *session_id = NULL;
	if(strlen(username) > MAX_USERNAME_LEN || strlen(password) > MAX_PASSWORD_LEN){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
	}
	// write data "command auth_user_paswd <username> <password>" to "/var/run/d3_trusted_core.sock" 
	// and read response as session id
	int sock = conn_d3_trusted_core();
	if(sock < 0){
		send_error(500, "Internal Server Error", "", "Internal Server Error.");
	}
	char *buf = calloc(1, 1024+1);
	if(!buf){
		close(sock);
		send_error(500, "Internal Server Error", "", "Internal Server Error.");
	}
	// write cmd
	snprintf(buf, 1024, "!! command auth_user_passwd %s %s", username, password);
    // write to sock in a loop
    int buf_len = strlen(buf);
    int offset = 0;
    while(buf_len > 0){
        int ret = write(sock, buf+offset, buf_len);
        if(ret < 0){
            free(buf);
            close(sock);
            send_error(500, "Internal Server Error", "", "Internal Server Error.");
        }
        buf_len -= ret;
        offset += ret;
    }
	memset(buf, 0, 1024);
	// read session id
    int recv_size = recv(sock, buf, 1024, 0);
    if(recv_size < 0){
        free(buf);
        close(sock);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
	if(strcasecmp(buf, "<error>") == 0){
		// failed
		login_result = 0;
	} else{
		// success
		session_id = calloc(1, strlen(buf)+1);
		if(!session_id){
			free(buf);
			close(sock);
			send_error(500, "Internal Server Error", "", "Internal Server Error.");
		}
		strncpy(session_id, buf, strlen(buf));
        login_result = 1;
	}
	free(buf);
	close(sock);

	if(login_result){ // success
		char cookie_head[] = "Set-Cookie: session_id=";
		char cookie_tail[] = "; Path=/;";
		char resp_data_success[] = "{\"code\": 0, \"msg\":\"success\"}";
		uint32_t extra_header_size = strlen(cookie_head)+strlen(session_id)+strlen(cookie_tail)+8;
		char *extra_header = calloc(1, extra_header_size);
		if (!extra_header) {
			free(session_id);
			close(sock);
			send_error(500, "Internal Server Error", "", "Internal Server Error.");
		}
		snprintf(extra_header, extra_header_size, "%s%s%s", cookie_head, session_id, cookie_tail);
		add_headers(200, "OK", extra_header, NULL, "text/html", strlen(resp_data_success), (time_t)-1);
		add_to_response(resp_data_success);
		send_response();
		free(extra_header);
		free(session_id);
	} else{
		char resp_data_fail[] = "{\"code\": 1, \"msg\":\"fail\"}";
		add_headers(200, "OK", "", NULL, "text/html", strlen(resp_data_fail), (time_t)-1);
		add_to_response(resp_data_fail);
		send_response();
	}
}

static void do_login_face_id(const char *username, const vec_float *face_data){
	int login_result = 0;
	char *session_id = NULL;
	if(strlen(username) > MAX_USERNAME_LEN){
		send_error(500, "Internal Server Error", "", "Internal Server Error.");
	}
	// write data "command auth_user_face <username> <face_data>" to "/var/run/d3_trusted_core.sock" 
	// and read response as session id
	int sock = conn_d3_trusted_core();
	if(sock < 0){
		send_error(500, "Internal Server Error", "", "Internal Server Error.");
	}
	char *buf = calloc(1, 1024);
	// write cmd
	snprintf(buf, 1024, "!! command auth_user_face_id %s", username);
	if(write(sock, buf, strlen(buf)) < 0){
		free(buf);
		close(sock);
		send_error(500, "Internal Server Error", "", "Internal Server Errror 3.");
	}
	// if read <data> then send face data, <error> means fail
	memset(buf, 0, 1024);
    // get recv data by recv()
	int recv_size = recv(sock, buf, 1023, 0);
	if(recv_size <= 0){
		printf("Rpc recv error!\n");
		send_error(500, "Internal Server Error", "", "Internal Server Error.");
	}
	// send face data
	if(strncasecmp(buf, "<data>", 6) == 0){
		if(write(sock, (uint8_t *)face_data, 128*sizeof(vec_float)) != 128*sizeof(vec_float)){
			free(buf);
			close(sock);
			send_error(500, "Internal Server Error", "", "Internal Server Error.");
		}
	} else{
        free(buf);
        close(sock);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
	// read session id
	memset(buf, 0, 1024);
	recv_size = recv(sock, buf, 1023, 0);
	if(recv_size <= 0){
		free(buf);
		close(sock);
		send_error(500, "Internal Server Error", "", "Internal Server Error.");
	}
    if(strncasecmp(buf, "<disabled>", 10) == 0){
        // face id disabled
        char resp_data_fail[] = "{\"code\": 2, \"msg\":\"disabled\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(resp_data_fail), (time_t)-1);
        add_to_response(resp_data_fail);
        send_response();
        free(buf);
        close(sock);
        return;
    }
    if(strncasecmp(buf, "<expired>", 9) == 0){
        // face id disabled
        char resp_data_fail[] = "{\"code\": 3, \"msg\":\"expired\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(resp_data_fail), (time_t)-1);
        add_to_response(resp_data_fail);
        send_response();
        free(buf);
        close(sock);
        return;
    }
	if(strncasecmp(buf, "<error>", 7) == 0){
		// failed
		session_id = NULL;
		login_result = 0;
	} else{
		// success
        // read session_id
        if (!(strlen(buf) > 0)) {
            free(buf);
            close(sock);
            send_error(500, "Internal Server Error", "", "Internal Server Error.");
        } else{
            session_id = calloc(1, strlen(buf)+1);
            strncpy(session_id, buf, strlen(buf));
            login_result = 1;
        }
	}
	free(buf);
	close(sock);

	if(login_result){ // success
		char cookie_head[] = "Set-Cookie: session_id=";
		char cookie_tail[] = "; Path=/;";
		char resp_data_success[] = "{\"code\": 0, \"msg\":\"success\"}";
		uint32_t extra_header_size = strlen(cookie_head)+strlen(session_id)+strlen(cookie_tail)+8;
		char *extra_header = calloc(1, extra_header_size);
		if (!extra_header) {
			free(session_id);
			close(sock);
			send_error(500, "Internal Server Error", "", "Internal Server Error.");
		}
		snprintf(extra_header, extra_header_size, "%s%s%s", cookie_head, session_id, cookie_tail);
		add_headers(200, "OK", extra_header, NULL, "text/html", strlen(resp_data_success), (time_t)-1);
		add_to_response(resp_data_success);
		send_response();
		free(session_id);
	} else{
        char resp_data_fail[] = "{\"code\": 1, \"msg\":\"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(resp_data_fail), (time_t)-1);
        add_to_response(resp_data_fail);
		send_response();
	}
}

static int do_auth_session_id(const char *session_id){
    if (do_check_session_format(session_id)) {
        return 1;
    }
    int sock = conn_d3_trusted_core();
    if(sock < 0){
        return 1;
    }
    char *buf = calloc(1, 1024);
    // write cmd
    snprintf(buf, 1024, "!! command auth_session_id %s", session_id);
    if(write(sock, buf, strlen(buf)) < 0){
        free(buf);
        close(sock);
        return 1;
    }
    memset(buf, 0, 1024);
    // get recv data by recv()
    int recv_size = recv(sock, buf, 1023, 0);
    if(recv_size <= 0){
        free(buf);
        close(sock);
        return 1;
    }
    if(strncasecmp(buf, "<error>", 7) == 0){
        free(buf);
        close(sock);
        return 1;
    } else if (strncasecmp(buf, "<disabled>", 10) == 0){
        free(buf);
        close(sock);
        return 2;
    } else{
        free(buf);
        close(sock);
        return 0;
    }
}

static int internal_get_user_info(const char *session_id, user_info_out_t **res){
    if(!session_id || !res){
        return 1;
    }
    int sock = conn_d3_trusted_core();
    if(sock < 0){
        return 1;
    }
    char *buf = calloc(1, 1024);
    // write cmd
    snprintf(buf, 1024, "!! command user info %s", session_id);
    if(write(sock, buf, strlen(buf)) < 0){
        free(buf);
        close(sock);
        return 1;
    }
    memset(buf, 0, 1024);
    // get recv data by recv()
    int recv_size = recv(sock, buf, 1023, 0);
    if(recv_size <= 0){
        printf("Rpc recv error!\n");
        return 1;
    }
    if(!strncasecmp(buf, "<error>", 7)){
        // failed
        free(buf);
        close(sock);
        return 1;
    } else{
        // success
        user_info_out_t *tmp_res = (user_info_out_t *)calloc(1, sizeof(user_info_out_t)+sizeof(size_t));
        if (tmp_res == NULL) {
            free(buf);
            close(sock);
            return 1;
        }
        memcpy(tmp_res, buf, sizeof(user_info_out_t));
        *res = tmp_res;
        free(buf);
        close(sock);
        return 0;
    }
}

static void do_user_info(const char *session_id){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    user_info_out_t *user_info = NULL;
    if(internal_get_user_info(session_id, &user_info)){
        send_error(500, "Internal Server Error", "", "Internal Server Error. 1");
    }
    // parse user info
    char *user_name = NULL;
    uint32_t user_uid = -1;
    char *user_type = NULL;
    char *user_face_id = NULL;
    char *user_status = NULL;
    switch(user_info->magic){
        case USER_MAGIC_NORMAL:
            user_status = "normal";
            break;
        case USER_MAGIC_DISABLED:
            user_status = "disabled";
            break;         
        default:
            user_status = "invalid";
            break;
    }
    user_name = strdup(user_info->username);
    user_uid = user_info->uid;
    switch(user_info->type){
        case USER_TYPE_ADMIN:
            user_type = "admin";
            break;
        case USER_TYPE_USER:
            user_type = "user";
            break;
        case USER_TYPE_GUEST:
            user_type = "guest";
            break;
        default:
            user_type = "unknown";
            break;
    }
    user_face_id = user_info->face_id == 0 ? "disabled" : "enabled";
    

    char *result_json_fmt = "{\"code\": 0, \"msg\": \"success\", \"data\": "
    "{\"status\": \"%s\", \"uid\": %d, \"name\": \"%s\", \"type\": \"%s\", \"face_id\": \"%s\"}}";
    uint32_t result_json_size = strlen(result_json_fmt) + strlen(user_status) + strlen(user_name) + strlen(user_type) + strlen(user_face_id) + 32;
    char *result_json = calloc(1, result_json_size+1);
    if (!result_json) {
        free(user_name);
        free(user_info);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    snprintf(result_json, result_json_size+1, result_json_fmt, user_status, user_uid, user_name, user_type, user_face_id);
    add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
    add_to_response(result_json);
    send_response();
    free(user_name);
    free(result_json);
    free(user_info);
}

static int internal_do_user_list(const char *session_id, uint32_t *count, user_info_out_t **res){
    if(!session_id || !count || !res){
        return 1;
    }
    int sock = conn_d3_trusted_core();
    if(sock < 0){
        return 1;
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! command user list %s", session_id);
    if(write(sock, buf, strlen(buf)) < 0){
        free(buf);
        close(sock);
        return 1;
    }
    memset(buf, 0, 1024);
    // get recv data by recv()
    int recv_size = recv(sock, buf, 1023, 0);
    if(recv_size <= 0){
        printf("Rpc recv error!\n");
        return 1;
    }
    if(!strncasecmp(buf, "<error>", 7)){
        // failed
        free(buf);
        close(sock);
        return 1;
    }
    // read num
    uint32_t res_count = 0;
    res_count = strtol(buf, NULL, 10);
    if(res_count == 0){
        *count = res_count;
        *res = NULL;
    }
    if(write(sock, "<data>", 6) < 0){
        free(buf);
        close(sock);
        return 1;
    }
    user_info_out_t *list = calloc(sizeof(user_info_out_t), res_count);
    if(!list){
        free(buf);
        close(sock);
        return 1;            
    }
    recv_size = recv(sock, list, res_count*sizeof(user_info_out_t), 0);
    if(recv_size <= 0){
        printf("Rpc recv error!\n");
        return 1;
    }
    if(!strncasecmp((char *)list, "<error>", 7)){
        // failed
        free(buf);
        free(list);
        close(sock);
        return 1;
    }
    *count = res_count;
    *res = list;
    free(buf);
    close(sock);
    return 0;
}

static void do_user_list(const char *session_id){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    uint32_t count = 0;
    user_info_out_t *res = NULL;
    if(internal_do_user_list(session_id, &count, &res)){
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        return;
    }

    char *tmp_buf = NULL;
    uint32_t tmp_size = 0;
    char *resp = NULL;
    size_t content_size = 0;
    size_t content_length = 0;

    char *json_header = "{\"code\": 0, \"msg\": \"success\", \"data\": [";
    char *json_tail = "]}";
    char *user_info_fmt = "{\"status\": \"%s\", \"uid\": %d, \"name\": \"%s\", \"type\": \"%s\", \"face_id\": \"%s\"}";
    
    add_str(&resp, &content_size, &content_length, json_header);
    for(int i=0; i<count; i++){
        char *user_name = NULL;
        uint32_t user_uid = -1;
        char *user_type = NULL;
        char *user_face_id = NULL;
        char *user_status = NULL;

        switch(res[i].magic){
            case USER_MAGIC_NORMAL:
                user_status = "normal";
                break;
            case USER_MAGIC_DISABLED:
                user_status = "disabled";
                break;         
            default:
                user_status = "invalid";
                break;
        }
        user_name = strdup(res[i].username);
        user_uid = res[i].uid;
        switch(res[i].type){
            case USER_TYPE_ADMIN:
                user_type = "admin";
                break;
            case USER_TYPE_USER:
                user_type = "user";
                break;
            case USER_TYPE_GUEST:
                user_type = "guest";
                break;
            default:
                user_type = "unknown";
                break;
        }
        user_face_id = res[i].face_id == 0 ? "disabled" : "enabled";
        tmp_size = strlen(user_info_fmt) + strlen(user_status) + strlen(user_name) + strlen(user_type) + strlen(user_face_id) + 32;
        tmp_buf = calloc(tmp_size+1, 1);
        snprintf(tmp_buf, tmp_size+1, user_info_fmt, user_status, user_uid, user_name, user_type, user_face_id);
        add_str(&resp, &content_size, &content_length, tmp_buf);
        free(tmp_buf);
        if(i != count-1){
            add_str(&resp, &content_size, &content_length, ", ");
        }
    }
    add_str(&resp, &content_size, &content_length, json_tail);
    add_headers(200, "OK", "", NULL, "text/html", content_length, (time_t)-1);
    add_to_response(resp);
    send_response();
    free(resp);
    free(res);
    return;
}

static void do_user_passwd(const char *session_id, const char *old_passwd, const char *new_passwd){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    if(!old_passwd || !new_passwd 
    || strlen(old_passwd) > MAX_PASSWORD_LEN || strlen(new_passwd) > MAX_PASSWORD_LEN){
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    if(strlen(new_passwd) < MIN_PASSWORD_LEN){
        char *result_json = "{\"code\": 2, \"msg\": \"too short\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        return;
    }

    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! command user passwd %s %s %s", session_id, old_passwd, new_passwd);
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        // failed
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        close(conn);
        free(buf);
        return;
    } else{
        // success
        char *result_json = "{\"code\": 0, \"msg\": \"success\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        close(conn);
        free(buf);
        return;
    }
}

static void gen_random_passwd(char *passwd, int len){
    int i;
    // random seed
    srand((unsigned)time(NULL));
    for(i = 0; i < len; i++){
        passwd[i] = rand() % 26 + 'a';
    }
}

static void do_user_enable(const char *session_id, const char *username){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    if (!username || strlen(username) > MAX_USERNAME_LEN) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! command user enable %s %s", session_id, username);
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        // failed
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        close(conn);
        free(buf);
        return;
    } else{
        // success
        char *result_json = calloc(1, 1024);
        snprintf(result_json, 1024, "{\"code\": 0, \"msg\": \"success\"}");
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        close(conn);
        free(buf);
        free(result_json);
        return;
    }
}

static void do_user_disable(const char *session_id, const char *username){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    if (!username || strlen(username) > MAX_USERNAME_LEN) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    // command 1
    int conn1 = conn_d3_trusted_core();
    if(conn1 < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! command user kickout %s %s", session_id, username);
    if(write(conn1, buf, strlen(buf)) < 0){
        free(buf);
        close(conn1);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn1, buf, 1023, 0) < 0){
        free(buf);
        close(conn1);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        // failed
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        close(conn1);
        free(buf);
        return;
    } else{
        close(conn1);
    }
    // command 2
    int conn2 = conn_d3_trusted_core();
    if(conn2 < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    snprintf(buf, 1024, "!! command user disable %s %s", session_id, username);
    if(write(conn2, buf, strlen(buf)) < 0){
        free(buf);
        close(conn2);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn1, buf, 1023, 0) < 0){
        free(buf);
        close(conn2);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        // failed
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        close(conn2);
        free(buf);
        return;
    } else{
        // success
        char *result_json = "{\"code\": 0, \"msg\": \"success\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        close(conn2);
        free(buf);
        return;
    }
}

static void do_user_reset(const char *session_id, const char *username, const vec_float *face_data){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    if (!username || strlen(username) > MAX_USERNAME_LEN) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    if(!face_data){
        snprintf(buf, 1024, "!! command user reset %s %s", session_id, username);
        if(write(conn, buf, strlen(buf)) < 0){
            free(buf);
            close(conn);
            send_error(500, "Internal Server Error", "", "Internal Server Error.");
        }
        memset(buf, 0, 1024);
        if(recv(conn, buf, 1023, 0) < 0){
            free(buf);
            close(conn);
            send_error(500, "Internal Server Error", "", "Internal Server Error.");
        }
        if(!strncasecmp(buf, "<error>", 7)){
            // failed
            char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
            add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
            add_to_response(result_json);
            send_response();
            close(conn);
            free(buf);
            return;
        } else{
            // success
            char *result_json = "{\"code\": 0, \"msg\": \"success\"}";
            add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
            add_to_response(result_json);
            send_response();
            close(conn);
            free(buf);
            return;
        }
    } else{
        snprintf(buf, 1024, "!! command user reset %s %s set_face_id", session_id, username);
        if(write(conn, buf, strlen(buf)) < 0){
            free(buf);
            close(conn);
            send_error(500, "Internal Server Error", "", "Internal Server Error.");
        }
        memset(buf, 0, 1024);
        if(recv(conn, buf, 1023, 0) < 0){
            free(buf);
            close(conn);
            send_error(500, "Internal Server Error", "", "Internal Server Error.");
        }
        if(strncasecmp(buf, "<data>", 6)){
            // failed
            char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
            add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
            add_to_response(result_json);
            send_response();
            close(conn);
            free(buf);
            return;
        }
        // send face data
		if(write(conn, (uint8_t *)face_data, 128*sizeof(vec_float)) != 128*sizeof(vec_float)){
			free(buf);
			close(conn);
			send_error(500, "Internal Server Error", "", "Internal Server Error.");
		}
        memset(buf, 0, 1024);
        if(recv(conn, buf, 1023, 0) < 0){
            free(buf);
            close(conn);
            send_error(500, "Internal Server Error", "", "Internal Server Error.");
        }
        if(!strncasecmp(buf, "<error>", 7)){
            // failed
            char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
            add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
            add_to_response(result_json);
            send_response();
            close(conn);
            free(buf);
            return;
        } else{
            // success
            char *result_json = "{\"code\": 0, \"msg\": \"success\"}";
            add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
            add_to_response(result_json);
            send_response();
            close(conn);
            free(buf);
            return;
        }
    }
}

static void do_user_logout(const char *session_id){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! command user logout %s", session_id);
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    int recv_size = recv(conn, buf, 1023, 0);
    if(recv_size <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        free(buf);
        close(conn);
        send_error(400, "Bad Request", "", "Bad parameter.");
    } else{
        free(buf);
        close(conn);
        char redirect_header[] = "Location: /login.html";
        char set_cookie_header[] = "Set-Cookie: session_id=; Path=/;";
        uint32_t extra_header_len = strlen(redirect_header) + strlen(set_cookie_header) + 2 + sizeof(size_t);
        char *extra_header = calloc(extra_header_len, sizeof(char));
        snprintf(extra_header, extra_header_len, "%s\r\n%s", redirect_header, set_cookie_header);
        char *result_json = "{\"code\": 0, \"msg\":\"success\"}";
        add_headers(200, "Found", "", extra_header, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    }
}

static void do_secfs_file_create(const char *session_id, uint32_t parent_id, const char *filename, const char *data, uint32_t data_sz){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! secfs create %s %d %s", session_id, parent_id, filename);
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(strncasecmp(buf, "<data>", 6) != 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    // send file data
    int wn = 0;
    while(wn < data_sz){
        int n = write(conn, data + wn, data_sz - wn);
        if(n < 0){
            free(buf);
            close(conn);
            send_error(500, "Internal Server Error", "", "Internal Server Error.");
        }
        wn += n;
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<ok>", 4)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 0, \"msg\":\"success\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    } else if(!strncasecmp(buf, "<ext_id:", 8)){
        uint32_t ext_id_out = strtol(buf + 8, NULL, 10);
        free(buf);
        close(conn);
        char *result_json_fmt = "{\"code\": 0, \"msg\":\"success\", \"data\": {\"ext_id\": %d}}";
        uint32_t result_json_len = strlen(result_json_fmt) + 32;
        char *result_json = calloc(result_json_len, sizeof(char));
        snprintf(result_json, result_json_len, result_json_fmt, ext_id_out);
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        free(result_json);
    } else if(!strncasecmp(buf, "<conflict>", 10)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 2, \"msg\": \"filename conflict\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();        
    } else if(!strncasecmp(buf, "<nospace>", 9)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 3, \"msg\": \"no space in secure file system\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();         
    } else{
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    }
}

static void do_secfs_file_update(const char *session_id, uint32_t ext_id, const char *data, uint32_t data_sz){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! secfs update %s %d", session_id, ext_id);
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(strncasecmp(buf, "<data>", 6) != 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    // send file data
    int wn = 0;
    while(wn < data_sz){
        int n = write(conn, data + wn, data_sz - wn);
        if(n < 0){
            free(buf);
            close(conn);
            send_error(500, "Internal Server Error", "", "Internal Server Error.");
        }
        wn += n;
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<ok>", 4)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 0, \"msg\":\"success\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    } else {
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    }
}

static void do_secfs_dir_create(const char *session_id, uint32_t parent_id, const char *dir_name){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! secfs mkdir %s %d %s", session_id, parent_id, dir_name);
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<ok>", 4)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 0, \"msg\":\"success\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    } else if(!strncasecmp(buf, "<ext_id:", 8)){
        uint32_t ext_id_out = strtol(buf + 8, NULL, 10);
        free(buf);
        close(conn);
        char *result_json_fmt = "{\"code\": 0, \"msg\":\"success\", \"data\": {\"ext_id\": %d}}";
        uint32_t result_json_len = strlen(result_json_fmt) + 32;
        char *result_json = calloc(result_json_len, sizeof(char));
        snprintf(result_json, result_json_len, result_json_fmt, ext_id_out);
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        free(result_json);
    } else if(!strncasecmp(buf, "<conflict>", 10)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 2, \"msg\": \"filename conflict\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();        
    } else if(!strncasecmp(buf, "<nospace>", 9)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 3, \"msg\": \"no space in secure file system\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();         
    } else{
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    }
}

static void do_secfs_file_delete(const char *session_id, uint32_t ext_id, const char* del_mode){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    if(del_mode){
        snprintf(buf, 1024, "!! secfs delete %s %d %s", session_id, ext_id, del_mode);
    } else{
        snprintf(buf, 1024, "!! secfs delete %s %d", session_id, ext_id);
    }
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    } else{
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 0, \"msg\":\"success\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    }
}

static void do_secfs_dir_delete(const char *session_id, uint32_t ext_id, const char *rm_mode){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    if(rm_mode){
        snprintf(buf, 1024, "!! secfs rmdir %s %d %s", session_id, ext_id, rm_mode);
    } else{
        snprintf(buf, 1024, "!! secfs rmdir %s %d nonrecur", session_id, ext_id);
    }
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    } else{
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 0, \"msg\":\"success\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    }
}

static void do_secfs_file_info(const char *session_id, uint32_t ext_id){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! secfs info file %s %d", session_id, ext_id);
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        goto READ_FAIL;
    } else{
        /*
        typedef struct FileInfo file_info_t;
        #pragma pack(1)
        struct FileInfo{
            uint32_t magic; // "file" 0x656c6966
            uint32_t node_type;
            uint32_t parent_id;
            uint32_t ext_id;
            uint32_t owner;
            uint32_t file_size;
            char filename[MAX_FILE_NAME];
            char hash[TEE_SHA256_HASH_SIZE*2];
        };
        */
        file_info_t file_info;
        memset(&file_info, 0, sizeof(file_info_t));
        memcpy(&file_info, buf, sizeof(file_info_t));
        if(file_info.magic != 0x656c6966){
            goto READ_FAIL;
        }
        char *note_type = NULL;
        uint32_t parent_id = file_info.parent_id;
        uint32_t ext_id = file_info.ext_id;
        uint32_t owner = file_info.owner;
        uint32_t file_size = file_info.file_size;
        char filename[MAX_FILE_NAME+1] = {0};
        char hash[SHA256_DIGEST_LENGTH*2+1] = {0};
        memcpy(filename, file_info.filename, MAX_FILE_NAME);
        memcpy(hash, file_info.hash, SHA256_DIGEST_LENGTH*2);
        switch (file_info.node_type) {
            case FILE_NODE_FILE:
                note_type = "file";
                break;
            default:
                goto READ_FAIL;
                break;
        }
        char *result_json = "{\"code\": 0, \"msg\":\"success\", \"data\": {\"note_type\": \"%s\", \"parent_id\": %d, \"ext_id\": %d, \"owner\": %d, \"file_size\": %d, \"filename\": \"%s\", \"hash\": \"%s\"}}";
        uint32_t json_size = strlen(result_json)+strlen(note_type)+strlen(filename)+strlen(hash)+256;
        char *result = calloc(1, json_size);
        snprintf(result, json_size, result_json, note_type, parent_id, ext_id, owner, file_size, filename, hash);
        add_headers(200, "OK", "", NULL, "text/html", strlen(result), (time_t)-1);
        add_to_response(result);
        send_response();
        free(buf);
        close(conn);
        free(result);
        return;
    }
READ_FAIL:
    free(buf);
    close(conn);
    char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
    add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
    add_to_response(result_json);
    send_response();
}

static void do_secfs_dir_info(const char *session_id, uint32_t ext_id){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! secfs info dir %s %d", session_id, ext_id);
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error.");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        goto READ_FAIL;
    } else{
        /*
        typedef struct DirInfo dir_info_t;
        #pragma pack(1)
        struct DirInfo{
            uint32_t magic; // "dir" 0x726964
            uint32_t node_type;
            uint32_t parent_id;
            uint32_t ext_id;
            uint32_t owner;
            char dir_name[MAX_FILE_NAME];
            uint8_t sub_items[MAX_FILE_COUNT];
        };
        */
        dir_info_t dir_info;
        memset(&dir_info, 0, sizeof(dir_info_t));
        memcpy(&dir_info, buf, sizeof(dir_info_t));
        if(dir_info.magic != 0x726964){
            goto READ_FAIL;
        }
        char *note_type = NULL;
        uint32_t parent_id = dir_info.parent_id;
        uint32_t ext_id = dir_info.ext_id;
        uint32_t owner = dir_info.owner;
        char dir_name[MAX_FILE_NAME+1] = {0};
        memcpy(dir_name, dir_info.dir_name, MAX_FILE_NAME);
        switch (dir_info.node_type) {
            case FILE_NODE_DIR:
                note_type = "dir";
                break;
            default:
                goto READ_FAIL;
                break;
        }
        char *resp = NULL;
        size_t content_size = 0;
        size_t content_length = 0;
        char *json_head = "{\"code\": 0, \"msg\":\"success\", \"data\": {\"note_type\": \"%s\", \"parent_id\": %d, \"ext_id\": %d, \"owner\": %d, \"dir_name\": \"%s\", \"sub_ext_id\": [";
        char *json_tail = "]}}";
        uint32_t sub_items_count = 0;
        uint32_t json_head_size = strlen(json_head)+strlen(note_type)+strlen(dir_name)+128;
        char *json_head_buf = calloc(1, json_head_size);
        snprintf(json_head_buf, json_head_size, json_head, note_type, parent_id, ext_id, owner, dir_name);
        add_str(&resp, &content_size, &content_length, json_head_buf);
        free(json_head_buf);
        for(int i = 0; i < MAX_FILE_COUNT; i++){
            if(dir_info.sub_items[i]){
                if(sub_items_count != 0){
                    add_str(&resp, &content_size, &content_length, ", ");
                }
                char tmp[32] = {0};
                snprintf(tmp, 32, "%d", i);
                add_str(&resp, &content_size, &content_length, tmp);
                sub_items_count += 1;
            }
        }
        add_str(&resp, &content_size, &content_length, json_tail);
        add_headers(200, "OK", "", NULL, "text/html", strlen(resp), (time_t)-1);
        add_to_response(resp);
        send_response();
        return;
    }
READ_FAIL:
    free(buf);
    close(conn);
    char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
    add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
    add_to_response(result_json);
    send_response();
}

static void do_secfs_file_read(const char *session_id, uint32_t ext_id, uint32_t max_sz){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error");
    }
    char *buf = calloc(1, 1024);
    if(max_sz != 0){
        max_sz = max_sz > MAX_FILE_DATA ? MAX_FILE_DATA : max_sz;
        snprintf(buf, 1024, "!! secfs read %s %d %d", session_id, ext_id, max_sz);
    } else{
        snprintf(buf, 1024, "!! secfs read %s %d", session_id, ext_id);
    }
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    } else{
        uint32_t data_sz =  strtol(buf, NULL, 10);
        if(data_sz > MAX_FILE_DATA){
            free(buf);
            close(conn);
            send_error(500, "Internal Server Error", "", "Internal Server Error");
        }
        write(conn, "<data>", 6);
        char *data = calloc(1, data_sz+1);
        if(recv(conn, data, data_sz, 0) < 0){
            free(buf);
            free(data);
            close(conn);
            send_error(500, "Internal Server Error", "", "Internal Server Error");
        }
        char *result_json = "{\"code\": 0, \"msg\":\"success\", \"data\": {\"file_data\": \"%s\"}}";
        uint32_t json_size = strlen(result_json)+data_sz+1;
        char *result = calloc(1, json_size);
        snprintf(result, json_size, result_json, data);
        add_headers(200, "OK", "", NULL, "text/html", strlen(result), (time_t)-1);
        add_to_response(result);
        send_response();
        free(buf);
        free(data);
        free(result);
    }
}


static void do_secfs_file_rename(const char *session_id, uint32_t ext_id, const char *new_name){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! secfs rename %s %d %s", session_id, ext_id, new_name);
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error");
    }
    memset(buf, 0, 1024);
    if(recv(conn, buf, 1023, 0) <= 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error");
    }
    if(!strncasecmp(buf, "<error>", 7)){
        free(buf);
        close(conn);
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    } else{
        char *result_json = "{\"code\": 0, \"msg\":\"success\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
        free(buf);
    }
}

static void do_secfs_file_slots(const char *session_id){
    if (do_check_session_format(session_id)) {
        send_error(400, "Bad Request", "", "Bad parameter.");
    }
    int conn = conn_d3_trusted_core();
    if(conn < 0){
        send_error(500, "Internal Server Error", "", "Internal Server Error");
    }
    char *buf = calloc(1, 1024);
    snprintf(buf, 1024, "!! secfs slots %s", session_id);
    if(write(conn, buf, strlen(buf)) < 0){
        free(buf);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error");
    }
    free(buf);
    uint8_t *slots = calloc(1, MAX_FILE_COUNT*sizeof(uint8_t)+16);
    if(recv(conn, slots, MAX_FILE_COUNT*sizeof(uint8_t)+16, 0) <= 0){
        free(slots);
        close(conn);
        send_error(500, "Internal Server Error", "", "Internal Server Error");
    }
    if(!strncasecmp((char *)slots, "<error>", 7)){
        free(slots);
        close(conn);
        char *result_json = "{\"code\": 1, \"msg\": \"fail\"}";
        add_headers(200, "OK", "", NULL, "text/html", strlen(result_json), (time_t)-1);
        add_to_response(result_json);
        send_response();
    } else{
        char *resp = NULL;
        size_t content_size = 0;
        size_t content_length = 0;
        char *json_head = "{\"code\": 0, \"msg\":\"success\", \"data\": {\"file_slots\": [";
        char *json_tail = "]}}";
        add_str(&resp, &content_size, &content_length, json_head);
        for(int i = 0; i < MAX_FILE_COUNT; i++){
            //printf("slot[%d]: 0x%x\n", i, slots[i]);
            switch (slots[i])
            {
            case FILE_NODE_EMPTY:
                add_str(&resp, &content_size, &content_length, "\"N\"");
                break;
            case FILE_NODE_DIR:
                add_str(&resp, &content_size, &content_length, "\"D\"");
                break;
            case FILE_NODE_FILE:
                add_str(&resp, &content_size, &content_length, "\"F\"");
                break;
            default:
                add_str(&resp, &content_size, &content_length, "\"E\"");
                break;
            }
            if(i < MAX_FILE_COUNT-1){
                add_str(&resp, &content_size, &content_length, ", ");
            }
        }
        add_str(&resp, &content_size, &content_length, json_tail);
        add_headers(200, "OK", "", NULL, "text/html", strlen(resp), (time_t)-1);
        add_to_response(resp);
        send_response();
    }
}

/* This runs in a child process, and exits when done, so cleanup is
** not needed.
*/
static void
handle_request(void) {
    char *method_str = NULL;
    char* line = NULL;;
    char* cp = NULL;;
    int r, file_len, i;
    const char* index_names[] = {
        "index.html", "index.htm", "index.xhtml", "index.xht", "Default.htm",
        "index.cgi"};

    /* Set up the timeout for reading. */
#ifdef HAVE_SIGSET
    (void)sigset(SIGALRM, handle_read_timeout);
#else  /* HAVE_SIGSET */
    (void)signal(SIGALRM, handle_read_timeout);
#endif /* HAVE_SIGSET */
    (void)alarm(READ_TIMEOUT);

    /* Initialize the request variables. */
    remoteuser = (char*)0;
    method = METHOD_UNKNOWN;
    path = (char*)0;
    file = (char*)0;
    pathinfo = (char*)0;
    query = "";
    protocol = (char*)0;
    status = 0;
    bytes = -1;
    req_hostname = (char*)0;

    authorization = (char*)0;
    content_type = (char*)0;
    content_length = -1;
    cookie = (char*)0;
    host = (char*)0;
    if_modified_since = (time_t)-1;
    referrer = "";
    useragent = "";

#ifdef TCP_NOPUSH
    if (!do_ssl) {
        /* Set the TCP_NOPUSH socket option, to try and avoid the 0.2 second
        ** delay between sending the headers and sending the data.  A better
        ** solution is writev() (as used in thttpd), or send the headers with
        ** send(MSG_MORE) (only available in Linux so far).
        */
        r = 1;
        (void)setsockopt(
            conn_fd, IPPROTO_TCP, TCP_NOPUSH, (void*)&r, sizeof(r));
    }
#endif /* TCP_NOPUSH */

#ifdef USE_SSL
    if (do_ssl) {
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, conn_fd);
        if (SSL_accept(ssl) == 0) {
            ERR_print_errors_fp(stderr);
            finish_request(1);
        }
    }
#endif /* USE_SSL */

    /* Read in the request. */
    start_request();

    /* read http headr */
    
    (void)alarm(READ_TIMEOUT);
    for (;;) {
        //char buf[60000];
        char ch;
        int rr = my_read(&ch, 1);
        if (rr < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (rr <= 0)
            break;
        add_to_request(&ch, 1);
        //if (strstr(request, "\r\n\r\n") != (char*)0 ||
        //    strstr(request, "\r\n") != (char*)0)
        //    break;
        if (strstr(request, "\r\n\r\n") != NULL)
            break;
    }
    (void)alarm(0);

    /* Fuck you mini_httpd!!! */

    /* Parse the first line of the request. */
    method_str = strdup(get_request_line());
    if (method_str == (char*)0)
        send_error(400, "Bad Request", "", "Can't parse request.");
    path = strpbrk(method_str, " \t\012\015");
    if (path == (char*)0)
        send_error(400, "Bad Request", "", "Can't parse request.");
    *path++ = '\0';
    path += strspn(path, " \t\012\015");
    protocol = strpbrk(path, " \t\012\015");
    if (protocol == (char*)0)
        send_error(400, "Bad Request", "", "Can't parse request.");
    *protocol++ = '\0';
    protocol += strspn(protocol, " \t\012\015");
    query = strchr(path, '?');
    if (query == (char*)0)
        query = "";
    else
        *query++ = '\0';

    /* Parse the rest of the request headers. */
    while ((line = strdup(get_request_line())) != (char*)0) {
        if (line[0] == '\0')
            break;
        else if (strncasecmp(line, "Authorization:", 14) == 0) {
            cp = &line[14];
            cp += strspn(cp, " \t");
            authorization = cp;
        } else if (strncasecmp(line, "Content-Length:", 15) == 0) {
            cp = &line[15];
            cp += strspn(cp, " \t");
            content_length = atol(cp);
            if (content_length < 0 || content_length > MAX_CONTENT_LENGTH){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            // read http body
            uint32_t true_content_length = 0;
            (void)alarm(READ_TIMEOUT);
            for (i = 0; i < content_length; i++) {
                char ch;
                int rr = my_read(&ch, 1);
                if (rr < 0 && (errno == EINTR || errno == EAGAIN))
                    continue;
                if (rr <= 0)
                    break;
                add_to_request(&ch, 1);
                true_content_length++;
            }
            (void)alarm(0);

            if (true_content_length != content_length) {
                send_error(400, "Bad Request", "", "Content-Length is not equal to the length of http body.");
            }
        } else if (strncasecmp(line, "Content-Type:", 13) == 0) {
            cp = &line[13];
            cp += strspn(cp, " \t");
            content_type = cp;
        } else if (strncasecmp(line, "Cookie:", 7) == 0) {
            cp = &line[7];
            cp += strspn(cp, " \t");
            cookie = cp;
        } else if (strncasecmp(line, "Host:", 5) == 0) {
            cp = &line[5];
            cp += strspn(cp, " \t");
            host = cp;
            if (host[0] == '\0' || host[0] == '.' ||
                strchr(host, '/') != (char*)0)
                send_error(400, "Bad Request", "", "Can't parse request.");
        } else if (strncasecmp(line, "If-Modified-Since:", 18) == 0) {
            cp = &line[18];
            cp += strspn(cp, " \t");
            if_modified_since = tdate_parse(cp);
        } else if (strncasecmp(line, "Referer:", 8) == 0) {
            cp = &line[8];
            cp += strspn(cp, " \t");
            referrer = cp;
        } else if (strncasecmp(line, "Referrer:", 9) == 0) {
            cp = &line[9];
            cp += strspn(cp, " \t");
            referrer = cp;
        } else if (strncasecmp(line, "User-Agent:", 11) == 0) {
            cp = &line[11];
            cp += strspn(cp, " \t");
            useragent = cp;
        }
    }

    if (strcasecmp(method_str, get_method_str(METHOD_GET)) == 0)
        method = METHOD_GET;
    else if (strcasecmp(method_str, get_method_str(METHOD_HEAD)) == 0)
        method = METHOD_HEAD;
    else if (strcasecmp(method_str, get_method_str(METHOD_POST)) == 0)
        method = METHOD_POST;
    else if (strcasecmp(method_str, get_method_str(METHOD_PUT)) == 0)
        method = METHOD_PUT;
    else if (strcasecmp(method_str, get_method_str(METHOD_DELETE)) == 0)
        method = METHOD_DELETE;
    else if (strcasecmp(method_str, get_method_str(METHOD_TRACE)) == 0)
        method = METHOD_TRACE;
    else
        send_error(501, "Not Implemented", "", "That method is not implemented.");

    strdecode(path, path);
    if (path[0] != '/')
        send_error(400, "Bad Request", "", "Bad filename.");
    file = &(path[1]);
    de_dotdot(file);
    if (file[0] == '\0')
        file = "./";
    if (file[0] == '/' ||
        (file[0] == '.' && file[1] == '.' &&
         (file[2] == '\0' || file[2] == '/')))
        send_error(400, "Bad Request", "", "Illegal filename.");
    if (vhost)
        file = virtual_file(file);

        /* Set up the timeout for writing. */
#ifdef HAVE_SIGSET
    (void)sigset(SIGALRM, handle_write_timeout);
#else  /* HAVE_SIGSET */
    (void)signal(SIGALRM, handle_write_timeout);
#endif /* HAVE_SIGSET */
    (void)alarm(WRITE_TIMEOUT);


	#define API_PREFIX "/api/"

	if(strcasecmp(path, API_PREFIX "login") == 0){
		if(method != METHOD_POST){
			send_error(405, "Method Not Allowed", "", "Method in client request is prohibited.");
		}
		// parse http body
        if(!(content_length > 0)){
            send_error(411, "Length Required", "", "Length Required.");
        }
		char *body = (char*)calloc(1, content_length + 1);
		// get http body from request buffer
        if (request_idx + content_length > request_len){
            send_error(400, "Bad Request", "", "Failed to read http body.");
        }
        memcpy(body, request + request_idx, content_length);

		// parse args and do strdecode
		char *raw_username = NULL;
		char *raw_password = NULL;
		char *raw_auth_mode = NULL;
		char *raw_face_data_str = NULL;
		char *username = NULL;
		char *password = NULL;
		char *auth_mode = NULL;
		char *face_data_str = NULL;
		vec_float *face_data = NULL;
		char *token = strtok(body, "&");
		while(token != NULL){
			if(strncasecmp(token, "auth_mode=", strlen("auth_mode=")) == 0){
				raw_auth_mode = token + strlen("auth_mode=");
                if(username) free(auth_mode);
				auth_mode = calloc(strlen(raw_auth_mode) + 1, sizeof(char));
				urldecode(auth_mode, raw_auth_mode);
			}
			if(strncasecmp(token, "username=", strlen("username=")) == 0){
				raw_username = token + strlen("username=");
                if(username) free(username);
				username = calloc(strlen(raw_username) + 1, sizeof(char));
				urldecode(username, raw_username);
                // remove space in username
                char *p = username;
                while(*p != '\0'){
                    if(*p == ' '){
                        *p = '\0';
                        break;
                    }
                    p++;
                }
			}
			if(strncasecmp(token, "password=", strlen("password=")) == 0){
				raw_password = token + strlen("password=");
                if(password) free(password);
				password = calloc(strlen(raw_password) + 1, sizeof(char));
				urldecode(password, raw_password);
                // remove space in password
                char *p = password;
                while(*p != '\0'){
                    if(*p == ' '){
                        *p = '\0';
                        break;
                    }
                    p++;
                }
			}
			if(strncasecmp(token, "face_data=", strlen("face_data=")) == 0){
				raw_face_data_str = token + strlen("face_data=");
                if(face_data_str) free(face_data_str);
				face_data_str = calloc(strlen(raw_face_data_str) + 1, sizeof(char));
				urldecode(face_data_str, raw_face_data_str);
			}
			token = strtok(NULL, "&");
		}

		if (auth_mode == NULL){
			send_error(400, "Bad Request", "", "Unknown auth mode.");
		}
		// login
		if (strncasecmp(auth_mode, "passwd", strlen("passwd")) == 0){
			if (username == NULL || password == NULL 
			|| strlen(username) == 0 || strlen(password) == 0
			|| strlen(username) > MAX_USERNAME_LEN || strlen(password) > MAX_PASSWORD_LEN){
				send_error(400, "Bad Request", "", "Bad parameter.");
			} else{
				do_login_passwd(username, password);
			}
		}
		else if (strncasecmp(auth_mode, "face_id", strlen("face_id")) == 0){
			// parse face_data
			if (!face_data_str || strlen(face_data_str) == 0){
				send_error(400, "Bad Request", "", "Bad parameter.");
			}
			int i = 0;
			while(face_data_str[i] != '\0'){
				if(face_data_str[i] == '[' || face_data_str[i] == ']'){
					face_data_str[i] = ' ';
				}
				i++;
			}
			face_data = calloc(128, sizeof(vec_float));
			char *face_data_token = strtok(face_data_str, ",");
			int dimension_count = 0;
			while(face_data_token != NULL){
				face_data[dimension_count] = strtold(face_data_token, NULL);
				face_data_token = strtok(NULL, ",");
				dimension_count++;
			}
			if (dimension_count != 128){
				send_error(400, "Bad Request", "", "Bad parameter.");
			}
			if (username == NULL || face_data == NULL
			|| strlen(username) == 0 || strlen(username) > MAX_USERNAME_LEN){
				send_error(400, "Bad Request", "", "Bad parameter.");
			} else{
				do_login_face_id(username, face_data);
			}
		} else{
			send_error(400, "Bad Request", "", "Unknown auth mode.");
		}
		goto FINI_REQ;	
	}

    // apis need auth
    static char *auth_apis[] = {
        API_PREFIX "user",
        API_PREFIX "user/list",
        API_PREFIX "user/passwd",
        API_PREFIX "user/logout",

        API_PREFIX "man/user/enable",
        API_PREFIX "man/user/disable",
        API_PREFIX "man/user/reset",

        API_PREFIX "secfs/file/create",
        API_PREFIX "secfs/file/delete",
        API_PREFIX "secfs/file/info",
        API_PREFIX "secfs/file/slots",
        API_PREFIX "secfs/file/read",
        API_PREFIX "secfs/file/update",
        API_PREFIX "secfs/file/rename",

        API_PREFIX "secfs/dir/create",
        API_PREFIX "secfs/dir/delete",
        API_PREFIX "secfs/dir/info",
        
        NULL
    };
    uint32_t access_auth_api = 0;
    char *session_id = NULL;
    for (int i = 0; auth_apis[i] != NULL; i++){
        if(strcasecmp(path, auth_apis[i]) == 0){
            if(method != METHOD_POST){
                send_error(405, "Method Not Allowed", "", "Method in client request is prohibited.");
            }
            // parse session_id from cookie pointer
            if(!cookie){
                // add a redirect header
                char redirect_header[] = "Location: /login.html";
                send_error(403, "Forbidden", redirect_header, "Login first!");   
            }
            //fprintf(stderr, "[Access API: %s with cookie: %s]\n", path, cookie);
            char *tmp_cookie = strdup(cookie);
            if(tmp_cookie != NULL){
                char *token = strtok(tmp_cookie, ";");
                while(token != NULL){
                    // trim space
                    while(*token == ' ' || *token == '\t'){
                        token++;
                    }
                    if(strncasecmp(token, "session_id=", strlen("session_id=")) == 0){
                        session_id = strdup(token + strlen("session_id="));
                        break; // prevent overwrite
                    }
                    token = strtok(NULL, ";");
                }
            }
            free(tmp_cookie);
            if(session_id == NULL){
                // add a redirect header
                char redirect_header[] = "Location: /login.html";
                send_error(403, "Forbidden", redirect_header, "Login first!");
            }
            uint32_t auth_res = do_auth_session_id(session_id);
            if (auth_res == 0){
                access_auth_api = 1;
            } else if(auth_res == 2){
                char redirect_header[] = "Location: /login.html";
                // clear cookie
                char set_cookie_header[] = "Set-Cookie: session_id=; Path=/;";
                // make extra header
                uint32_t extra_header_len = strlen(redirect_header) + strlen(set_cookie_header) + 2 + sizeof(size_t);
                char *extra_header = calloc(extra_header_len, sizeof(char));
                snprintf(extra_header, extra_header_len, "%s\r\n%s", redirect_header, set_cookie_header);
                send_error(403, "Forbidden", extra_header, "Disabled User!");
            } else{
                char redirect_header[] = "Location: /login.html";
                // clear cookie
                char set_cookie_header[] = "Set-Cookie: session_id=; Path=/;";
                // make extra header
                uint32_t extra_header_len = strlen(redirect_header) + strlen(set_cookie_header) + 2 + sizeof(size_t);
                char *extra_header = calloc(extra_header_len, sizeof(char));
                snprintf(extra_header, extra_header_len, "%s\r\n%s", redirect_header, set_cookie_header);
                send_error(403, "Forbidden", extra_header, "Login First!");
            }
            
            break;
        }
    }
    if(access_auth_api){
        // handle api
        if(strcasecmp(path, API_PREFIX "user") == 0){        
            if(session_id){
                do_user_info(session_id); // return a json
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }
            goto FINI_REQ;
        }
        if(strcasecmp(path, API_PREFIX "user/list") == 0){        
            if(session_id){
                do_user_list(session_id);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }
            goto FINI_REQ;
        }
        if(strcasecmp(path, API_PREFIX "user/logout") == 0){
            if(session_id){
                do_user_logout(session_id);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }
            goto FINI_REQ;
        }
        if(strcasecmp(path, API_PREFIX "man/user/enable") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_username = NULL;
                char *username = NULL;
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "username=", strlen("username=")) == 0){
                        raw_username = strdup(token + strlen("username="));
                        if(username) free(username);
                        username = calloc(strlen(raw_username) + 1, sizeof(char));
                        urldecode(username, raw_username);
                        char *p = username;
                        while(*p != '\0'){
                            if(*p == ' '){
                                *p = '\0';
                                break;
                            }
                            p++;
                        }
                    }
                    token = strtok(NULL, "&");
                }
                do_user_enable(session_id, username);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }
            goto FINI_REQ;
        }
        if(strcasecmp(path, API_PREFIX "man/user/disable") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_username = NULL;
                char *username = NULL;
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "username=", strlen("username=")) == 0){
                        raw_username = strdup(token + strlen("username="));
                        if(username) free(username);
                        username = calloc(strlen(raw_username) + 1, sizeof(char));
                        urldecode(username, raw_username);
                        char *p = username;
                        while(*p != '\0'){
                            if(*p == ' '){
                                *p = '\0';
                                break;
                            }
                            p++;
                        }
                    }
                    token = strtok(NULL, "&");
                }
                do_user_disable(session_id, username);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }
            goto FINI_REQ;
        }
        if(strcasecmp(path, API_PREFIX "man/user/reset") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_username = NULL;
                char *username = NULL;
                char *raw_option = NULL;
                char *option = NULL;
                char *raw_face_data_str = NULL;
                char *face_data_str = NULL;
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "username=", strlen("username=")) == 0){
                        raw_username = strdup(token + strlen("username="));
                        if(username) free(username);
                        username = calloc(strlen(raw_username) + 1, sizeof(char));
                        urldecode(username, raw_username);
                        char *p = username;
                        while(*p != '\0'){
                            if(*p == ' '){
                                *p = '\0';
                                break;
                            }
                            p++;
                        }
                    }
                    if(strncasecmp(token, "option=", strlen("option=")) == 0){
                        raw_option = strdup(token + strlen("option="));
                        if(option) free(option);
                        option = calloc(strlen(raw_option) + 1, sizeof(char));
                        urldecode(option, raw_option);
                    }
                    if(strncasecmp(token, "face_data=", strlen("face_data=")) == 0){
                        raw_face_data_str = token + strlen("face_data=");
                        if(face_data_str) free(face_data_str);
                        face_data_str = calloc(strlen(raw_face_data_str) + 1, sizeof(char));
                        urldecode(face_data_str, raw_face_data_str);
                    }
                    token = strtok(NULL, "&");
                }
                if(option && strncasecmp(option, "set_face_id", 11) == 0){
                    // parse face_data
                    vec_float *face_data = NULL;
                    if (!face_data_str || strlen(face_data_str) == 0){
                        send_error(400, "Bad Request", "", "Bad parameter.");
                    }
                    int i = 0;
                    while(face_data_str[i] != '\0'){
                        if(face_data_str[i] == '[' || face_data_str[i] == ']'){
                            face_data_str[i] = ' ';
                        }
                        i++;
                    }
                    face_data = calloc(128, sizeof(vec_float));
                    char *face_data_token = strtok(face_data_str, ",");
                    int dimension_count = 0;
                    while(face_data_token != NULL){
                        face_data[dimension_count] = strtold(face_data_token, NULL);
                        face_data_token = strtok(NULL, ",");
                        dimension_count++;
                    }
                    if (dimension_count != 128){
                        send_error(400, "Bad Request", "", "Bad parameter.");
                    }
                    do_user_reset(session_id, username, face_data);
                } else{
                    do_user_reset(session_id, username, NULL);
                }
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }
            goto FINI_REQ;
        }
        if(strcasecmp(path, API_PREFIX "user/passwd") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_old_passwd = NULL;
                char *raw_new_passwd = NULL;
                char *old_passwd = NULL;
                char *new_passwd = NULL;                
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "old_password=", strlen("old_password=")) == 0){
                        raw_old_passwd = token + strlen("old_password=");
                        if(old_passwd) free(old_passwd);
                        old_passwd = calloc(strlen(raw_old_passwd) + 1, sizeof(char));
                        urldecode(old_passwd, raw_old_passwd);
                        // remove space in password
                        char *p = old_passwd;
                        while(*p != '\0'){
                            if(*p == ' '){
                                *p = '\0';
                                break;
                            }
                            p++;
                        }
                    }
                    if(strncasecmp(token, "new_password=", strlen("new_password=")) == 0){
                        raw_new_passwd = token + strlen("new_password=");
                        if(new_passwd) free(new_passwd);
                        new_passwd = calloc(strlen(raw_new_passwd) + 1, sizeof(char));
                        urldecode(new_passwd, raw_new_passwd);
                        // remove space in password
                        char *p = new_passwd;
                        while(*p != '\0'){
                            if(*p == ' '){
                                *p = '\0';
                                break;
                            }
                            p++;
                        }
                    }
                    token = strtok(NULL, "&");
                }
                if(!old_passwd || !new_passwd){
                    send_error(400, "Bad Request", "", "Bad parameter.");
                }
                do_user_passwd(session_id, old_passwd, new_passwd);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }
            goto FINI_REQ;
        }
        if(strcasecmp(path, API_PREFIX "secfs/file/create") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_filename = NULL;
                char *filename = NULL;
                char *raw_parent_id = NULL;
                char *parent_id = NULL;
                char *raw_data = NULL;
                char *data = NULL;
                uint32_t data_sz = 0;  
                uint32_t parent_id_int = 0; 
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "filename=", strlen("filename=")) == 0){
                        raw_filename = token + strlen("filename=");
                        if(filename) free(filename);
                        filename = calloc(strlen(raw_filename) + 1, sizeof(char));
                        urldecode(filename, raw_filename);
                        char *p = filename;
                        while(*p != '\0'){
                            // filename char in 'A'-'Z', 'a'-'z', '0'-'9', '.', '-', '_'
                            if(!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_')){
                                send_error(400, "Bad Request", "", "Invalid File Name.");
                            }
                            p++;
                        }
                        if(strlen(filename) > MAX_FILE_NAME || strlen(filename) == 0){
                            send_error(400, "Bad Request", "", "Invalid File Name.");
                        }
                    }
                    if(strncasecmp(token, "data=", strlen("data=")) == 0){
                        raw_data = token + strlen("data=");
                        if(data) free(data);
                        data = calloc(strlen(raw_data) + 1, sizeof(char));
                        data_sz = urldecode(data, raw_data);

                        if(data_sz > MAX_FILE_DATA || data_sz == 0){
                            send_error(400, "Bad Request", "", "Invalid File Size.");
                        }
                    }             
                    if(strncasecmp(token, "parent_id=", strlen("parent_id=")) == 0){
                        raw_parent_id = token + strlen("parent_id=");
                        if(parent_id) free(parent_id);
                        parent_id = calloc(strlen(raw_parent_id) + 1, sizeof(char));
                        urldecode(parent_id, raw_parent_id);
                        parent_id_int = strtol(parent_id, NULL, 10);
                        if(parent_id_int >= MAX_FILE_COUNT){
                            send_error(400, "Bad Request", "", "Invalid Parent ID.");
                        }
                    }
                    token = strtok(NULL, "&");
                }
                if(!filename || !data || !parent_id){
                    send_error(400, "Bad Request", "", "Bad Request.");
                }
                do_secfs_file_create(session_id, parent_id_int, filename, data, data_sz);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }
            goto FINI_REQ;
        }
        if(strcasecmp(path, API_PREFIX "secfs/file/delete") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_ext_id = NULL;
                char *ext_id = NULL;
                uint32_t ext_id_int = 0; 
                char *raw_del_mode = NULL;
                char *del_mode = NULL;
                uint32_t del_mode_int = 0;
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "ext_id=", strlen("ext_id=")) == 0){
                        raw_ext_id = token + strlen("ext_id=");
                        if(ext_id) free(ext_id);
                        ext_id = calloc(strlen(raw_ext_id) + 1, sizeof(char));
                        urldecode(ext_id, raw_ext_id);
                        ext_id_int = strtol(ext_id, NULL, 10);
                        if(ext_id_int >= MAX_FILE_COUNT){
                            send_error(400, "Bad Request", "", "Invalid File ID.");
                        }
                    }
                    if(strncasecmp(token, "del_mode=", strlen("del_mode=")) == 0){
                        raw_del_mode = token + strlen("del_mode=");
                        if(del_mode) free(del_mode);
                        del_mode = calloc(strlen(raw_del_mode) + 1, sizeof(char));
                        urldecode(del_mode, raw_del_mode);
                        //del_mode_int = strtol(del_mode, NULL, 10);
                    }
                    token = strtok(NULL, "&");
                }
                if(!ext_id){
                    send_error(400, "Bad Request", "", "Bad Request.");
                }
                do_secfs_file_delete(session_id, ext_id_int, del_mode);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }         
            goto FINI_REQ;   
        }
        // secfs/file/info
        if(strcasecmp(path, API_PREFIX "secfs/file/info") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_ext_id = NULL;
                char *ext_id = NULL;
                uint32_t ext_id_int = 0; 
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "ext_id=", strlen("ext_id=")) == 0){
                        raw_ext_id = token + strlen("ext_id=");
                        if(ext_id) free(ext_id);
                        ext_id = calloc(strlen(raw_ext_id) + 1, sizeof(char));
                        urldecode(ext_id, raw_ext_id);
                        ext_id_int = strtol(ext_id, NULL, 10);
                        if(ext_id_int >= MAX_FILE_COUNT){
                            send_error(400, "Bad Request", "", "Invalid File ID.");
                        }
                    }
                    token = strtok(NULL, "&");
                }
                if(!ext_id){
                    send_error(400, "Bad Request", "", "Bad Request.");
                }
                do_secfs_file_info(session_id, ext_id_int);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }        
            goto FINI_REQ;  
        }
        // secfs/file/read  args: exit_id [max_size]
        if(strcasecmp(path, API_PREFIX "secfs/file/read") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_ext_id = NULL;
                char *ext_id = NULL;
                uint32_t ext_id_int = 0; 
                char *raw_max_size = NULL;
                char *max_size = NULL;
                uint32_t max_size_int = 0; 
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "ext_id=", strlen("ext_id=")) == 0){
                        raw_ext_id = token + strlen("ext_id=");
                        if(ext_id) free(ext_id);
                        ext_id = calloc(strlen(raw_ext_id) + 1, sizeof(char));
                        urldecode(ext_id, raw_ext_id);
                        ext_id_int = strtol(ext_id, NULL, 10);
                        if(ext_id_int >= MAX_FILE_COUNT){
                            send_error(400, "Bad Request", "", "Invalid File ID.");
                        }
                    }
                    if(strncasecmp(token, "max_size=", strlen("max_size=")) == 0){
                        raw_max_size = token + strlen("max_size=");
                        if(max_size) free(max_size);
                        max_size = calloc(strlen(raw_max_size) + 1, sizeof(char));
                        urldecode(max_size, raw_max_size);
                        max_size_int = strtol(max_size, NULL, 10);
                    }
                    token = strtok(NULL, "&");
                }
                if(!ext_id){
                    send_error(400, "Bad Request", "", "Bad Request.");
                }
                do_secfs_file_read(session_id, ext_id_int, max_size_int);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }          
            goto FINI_REQ;
        }
        // secfs/file/update args: ext_id data
        if(strcasecmp(path, API_PREFIX "secfs/file/update") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_ext_id = NULL;
                char *ext_id = NULL;
                uint32_t ext_id_int = 0; 
                char *raw_data = NULL;
                char *data = NULL;
                uint32_t data_sz;
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "ext_id=", strlen("ext_id=")) == 0){
                        raw_ext_id = token + strlen("ext_id=");
                        if(ext_id) free(ext_id);
                        ext_id = calloc(strlen(raw_ext_id) + 1, sizeof(char));
                        urldecode(ext_id, raw_ext_id);
                        ext_id_int = strtol(ext_id, NULL, 10);
                        if(ext_id_int >= MAX_FILE_COUNT){
                            send_error(400, "Bad Request", "", "Invalid File ID.");
                        }
                    }
                    if(strncasecmp(token, "data=", strlen("data=")) == 0){
                        raw_data = token + strlen("data=");
                        if(data) free(data);
                        data = calloc(strlen(raw_data) + 1, sizeof(char));
                        data_sz = urldecode(data, raw_data);
                        
                        if(data_sz > MAX_FILE_DATA || data_sz == 0){
                            send_error(400, "Bad Request", "", "Invalid File Size.");
                        }
                    }
                    token = strtok(NULL, "&");
                }
                if(!ext_id || !data){
                    send_error(400, "Bad Request", "", "Bad Request.");
                }
                do_secfs_file_update(session_id, ext_id_int, data, data_sz);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }          
            goto FINI_REQ;
        }
        // secfs/file/rename args: ext_id new_filename
        if(strcasecmp(path, API_PREFIX "secfs/file/rename") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_ext_id = NULL;
                char *ext_id = NULL;
                uint32_t ext_id_int = 0; 
                char *raw_new_filename = NULL;
                char *new_filename = NULL;
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "ext_id=", strlen("ext_id=")) == 0){
                        raw_ext_id = token + strlen("ext_id=");
                        if(ext_id) free(ext_id);
                        ext_id = calloc(strlen(raw_ext_id) + 1, sizeof(char));
                        urldecode(ext_id, raw_ext_id);
                        ext_id_int = strtol(ext_id, NULL, 10);
                        if(ext_id_int >= MAX_FILE_COUNT){
                            send_error(400, "Bad Request", "", "Invalid File ID.");
                        }
                    }
                    if(strncasecmp(token, "new_filename=", strlen("new_filename=")) == 0){
                        raw_new_filename = token + strlen("new_filename=");
                        if(new_filename) free(new_filename);
                        new_filename = calloc(strlen(raw_new_filename) + 1, sizeof(char));
                        urldecode(new_filename, raw_new_filename);
                        char *p = new_filename;
                        while(*p != '\0'){
                            // filename char in 'A'-'Z', 'a'-'z', '0'-'9', '.', '-', '_'
                            if(!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_')){
                                send_error(400, "Bad Request", "", "Invalid File Name.");
                            }
                            p++;
                        }
                        if(strlen(new_filename) > MAX_FILE_NAME || strlen(new_filename) == 0){
                            send_error(400, "Bad Request", "", "Invalid File Name.");
                        }
                    }
                    token = strtok(NULL, "&");
                }
                if(!ext_id || !new_filename){
                    send_error(400, "Bad Request", "", "Bad Request.");
                }
                do_secfs_file_rename(session_id, ext_id_int, new_filename);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }          
            goto FINI_REQ;
        }
        // secfs/file/slots no args
        if(strcasecmp(path, API_PREFIX "secfs/file/slots") == 0){
            if(session_id){
                do_secfs_file_slots(session_id);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }          
            goto FINI_REQ;
        }
        // secfs/dir/create args: dir_name parent_id
        if(strcasecmp(path, API_PREFIX "secfs/dir/create") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_dir_name = NULL;
                char *dir_name = NULL;
                char *raw_parent_id = NULL;
                char *parent_id = NULL;
                uint32_t parent_id_int = 0; 
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "dir_name=", strlen("dir_name=")) == 0){
                        raw_dir_name = token + strlen("dir_name=");
                        if(dir_name) free(dir_name);
                        dir_name = calloc(strlen(raw_dir_name) + 1, sizeof(char));
                        char *p = dir_name;
                        while(*p != '\0'){
                            if(!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_')){
                                send_error(400, "Bad Request", "", "Invalid Directory Name.");
                            }
                            p++;
                        }
                        urldecode(dir_name, raw_dir_name);
                    }
                    if(strncasecmp(token, "parent_id=", strlen("parent_id=")) == 0){
                        raw_parent_id = token + strlen("parent_id=");
                        if(parent_id) free(parent_id);
                        parent_id = calloc(strlen(raw_parent_id) + 1, sizeof(char));
                        urldecode(parent_id, raw_parent_id);
                        parent_id_int = strtol(parent_id, NULL, 10);
                        if(parent_id_int >= MAX_FILE_COUNT){
                            send_error(400, "Bad Request", "", "Invalid Parent ID.");
                        }
                    }
                    token = strtok(NULL, "&");
                }
                if(!dir_name || !parent_id){
                    send_error(400, "Bad Request", "", "Bad Request.");
                }
                do_secfs_dir_create(session_id, parent_id_int, dir_name);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }         
            goto FINI_REQ; 
        }
        // secfs/dir/delete args: ext_id [rm_mode]
        if(strcasecmp(path, API_PREFIX "secfs/dir/delete") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_ext_id = NULL;
                char *ext_id = NULL;
                uint32_t ext_id_int = 0; 
                char *raw_rm_mode = NULL;
                char *rm_mode = NULL;
                //uint32_t rm_mode_int = 0; 
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "ext_id=", strlen("ext_id=")) == 0){
                        raw_ext_id = token + strlen("ext_id=");
                        if(ext_id) free(ext_id);
                        ext_id = calloc(strlen(raw_ext_id) + 1, sizeof(char));
                        urldecode(ext_id, raw_ext_id);
                        ext_id_int = strtol(ext_id, NULL, 10);
                        if(ext_id_int >= MAX_FILE_COUNT){
                            send_error(400, "Bad Request", "", "Invalid File ID.");
                        }
                    }
                    if(strncasecmp(token, "rm_mode=", strlen("rm_mode=")) == 0){
                        raw_rm_mode = token + strlen("rm_mode=");
                        if(rm_mode) free(rm_mode);
                        rm_mode = calloc(strlen(raw_rm_mode) + 1, sizeof(char));
                        urldecode(rm_mode, raw_rm_mode);
                        //rm_mode_int = strtol(rm_mode, NULL, 10);
                    }
                    token = strtok(NULL, "&");
                }
                if(!ext_id){
                    send_error(400, "Bad Request", "", "Bad Request.");
                }
                //do_secfs_dir_delete(session_id, ext_id_int, rm_mode_int);
                do_secfs_dir_delete(session_id, ext_id_int, rm_mode);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }      
            goto FINI_REQ;    
        }
        // secfs/dir/info args: ext_id
        if(strcasecmp(path, API_PREFIX "secfs/dir/info") == 0){
            // get http body
            if(!(content_length > 0)){
                send_error(411, "Length Required", "", "Length Required.");
            }
            char *body = (char*)calloc(1, content_length + 1);
            if (request_idx + content_length > request_len){
                send_error(400, "Bad Request", "", "Failed to read http body.");
            }
            memcpy(body, request + request_idx, content_length);
            if(session_id){
                char *raw_ext_id = NULL;
                char *ext_id = NULL;
                uint32_t ext_id_int = 0; 
                char *token = strtok(body, "&");
                while(token != NULL){
                    if(strncasecmp(token, "ext_id=", strlen("ext_id=")) == 0){
                        raw_ext_id = token + strlen("ext_id=");
                        if(ext_id) free(ext_id);
                        ext_id = calloc(strlen(raw_ext_id) + 1, sizeof(char));
                        urldecode(ext_id, raw_ext_id);
                        ext_id_int = strtol(ext_id, NULL, 10);
                        if(ext_id_int >= MAX_FILE_COUNT){
                            send_error(400, "Bad Request", "", "Invalid File ID.");
                        }
                    }
                    token = strtok(NULL, "&");
                }
                if(!ext_id){
                    send_error(400, "Bad Request", "", "Bad Request.");
                }
                do_secfs_dir_info(session_id, ext_id_int);
            } else{
                send_error(400, "Bad Request", "", "Bad Request.");
            }      
            goto FINI_REQ;    
        }
    }

DO_FILE:
	if(method == METHOD_GET){
		/******************************* process normal file/dir *************************************/
		r = stat(file, &sb);
		if (r < 0)
			r = get_pathinfo();
		if (r < 0)
			send_error(404, "Not Found", "", "File not found.");
		file_len = strlen(file);
		if (!S_ISDIR(sb.st_mode)) {
			/* Not a directory. */
			while (file[file_len - 1] == '/') {
				file[file_len - 1] = '\0';
				--file_len;
			}
			do_file();
		} else {
			char idx[10000];

			/* The filename is a directory.  Is it missing the trailing slash? */
			if (file[file_len - 1] != '/' && pathinfo == (char*)0) {
				char location[10000];
				if (query[0] != '\0')
					(void)snprintf(
						location, sizeof(location), "Location: %s/?%s", path,
						query);
				else
					(void)snprintf(
						location, sizeof(location), "Location: %s/", path);
				send_error(302, "Found", location, "Directories must end with a slash.");
			}

			/* Check for an index file. */
			for (i = 0; i < sizeof(index_names) / sizeof(char*); ++i) {
				(void)snprintf(idx, sizeof(idx), "%s%s", file, index_names[i]);
				if (stat(idx, &sb) >= 0) {
					file = idx;
					do_file();
					goto got_one;
				}
			}

			/* Nope, no index file, so it's an actual directory request. */
			do_dir();

		got_one:;
		}
		/**********************************************************************************************/
	} else{
		// Can't access normal file/dir by other methods except GET.
		send_error(405, "Method Not Allowed", "", "Method in client request is prohibited.");
	}

FINI_REQ:
#ifdef USE_SSL
    SSL_free(ssl);
#endif /* USE_SSL */

    finish_request(0);
}

static void
finish_request(int exitstatus) {
#undef LINGER_SOCKOPT
#define LINGER_READ

#define LINGER_SECS 5

#ifdef LINGER_SOCKOPT
    /* The sockopt version of lingering close. Doesn't actually work. */
    struct linger lin;

    shutdown(conn_fd, SHUT_WR);
    lin.l_onoff = 1;
    lin.l_linger = LINGER_SECS;
    (void)setsockopt(
        conn_fd, SOL_SOCKET, SO_LINGER, (void*)&lin, sizeof(lin));
#endif /* LINGER_SOCKOPT */

#ifdef LINGER_READ
    /* The "non-blocking read until error/eof/timeout" version of
    ** lingering close.
    */
    int flags;
    fd_set rfds;
    struct timeval tv;
    int r;
    char* buf[1024];

    flags = fcntl(conn_fd, F_GETFL, 0);
    if (flags != -1) {
        flags |= (int)O_NDELAY;
        (void)fcntl(conn_fd, F_SETFL, flags);
    }
    shutdown(conn_fd, SHUT_WR);
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(conn_fd, &rfds);
        tv.tv_sec = LINGER_SECS;
        tv.tv_usec = 0;
        r = select(conn_fd + 1, &rfds, (fd_set*)0, (fd_set*)0, &tv);
        if (r <= 0) /* timeout or error */
            break;
        r = read(conn_fd, (void*)buf, sizeof(buf));
        if (r <= 0) /* eof or error */
            break;
    }
#endif /* LINGER_READ */

    exit(exitstatus);
}

static void
de_dotdot(char* f) {
    char* cp;
    char* cp2;
    int l;

    /* Collapse any multiple / sequences. */
    while ((cp = strstr(f, "//")) != (char*)0) {
        for (cp2 = cp + 2; *cp2 == '/'; ++cp2)
            continue;
        (void)ol_strcpy(cp + 1, cp2);
    }

    /* Remove leading ./ and any /./ sequences. */
    while (strncmp(f, "./", 2) == 0)
        (void)ol_strcpy(f, f + 2);
    while ((cp = strstr(f, "/./")) != (char*)0)
        (void)ol_strcpy(cp, cp + 2);

    /* Alternate between removing leading ../ and removing xxx/../ */
    for (;;) {
        while (strncmp(f, "../", 3) == 0)
            (void)ol_strcpy(f, f + 3);
        cp = strstr(f, "/../");
        if (cp == (char*)0)
            break;
        for (cp2 = cp - 1; cp2 >= f && *cp2 != '/'; --cp2)
            continue;
        (void)ol_strcpy(cp2 + 1, cp + 4);
    }

    /* Also elide any xxx/.. at the end. */
    while ((l = strlen(f)) > 3 &&
           strcmp((cp = f + l - 3), "/..") == 0) {
        for (cp2 = cp - 1; cp2 >= f && *cp2 != '/'; --cp2)
            continue;
        if (cp2 < f)
            break;
        *cp2 = '\0';
    }
}

static int
get_pathinfo(void) {
    int r;

    pathinfo = &file[strlen(file)];
    for (;;) {
        do {
            --pathinfo;
            if (pathinfo <= file) {
                pathinfo = (char*)0;
                return -1;
            }
        } while (*pathinfo != '/');
        *pathinfo = '\0';
        r = stat(file, &sb);
        if (r >= 0) {
            ++pathinfo;
            return r;
        } else
            *pathinfo = '/';
    }
}

static void
do_file(void) {
    char buf[10000];
    char mime_encodings[500];
    const char* mime_type;
    char fixed_mime_type[500];
    char* cp;
    int fd;

    /* Check authorization for this directory. */
    (void)strncpy(buf, file, sizeof(buf));
    cp = strrchr(buf, '/');
    if (cp == (char*)0)
        (void)strcpy(buf, ".");
    else
        *cp = '\0';
    auth_check(buf);

    /* Check if the filename is the AUTH_FILE itself - that's verboten. */
    if (strcmp(file, AUTH_FILE) == 0 ||
        (strcmp(&(file[strlen(file) - sizeof(AUTH_FILE) + 1]), AUTH_FILE) == 0 &&
         file[strlen(file) - sizeof(AUTH_FILE)] == '/')) {
        syslog(
            LOG_NOTICE, "%.80s URL \"%.80s\" tried to retrieve an auth file",
            ntoa(&client_addr), path);
        send_error(403, "Forbidden", "", "File is protected.");
    }

    /* Referrer check. */
    check_referrer();

    /* Is it CGI? */
    if (cgi_pattern != (char*)0 && match(cgi_pattern, file)) {
        do_cgi();
        return;
    }
    if (pathinfo != (char*)0)
        send_error(404, "Not Found", "", "File not found.");

    if (method != METHOD_GET && method != METHOD_HEAD)
        send_error(501, "Not Implemented", "", "That method is not implemented.");

    fd = open(file, O_RDONLY);
    if (fd < 0) {
        syslog(
            LOG_INFO, "%.80s File \"%.80s\" is protected",
            ntoa(&client_addr), path);
        send_error(403, "Forbidden", "", "File is protected.");
    }
    mime_type = figure_mime(file, mime_encodings, sizeof(mime_encodings));
    (void)snprintf(
        fixed_mime_type, sizeof(fixed_mime_type), mime_type, charset);
    if (if_modified_since != (time_t)-1 &&
        if_modified_since >= sb.st_mtime) {
        add_headers(
            304, "Not Modified", "", mime_encodings, fixed_mime_type,
            (off_t)-1, sb.st_mtime);
        send_response();
        return;
    }
    add_headers(
        200, "Ok", "", mime_encodings, fixed_mime_type, sb.st_size,
        sb.st_mtime);
    send_response();
    if (method == METHOD_HEAD)
        return;

    if (sb.st_size > 0) /* ignore zero-length files */
    {
#ifdef HAVE_SENDFILE

#ifndef USE_SSL
        send_via_sendfile(fd, conn_fd, sb.st_size);
#else  /* USE_SSL */
        if (do_ssl)
            send_via_write(fd, sb.st_size);
        else
            send_via_sendfile(fd, conn_fd, sb.st_size);
#endif /* USE_SSL */

#else /* HAVE_SENDFILE */

        send_via_write(fd, sb.st_size);

#endif /* HAVE_SENDFILE */
    }

    (void)close(fd);
}

static void
do_dir(void) {
    char buf[10000];
    char* contents;
    size_t contents_size, contents_len;
#ifdef HAVE_SCANDIR
    int n, i;
    struct dirent** dl;
    char* name_info;
#else  /* HAVE_SCANDIR */
    char command[10000];
    FILE* fp;
#endif /* HAVE_SCANDIR */

    if (pathinfo != (char*)0)
        send_error(404, "Not Found", "", "File not found.");

    /* Check authorization for this directory. */
    auth_check(file);

    /* Referrer check. */
    check_referrer();

#ifdef HAVE_SCANDIR
    n = scandir(file, &dl, NULL, alphasort);
    if (n < 0) {
        syslog(
            LOG_INFO, "%.80s Directory \"%.80s\" is protected",
            ntoa(&client_addr), path);
        send_error(403, "Forbidden", "", "Directory is protected.");
    }
#endif /* HAVE_SCANDIR */

    contents_size = 0;
    (void)snprintf(buf, sizeof(buf),
                   "\
<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n\
\n\
<html>\n\
\n\
  <head>\n\
    <meta http-equiv=\"Content-type\" content=\"text/html;charset=UTF-8\">\n\
    <title>Index of %s</title>\n\
  </head>\n\
\n\
  <body bgcolor=\"#99cc99\" text=\"#000000\" link=\"#2020ff\" vlink=\"#4040cc\">\n\
    <h4>Index of %s</h4>\n\
    <pre>\n",
                   file, file);
    add_str(&contents, &contents_size, &contents_len, buf);

#ifdef HAVE_SCANDIR

    for (i = 0; i < n; ++i) {
        name_info = file_details(file, dl[i]->d_name);
        add_str(&contents, &contents_size, &contents_len, name_info);
    }

#else  /* HAVE_SCANDIR */
    /* Magic HTML ls command! */
    if (strchr(file, '\'') == (char*)0) {
        (void)snprintf(
            command, sizeof(command),
            "ls -lgF '%s' | tail +2 | sed -e 's/^\\([^ ][^ ]*\\)\\(  *[^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*\\)\\(  *[^ ][^ ]*\\)  *\\([^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*\\)  *\\(.*\\)$/\\1 \\3  \\4  |\\5/' -e '/ -> /!s,|\\([^*]*\\)$,|<a href=\"\\1\">\\1</a>,' -e '/ -> /!s,|\\(.*\\)\\([*]\\)$,|<a href=\"\\1\">\\1</a>\\2,' -e '/ -> /s,|\\([^@]*\\)\\(@* -> \\),|<a href=\"\\1\">\\1</a>\\2,' -e 's/|//'",
            file);
        fp = popen(command, "r");
        for (;;) {
            size_t r;
            r = fread(buf, 1, sizeof(buf) - 1, fp);
            if (r == 0)
                break;
            buf[r] = '\0';
            add_str(&contents, &contents_size, &contents_len, buf);
        }
        (void)pclose(fp);
    }
#endif /* HAVE_SCANDIR */

    (void)snprintf(buf, sizeof(buf),
                   "\
    </pre>\n\
\n\
    <hr>\n\
\n\
    <address><a href=\"%s\">%s</a></address>\n\
  \n\
  </body>\n\
\n\
</html>\n",
                   SERVER_URL, SERVER_SOFTWARE);
    add_str(&contents, &contents_size, &contents_len, buf);

    add_headers(200, "Ok", "", "", "text/html", contents_len, sb.st_mtime);
    if (method != METHOD_HEAD) {
        contents[contents_len] = '\0';
        add_to_response(contents);
    }
    send_response();
}

#ifdef HAVE_SCANDIR

static char*
file_details(const char* d, const char* name) {
    struct stat sb2;
    char timestr[16];
    static char encname[1000];
    static char buf[2000];

    (void)snprintf(buf, sizeof(buf), "%s/%s", d, name);
    if (lstat(buf, &sb2) < 0)
        return "???";
    (void)strftime(timestr, sizeof(timestr), "%d%b%Y %H:%M", localtime(&sb2.st_mtime));
    strencode(encname, sizeof(encname), name);
    (void)snprintf(
        buf, sizeof(buf), "<a href=\"%s\">%-32.32s</a>    %15s %14lld\n",
        encname, name, timestr, (long long)sb2.st_size);
    return buf;
}

/* Copies and encodes a string. */
static void
strencode(char* to, size_t tosize, const char* from) {
    int tolen;

    for (tolen = 0; *from != '\0' && tolen + 4 < tosize; ++from) {
        if (isalnum(*from) || strchr("/_.-~", *from) != (char*)0) {
            *to = *from;
            ++to;
            ++tolen;
        } else {
            (void)sprintf(to, "%%%02x", (int)*from & 0xff);
            to += 3;
            tolen += 3;
        }
    }
    *to = '\0';
}

#endif /* HAVE_SCANDIR */

static void
do_cgi(void) {
    char** argp;
    char** envp;
    int parse_headers;
    char* binary;
    char* directory;

    /* If the socket happens to be using one of the stdin/stdout/stderr
    ** descriptors, move it to another descriptor so that the dup2 calls
    ** below don't screw things up.  We arbitrarily pick fd 3 - if there
    ** was already something on it, we clobber it, but that doesn't matter
    ** since at this point the only fd of interest is the connection.
    ** All others will be closed on exec.
    */
    if (conn_fd == STDIN_FILENO || conn_fd == STDOUT_FILENO || conn_fd == STDERR_FILENO) {
        int newfd = dup2(conn_fd, STDERR_FILENO + 1);
        if (newfd >= 0)
            conn_fd = newfd;
        /* If the dup2 fails, shrug.  We'll just take our chances.
        ** Shouldn't happen though.
        */
    }

    /* Make the environment vector. */
    envp = make_envp();

    /* Make the argument vector. */
    argp = make_argp();

    /* Set up stdin.  For POSTs we may have to set up a pipe from an
    ** interposer process, depending on if we've read some of the data
    ** into our buffer.  We also have to do this for all SSL CGIs.
    */
#ifdef USE_SSL
    if ((method == METHOD_POST && request_len > request_idx) || do_ssl)
#else  /* USE_SSL */
    if ((method == METHOD_POST && request_len > request_idx))
#endif /* USE_SSL */
    {
        int p[2];
        int r;

        if (pipe(p) < 0)
            send_error(500, "Internal Error", "", "Something unexpected went wrong making a pipe.");
        r = fork();
        if (r < 0)
            send_error(500, "Internal Error", "", "Something unexpected went wrong forking an interposer.");
        if (r == 0) {
            /* Interposer process. */
            (void)close(p[0]);
            cgi_interpose_input(p[1]);
            finish_request(0);
        }
        (void)close(p[1]);
        if (p[0] != STDIN_FILENO) {
            (void)dup2(p[0], STDIN_FILENO);
            (void)close(p[0]);
        }
    } else {
        /* Otherwise, the request socket is stdin. */
        if (conn_fd != STDIN_FILENO)
            (void)dup2(conn_fd, STDIN_FILENO);
    }

    /* Set up stdout/stderr.  For SSL, or if we're doing CGI header parsing,
    ** we need an output interposer too.
    */
    if (strncmp(argp[0], "nph-", 4) == 0)
        parse_headers = 0;
    else
        parse_headers = 1;
#ifdef USE_SSL
    if (parse_headers || do_ssl)
#else  /* USE_SSL */
    if (parse_headers)
#endif /* USE_SSL */
    {
        int p[2];
        int r;

        if (pipe(p) < 0)
            send_error(500, "Internal Error", "", "Something unexpected went wrong making a pipe.");
        r = fork();
        if (r < 0)
            send_error(500, "Internal Error", "", "Something unexpected went wrong forking an interposer.");
        if (r == 0) {
            /* Interposer process. */
            (void)close(p[1]);
            cgi_interpose_output(p[0], parse_headers);
            finish_request(0);
        }
        (void)close(p[0]);
        if (p[1] != STDOUT_FILENO)
            (void)dup2(p[1], STDOUT_FILENO);
        if (p[1] != STDERR_FILENO)
            (void)dup2(p[1], STDERR_FILENO);
        if (p[1] != STDOUT_FILENO && p[1] != STDERR_FILENO)
            (void)close(p[1]);
    } else {
        /* Otherwise, the request socket is stdout/stderr. */
        if (conn_fd != STDOUT_FILENO)
            (void)dup2(conn_fd, STDOUT_FILENO);
        if (conn_fd != STDERR_FILENO)
            (void)dup2(conn_fd, STDERR_FILENO);
    }

    /* At this point we would like to set conn_fd to be close-on-exec.
    ** Unfortunately there seems to be a Linux problem here - if we
    ** do this close-on-exec in Linux, the socket stays open but stderr
    ** gets closed - the last fd duped from the socket.  What a mess.
    ** So we'll just leave the socket as is, which under other OSs means
    ** an extra file descriptor gets passed to the child process.  Since
    ** the child probably already has that file open via stdin stdout
    ** and/or stderr, this is not a problem.
    */
    /* (void) fcntl( conn_fd, F_SETFD, 1 ); */

    /* Close the log file. */
    if (logfp != (FILE*)0)
        (void)fclose(logfp);

    /* Close syslog. */
    closelog();

    /* Set priority. */
    (void)nice(CGI_NICE);

    /* Split the program into directory and binary, so we can chdir()
    ** to the program's own directory.  This isn't in the CGI 1.1
    ** spec, but it's what other HTTP servers do.
    */
    directory = e_strdup(file);
    binary = strrchr(directory, '/');
    if (binary == (char*)0)
        binary = file;
    else {
        *binary++ = '\0';
        (void)chdir(directory); /* ignore errors */
    }

    /* Default behavior for SIGPIPE. */
#ifdef HAVE_SIGSET
    (void)sigset(SIGPIPE, SIG_DFL);
#else  /* HAVE_SIGSET */
    (void)signal(SIGPIPE, SIG_DFL);
#endif /* HAVE_SIGSET */

    /* Run the program. */
    (void)execve(binary, argp, envp);

    /* Something went wrong. */
    send_error(500, "Internal Error", "", "Something unexpected went wrong running a CGI program.");
}

/* This routine is used only for POST requests.  It reads the data
** from the request and sends it to the child process.  The only reason
** we need to do it this way instead of just letting the child read
** directly is that we have already read part of the data into our
** buffer.
**
** Oh, and it's also used for all SSL CGIs.
*/
static void
cgi_interpose_input(int wfd) {
    size_t c;
    ssize_t r, r2;
    char buf[1024];

    /* Set up the timeout for reading again, since we're in a sub-process. */
#ifdef HAVE_SIGSET
    (void)sigset(SIGALRM, handle_read_timeout);
#else  /* HAVE_SIGSET */
    (void)signal(SIGALRM, handle_read_timeout);
#endif /* HAVE_SIGSET */
    (void)alarm(READ_TIMEOUT);

    c = request_len - request_idx;
    if (c > 0) {
        if (write(wfd, &(request[request_idx]), c) != c)
            return;
    }
    while (c < content_length) {
        r = my_read(buf, MIN(sizeof(buf), content_length - c));
        if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
            sleep(1);
            continue;
        }
        if (r <= 0)
            return;
        for (;;) {
            r2 = write(wfd, buf, r);
            if (r2 < 0 && (errno == EINTR || errno == EAGAIN)) {
                sleep(1);
                continue;
            }
            if (r2 != r)
                return;
            break;
        }
        c += r;
        (void)alarm(READ_TIMEOUT);
    }
    post_post_garbage_hack();
}

/* Special hack to deal with broken browsers that send a LF or CRLF
** after POST data, causing TCP resets - we just read and discard up
** to 2 bytes.  Unfortunately this doesn't fix the problem for CGIs
** which avoid the interposer process due to their POST data being
** short.  Creating an interposer process for all POST CGIs is
** unacceptably expensive.
*/
static void
post_post_garbage_hack(void) {
    char buf[2];

#ifdef USE_SSL
    if (do_ssl)
        /* We don't need to do this for SSL, since the garbage has
        ** already been read.  Probably.
        */
        return;
#endif /* USE_SSL */

    set_ndelay(conn_fd);
    (void)read(conn_fd, buf, sizeof(buf));
    clear_ndelay(conn_fd);
}

/* This routine is used for parsed-header CGIs and for all SSL CGIs. */
static void
cgi_interpose_output(int rfd, int parse_headers) {
    ssize_t r, r2;
    char buf[1024];

    /* Set up the timeout for writing again, since we're in a sub-process. */
#ifdef HAVE_SIGSET
    (void)sigset(SIGALRM, handle_write_timeout);
#else  /* HAVE_SIGSET */
    (void)signal(SIGALRM, handle_write_timeout);
#endif /* HAVE_SIGSET */
    (void)alarm(WRITE_TIMEOUT);

    if (!parse_headers) {
        /* If we're not parsing headers, write out the default status line
        ** and proceed to the echo phase.
        */
        char http_head[] = "HTTP/1.0 200 OK\015\012";
        (void)my_write(http_head, sizeof(http_head));
    } else {
        /* Header parsing.  The idea here is that the CGI can return special
        ** headers such as "Status:" and "Location:" which change the return
        ** status of the response.  Since the return status has to be the very
        ** first line written out, we have to accumulate all the headers
        ** and check for the special ones before writing the status.  Then
        ** we write out the saved headers and proceed to echo the rest of
        ** the response.
        */
        size_t headers_size, headers_len;
        char* headers;
        char* br;
        int s;
        char* title;
        char* cp;

        /* Slurp in all headers. */
        headers_size = 0;
        add_data(&headers, &headers_size, &headers_len, (char*)0, 0);
        for (;;) {
            r = read(rfd, buf, sizeof(buf));
            if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
                sleep(1);
                continue;
            }
            if (r <= 0) {
                br = &(headers[headers_len]);
                break;
            }
            add_data(&headers, &headers_size, &headers_len, buf, r);
            if ((br = strstr(headers, "\015\012\015\012")) != (char*)0 ||
                (br = strstr(headers, "\012\012")) != (char*)0)
                break;
        }

        /* If there were no headers, bail. */
        if (headers_len == 0)
            return;

        /* Figure out the status. */
        s = 200;
        if ((cp = strstr(headers, "Location:")) != (char*)0 &&
            cp < br &&
            (cp == headers || *(cp - 1) == '\012'))
            s = 302;
        if ((cp = strstr(headers, "Status:")) != (char*)0 &&
            cp < br &&
            (cp == headers || *(cp - 1) == '\012')) {
            cp += 7;
            cp += strspn(cp, " \t");
            s = atoi(cp);
        }

        /* Write the status line. */
        switch (s) {
            case 200:
                title = "OK";
                break;
            case 302:
                title = "Found";
                break;
            case 304:
                title = "Not Modified";
                break;
            case 400:
                title = "Bad Request";
                break;
            case 401:
                title = "Unauthorized";
                break;
            case 403:
                title = "Forbidden";
                break;
            case 404:
                title = "Not Found";
                break;
            case 408:
                title = "Request Timeout";
                break;
            case 451:
                title = "Unavailable For Legal Reasons";
                break;
            case 500:
                title = "Internal Error";
                break;
            case 501:
                title = "Not Implemented";
                break;
            case 503:
                title = "Service Temporarily Overloaded";
                break;
            default:
                title = "Something";
                break;
        }
        (void)snprintf(
            buf, sizeof(buf), "HTTP/1.0 %d %s\015\012", s, title);
        (void)my_write(buf, strlen(buf));

        /* Write the saved headers. */
        (void)my_write(headers, headers_len);
    }

    /* Echo the rest of the output. */
    for (;;) {
        r = read(rfd, buf, sizeof(buf));
        if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
            sleep(1);
            continue;
        }
        if (r <= 0)
            return;
        for (;;) {
            r2 = my_write(buf, r);
            if (r2 < 0 && (errno == EINTR || errno == EAGAIN)) {
                sleep(1);
                continue;
            }
            if (r2 != r)
                return;
            break;
        }
        (void)alarm(WRITE_TIMEOUT);
    }
}

/* Set up CGI argument vector.  We don't have to worry about freeing
** stuff since we're a sub-process.  This gets done after make_envp() because
** we scribble on query.
*/
static char**
make_argp(void) {
    char** argp;
    int argn;
    char* cp1;
    char* cp2;

    /* By allocating an arg slot for every character in the query, plus
    ** one for the filename and one for the NULL, we are guaranteed to
    ** have enough.  We could actually use strlen/2.
    */
    argp = (char**)malloc((strlen(query) + 2) * sizeof(char*));
    if (argp == (char**)0)
        return (char**)0;

    argp[0] = strrchr(file, '/');
    if (argp[0] != (char*)0)
        ++argp[0];
    else
        argp[0] = file;

    argn = 1;
    /* According to the CGI spec at http://hoohoo.ncsa.uiuc.edu/cgi/cl.html,
    ** "The server should search the query information for a non-encoded =
    ** character to determine if the command line is to be used, if it finds
    ** one, the command line is not to be used."
    */
    if (strchr(query, '=') == (char*)0) {
        for (cp1 = cp2 = query; *cp2 != '\0'; ++cp2) {
            if (*cp2 == '+') {
                *cp2 = '\0';
                strdecode(cp1, cp1);
                argp[argn++] = cp1;
                cp1 = cp2 + 1;
            }
        }
        if (cp2 != cp1) {
            strdecode(cp1, cp1);
            argp[argn++] = cp1;
        }
    }

    argp[argn] = (char*)0;
    return argp;
}

/* Set up CGI environment variables. Be real careful here to avoid
** letting malicious clients overrun a buffer.  We don't have
** to worry about freeing stuff since we're a sub-process.
*/
static char**
make_envp(void) {
    static char* envp[50];
    int envn;
    char* cp;
    char buf[256];

    envn = 0;
    envp[envn++] = build_env("PATH=%s", CGI_PATH);
    envp[envn++] = build_env("LD_LIBRARY_PATH=%s", CGI_LD_LIBRARY_PATH);
    envp[envn++] = build_env("SERVER_SOFTWARE=%s", SERVER_SOFTWARE);
    if (vhost && req_hostname != (char*)0 && req_hostname[0] != '\0')
        cp = req_hostname; /* already computed by virtual_file() */
    else if (host != (char*)0 && host[0] != '\0')
        cp = host;
    else
        cp = hostname;
    if (cp != (char*)0)
        envp[envn++] = build_env("SERVER_NAME=%s", cp);
    envp[envn++] = "GATEWAY_INTERFACE=CGI/1.1";
    envp[envn++] = "SERVER_PROTOCOL=HTTP/1.0";
    (void)snprintf(buf, sizeof(buf), "%d", (int)port);
    envp[envn++] = build_env("SERVER_PORT=%s", buf);
    envp[envn++] = build_env(
        "REQUEST_METHOD=%s", get_method_str(method));
    envp[envn++] = build_env("SCRIPT_NAME=%s", path);
    if (pathinfo != (char*)0) {
        envp[envn++] = build_env("PATH_INFO=/%s", pathinfo);
        (void)snprintf(buf, sizeof(buf), "%s%s", cwd, pathinfo);
        envp[envn++] = build_env("PATH_TRANSLATED=%s", buf);
    }
    if (query[0] != '\0')
        envp[envn++] = build_env("QUERY_STRING=%s", query);
    envp[envn++] = build_env("REMOTE_ADDR=%s", ntoa(&client_addr));
    if (referrer[0] != '\0') {
        envp[envn++] = build_env("HTTP_REFERER=%s", referrer);
        envp[envn++] = build_env("HTTP_REFERRER=%s", referrer);
    }
    if (useragent[0] != '\0')
        envp[envn++] = build_env("HTTP_USER_AGENT=%s", useragent);
    if (cookie != (char*)0)
        envp[envn++] = build_env("HTTP_COOKIE=%s", cookie);
    if (host != (char*)0)
        envp[envn++] = build_env("HTTP_HOST=%s", host);
    if (content_type != (char*)0)
        envp[envn++] = build_env("CONTENT_TYPE=%s", content_type);
    if (content_length != -1) {
        (void)snprintf(
            buf, sizeof(buf), "%lu", (unsigned long)content_length);
        envp[envn++] = build_env("CONTENT_LENGTH=%s", buf);
    }
    if (remoteuser != (char*)0)
        envp[envn++] = build_env("REMOTE_USER=%s", remoteuser);
    if (authorization != (char*)0)
        envp[envn++] = build_env("AUTH_TYPE=%s", "Basic");
    if (getenv("TZ") != (char*)0)
        envp[envn++] = build_env("TZ=%s", getenv("TZ"));

    envp[envn] = (char*)0;
    return envp;
}

static char*
build_env(char* fmt, char* arg) {
    char* cp;
    int size;
    static char* buf;
    static int maxbuf = 0;

    size = strlen(fmt) + strlen(arg);
    if (size > maxbuf) {
        if (maxbuf == 0) {
            maxbuf = MAX(200, size + 100);
            buf = (char*)e_malloc(maxbuf);
        } else {
            maxbuf = MAX(maxbuf * 2, size * 5 / 4);
            buf = (char*)e_realloc((void*)buf, maxbuf);
        }
    }
    (void)snprintf(buf, maxbuf, fmt, arg);
    cp = e_strdup(buf);
    return cp;
}

static void
auth_check(char* dirname) {
    char authpath[10000];
    struct stat sb2;
    char authinfo[500];
    char* authpass;
    char* colon;
    static char line[10000];
    int l;
    FILE* fp;
    char* cryp;

    /* Construct auth filename. */
    if (dirname[strlen(dirname) - 1] == '/')
        (void)snprintf(authpath, sizeof(authpath), "%s%s", dirname, AUTH_FILE);
    else
        (void)snprintf(authpath, sizeof(authpath), "%s/%s", dirname, AUTH_FILE);

    /* Does this directory have an auth file? */
    if (stat(authpath, &sb2) < 0)
        /* Nope, let the request go through. */
        return;

    /* Does this request contain authorization info? */
    if (authorization == (char*)0)
        /* Nope, return a 401 Unauthorized. */
        send_authenticate(dirname);

    /* Basic authorization info? */
    if (strncmp(authorization, "Basic ", 6) != 0)
        send_authenticate(dirname);

    /* Decode it. */
    l = b64_decode(
        &(authorization[6]), (unsigned char*)authinfo, sizeof(authinfo) - 1);
    authinfo[l] = '\0';
    /* Split into user and password. */
    authpass = strchr(authinfo, ':');
    if (authpass == (char*)0)
        /* No colon?  Bogus auth info. */
        send_authenticate(dirname);
    *authpass++ = '\0';
    /* If there are more fields, cut them off. */
    colon = strchr(authpass, ':');
    if (colon != (char*)0)
        *colon = '\0';

    /* Open the password file. */
    fp = fopen(authpath, "r");
    if (fp == (FILE*)0) {
        /* The file exists but we can't open it?  Disallow access. */
        syslog(
            LOG_ERR, "%.80s auth file %.80s could not be opened - %m",
            ntoa(&client_addr), authpath);
        send_error(403, "Forbidden", "", "File is protected.");
    }

    /* Read it. */
    while (fgets(line, sizeof(line), fp) != (char*)0) {
        /* Nuke newline. */
        l = strlen(line);
        if (line[l - 1] == '\n')
            line[l - 1] = '\0';
        /* Split into user and encrypted password. */
        cryp = strchr(line, ':');
        if (cryp == (char*)0)
            continue;
        *cryp++ = '\0';
        /* Is this the right user? */
        if (strcmp(line, authinfo) == 0) {
            /* Yes. */
            (void)fclose(fp);
            /* So is the password right? */
            if (strcmp(crypt(authpass, cryp), cryp) == 0) {
                /* Ok! */
                remoteuser = line;
                return;
            } else
                /* No. */
                send_authenticate(dirname);
        }
    }

    /* Didn't find that user.  Access denied. */
    (void)fclose(fp);
    send_authenticate(dirname);
}

static void
send_authenticate(char* realm) {
    char header[10000];

    (void)snprintf(
        header, sizeof(header), "WWW-Authenticate: Basic realm=\"%s\"", realm);
    send_error(401, "Unauthorized", header, "Authorization required.");
}

static char*
virtual_file(char* f) {
    char* cp;
    static char vfile[10000];

    /* Use the request's hostname, or fall back on the IP address. */
    if (host != (char*)0)
        req_hostname = host;
    else {
        usockaddr usa;
        socklen_t sz = sizeof(usa);
        if (getsockname(conn_fd, &usa.sa, &sz) < 0)
            req_hostname = "UNKNOWN_HOST";
        else
            req_hostname = ntoa(&usa);
    }
    /* Pound it to lower case. */
    for (cp = req_hostname; *cp != '\0'; ++cp)
        if (isupper(*cp))
            *cp = tolower(*cp);
    (void)snprintf(vfile, sizeof(vfile), "%s/%s", req_hostname, f);
    return vfile;
}

static void
send_error(int s, char* title, char* extra_header, char* text) {
    add_headers(
        s, title, extra_header, "", "text/html", (off_t)-1, (time_t)-1);

    send_error_body(s, title, text);

    send_error_tail();

    send_response();

#ifdef USE_SSL
    SSL_free(ssl);
#endif /* USE_SSL */
    finish_request(1);
}

static void
send_error_body(int s, char* title, char* text) {
    char filename[1000];
    char buf[10000];

    if (vhost && req_hostname != (char*)0) {
        /* Try virtual-host custom error page. */
        (void)snprintf(
            filename, sizeof(filename), "%s/%s/err%d.html",
            req_hostname, ERR_DIR, s);
        if (send_error_file(filename))
            return;
    }

    /* Try server-wide custom error page. */
    (void)snprintf(
        filename, sizeof(filename), "%s/err%d.html", ERR_DIR, s);
    if (send_error_file(filename))
        return;

    /* Send built-in error page. */
    (void)snprintf(
        buf, sizeof(buf),
        "\
<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n\
\n\
<html>\n\
\n\
  <head>\n\
    <meta http-equiv=\"Content-type\" content=\"text/html;charset=UTF-8\">\n\
    <title>%d %s</title>\n\
  </head>\n\
\n\
  <body bgcolor=\"#cc9999\" text=\"#000000\" link=\"#2020ff\" vlink=\"#4040cc\">\n\
\n\
    <h4>%d %s</h4>\n",
        s, title, s, title);
    add_to_response(buf);
    (void)snprintf(buf, sizeof(buf), "%s\n", text);
    add_to_response(buf);
}

static int
send_error_file(char* filename) {
    FILE* fp;
    char buf[1000];
    size_t r;

    fp = fopen(filename, "r");
    if (fp == (FILE*)0)
        return 0;
    for (;;) {
        r = fread(buf, 1, sizeof(buf) - 1, fp);
        if (r == 0)
            break;
        buf[r] = '\0';
        add_to_response(buf);
    }
    (void)fclose(fp);
    return 1;
}

static void
send_error_tail(void) {
    char buf[500];

    if (match("**MSIE**", useragent)) {
        int n;
        (void)snprintf(buf, sizeof(buf), "<!--\n");
        add_to_response(buf);
        for (n = 0; n < 6; ++n) {
            (void)snprintf(buf, sizeof(buf), "Padding so that MSIE deigns to show this error instead of its own canned one.\n");
            add_to_response(buf);
        }
        (void)snprintf(buf, sizeof(buf), "-->\n");
        add_to_response(buf);
    }

    (void)snprintf(buf, sizeof(buf),
                   "\
    <hr>\n\
\n\
    <address><a href=\"%s\">%s</a></address>\n\
\n\
  </body>\n\
\n\
</html>\n",
                   SERVER_URL, SERVER_SOFTWARE);
    add_to_response(buf);
}

static void
add_headers(int s, char* title, char* extra_header, char* me, char* mt, off_t b, time_t mod) {
    time_t now, expires;
    char timebuf[100];
    char buf[10000];
    int s100;
    const char* rfc1123_fmt = "%a, %d %b %Y %H:%M:%S GMT";

    status = s;
    bytes = b;
    make_log_entry();
    start_response();
    (void)snprintf(buf, sizeof(buf), "%s %d %s\015\012", protocol, status, title);
    add_to_response(buf);
    (void)snprintf(buf, sizeof(buf), "Server: %s\015\012", SERVER_SOFTWARE);
    add_to_response(buf);
    now = time((time_t*)0);
    (void)strftime(timebuf, sizeof(timebuf), rfc1123_fmt, gmtime(&now));
    (void)snprintf(buf, sizeof(buf), "Date: %s\015\012", timebuf);
    add_to_response(buf);
    s100 = status / 100;
    if (s100 != 2 && s100 != 3) {
        (void)snprintf(buf, sizeof(buf), "Cache-Control: no-cache,no-store\015\012");
        add_to_response(buf);
    }
    if (extra_header != (char*)0 && extra_header[0] != '\0') {
        (void)snprintf(buf, sizeof(buf), "%s\015\012", extra_header);
        add_to_response(buf);
    }
    if (me != (char*)0 && me[0] != '\0') {
        (void)snprintf(buf, sizeof(buf), "Content-Encoding: %s\015\012", me);
        add_to_response(buf);
    }
    if (mt != (char*)0 && mt[0] != '\0') {
        (void)snprintf(buf, sizeof(buf), "Content-Type: %s\015\012", mt);
        add_to_response(buf);
    }
    if (bytes >= 0) {
        (void)snprintf(
            buf, sizeof(buf), "Content-Length: %lld\015\012", (long long)bytes);
        add_to_response(buf);
    }
    if (p3p != (char*)0 && p3p[0] != '\0') {
        (void)snprintf(buf, sizeof(buf), "P3P: %s\015\012", p3p);
        add_to_response(buf);
    }
    if (max_age >= 0) {
        expires = now + max_age;
        (void)strftime(
            timebuf, sizeof(timebuf), rfc1123_fmt, gmtime(&expires));
        (void)snprintf(buf, sizeof(buf),
                       "Cache-Control: max-age=%d\015\012Expires: %s\015\012", max_age, timebuf);
        add_to_response(buf);
    }
    if (mod != (time_t)-1) {
        (void)strftime(
            timebuf, sizeof(timebuf), rfc1123_fmt, gmtime(&mod));
        (void)snprintf(buf, sizeof(buf), "Last-Modified: %s\015\012", timebuf);
        add_to_response(buf);
    }
    (void)snprintf(buf, sizeof(buf), "Connection: close\015\012\015\012");
    add_to_response(buf);
}

static void
start_request(void) {
    request_size = 0;
    request_idx = 0;
}

static void
add_to_request(char* str, size_t len) {
    add_data(&request, &request_size, &request_len, str, len);
}

static char*
get_request_line(void) {
    int i;
    char c;

    for (i = request_idx; request_idx < request_len; ++request_idx) {
        c = request[request_idx];
        if (c == '\012' || c == '\015') {
            request[request_idx] = '\0';
            ++request_idx;
            if (c == '\015' && request_idx < request_len &&
                request[request_idx] == '\012') {
                request[request_idx] = '\0';
                ++request_idx;
            }
            return &(request[i]);
        }
    }
    return (char*)0;
}

static char* response;
static size_t response_size, response_len;

static void
start_response(void) {
    response_size = 0;
}

static void
add_to_response(char* str) {
    add_str(&response, &response_size, &response_len, str);
}

static void
send_response(void) {
    (void)my_write(response, response_len);
}

static void
send_via_write(int fd, off_t size) {
    /* On some systems an off_t is 64 bits while a size_t is still only
    ** 32 bits.  The mmap() system call takes a size_t as the length argument,
    ** so we can only use mmap() if the size will fit into a size_t.
    */
    if (size <= SIZE_T_MAX) {
        size_t size_size = (size_t)size;
        unsigned char* ptr = mmap(0, size_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (ptr != (unsigned char*)-1) {
            unsigned char* p = ptr;
            size_t remaining_size = size_size;
#ifdef MADV_SEQUENTIAL
            /* If we have madvise, might as well call it.  Although sequential
            ** access is probably already the default.
            */
            (void)madvise(ptr, size_size, MADV_SEQUENTIAL);
#endif /* MADV_SEQUENTIAL */
            /* We could send the whole file in a single write, but if
            ** it's huge then we run the risk of hitting the timeout.
            ** So we do a loop writing large segments, and reseting the
            ** timeout each time through.
            */
            while (remaining_size > 0) {
                size_t buf_size = MIN(remaining_size, MAX_SEND_BUFFER_SIZE);
                ssize_t r = my_write(p, buf_size);
                if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
                    sleep(1);
                    continue;
                }
                if (r != buf_size)
                    return;
                remaining_size -= r;
                p += r;
                (void)alarm(WRITE_TIMEOUT);
            }
            (void)munmap(ptr, size_size);
        }
    } else {
        /* The file is too big for mmap, so we'll send it via read & write
        ** instead.  This would be less efficient for small files because
        ** it bypasses the buffer cache, but with a file this huge the
        ** cache will get blown anyway.
        */
        char buf[30000];

        for (;;) {
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
                sleep(1);
                continue;
            }
            if (r <= 0)
                return;
            for (;;) {
                ssize_t r2 = my_write(buf, r);
                if (r2 < 0 && (errno == EINTR || errno == EAGAIN)) {
                    sleep(1);
                    continue;
                }
                if (r2 != r)
                    return;
                break;
            }
            (void)alarm(WRITE_TIMEOUT);
        }
    }
}

static void
send_via_sendfile(int fd, int s, off_t size) {
    /* We could send the whole file in a single sendfile, but if
    ** it's huge then we run the risk of hitting the timeout.
    ** So we do a loop writing large segments, and reseting the
    ** timeout each time through.
    **
    ** This also avoids the problem of using sendfile on a file larger
    ** than 2GB, since each segment size will now fit into a size_t.
    */
    off_t remaining_size = size;
    off_t off = 0;
    while (remaining_size > 0) {
        size_t buf_size = MIN(remaining_size, MAX_SEND_BUFFER_SIZE);
        ssize_t r = my_sendfile(fd, s, off, buf_size);
        if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
            sleep(1);
            continue;
        }
        if (r != buf_size)
            return;
        remaining_size -= r;
        off += r;
        (void)alarm(WRITE_TIMEOUT);
    }
}

static ssize_t
my_read(char* buf, size_t size) {
#ifdef USE_SSL
    if (do_ssl)
        return SSL_read(ssl, buf, size);
    else
        return read(conn_fd, buf, size);
#else  /* USE_SSL */
    //return recv(conn_fd, buf, size, 0);
    return read(conn_fd, buf, size);
#endif /* USE_SSL */
}

static ssize_t
my_write(void* buf, size_t size) {
#ifdef USE_SSL
    if (do_ssl)
        return SSL_write(ssl, buf, size);
    else
        return write(conn_fd, buf, size);
#else  /* USE_SSL */
    return write(conn_fd, buf, size);
#endif /* USE_SSL */
}

#ifdef HAVE_SENDFILE
static ssize_t
my_sendfile(int fd, int s, off_t offset, size_t nbytes) {
#ifdef HAVE_LINUX_SENDFILE
    off_t lo = offset;
    return sendfile(s, fd, &lo, nbytes);
#else  /* HAVE_LINUX_SENDFILE */
    int r;
    r = sendfile(fd, s, offset, nbytes, (struct sf_hdtr*)0, (off_t*)0, 0);
    if (r == 0)
        return nbytes;
    else
        return r;
#endif /* HAVE_LINUX_SENDFILE */
}
#endif /* HAVE_SENDFILE */

static void
add_str(char** bufP, size_t* bufsizeP, size_t* buflenP, char* str) {
    size_t len;

    if (str == (char*)0)
        len = 0;
    else
        len = strlen(str);
    add_data(bufP, bufsizeP, buflenP, str, len);
}

static void
add_data(char** bufP, size_t* bufsizeP, size_t* buflenP, char* str, size_t len) {
    if (*bufsizeP == 0) {
        *bufsizeP = len + 500;
        *buflenP = 0;
        *bufP = (char*)e_malloc(*bufsizeP);
    } else if (*buflenP + len >= *bufsizeP) /* allow for NUL */
    {
        *bufsizeP = *buflenP + len + 500;
        *bufP = (char*)e_realloc((void*)*bufP, *bufsizeP);
    }

    if (len > 0) {
        (void)memmove(&((*bufP)[*buflenP]), str, len);
        *buflenP += len;
    }

    (*bufP)[*buflenP] = '\0';
}

static void
make_log_entry(void) {
    char* ru;
    char url[500];
    char bytes_str[40];
    time_t now;
    struct tm* t;
    const char* cernfmt_nozone = "%d/%b/%Y:%H:%M:%S";
    char date_nozone[100];
    int zone;
    char sign;
    char date[100];

    if (logfp == (FILE*)0)
        return;

    /* Fill in some null values. */
    if (protocol == (char*)0)
        protocol = "UNKNOWN";
    if (path == (char*)0)
        path = "";
    if (req_hostname == (char*)0)
        req_hostname = hostname;

    /* Format the user. */
    if (remoteuser != (char*)0)
        ru = remoteuser;
    else
        ru = "-";
    now = time((time_t*)0);
    /* If we're vhosting, prepend the hostname to the url.  This is
    ** a little weird, perhaps writing separate log files for
    ** each vhost would make more sense.
    */
    if (vhost)
        (void)snprintf(url, sizeof(url), "/%s%s", req_hostname, path);
    else
        (void)snprintf(url, sizeof(url), "%s", path);
    /* Format the bytes. */
    if (bytes >= 0)
        (void)snprintf(
            bytes_str, sizeof(bytes_str), "%lld", (long long)bytes);
    else
        (void)strcpy(bytes_str, "-");
    /* Format the time, forcing a numeric timezone (some log analyzers
    ** are stoooopid about this).
    */
    t = localtime(&now);
    (void)strftime(date_nozone, sizeof(date_nozone), cernfmt_nozone, t);
#ifdef HAVE_TM_GMTOFF
    zone = t->tm_gmtoff / 60L;
#else
    zone = -(timezone / 60L);
    /* Probably have to add something about daylight time here. */
#endif
    if (zone >= 0)
        sign = '+';
    else {
        sign = '-';
        zone = -zone;
    }
    zone = (zone / 60) * 100 + zone % 60;
    (void)snprintf(date, sizeof(date), "%s %c%04d", date_nozone, sign, zone);
    /* And write the log entry. */
    (void)fprintf(logfp,
                  "%.80s - %.80s [%s] \"%.80s %.200s %.80s\" %d %s \"%.200s\" \"%.200s\"\n",
                  ntoa(&client_addr), ru, date, get_method_str(method), url,
                  protocol, status, bytes_str, referrer, useragent);
    (void)fflush(logfp);
}

/* Returns if it's ok to serve the url, otherwise generates an error
** and exits.
*/
static void
check_referrer(void) {
    char* cp;

    /* Are we doing referrer checking at all? */
    if (url_pattern == (char*)0)
        return;

    /* Is it ok? */
    if (really_check_referrer())
        return;

    /* Lose. */
    if (vhost && req_hostname != (char*)0)
        cp = req_hostname;
    else
        cp = hostname;
    if (cp == (char*)0)
        cp = "";
    syslog(
        LOG_INFO, "%.80s non-local referrer \"%.80s%.80s\" \"%.80s\"",
        ntoa(&client_addr), cp, path, referrer);
    send_error(403, "Forbidden", "", "You must supply a local referrer.");
}

/* Returns 1 if ok to serve the url, 0 if not. */
static int
really_check_referrer(void) {
    char* cp1;
    char* cp2;
    char* cp3;
    char* refhost;
    char* lp;

    /* Check for an empty referrer. */
    if (referrer == (char*)0 || referrer[0] == '\0' ||
        (cp1 = strstr(referrer, "//")) == (char*)0) {
        /* Disallow if we require a referrer and the url matches. */
        if (no_empty_referrers && match(url_pattern, path))
            return 0;
        /* Otherwise ok. */
        return 1;
    }

    /* Extract referrer host. */
    cp1 += 2;
    for (cp2 = cp1; *cp2 != '/' && *cp2 != ':' && *cp2 != '\0'; ++cp2)
        continue;
    refhost = (char*)e_malloc(cp2 - cp1 + 1);
    for (cp3 = refhost; cp1 < cp2; ++cp1, ++cp3)
        if (isupper(*cp1))
            *cp3 = tolower(*cp1);
        else
            *cp3 = *cp1;
    *cp3 = '\0';

    /* Local pattern? */
    if (local_pattern != (char*)0)
        lp = local_pattern;
    else {
        /* No local pattern.  What's our hostname? */
        if (!vhost) {
            /* Not vhosting, use the server name. */
            lp = hostname;
            if (lp == (char*)0)
                /* Couldn't figure out local hostname - give up. */
                return 1;
        } else {
            /* We are vhosting, use the hostname on this connection. */
            lp = req_hostname;
            if (lp == (char*)0)
                /* Oops, no hostname.  Maybe it's an old browser that
                ** doesn't send a Host: header.  We could figure out
                ** the default hostname for this IP address, but it's
                ** not worth it for the few requests like this.
                */
                return 1;
        }
    }

    /* If the referrer host doesn't match the local host pattern, and
    ** the URL does match the url pattern, it's an illegal reference.
    */
    if (!match(lp, refhost) && match(url_pattern, path))
        return 0;
    /* Otherwise ok. */
    return 1;
}

static char*
get_method_str(int m) {
    switch (m) {
        case METHOD_GET:
            return "GET";
        case METHOD_HEAD:
            return "HEAD";
        case METHOD_POST:
            return "POST";
        case METHOD_PUT:
            return "PUT";
        case METHOD_DELETE:
            return "DELETE";
        case METHOD_TRACE:
            return "TRACE";
        default:
            return "UNKNOWN";
    }
}

struct mime_entry {
    char* ext;
    size_t ext_len;
    char* val;
    size_t val_len;
};
static struct mime_entry enc_tab[] = {
#include "mime_encodings.h"
};
static const int n_enc_tab = sizeof(enc_tab) / sizeof(*enc_tab);
static struct mime_entry typ_tab[] = {
#include "mime_types.h"
};
static const int n_typ_tab = sizeof(typ_tab) / sizeof(*typ_tab);

/* qsort comparison routine */
static int
ext_compare(const void* v1, const void* v2) {
    const struct mime_entry* m1 = (const struct mime_entry*)v1;
    const struct mime_entry* m2 = (const struct mime_entry*)v2;
    return strcmp(m1->ext, m2->ext);
}

static void
init_mime(void) {
    int i;

    /* Sort the tables so we can do binary search. */
    qsort(enc_tab, n_enc_tab, sizeof(*enc_tab), ext_compare);
    qsort(typ_tab, n_typ_tab, sizeof(*typ_tab), ext_compare);

    /* Fill in the lengths. */
    for (i = 0; i < n_enc_tab; ++i) {
        enc_tab[i].ext_len = strlen(enc_tab[i].ext);
        enc_tab[i].val_len = strlen(enc_tab[i].val);
    }
    for (i = 0; i < n_typ_tab; ++i) {
        typ_tab[i].ext_len = strlen(typ_tab[i].ext);
        typ_tab[i].val_len = strlen(typ_tab[i].val);
    }
}

/* Figure out MIME encodings and type based on the filename.  Multiple
** encodings are separated by commas, and are listed in the order in
** which they were applied to the file.
*/
static const char*
figure_mime(char* name, char* me, size_t me_size) {
    char* prev_dot;
    char* dot;
    char* ext;
    int me_indexes[100], n_me_indexes;
    size_t ext_len, me_len;
    int i, top, bot, mid;
    int r;
    const char* default_type = "text/plain";
    const char* type;

    /* Peel off encoding extensions until there aren't any more. */
    n_me_indexes = 0;
    for (prev_dot = &name[strlen(name)];; prev_dot = dot) {
        for (dot = prev_dot - 1; dot >= name && *dot != '.'; --dot)
            ;
        if (dot < name) {
            /* No dot found.  No more encoding extensions, and no type
            ** extension either.
            */
            type = default_type;
            goto done;
        }
        ext = dot + 1;
        ext_len = prev_dot - ext;
        /* Search the encodings table.  Linear search is fine here, there
        ** are only a few entries.
        */
        for (i = 0; i < n_enc_tab; ++i) {
            if (ext_len == enc_tab[i].ext_len && strncasecmp(ext, enc_tab[i].ext, ext_len) == 0) {
                if (n_me_indexes < sizeof(me_indexes) / sizeof(*me_indexes)) {
                    me_indexes[n_me_indexes] = i;
                    ++n_me_indexes;
                }
                goto next;
            }
        }
        /* No encoding extension found.  Break and look for a type extension. */
        break;

    next:;
    }

    /* Binary search for a matching type extension. */
    top = n_typ_tab - 1;
    bot = 0;
    while (top >= bot) {
        mid = (top + bot) / 2;
        r = strncasecmp(ext, typ_tab[mid].ext, ext_len);
        if (r < 0)
            top = mid - 1;
        else if (r > 0)
            bot = mid + 1;
        else if (ext_len < typ_tab[mid].ext_len)
            top = mid - 1;
        else if (ext_len > typ_tab[mid].ext_len)
            bot = mid + 1;
        else {
            type = typ_tab[mid].val;
            goto done;
        }
    }
    type = default_type;

done:

    /* The last thing we do is actually generate the mime-encoding header. */
    me[0] = '\0';
    me_len = 0;
    for (i = n_me_indexes - 1; i >= 0; --i) {
        if (me_len + enc_tab[me_indexes[i]].val_len + 1 < me_size) {
            if (me[0] != '\0') {
                (void)strcpy(&me[me_len], ",");
                ++me_len;
            }
            (void)strcpy(&me[me_len], enc_tab[me_indexes[i]].val);
            me_len += enc_tab[me_indexes[i]].val_len;
        }
    }

    return type;
}

static void
handle_sigterm(int sig) {
    /* Don't need to set up the handler again, since it's a one-shot. */

    syslog(LOG_NOTICE, "exiting due to signal %d", sig);
    (void)fprintf(stderr, "%s: exiting due to signal %d\n", argv0, sig);
    closelog();
    exit(1);
}

/* SIGHUP says to re-open the log file. */
static void
handle_sighup(int sig) {
    const int oerrno = errno;

#ifndef HAVE_SIGSET
    /* Set up handler again. */
    (void)signal(SIGHUP, handle_sighup);
#endif /* ! HAVE_SIGSET */

    /* Just set a flag that we got the signal. */
    got_hup = 1;

    /* Restore previous errno. */
    errno = oerrno;
}

static void
handle_sigchld(int sig) {
    const int oerrno = errno;
    pid_t pid;
    int s;

#ifndef HAVE_SIGSET
    /* Set up handler again. */
    (void)signal(SIGCHLD, handle_sigchld);
#endif /* ! HAVE_SIGSET */

    /* Reap defunct children until there aren't any more. */
    for (;;) {
#ifdef HAVE_WAITPID
        pid = waitpid((pid_t)-1, &s, WNOHANG);
#else                      /* HAVE_WAITPID */
        pid = wait3(&s, WNOHANG, (struct rusage*)0);
#endif                     /* HAVE_WAITPID */
        if ((int)pid == 0) /* none left */
            break;
        if ((int)pid < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            /* ECHILD shouldn't happen with the WNOHANG option,
            ** but with some kernels it does anyway.  Ignore it.
            */
            if (errno != ECHILD) {
                syslog(LOG_ERR, "child wait - %m");
                perror("child wait");
            }
            break;
        }
    }

    /* Restore previous errno. */
    errno = oerrno;
}

static void
re_open_logfile(void) {
    if (logfp != (FILE*)0) {
        (void)fclose(logfp);
        logfp = (FILE*)0;
    }
    if (logfile != (char*)0) {
        syslog(LOG_NOTICE, "re-opening logfile");
        logfp = fopen(logfile, "a");
        if (logfp == (FILE*)0) {
            syslog(LOG_CRIT, "%s - %m", logfile);
            perror(logfile);
            exit(1);
        }
    }
}

static void
handle_read_timeout(int sig) {
    syslog(LOG_INFO, "%.80s connection timed out reading", ntoa(&client_addr));
    send_error(
        408, "Request Timeout", "",
        "No request appeared within a reasonable time period.");
}

static void
handle_write_timeout(int sig) {
    syslog(LOG_INFO, "%.80s connection timed out writing", ntoa(&client_addr));
    finish_request(1);
}

static void
lookup_hostname(usockaddr* usa4P, size_t sa4_len, int* gotv4P, usockaddr* usa6P, size_t sa6_len, int* gotv6P) {
#ifdef USE_IPV6

    struct addrinfo hints;
    char portstr[10];
    int gaierr;
    struct addrinfo* ai;
    struct addrinfo* ai2;
    struct addrinfo* aiv6;
    struct addrinfo* aiv4;

    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    (void)snprintf(portstr, sizeof(portstr), "%d", (int)port);
    if ((gaierr = getaddrinfo(hostname, portstr, &hints, &ai)) != 0) {
        syslog(
            LOG_CRIT, "getaddrinfo %.80s - %s", hostname,
            gai_strerror(gaierr));
        (void)fprintf(
            stderr, "%s: getaddrinfo %.80s - %s\n", argv0, hostname,
            gai_strerror(gaierr));
        exit(1);
    }

    /* Find the first IPv6 and IPv4 entries. */
    aiv6 = (struct addrinfo*)0;
    aiv4 = (struct addrinfo*)0;
    for (ai2 = ai; ai2 != (struct addrinfo*)0; ai2 = ai2->ai_next) {
        switch (ai2->ai_family) {
            case AF_INET6:
                if (aiv6 == (struct addrinfo*)0)
                    aiv6 = ai2;
                break;
            case AF_INET:
                if (aiv4 == (struct addrinfo*)0)
                    aiv4 = ai2;
                break;
        }
    }

    if (aiv6 == (struct addrinfo*)0)
        *gotv6P = 0;
    else {
        if (sa6_len < aiv6->ai_addrlen) {
            syslog(
                LOG_CRIT, "%.80s - sockaddr too small (%lu < %lu)",
                hostname, (unsigned long)sa6_len,
                (unsigned long)aiv6->ai_addrlen);
            (void)fprintf(
                stderr, "%s: %.80s - sockaddr too small (%lu < %lu)\n",
                argv0, hostname, (unsigned long)sa6_len,
                (unsigned long)aiv6->ai_addrlen);
            exit(1);
        }
        (void)memset(usa6P, 0, sa6_len);
        (void)memmove(usa6P, aiv6->ai_addr, aiv6->ai_addrlen);
        *gotv6P = 1;
    }

    if (aiv4 == (struct addrinfo*)0)
        *gotv4P = 0;
    else {
        if (sa4_len < aiv4->ai_addrlen) {
            syslog(
                LOG_CRIT, "%.80s - sockaddr too small (%lu < %lu)",
                hostname, (unsigned long)sa4_len,
                (unsigned long)aiv4->ai_addrlen);
            (void)fprintf(
                stderr, "%s: %.80s - sockaddr too small (%lu < %lu)\n",
                argv0, hostname, (unsigned long)sa4_len,
                (unsigned long)aiv4->ai_addrlen);
            exit(1);
        }
        (void)memset(usa4P, 0, sa4_len);
        (void)memmove(usa4P, aiv4->ai_addr, aiv4->ai_addrlen);
        *gotv4P = 1;
    }

    freeaddrinfo(ai);

#else /* USE_IPV6 */

    struct hostent* he;

    *gotv6P = 0;

    (void)memset(usa4P, 0, sa4_len);
    usa4P->sa.sa_family = AF_INET;
    if (hostname == (char*)0)
        usa4P->sa_in.sin_addr.s_addr = htonl(INADDR_ANY);
    else {
        usa4P->sa_in.sin_addr.s_addr = inet_addr(hostname);
        if ((int)usa4P->sa_in.sin_addr.s_addr == -1) {
            he = gethostbyname(hostname);
            if (he == (struct hostent*)0) {
#ifdef HAVE_HSTRERROR
                syslog(
                    LOG_CRIT, "gethostbyname %.80s - %s", hostname,
                    hstrerror(h_errno));
                (void)fprintf(
                    stderr, "%s: gethostbyname %.80s - %s\n", argv0, hostname,
                    hstrerror(h_errno));
#else  /* HAVE_HSTRERROR */
                syslog(LOG_CRIT, "gethostbyname %.80s failed", hostname);
                (void)fprintf(
                    stderr, "%s: gethostbyname %.80s failed\n", argv0,
                    hostname);
#endif /* HAVE_HSTRERROR */
                exit(1);
            }
            if (he->h_addrtype != AF_INET) {
                syslog(LOG_CRIT, "%.80s - non-IP network address", hostname);
                (void)fprintf(
                    stderr, "%s: %.80s - non-IP network address\n", argv0,
                    hostname);
                exit(1);
            }
            (void)memmove(
                &usa4P->sa_in.sin_addr.s_addr, he->h_addr, he->h_length);
        }
    }
    usa4P->sa_in.sin_port = htons(port);
    *gotv4P = 1;

#endif /* USE_IPV6 */
}

static char*
ntoa(usockaddr* usaP) {
#ifdef USE_IPV6
    static char str[200];

    if (getnameinfo(&usaP->sa, sockaddr_len(usaP), str, sizeof(str), 0, 0, NI_NUMERICHOST) != 0) {
        str[0] = '?';
        str[1] = '\0';
    } else if (IN6_IS_ADDR_V4MAPPED(&usaP->sa_in6.sin6_addr) && strncmp(str, "::ffff:", 7) == 0)
        /* Elide IPv6ish prefix for IPv4 addresses. */
        (void)ol_strcpy(str, &str[7]);

    return str;

#else /* USE_IPV6 */

    return inet_ntoa(usaP->sa_in.sin_addr);

#endif /* USE_IPV6 */
}

static int
sockaddr_check(usockaddr* usaP) {
    switch (usaP->sa.sa_family) {
        case AF_INET:
            return 1;
#ifdef USE_IPV6
        case AF_INET6:
            return 1;
#endif /* USE_IPV6 */
        default:
            return 0;
    }
}

static size_t
sockaddr_len(usockaddr* usaP) {
    switch (usaP->sa.sa_family) {
        case AF_INET:
            return sizeof(struct sockaddr_in);
#ifdef USE_IPV6
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
#endif /* USE_IPV6 */
        default:
            return 0; /* shouldn't happen */
    }
}

/* Copies and decodes a string.  It's ok for from and to to be the
** same string.
*/
static void
strdecode(char* to, char* from) {
    for (; *from != '\0'; ++to, ++from) {
        if (from[0] == '%' && isxdigit(from[1]) && isxdigit(from[2])) {
            *to = hexit(from[1]) * 16 + hexit(from[2]);
            from += 2;
        } else
            *to = *from;
    }
    *to = '\0';
}

static uint32_t urldecode(char *to, const char *from) {
    uint32_t size = 0;
    char *cur = to;
    while (*from) {
        if (*from == '+') {
            *cur++ = ' ';
            size++;
            from++;
        } else if (*from == '%' && isxdigit(from[1]) && isxdigit(from[2])) {
            *cur++ = hexit(from[1]) * 16 + hexit(from[2]);
            size++;
            from += 3;
        } else {
            *cur++ = *from++;
            size++;
        }
    }
    *cur = '\0';
    return size;
}


static int
hexit(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0; /* shouldn't happen, we're guarded by isxdigit() */
}

/* Base-64 decoding.  This represents binary data as printable ASCII
** characters.  Three 8-bit binary bytes are turned into four 6-bit
** values, like so:
**
**   [11111111]  [22222222]  [33333333]
**
**   [111111] [112222] [222233] [333333]
**
** Then the 6-bit values are represented using the characters "A-Za-z0-9+/".
*/

static int b64_decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 00-0F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 10-1F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /* 20-2F */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /* 30-3F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,           /* 40-4F */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /* 50-5F */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 60-6F */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 70-7F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 80-8F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 90-9F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* A0-AF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* B0-BF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* C0-CF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* D0-DF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* E0-EF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /* F0-FF */
};

/* Do base-64 decoding on a string.  Ignore any non-base64 bytes.
** Return the actual number of bytes generated.  The decoded size will
** be at most 3/4 the size of the encoded, and may be smaller if there
** are padding characters (blanks, newlines).
*/
static int
b64_decode(const char* str, unsigned char* space, int size) {
    const char* cp;
    int space_idx, phase;
    int d, prev_d = 0;
    unsigned char c;

    space_idx = 0;
    phase = 0;
    for (cp = str; *cp != '\0'; ++cp) {
        d = b64_decode_table[(int)((unsigned char)*cp)];
        if (d != -1) {
            switch (phase) {
                case 0:
                    ++phase;
                    break;
                case 1:
                    c = ((prev_d << 2) | ((d & 0x30) >> 4));
                    if (space_idx < size)
                        space[space_idx++] = c;
                    ++phase;
                    break;
                case 2:
                    c = (((prev_d & 0xf) << 4) | ((d & 0x3c) >> 2));
                    if (space_idx < size)
                        space[space_idx++] = c;
                    ++phase;
                    break;
                case 3:
                    c = (((prev_d & 0x03) << 6) | d);
                    if (space_idx < size)
                        space[space_idx++] = c;
                    phase = 0;
                    break;
            }
            prev_d = d;
        }
    }
    return space_idx;
}

/* Set NDELAY mode on a socket. */
static void
set_ndelay(int fd) {
    int flags, newflags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        newflags = flags | (int)O_NDELAY;
        if (newflags != flags)
            (void)fcntl(fd, F_SETFL, newflags);
    }
}

/* Clear NDELAY mode on a socket. */
static void
clear_ndelay(int fd) {
    int flags, newflags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        newflags = flags & ~(int)O_NDELAY;
        if (newflags != flags)
            (void)fcntl(fd, F_SETFL, newflags);
    }
}

static void*
e_malloc(size_t size) {
    void* ptr;

    ptr = malloc(size);
    if (ptr == (void*)0) {
        syslog(LOG_CRIT, "out of memory");
        (void)fprintf(stderr, "%s: out of memory\n", argv0);
        exit(1);
    }
    return ptr;
}

static void*
e_realloc(void* optr, size_t size) {
    void* ptr;

    ptr = realloc(optr, size);
    if (ptr == (void*)0) {
        syslog(LOG_CRIT, "out of memory");
        (void)fprintf(stderr, "%s: out of memory\n", argv0);
        exit(1);
    }
    return ptr;
}

static char*
e_strdup(char* ostr) {
    char* str;

    str = strdup(ostr);
    if (str == (char*)0) {
        syslog(LOG_CRIT, "out of memory copying a string");
        (void)fprintf(stderr, "%s: out of memory copying a string\n", argv0);
        exit(1);
    }
    return str;
}

#ifdef NO_SNPRINTF
/* Some systems don't have snprintf(), so we make our own that uses
** vsprintf().  This workaround is probably vulnerable to buffer overruns,
** so upgrade your OS!
*/
static int
snprintf(char* str, size_t size, const char* format, ...) {
    va_list ap;
    int r;

    va_start(ap, format);
    r = vsprintf(str, format, ap);
    va_end(ap);
    return r;
}
#endif /* NO_SNPRINTF */
