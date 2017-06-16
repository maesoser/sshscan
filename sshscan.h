#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <ctype.h>
#include <getopt.h>

#include "thpool.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

#define ANSI_COLOR_HEADER "\033[95m"
#define ANSI_COLOR_OKBLUE "\033[94m"
#define ANSI_COLOR_OKGREEN "\033[92m"
#define ANSI_COLOR_WARNING "\033[93m"
#define ANSI_COLOR_FAIL "\033[91m"
#define ANSI_COLOR_ENDC "\033[0m"
#define ANSI_COLOR_BOLD "\033[1m"
#define ANSI_COLOR_UNDERLINE "\033[4m"
    
#define DEBUGON 1
#define MAX_WORD_SIZE 128
#define DEFAULT_THREADPOOL_SIZE 16

typedef struct {
	uint32_t ipadrr;
	uint32_t wlen;
	int32_t solution;
	char **wtable;
} thread_arg_t;


void to_bytes(uint32_t val, uint8_t *bytes);
char *ip2str(uint32_t val);
int parseSubnet(char *subnet_str, uint32_t *prefix, uint32_t *prefixLength);
int ConnectSSH(uint32_t ipaddr, char* user, char *passwd);
void checkSSH(void *context);
