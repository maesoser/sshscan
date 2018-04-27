#include "sshscan.h"

unsigned int nproc = 10;
unsigned long timeout = 3;
FILE *fp;
unsigned int wlen = 0;
uint32_t n = 0;
char buff[MAX_WORD_SIZE];
uint8_t verbose = 0;
uint32_t port = 22;

const unsigned int d_nproc = 10;
const unsigned long d_timeout = 3;

void help(){
    printf("\nMultithreaded SSH scan tool for networks\n");
    printf("Use: sshscan [OPTIONS] [USER_PASSW FILE] [IP RANGE]\n");
    printf("Options:\n");
    printf("\t-t [NUMTHREADS]: Change the number of threads used. Default is %d\n",d_nproc);
    printf("\t-s [TIMEOUT]: Change the timeout for the connection in seconds. Default is %ld\n",d_timeout);
    printf("\t-p [PORT]: Specify another port to connect to\n");
    printf("\t-h : Show this help\n");
    printf("\t-v : Verbose mode\n");

}
void to_bytes(uint32_t val, uint8_t *bytes){
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}

char *ip2str(uint32_t val)
{
    char *buf;
    size_t sz;
    uint8_t ipblock[4] = {0,0,0,0};
    to_bytes(val, ipblock);
    sz = snprintf(NULL, 0, "%d.%d.%d.%d", ipblock[0],ipblock[1],ipblock[2],ipblock[3]);
    buf = (char *) malloc(sz + 1); /* make sure you check for != NULL in real code */
    snprintf(buf, sz+1, "%d.%d.%d.%d", ipblock[0],ipblock[1],ipblock[2],ipblock[3]);
    return (char *)buf;
}

int parseSubnet(char *subnet_str, uint32_t *prefix, uint32_t *prefixLength){
    int result;
    uint8_t ipbytes[4] = {0,0,0,0};

    result = sscanf(subnet_str, "%hhd.%hhd.%hhd.%hhd/%d", &ipbytes[0], &ipbytes[1], &ipbytes[2], &ipbytes[3], prefixLength);
    if (result < 0 ) return result;
    else{
        *prefix = 0x00;
        *prefix = ipbytes[0] | (ipbytes[1] << 8) | (ipbytes[2] << 16) | (ipbytes[3] << 24);
        return result;
    }
}

int ConnectSSH(uint32_t ipaddr, char* user, char *passwd){
    int return_val = -1;    
    ssh_session my_ssh_session;
    int rc;
    
    //if (DEBUGON) printf(ANSI_COLOR_BOLD"[%s]"ANSI_COLOR_ENDC" Trying with user:%s  pass:%s\n",ip2str(ipaddr),user,passwd);

    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        return return_val;
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, ip2str(ipaddr));
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, user);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_TIMEOUT, &timeout);

    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK){
        //fprintf(stderr, ANSI_COLOR_BOLD"[%s]"ANSI_COLOR_ENDC" Error connecting: %s\n",ip2str(ipaddr),ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        return return_val;
    }

    rc = ssh_userauth_password(my_ssh_session, NULL, passwd);
    if (rc != SSH_AUTH_SUCCESS){
        if (verbose) fprintf(stderr, ANSI_COLOR_BOLD"[%s]"ANSI_COLOR_ENDC"Error authenticating with user:%s pass: %s, %s\n",ip2str(ipaddr),user,passwd,ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        return return_val;
    }else if(rc == SSH_AUTH_SUCCESS){
        printf(ANSI_COLOR_BOLD"[%s]"ANSI_COLOR_ENDC" Succeed with user:%s  pass:%s\n",ip2str(ipaddr),user,passwd);

	FILE *f = fopen("valid_credentials", "a");
	fprintf(f, "[%s][%s:%s]\n",ip2str(ipaddr),user,passwd);
	fclose(f);

        return_val=1;
    }
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    return return_val;
}

void checkSSH(void *context){
    thread_arg_t *targs = context;
    int j = 0;
    if (verbose) printf(ANSI_COLOR_BOLD"[%s]"ANSI_COLOR_ENDC" Connecting\n",ip2str(targs->ipadrr));
    for(j=0;j<targs->wlen;j++){
        char user[MAX_WORD_SIZE];
        char passwd[MAX_WORD_SIZE];
        int result = 0;
        result = sscanf(targs->wtable[j], "%128[^,],%s", user,passwd);
        //printf(ANSI_COLOR_YELLOW"user:%s   paswd:%s\n"ANSI_COLOR_RESET,user,passwd);
        if(result<0) {
            printf("Error splitting user and password from user,password file.\n");
            break;
        }
        //if (DEBUGON) printf("[%s] %d\n",ip2str(targs->ipadrr),targs->ipadrr);

        int res = ConnectSSH(targs->ipadrr, user, passwd);
        if(res>0) targs->solution=j+1;
    }
}

int main(int argc, char ** argv){
  int c;

  while ((c = getopt (argc, argv, "hvp:t:s:")) != -1)
    switch (c){
      case 'h':
        help();
        exit(0);
        break;
      case 'v':
        verbose = 1;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 't':
        nproc = atoi(optarg);
        break;
      case 's':
        timeout = atol(optarg);
        break;
      }
    
    if(argc-optind!=2){
	help();
	exit(0);
    }
    
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();

    threadpool thpool = thpool_init(nproc);

    uint32_t ip_addr = 0;
    uint32_t prefix = 0;
    uint32_t nhosts = 0;

    if(parseSubnet(argv[optind + 1], &ip_addr,&prefix)<0){
        printf("Error reading subnet: %s, format must be X.X.X.X/S\n",argv[2]);
        exit(-1);
    }
    if(prefix>32){
        printf("Error, mask too big: %d\n",prefix);
        exit(-1);
    }
    
    nhosts = pow(2,32 - prefix);
    if(nhosts!=0){
    printf("IP subnet %s/%d has %d hosts\n", ip2str(ip_addr), prefix, nhosts);
    }else{
        printf("Trying with %s\n", ip2str(ip_addr));
    }

    fp = fopen(argv[optind], "r");
    while(fgets(buff, MAX_WORD_SIZE, (FILE*)fp)!=NULL)  wlen++;
    printf("password-user file \"%s\" has %d combinations\n",argv[optind],wlen);
    fclose(fp);
    
    if (verbose) printf("Reading password-user file\n");
    char *words[wlen];
    fp = fopen(argv[optind], "r");
    unsigned int index = 0;
    while(fgets(buff, MAX_WORD_SIZE, (FILE*)fp)!=NULL){
        words[index] = (char *) malloc(strlen(buff));
        memcpy(words[index],buff,strlen(buff)-1);
        //if (DEBUGON) printf("pass-user: %s\n",words[index]);

        index++;
    }
    fclose(fp);
    
    thread_arg_t targs[nhosts];
    
    if(nhosts!=0){
        for(n=0;n<nhosts;n++){
            targs[n].ipadrr = ip_addr + htonl(n);
            targs[n].wlen = wlen;
            targs[n].wtable = words;
            targs[n].solution = -1;
            thpool_add_work(thpool, (void*)checkSSH, (void*)&targs[n]);
        }   
    }else{
        thread_arg_t targs;
        targs.ipadrr = ip_addr;
        targs.wlen = wlen;
        targs.wtable = words;
        targs.solution = -1;
        thpool_add_work(thpool, (void*)checkSSH, (void*)&targs);
    }

    thpool_wait(thpool);
    thpool_destroy(thpool);
    printf("Done\n");
    
    uint32_t autenticated = 0;
    for(n=0;n<nhosts;n++){
        if(targs[n].solution!=-1) autenticated++;
    }
    
    /*
    for(n=0;n<nhosts;n++){
        int solindx = targs[n].solution;
        if(solindx!=-1){
            printf("\t [%s] user,pass:  %s \n",ip2str(targs[n].ipadrr),words[solindx-1]);
        }
    }*/
    for(n=0;n<wlen;n++){
        free(words[n]);
    }

    return 0;
}
