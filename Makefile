CFLAGS = -Wall -O3 -std=c99
CLIBS = -lm -lssh -lssh_threads -pthread
CSRC = *.c
OUTNAME = sshscan

all:
	gcc $(CFLAGS) $(CSRC) $(CLIBS) -o $(OUTNAME)
	
debug:
	gcc $(CFLAGS) $(CSRC) -D THPOOL_DEBUG $(CLIBS) -o $(OUTNAME)

