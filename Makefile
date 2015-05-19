CC=gcc
SRVBIN=srv
CLIBIN=cli

CFLAGS=-O2 -Wall -DSOCK_TIMEOUT=60

all: srv cli

srv: simplevpn-srv.c md5.c
	$(CC) -o $(SRVBIN) $(CFLAGS) simplevpn-srv.c md5.c -pthread

cli: simplevpn-cli.c md5.c
	$(CC) -o $(CLIBIN) $(CFLAGS) simplevpn-cli.c md5.c


clean:
	rm -f $(SRVBIN) $(CLIBIN)


