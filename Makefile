CC=gcc
CFLAGS=-Wall -std=c99 -pedantic -O2 -g -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fPIC
LDFLAGS=-Wl,-z,relro -Wl,-z,now -pie
LIBS=-lmicrohttpd

lehttpd: lehttpd.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o lehttpd lehttpd.c ${LIBS}

clean:
	rm -f lehttpd
