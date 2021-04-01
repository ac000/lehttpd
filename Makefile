CC	= gcc
CFLAGS	= -Wall -Wextra -Wdeclaration-after-statement -Wvla -std=c99 -O2 -g \
	  -Wp,-D_FORTIFY_SOURCE=2 --param=ssp-buffer-size=4 -fstack-protector \
	  -fexceptions -fPIE
LDFLAGS	= -Wl,-z,defs,-z,relro,-z,now,--as-needed -pie
LIBS	= -lmicrohttpd

ifeq ($(shell pkg-config --exists libseccomp && echo 1), 1)
LIBS	+= -lseccomp
CFLAGS	+= -D_HAVE_LIBSECCOMP
endif

lehttpd: lehttpd.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f lehttpd
