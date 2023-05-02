CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

CDEFS =		$(SSL_DEFS) $(SSL_INC)
CFLAGS =	-O $(CDEFS) -Wall -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wno-long-long
LDFLAGS =	-s
CRYPT_LIB = -lcrypt -lcrypto
LDLIBS =	$(CRYPT_LIB) $(SSL_LIBS) $(SYSV_LIBS)

all:		mini_httpd htpasswd

mini_httpd:	mini_httpd.o match.o tdate_parse.o
	$(CC) $(LDFLAGS) mini_httpd.o match.o tdate_parse.o $(LDLIBS) -o mini_httpd

mini_httpd.o:	mini_httpd.c version.h port.h match.h tdate_parse.h mime_encodings.h mime_types.h
	$(CC) $(CFLAGS) -c mini_httpd.c

match.o:	match.c match.h
	$(CC) $(CFLAGS) -c match.c

tdate_parse.o:	tdate_parse.c tdate_parse.h
	$(CC) $(CFLAGS) -c tdate_parse.c

mime_encodings.h: mime_encodings.txt
	rm -f mime_encodings.h
	sed < mime_encodings.txt > mime_encodings.h \
	  -e 's/#.*//' -e 's/[ 	]*$$//' -e '/^$$/d' \
	  -e 's/[ 	][ 	]*/", 0, "/' -e 's/^/{ "/' -e 's/$$/", 0 },/'

mime_types.h: mime_types.txt
	rm -f mime_types.h
	sed < mime_types.txt > mime_types.h \
	  -e 's/#.*//' -e 's/[ 	]*$$//' -e '/^$$/d' \
	  -e 's/[ 	][ 	]*/", 0, "/' -e 's/^/{ "/' -e 's/$$/", 0 },/'


htpasswd:	htpasswd.o
	$(CC) $(LDFLAGS) htpasswd.o $(CRYPT_LIB) -o htpasswd

htpasswd.o:	htpasswd.c
	$(CC) $(CFLAGS) -c htpasswd.c


cert:		mini_httpd.pem
mini_httpd.pem:	mini_httpd.cnf
	openssl req -new -x509 -days 3650 -nodes -config mini_httpd.cnf -out mini_httpd.pem -keyout mini_httpd.pem
	openssl x509 -subject -dates -fingerprint -noout -in mini_httpd.pem
	chmod 600 mini_httpd.pem

clean:
	rm -f mini_httpd mime_encodings.h mime_types.h htpasswd mini_httpd.rnd *.o core core.* *.core

tar:
	@name=`sed -n -e '/#define SERVER_SOFTWARE /!d' -e 's,.*mini_httpd/,mini_httpd-,' -e 's, .*,,p' version.h` ; \
	  rm -rf $$name ; \
	  mkdir $$name ; \
	  tar cf - `cat FILES` | ( cd $$name ; tar xfBp - ) ; \
	  chmod 644 $$name/Makefile $$name/mime_encodings.txt $$name/mime_types.txt ; \
	  chmod 755 $$name/contrib $$name/contrib/redhat-rpm ; \
	  tar cf $$name.tar $$name ; \
	  rm -rf $$name ; \
	  gzip $$name.tar
