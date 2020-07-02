CC=gcc
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=c99

USEREXEC=useradd-aad
GROUPEXEC=groupadd-aad

DESTDIR=/
PREFIX=$(DESTDIR)/usr
BINDIR=$(PREFIX)/bin
CONFDIR=$(DESTDIR)/etc/azuread
CONFFILE=parameters.json.example
BUILD=.libs

default: build
build: useradd-aad groupadd-aad 

build_dir:
	[ -d $(BUILD) ] || mkdir $(BUILD)

useradd-aad: build_dir
	$(CC) $(CFLAGS) -c nss_http.c -o $(BUILD)/nss_http.o
	$(CC) $(CFLAGS) $(USEREXEC).c -o $(BUILD)/$(USEREXEC) \
		$(BUILD)/nss_http.o \
        	-lcurl -ljansson -I.

groupadd-aad: build_dir
	$(CC) $(CFLAGS) -c nss_http.c -o $(BUILD)/nss_http.o
	$(CC) $(GROUPEXEC).c -o $(BUILD)/$(GROUPEXEC) \
		$(BUILD)/nss_http.o \
        	-lcurl -ljansson -I.

clean:
	rm -rf $(BUILD)

install:
	mkdir -p $(CONFDIR)
	cp $(CONFFILE) $(CONFDIR)/$(CONFFILE)
	cp $(BUILD)/$(USEREXEC) $(BINDIR)/$(USEREXEC)
	cp $(BUILD)/$(GROUPEXEC) $(BINDIR)/$(GROUPEXEC)
	

.PHONY: clean install nss_http_build_dir nss_http
