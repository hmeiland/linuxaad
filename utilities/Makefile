CC=gcc
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=c99

EXEC=useradd-aad

DESTDIR=/
PREFIX=$(DESTDIR)/usr
BINDIR=$(PREFIX)/bin
CONFDIR=$(DESTDIR)/etc/azuread
CONFFILE=parameters.json.example
BUILD=.libs

default: build
build: useradd-aad 

useradd-aad_build_dir:
	[ -d $(BUILD) ] || mkdir $(BUILD)

useradd-aad: useradd-aad_build_dir
	$(CC) $(CFLAGS) -c nss_http.c -o $(BUILD)/nss_http.o
	$(CC) $(EXEC).c -o $(BUILD)/$(EXEC) \
		$(BUILD)/nss_http.o \
        	-lcurl -ljansson -I.

clean:
	rm -rf $(BUILD)

install:
	mkdir -p $(CONFDIR)
	cp $(CONFFILE) $(CONFDIR)/$(CONFFILE)
	cp $(BUILD)/$(EXEC) $(BINDIR)/$(EXEC)
	

.PHONY: clean install nss_http_build_dir nss_http
