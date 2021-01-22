CC=gcc
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=c99

LD_SONAME=-Wl,-soname,libnss_aad.so.2
LIBRARY=libnss_aad.so.2.0
LINKS=libnss_aad.so.2 libnss_aad.so

DESTDIR=/
PREFIX=$(DESTDIR)/usr
#LIBDIR=$(PREFIX)/lib/x86_64-linux-gnu/
LIBDIR=$(PREFIX)/lib/
#LIBDIR=$(PREFIX)/lib64
CONFDIR=$(DESTDIR)/etc/azuread
CONFFILE=parameters.json.example
BUILD=.libs

default: build
build: nss_aad

nss_aad_build_dir:
	[ -d $(BUILD) ] || mkdir $(BUILD)

nss_aad-passwd:
	$(CC) $(CFLAGS) -c nss_aad-passwd.c -o $(BUILD)/nss_aad-passwd.o -I.

nss_aad-group:
	$(CC) $(CFLAGS) -c nss_aad-group.c -o $(BUILD)/nss_aad-group.o -I.

nss_aad-shadow:
	$(CC) $(CFLAGS) -c nss_aad-shadow.c -o $(BUILD)/nss_aad-shadow.o -I.

nss_aad_services: nss_aad-passwd nss_aad-group nss_aad-shadow

nss_aad: nss_aad_build_dir nss_aad_services
	$(CC) $(CFLAGS) -c nss_aad.c -o $(BUILD)/nss_aad.o

	$(CC) -shared $(LD_SONAME) -o $(BUILD)/$(LIBRARY) \
		$(BUILD)/nss_aad.o \
		$(BUILD)/nss_aad-passwd.o \
		$(BUILD)/nss_aad-group.o \
		$(BUILD)/nss_aad-shadow.o \
                -lcurl -ljansson

clean:
	rm -rf $(BUILD)

install:
	[ -d $(LIBDIR) ] || install -d $(LIBDIR)
	install $(BUILD)/$(LIBRARY) $(LIBDIR)
	cd $(LIBDIR); for link in $(LINKS); do ln -sf $(LIBRARY) $$link ; done
	mkdir -p $(CONFDIR)
	cp $(CONFFILE) $(CONFDIR)/$(CONFFILE)
	

.PHONY: clean install nss_http_build_dir nss_http
