##
# Building apk-tools

-include config.mk

PACKAGE := apk-tools
VERSION := 2.12.0

export VERSION

##
# Default directories

DESTDIR		:=
SBINDIR		:= /sbin
LIBDIR		:= /lib
CONFDIR		:= /etc/apk
MANDIR		:= /usr/share/man
DOCDIR		:= /usr/share/doc/apk
INCLUDEDIR	:= /usr/include
PKGCONFIGDIR	:= /usr/lib/pkgconfig

export DESTDIR SBINDIR LIBDIR CONFDIR MANDIR DOCDIR INCLUDEDIR PKGCONFIGDIR

##
# Top-level subdirs

subdirs		:= libfetch/ src/ doc/

##
# Include all rules and stuff

include Make.rules

##
# Top-level targets

install:
	$(INSTALLDIR) $(DESTDIR)$(DOCDIR)
	$(INSTALL) README.md $(DESTDIR)$(DOCDIR)

check test: FORCE src/
	$(Q)$(MAKE) TEST=y
	$(Q)$(MAKE) -C test

static:
	$(Q)$(MAKE) STATIC=y

tag: check
	git commit . -m "apk-tools-$(VERSION)"
	git tag -s v$(VERSION) -m "apk-tools-$(VERSION)"

src/: libfetch/

image:
	docker build -t martencassel/alpine:latest .

shell:
	docker run -it --net=host -v $(PWD):/src martencassel/alpine:latest

build:
	LUA=no make

debug:
	echo "Launch from vscode, inside the container. Install c++ extension"
