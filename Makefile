# Makefile for dd_rescue
# (c) garloff@suse.de, 99/10/09, GNU GPL
# $Id$

VERSION = 1.39

DESTDIR = 

CC = gcc
RPM_OPT_FLAGS = -Os -Wall -g
CFLAGS = $(RPM_OPT_FLAGS) $(EXTRA_CFLAGS) -DHAVE_CONFIG_H
CFLAGS_OPT = $(CFLAGS) -O3
INSTALL = install
INSTALLFLAGS = -s
prefix = $(DESTDIR)/usr
#INSTALLDIR = $(prefix)/bin
INSTALLDIR = $(DESTDIR)/bin
MANDIR = $(prefix)/share/man/
#MYDIR = dd_rescue-$(VERSION)
MYDIR = dd_rescue
TARGETS = dd_rescue
#TARGETS = libfalloc-dl
OBJECTS = frandom.o fmt_no.o find_nonzero.o
HEADERS = frandom.h fmt_no.h find_nonzero.h config.h
DOCDIR = $(prefix)/share/doc/packages
INSTASROOT = -o root -g root
LIBDIR = /usr/lib
COMPILER = $(shell $(CC) --version | head -n1)
DEFINES = -DVERSION=\"$(VERSION)\"  -D__COMPILER__="\"$(COMPILER)\""
OUT = -o dd_rescue

ifeq ($(CC),wcl386)
  CFLAGS = "-ox -wx $(EXTRA_CFLAGS)"
  DEFINES = -dMISS_STRSIGNAL -dMISS_PREAD -dVERSION=\"$(VERSION)\" -d__COMPILER__="\"$(COMPILER)\""
  OUT = ""
endif

MACH := $(shell uname -m | tr A-Z a-z | sed 's/i[3456]86/i386/')

ifeq ($(MACH),i386)
	SSE = "-msse2"
	#SSE = "-msse2 -funroll-loops"
	#SSE = "-msse2 -funroll-loops -ftree-vectorize"
endif

.phony: libfalloc libfalloc-static libfalloc-dl nolib nocolor static strip

default: $(TARGETS)

config.h: configure config.h.in
	./configure

configure: configure.in
	autoconf

config.h.in: configure.in
	autoheader

frandom.o: frandom.c frandom.h config.h
	$(CC) $(CFLAGS_OPT) -c $<

fmt_no.o: fmt_no.c fmt_no.h config.h
	$(CC) $(CFLAGS_OPT) -c $<

find_nonzero.o: find_nonzero.c find_nonzero.h config.h
	$(CC) $(CFLAGS_OPT) -c $< $(SSE)

find_nonzero_avx.o: find_nonzero_avx.c find_nonzero.h config.h
	$(CC) $(CFLAGS_OPT) -mavx2 -c $<

libfalloc: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DNO_LIBDL $(DEFINES) $< $(OUT) $(OBJECTS) -lfallocate

libfalloc-static: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DNO_LIBDL $(DEFINES) $< $(OUT) $(OBJECTS) $(LIBDIR)/libfallocate.a

dd_rescue: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) $(DEFINES) $< $(OUT) $(OBJECTS) -ldl

libfalloc-dl: dd_rescue

nolib: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DNO_LIBDL -DNO_LIBFALLOCATE $(DEFINES) $< $(OUT) $(OBJECTS)

nocolor: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DNO_COLORS=1 $(DEFINES) $< $(OUT) $(OBJECTS)

static: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DNO_LIBDL -DNO_LIBFALLOCATE -static $(DEFINES) $< $(OUT) $(OBJECTS)

strip: dd_rescue
	strip -S $<

clean:
	rm -f $(TARGETS) $(OBJECTS) dd_rescue.o core test log find_nonzero fmt_no file_zblock find_nonzero_avx.o find_nonzero_avx

find_nonzero: find_nonzero.c find_nonzero.h
	$(CC) $(CFLAGS_OPT) -o $@ $< -DTEST $(SSE)

find_nonzero_avx: find_nonzero.c find_nonzero.h find_nonzero_avx.o
	$(CC) $(CFLAGS_OPT) -o $@ $< -DHAVE_AVX2 -DTEST $(SSE) find_nonzero_avx.o

fmt_no: fmt_no.c fmt_no.h
	$(CC) $(CFLAGS) -o $@ $< -DTEST

file_zblock: file_zblock.c find_nonzero.h find_nonzero.c find_nonzero.o
	$(CC) $(CFLAGS) -o $@ $< find_nonzero.o

distclean: clean
	rm -f *~ config.h config.h.in config.status config.log configure
	rm -rf autom4te.cache

dist: distclean
	tar cvzf ../dd_rescue-$(VERSION).tar.gz -C.. --exclude=$(MYDIR)/CV* --exclude $(MYDIR)/dd_rescue2* --exclude $(MYDIR)/.* $(MYDIR)

install: $(TARGETS)
	mkdir -p $(INSTALLDIR)
	$(INSTALL) $(INSTALLFLAGS) $(INSTASROOT) -m 755 $(TARGETS) $(INSTALLDIR)
	#$(INSTALL) $(INSTASROOT) -m 755 -d $(DOCDIR)/dd_rescue
	#$(INSTALL) $(INSTASROOT) -g root -m 644 README.dd_rescue $(DOCDIR)/dd_rescue/
	mkdir -p $(MANDIR)/man1
	$(INSTALL) $(INSTASROOT) -m 644 dd_rescue.1 $(MANDIR)/man1/
	gzip -9 $(MANDIR)/man1/dd_rescue.1

check: $(TARGETS) find_nonzero
	./dd_rescue -apP dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy 
	./find_nonzero 2
	rm dd_rescue.copy

