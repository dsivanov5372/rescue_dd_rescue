# Makefile for dd_rescue
# (c) garloff@suse.de, 99/10/09, GNU GPL
# $Id$

VERSION = 1.41

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
FNZ_HEADERS = find_nonzero.h archdep.h ffs.h
HEADERS = frandom.h fmt_no.h config.h $(FNZ_HEADERS)
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
	OBJECTS2 = find_nonzero_avx.o find_nonzero_sse2.o ffs_sse42.o
endif
ifeq ($(MACH),x86_64)
	OBJECTS2 = find_nonzero_avx.o find_nonzero_sse2.o ffs_sse42.o
endif
MACH := $(shell uname -m |sed 's/armv[0-9a-z]*/arm/')
ifeq ($(MACH),arm)
	OBJECTS2 = find_nonzero_arm.o
endif

.phony: libfalloc libfalloc-static libfalloc-dl nolib nocolor static strip

default: $(TARGETS)

all: $(TARGETS) find_nonzero fiemap file_zblock fmt_no

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

find_nonzero.o: find_nonzero.c $(FNZ_HEADERS) config.h
	$(CC) $(CFLAGS_OPT) -c $< $(SSE)

find_nonzero_avx.o: find_nonzero_avx.c $(FNZ_HEADERS) config.h
	$(CC) $(CFLAGS_OPT) -mavx2 -c $<

find_nonzero_sse2.o: find_nonzero_sse2.c $(FNZ_HEADERS) config.h
	$(CC) $(CFLAGS_OPT) -msse2 -c $<

find_nonzero_arm.o: find_nonzero_arm.c $(FNZ_HEADERS) config.h
	$(CC) $(CFLAGS_OPT) -c $< 

find_nonzero_main.o: find_nonzero.c $(FNZ_HEADERS) config.h
	$(CC) $(CFLAGS_OPT) -o $@ -c $< -DTEST 

ffs_sse42.o: ffs_sse42.c ffs.h archdep.h config.h
	$(CC) $(CFLAGS_OPT) -msse4.2 -c $<

libfalloc: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -DNO_LIBDL $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) -lfallocate

libfalloc-static: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -DNO_LIBDL $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) $(LIBDIR)/libfallocate.a

dd_rescue: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) -ldl

libfalloc-dl: dd_rescue

nolib: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -DNO_LIBDL -DNO_LIBFALLOCATE $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2)

nocolor: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -DNO_COLORS=1 $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2)

static: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DNO_LIBDL -DNO_LIBFALLOCATE -static $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2)

strip: dd_rescue
	strip -S $<

clean:
	rm -f $(TARGETS) $(OBJECTS) $(OBJECTS2) dd_rescue.o core test log find_nonzero fmt_no file_zblock find_nonzero_main.o fiemap

find_nonzero: find_nonzero_main.o $(OBJECTS2)
	$(CC) $(CFLAGS_OPT) -o $@ $^ 

fmt_no: fmt_no.c fmt_no.h
	$(CC) $(CFLAGS) -o $@ $< -DTEST

file_zblock: file_zblock.c $(FNZ_HEADERS) config.h find_nonzero.o $(OBJECTS2)
	$(CC) $(CFLAGS) -o $@ $< find_nonzero.o $(OBJECTS2)

fiemap: fiemap.c fiemap.h config.h
	$(CC) $(CFLAGS) -DTEST_FIEMAP -o $@ $<

distclean: clean
	rm -f *~ config.h config.h.in config.status config.log configure
	rm -rf autom4te.cache

dist: distclean
	tar cvzf ../dd_rescue-$(VERSION).tar.gz -C.. --exclude=$(MYDIR)/CV* --exclude $(MYDIR)/dd_rescue2* --exclude $(MYDIR)/.* $(MYDIR) --exclude $(MYDIR)/*.i --exclude $(MYDIR)/*~ --exclude $(MYDIR)*.S --exclude $(MYDIR)/*_32 --exclude $(MYDIR)/*_64

install: $(TARGETS)
	mkdir -p $(INSTALLDIR)
	$(INSTALL) $(INSTALLFLAGS) $(INSTASROOT) -m 755 $(TARGETS) $(INSTALLDIR)
	#$(INSTALL) $(INSTASROOT) -m 755 -d $(DOCDIR)/dd_rescue
	#$(INSTALL) $(INSTASROOT) -g root -m 644 README.dd_rescue $(DOCDIR)/dd_rescue/
	mkdir -p $(MANDIR)/man1
	$(INSTALL) $(INSTASROOT) -m 644 dd_rescue.1 $(MANDIR)/man1/
	gzip -9 $(MANDIR)/man1/dd_rescue.1

check: $(TARGETS) find_nonzero
	./find_nonzero 2
	rm -f dd_rescue.copy dd_rescue.copy2
	./dd_rescue -apP dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy 
	rm dd_rescue.copy
	./dd_rescue -b16k -B16k -a dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy
	rm dd_rescue.copy
	./dd_rescue -r dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy
	./dd_rescue -x dd_rescue dd_rescue.copy
	cat dd_rescue dd_rescue > dd_rescue.copy2
	cmp dd_rescue.copy dd_rescue.copy2
	rm dd_rescue.copy dd_rescue.copy2
	rm -f zero zero2
	./dd_rescue -a -m 261k /dev/zero zero
	du zero
	./dd_rescue -S 12k -m 4k -b 4k -Z 0 zero
	./dd_rescue -S 20k -m 4k -b 4k -Z 0 zero
	./dd_rescue -a -b 8k zero zero2
	du zero zero2
	cmp zero zero2
	rm zero2
	./dd_rescue -a -b 16k zero zero2
	du zero zero2
	cmp zero zero2
	rm zero zero2
	

