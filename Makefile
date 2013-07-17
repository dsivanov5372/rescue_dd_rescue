# Makefile for dd_rescue
# (c) garloff@suse.de, 99/10/09, GNU GPL
# $Id$

VERSION = 1.35

DESTDIR = 

CC = gcc
RPM_OPT_FLAGS = -Os -Wall -g
CFLAGS = $(RPM_OPT_FLAGS) $(EXTRA_CFLAGS)
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
OBJECTS = frandom.o fmt_no.o
HEADERS = frandom.h fmt_no.h find_nonzero.h
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

default: $(TARGETS)

frandom.o: frandom.c frandom.h
	$(CC) $(CFLAGS_OPT) -c $<

fmt_no.o: fmt_no.c fmt_no.h
	$(CC) $(CFLAGS_OPT) -c $<

libfalloc: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DHAVE_LIBFALLOCATE=1 $(DEFINES) $< $(OUT) $(OBJECTS) -lfallocate

libfalloc-static: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DHAVE_LIBFALLOCATE=1 $(DEFINES) $< $(OUT) $(OBJECTS) $(LIBDIR)/libfallocate.a

libfalloc-dl: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DHAVE_LIBDL=1 -DHAVE_LIBFALLOCATE=1 -DHAVE_FALLOCATE=1 $(DEFINES) $< $(OUT) $(OBJECTS) -ldl

falloc: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DHAVE_FALLOCATE=1 $(DEFINES) $< $(OUT) $(OBJECTS)

dd_rescue: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) $(DEFINES) $< $(OUT) $(OBJECTS)

nocolor: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DNO_COLORS=1 $(DEFINES) $< $(OUT) $(OBJECTS)

strip: dd_rescue
	strip -S $<

clean:
	rm -f $(TARGETS) $(OBJECTS) dd_rescue.o core test log

distclean: clean
	rm -f *~

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

