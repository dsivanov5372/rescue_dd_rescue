# Makefile for dd_rescue
# (c) garloff@suse.de, 99/10/09, GNU GPL
# $Id$

VERSION = 1.19

DESTDIR = 

CC = gcc
RPM_OPT_FLAGS = -O2 -Wall -g
CFLAGS = $(RPM_OPT_FLAGS) $(EXTRA_CFLAGS)
DEFINES = -DVERSION=\"$(VERSION)\" 
INSTALL = install
INSTALLFLAGS = -s
prefix = $(DESTDIR)/usr
#INSTALLDIR = $(prefix)/bin
INSTALLDIR = $(DESTDIR)/bin
#MYDIR = dd_rescue-$(VERSION)
MYDIR = dd_rescue
TARGETS = dd_rescue
OBJECTS = dd_rescue.o
DOCDIR = $(prefix)/share/doc/packages
INSTASROOT = -o root -g root

default: $(TARGETS)

libfalloc: dd_rescue.c
	$(CC) $(CFLAGS) -DHAVE_FALLOCATE=1 -DHAVE_LIBFALLOCATE=1 $(DEFINES) $< -o dd_rescue -lfallocate

falloc: dd_rescue.c
	$(CC) $(CFLAGS) -DHAVE_FALLOCATE=1 $(DEFINES) $< -o dd_rescue

dd_rescue: dd_rescue.c
	$(CC) $(CFLAGS) $(DEFINES) $< -o $@

clean:
	rm -f $(TARGETS) $(OBJECTS) core

distclean: clean
	rm -f *~

dist: distclean
	tar cvzf ../dd_rescue-$(VERSION).tar.gz -C.. --exclude=$(MYDIR)/CV* --exclude $(MYDIR)/dd_rescue2 --exclude $(MYDIR)/.*.sw? $(MYDIR)

install: $(TARGETS)
	mkdir -p $(INSTALLDIR)
	$(INSTALL) $(INSTALLFLAGS) $(INSTASROOT) -m 755 $(TARGETS) $(INSTALLDIR)
	#$(INSTALL) $(INSTASROOT) -m 755 -d $(DOCDIR)/dd_rescue
	#$(INSTALL) $(INSTASROOT) -g root -m 644 README.dd_rescue $(DOCDIR)/dd_rescue/
