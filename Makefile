# Makefile for dd_rescue
# (c) garloff@suse.de, 99/10/09, GNU GPL
# $Id$

VERSION = 1.43pre

DESTDIR = 

CC = gcc
RPM_OPT_FLAGS = -Os -Wall -g -D_FORTIFY_SOURCE=2
CFLAGS = $(RPM_OPT_FLAGS) $(EXTRA_CFLAGS) -DHAVE_CONFIG_H
CFLAGS_OPT = $(CFLAGS) -O3
INSTALL = install
INSTALLFLAGS = -s
prefix = $(DESTDIR)/usr
INSTALLDIR = $(prefix)/bin
#INSTALLDIR = $(DESTDIR)/bin
INSTALLLIBDIR = $(prefix)/$(LIB)
MANDIR = $(prefix)/share/man
#MYDIR = dd_rescue-$(VERSION)
MYDIR = dd_rescue
BINTARGETS = dd_rescue 
LIBTARGETS = libddr_MD5.so 
TARGETS = $(BINTARGETS) $(LIBTARGETS)
#TARGETS = libfalloc-dl
OTHTARGETS = find_nonzero fiemap file_zblock fmt_no md5
OBJECTS = frandom.o fmt_no.o find_nonzero.o 
FNZ_HEADERS = find_nonzero.h archdep.h ffs.h
HEADERS = frandom.h fmt_no.h config.h list.h fstrim.h $(FNZ_HEADERS) splice.h fallocate64.h pread64.h ddr_plugin.h
DOCDIR = $(prefix)/share/doc/packages
INSTASROOT = -o root -g root
LIB = lib
LIBDIR = /usr/$(LIB)
COMPILER = $(shell $(CC) --version | head -n1)
DEFINES = -DVERSION=\"$(VERSION)\"  -D__COMPILER__="\"$(COMPILER)\"" # -DPLUGSEARCH="\"$(LIBDIR)\""
OUT = -o dd_rescue

ifeq ($(shell grep 'HAVE_LZO_LZO1X_H 1' config.h >/dev/null 2>&1 && echo 1), 1)
  LIBTARGETS += libddr_lzo.so
endif

ifeq ($(CC),wcl386)
  CFLAGS = "-ox -wx $(EXTRA_CFLAGS)"
  DEFINES = -dMISS_STRSIGNAL -dMISS_PREAD -dVERSION=\"$(VERSION)\" -d__COMPILER__="\"$(COMPILER)\""
  OUT = ""
endif

HAVE_AVX2 := $(shell echo "" | $(CC) -mavx2 -xc - 2>&1 | grep unrecognized || echo 1)
HAVE_SSE42 := $(shell echo "" | $(CC) -msse4.2 -xc - 2>&1 | grep unrecognized || echo 1)

MACH := $(shell uname -m | tr A-Z a-z | sed 's/i[3456]86/i386/')

ifeq ($(MACH),i386)
	SSE = "-msse2"
	#SSE = "-msse2 -funroll-loops"
	#SSE = "-msse2 -funroll-loops -ftree-vectorize"
	OBJECTS2 = find_nonzero_sse2.o 
ifeq ($(HAVE_SSE42),1)
	OBJECTS2 += ffs_sse42.o
else
	CFLAGS += -DNO_SSE42
endif
ifeq ($(HAVE_AVX2),1)
	OBJECTS2 += find_nonzero_avx.o
else
	CFLAGS += -DNO_AVX2
endif
endif

ifeq ($(MACH),x86_64)
	LIB = lib64
	OBJECTS2 = find_nonzero_sse2.o
ifeq ($(HAVE_SSE42),1)
	OBJECTS2 += ffs_sse42.o
else
	CFLAGS += -DNO_SSE42
endif
ifeq ($(HAVE_AVX2),1)
	OBJECTS2 += find_nonzero_avx.o
else
	CFLAGS += -DNO_AVX2
endif
endif

MACH := $(shell uname -m |sed 's/armv[0-9a-z]*/arm/')
ifeq ($(MACH),arm)
	OBJECTS2 = find_nonzero_arm.o
endif
ifeq ($(MACH),aarch64)
	OBJECTS2 = find_nonzero_arm64.o
endif

OS = $(shell uname)
ifeq ($(OS), Linux)
	OBJECTS += fstrim.o
endif

.phony: libfalloc libfalloc-static libfalloc-dl nolib nocolor static strip

default: $(TARGETS)

all: $(TARGETS) $(OTHTARGETS)

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

%.o: %.c %.h config.h
	$(CC) $(CFLAGS) -c $<

%.po: %.c ddr_plugin.h config.h
	$(CC) $(CFLAGS) -fPIC -o $@ -c $<

md5.po: md5.c md5.h config.h
	$(CC) $(CFLAGS_OPT) -fPIC -o $@ -c $<

libddr_MD5.so: libddr_MD5.po md5.po
	$(CC) -shared -o $@ $^

libddr_lzo.so: libddr_lzo.po
	$(CC) -shared -o $@ $^ -llzo2

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

md5: md5.c md5.h config.h
	$(CC) $(CFLAGS_OPT) -DMD5_MAIN -o $@ $<

libfalloc-dl: dd_rescue

nolib: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -DNO_LIBDL -DNO_LIBFALLOCATE $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2)

nocolor: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -DNO_COLORS=1 $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2)

static: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DNO_LIBDL -DNO_LIBFALLOCATE -static $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2)

strip: $(TARGETS)
	strip -S $^

strip-all: $(OTHTARGETS)
	strip -S $^

clean:
	rm -f $(TARGETS) $(OTHTARGETS) $(OBJECTS) $(OBJECTS2) core test log *.o *.po

find_nonzero: find_nonzero_main.o $(OBJECTS2)
	$(CC) $(CFLAGS_OPT) -o $@ $^ 

fmt_no: fmt_no.c fmt_no.h
	$(CC) $(CFLAGS) -o $@ $< -DTEST

file_zblock: file_zblock.c $(FNZ_HEADERS) config.h find_nonzero.o $(OBJECTS2)
	$(CC) $(CFLAGS) -o $@ $< find_nonzero.o $(OBJECTS2)

fiemap: fiemap.c fiemap.h fstrim.h config.h fstrim.o
	$(CC) $(CFLAGS) -DTEST_FIEMAP -o $@ $< fstrim.o

distclean: clean
	rm -f *~ config.h config.h.in config.status config.log configure
	rm -rf autom4te.cache

dist: distclean
	tar cvzf ../dd_rescue-$(VERSION).tar.gz -C.. --exclude=$(MYDIR)/CV* --exclude $(MYDIR)/dd_rescue2* --exclude $(MYDIR)/.* $(MYDIR) --exclude $(MYDIR)/*.i --exclude $(MYDIR)/*~ --exclude $(MYDIR)*.S --exclude $(MYDIR)/*_32 --exclude $(MYDIR)/*_64 --exclude $(MYDIR)/*_android --exclude $(MYDIR)/*.o --exclude $(MYDIR)/*.po --exclude $(MYDIR)/*.so

install: $(TARGETS)
	mkdir -p $(INSTALLDIR)
	$(INSTALL) $(INSTALLFLAGS) $(INSTASROOT) -m 755 $(BINTARGETS) $(INSTALLDIR)
	#$(INSTALL) $(INSTASROOT) -m 755 -d $(DOCDIR)/dd_rescue
	#$(INSTALL) $(INSTASROOT) -g root -m 644 README.dd_rescue $(DOCDIR)/dd_rescue/
	mkdir -p $(INSTALLLIBDIR)
	$(INSTALL) $(INSTALLFLAGS) $(INSTASROOT) -m 755 $(LIBTARGETS) $(INSTALLLIBDIR)
	mkdir -p $(MANDIR)/man1
	$(INSTALL) $(INSTASROOT) -m 644 dd_rescue.1 $(MANDIR)/man1/
	gzip -9 $(MANDIR)/man1/dd_rescue.1

check: $(TARGETS) find_nonzero
	./dd_rescue --version
	@echo "***** find_nonzero tests *****"
	./find_nonzero 2
	@echo "***** dd_rescue tests *****"
	@rm -f dd_rescue.copy dd_rescue.copy2
	./dd_rescue -apP dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy 
	@rm dd_rescue.copy
	./dd_rescue -b16k -B16k -a dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy
	@rm dd_rescue.copy
	./dd_rescue -r dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy
	./dd_rescue -x dd_rescue dd_rescue.copy
	cat dd_rescue dd_rescue > dd_rescue.copy2
	cmp dd_rescue.copy dd_rescue.copy2
	@rm dd_rescue.copy dd_rescue.copy2
	@rm -f zero zero2
	@echo "***** dd_rescue sparse tests *****"
	./dd_rescue -a -m 261k /dev/zero zero
	du zero
	./dd_rescue -S 12k -m 4k -b 4k -Z 0 zero
	./dd_rescue -S 20k -m 4k -b 4k -Z 0 zero
	./dd_rescue -a -b 8k zero zero2
	du zero zero2
	cmp zero zero2
	@rm zero2
	./dd_rescue -a -b 16k zero zero2
	du zero zero2
	cmp zero zero2
	@rm zero zero2
	@rm -f TEST TEST2
	@echo "***** dd_rescue MD5 plugin tests *****"
	./dd_rescue -a -b 16k -m 32k /dev/zero TEST
	./dd_rescue -x -a -b 16k -m32k dd_rescue TEST
	./dd_rescue -x -a -b 16k -m17k /dev/zero TEST
	MD5=$$(./dd_rescue -c0 -a -b16k -L ./libddr_MD5.so TEST TEST2 2>&1 | grep MD5: | tail -n1 | sed 's/^dd_rescue: (info): MD5:[^:]*: //'); MD5S=$$(md5sum TEST | sed 's/ .*$$//'); echo $$MD5 $$MD5S; if test "$$MD5" != "$$MD5S"; then false; fi
	rm -f TEST TEST2
	@echo "***** dd_rescue lzo (and MD5) plugin tests *****"
	./dd_rescue -b32k -TL ./libddr_lzo.so dd_rescue dd_rescue.ddr.lzo
	lzop -t dd_rescue.ddr.lzo
	@rm -f dd_rescue.ddr
	lzop -d dd_rescue.ddr.lzo
	cmp dd_rescue dd_rescue.ddr
	@rm -f dd_rescue.ddr dd_rescue.ddr.lzo
	./dd_rescue -b1M -L ./libddr_lzo.so=compress,./libddr_MD5.so dd_rescue dd_rescue.ddr.lzo
	# TODO: Compare md5sums ...
	md5sum dd_rescue dd_rescue.ddr.lzo
	lzop -t dd_rescue.ddr.lzo
	./dd_rescue -b1M -TL ./libddr_MD5.so,./libddr_lzo.so=compress,./libddr_MD5.so,./libddr_lzo.so=decompress,./libddr_MD5.so dd_rescue dd_rescue.ddr
	cmp dd_rescue dd_rescue.ddr
	@rm -f dd_rescue.ddr dd_rescue.ddr.lzo dd_rescue.lzo
	lzop dd_rescue
	./dd_rescue -b1M -L ./libddr_lzo.so dd_rescue.lzo dd_rescue.cmp
	cmp dd_rescue dd_rescue.cmp
	@rm -f dd_rescue.cmp dd_rescue.lzo
	./dd_rescue -b16k -L ./libddr_MD5.so,./libddr_lzo.so,./libddr_MD5.so dd_rescue dd_rescue.lzo
	./dd_rescue -b8k -L ./libddr_MD5.so,./libddr_lzo.so,./libddr_MD5.so dd_rescue.lzo dd_rescue.cmp
	cmp dd_rescue dd_rescue.cmp
	md5sum dd_rescue dd_rescue.lzo
	@rm -f dd_rescue.lzo dd_rescue.cmp

	

