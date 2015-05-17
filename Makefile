# Makefile for dd_rescue
# (c) garloff@suse.de, 99/10/09, GNU GPL

VERSION = 1.98

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
#INSTALLLIBDIR = $(DESTDIR)/$(LIBDIR)
MANDIR = $(prefix)/share/man
#MYDIR = dd_rescue-$(VERSION)
MYDIR = dd_rescue
BINTARGETS = dd_rescue 
LIBTARGETS = libddr_hash.so libddr_MD5.so libddr_null.so libddr_crypt.so
#TARGETS = libfalloc-dl
OTHTARGETS = find_nonzero fiemap file_zblock fmt_no md5 sha256 sha512 sha224 sha384 sha1 test_aes
OBJECTS = random.o frandom.o fmt_no.o find_nonzero.o 
FNZ_HEADERS = find_nonzero.h archdep.h ffs.h
HEADERS = random.h frandom.h fmt_no.h config.h list.h fstrim.h $(FNZ_HEADERS) splice.h fallocate64.h pread64.h ddr_plugin.h
DOCDIR = $(prefix)/share/doc/packages
INSTASROOT = -o root -g root
LIB = lib
LIBDIR = /usr/$(LIB)
COMPILER = $(shell $(CC) --version | head -n1)
ID = $(shell git describe --tags || cat REL-ID)
DEFINES = -DVERSION=\"$(VERSION)\"  -D__COMPILER__="\"$(COMPILER)\"" -DID=\"$(ID)\" # -DPLUGSEARCH="\"$(LIBDIR)\""
OUT = -o dd_rescue

LZOP = $(shell type -p lzop || type -P true)
HAVE_SHA256SUM = $(shell type -p sha256sum >/dev/null && echo 1 || echo 0)

ifeq ($(shell grep 'HAVE_LZO_LZO1X_H 1' config.h >/dev/null 2>&1 && echo 1), 1)
  LIBTARGETS += libddr_lzo.so
  OTHTARGETS += fuzz_lzo
  HAVE_LZO=1
else
  HAVE_LZO=0
endif

ifeq ($(shell grep 'HAVE_OPENSSL_EVP_H 1' config.h >/dev/null 2>&1 && echo 1), 1)
  OTHTARGETS += pbkdf2
  AES_OSSL_PO = aes_ossl.po
  AES_OSSL_O = aes_ossl.o
  CRYPTOLIB = -lcrypto
  HAVE_OPENSSL=1
else
  HAVE_OPENSSL=0
endif

ifeq ($(CC),wcl386)
  CFLAGS = "-ox -wx $(EXTRA_CFLAGS)"
  DEFINES = -dMISS_STRSIGNAL -dMISS_PREAD -dVERSION=\"$(VERSION)\" -d__COMPILER__="\"$(COMPILER)\""
  OUT = ""
endif

HAVE_AVX2 := $(shell echo "" | $(CC) -mavx2 -xc - 2>&1 | grep unrecognized || echo 1)
HAVE_SSE42 := $(shell echo "" | $(CC) -msse4.2 -xc - 2>&1 | grep unrecognized || echo 1)
HAVE_RDRNDAES := $(shell echo "" | $(CC) -mrdrnd -maes -xc - 2>&1 | grep unrecognized || echo 1)

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
ifeq ($(HAVE_RDRNDAES),1)
	OBJECTS2 += rdrand.o
	POBJECTS2 += rdrand.po
	AESNI_O = aesni.o
	AESNI_PO = aesni.po
	CFLAGS += -DHAVE_AESNI
else
	CFLAGS += -DNO_RDRND -DNO_AES
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
ifeq ($(HAVE_RDRNDAES),1)
	OBJECTS2 += rdrand.o
	POBJECTS2 += rdrand.po
	AESNI_O = aesni.o
	AESNI_PO = aesni.po
	CFLAGS += -DHAVE_AESNI
else
	CFLAGS += -DNO_RDRND -DNO_AES
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

TARGETS = $(BINTARGETS) $(LIBTARGETS)

.phony: libfalloc libfalloc-static libfalloc-dl nolib nocolor static strip

default: $(TARGETS)

all: $(TARGETS) $(OTHTARGETS)

config.h: configure config.h.in
	./configure

configure: configure.in
	autoconf

config.h.in: configure.in
	autoheader

frandom.o: frandom.c frandom.h config.h ddr_ctrl.h
	$(CC) $(CFLAGS_OPT) -fpie -c $<

fmt_no.o: fmt_no.c fmt_no.h config.h ddr_ctrl.h
	$(CC) $(CFLAGS_OPT) -fpie -c $<

%.o: %.c %.h config.h ddr_ctrl.h
	$(CC) $(CFLAGS) -fpie -c $<

%.po: %.c ddr_plugin.h config.h ddr_ctrl.h md5.h sha256.h sha512.h sha1.h hash.h
	$(CC) $(CFLAGS) -fPIC -o $@ -c $<

md5.po: md5.c md5.h hash.h config.h
	$(CC) $(CFLAGS_OPT) -fPIC -o $@ -c $<

sha256.po: sha256.c sha256.h hash.h config.h
	$(CC) $(CFLAGS_OPT) -fPIC -o $@ -c $<

sha512.po: sha512.c sha512.h hash.h config.h
	$(CC) $(CFLAGS_OPT) -fPIC -o $@ -c $<

sha1.po: sha1.c sha1.h hash.h config.h
	$(CC) $(CFLAGS_OPT) -fPIC -o $@ -c $<

libddr_hash.so: libddr_MD5.po md5.po sha256.po sha512.po sha1.po pbkdf2.po checksum_file.po
	$(CC) -shared -o $@ $^ $(EXTRA_LDFLAGS)

libddr_MD5.so: libddr_hash.so
	ln -sf $< $@

libddr_lzo.so: libddr_lzo.po
	$(CC) -shared -o $@ $^ -llzo2

libddr_null.so: libddr_null.po
	$(CC) -shared -o $@ $^

libddr_crypt.so: libddr_crypt.po aes.po aes_c.po $(AESNI_PO) $(AES_OSSL_PO) pbkdf2.po sha256.po checksum_file.po secmem.po random.po $(POBJECTS2)
	$(CC) -shared -o $@ $^ $(CRYPTOLIB) $(EXTRA_LDFLAGS)

find_nonzero.o: find_nonzero.c $(FNZ_HEADERS) config.h
	$(CC) $(CFLAGS_OPT) -fpie -c $< $(SSE)

find_nonzero_avx.o: find_nonzero_avx.c $(FNZ_HEADERS) config.h
	$(CC) $(CFLAGS_OPT) -fpie -mavx2 -c $<

find_nonzero_sse2.o: find_nonzero_sse2.c $(FNZ_HEADERS) config.h
	$(CC) $(CFLAGS_OPT) -fpie -msse2 -c $<

find_nonzero_arm.o: find_nonzero_arm.c $(FNZ_HEADERS) config.h
	$(CC) $(CFLAGS_OPT) -fpie -c $< 

find_nonzero_main.o: find_nonzero.c $(FNZ_HEADERS) config.h
	$(CC) $(CFLAGS_OPT) -fpie -o $@ -c $< -DTEST 

ffs_sse42.o: ffs_sse42.c ffs.h archdep.h config.h
	$(CC) $(CFLAGS_OPT) -fpie -msse4.2 -c $<

rdrand.o: rdrand.c archdep.h
	$(CC) $(CFLAGS) -fpie -mrdrnd -maes -c $<

rdrand.po: rdrand.c archdep.h
	$(CC) $(CFLAGS) -fPIC -mrdrnd -maes -o $@ -c $<

libfalloc: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -fpie -DNO_LIBDL $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) -lfallocate

libfalloc-static: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -fpie -DNO_LIBDL $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) $(LIBDIR)/libfallocate.a

dd_rescue: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -fpie $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) -ldl $(EXTRA_LDFLAGS)

md5: md5.c md5.h hash.h config.h
	$(CC) $(CFLAGS_OPT) -fpie -DMD5_MAIN -o $@ $<

sha256: sha256.c sha256.h hash.h config.h
	$(CC) $(CFLAGS_OPT) -fpie -DSHA256_MAIN -o $@ $<

sha224: sha256
	ln -sf sha256 sha224

sha512: sha512.c sha512.h hash.h config.h
	$(CC) $(CFLAGS_OPT) -fpie -DSHA512_MAIN -o $@ $<
	
sha384: sha512
	ln -sf sha512 sha384

sha1: sha1.c sha1.h hash.h config.h
	$(CC) $(CFLAGS_OPT) -fpie -DSHA1_MAIN -o $@ $<

fuzz_lzo: fuzz_lzo.o
	$(CC) -o $@ $^ -llzo2

libfalloc-dl: dd_rescue

nolib: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -DNO_LIBDL -DNO_LIBFALLOCATE $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2)

nocolor: dd_rescue.c $(HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -DNO_COLORS=1 $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2)

static: dd_rescue.c $(HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DNO_LIBDL -DNO_LIBFALLOCATE -static $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2)

strip: $(TARGETS) $(LIBTARGETS)
	strip -S $^

strip-all: $(OTHTARGETS)
	strip -S $^

clean:
	rm -f $(TARGETS) $(OTHTARGETS) $(OBJECTS) $(OBJECTS2) core test log *.o *.po

find_nonzero: find_nonzero_main.o $(OBJECTS2)
	$(CC) $(CFLAGS_OPT) -fpie -o $@ $^ 

fmt_no: fmt_no.c fmt_no.h
	$(CC) $(CFLAGS) -fpie -o $@ $< -DTEST

file_zblock: file_zblock.c $(FNZ_HEADERS) config.h find_nonzero.o $(OBJECTS2)
	$(CC) $(CFLAGS) -fpie -o $@ $< find_nonzero.o $(OBJECTS2)

fiemap: fiemap.c fiemap.h fstrim.h config.h fstrim.o
	$(CC) $(CFLAGS) -fpie -DTEST_FIEMAP -o $@ $< fstrim.o

pbkdf2: ossl_pbkdf2.c
	$(CC) $(CFLAGS) -fpie -o $@ $< $(CRYPTOLIB)

test_aes: test_aes.c $(AESNI_O) aes_c.o secmem.o sha256.o $(AES_OSSL_O) aes.o aesni.h config.h
	$(CC) $(CFLAGS) -fpie $(DEF) -o $@ $< $(AESNI_O) aes_c.o secmem.o sha256.o $(AES_OSSL_O) aes.o $(CRYPTOLIB)

aesni.o: aesni.c aesni.h aes.h sha256.h config.h
	$(CC) $(CFLAGS) -fpie -O3 -maes -msse4.1 -c $<

aesni.po: aesni.c aesni.h aes.h sha256.h config.h
	$(CC) $(CFLAGS) -fPIC -O3 -maes -msse4.1 -c $< -o $@

aes_c.o: aes_c.c aes_c.h aes.h sha256.h config.h
	$(CC) $(CFLAGS) -fpie $(FULL_UNROLL) -O3 -c $<

aes_ossl.o: aes_ossl.c aes_ossl.h aes.h sha256.h config.h
	$(CC) $(CFLAGS) -fpie -O3 -c $<

distclean: clean
	rm -f *~ config.h config.h.in config.status config.log configure REL-ID
	rm -rf autom4te.cache
	rm -f *.cmp *.lzo test
	rm -f dd_rescue-?.??.tar.bz2

dist: distclean
	#tar cvzf ../dd_rescue-$(VERSION).tar.gz -C.. --exclude=$(MYDIR)/CV* --exclude $(MYDIR)/dd_rescue2* --exclude $(MYDIR)/.* --exclude $(MYDIR)/*.i --exclude $(MYDIR)/*~ --exclude $(MYDIR)*.S --exclude $(MYDIR)/*_32 --exclude $(MYDIR)/*_64 --exclude $(MYDIR)/*_android --exclude $(MYDIR)/*.o --exclude $(MYDIR)/*.po --exclude $(MYDaIR)/*.so $(MYDIR) 
	#cd .. && tar cvzf dd_rescue-$(VERSION).tar.gz $(MYDIR)/*.c $(MYDIR)/*.h $(MYDIR)/*.in $(MYDIR)/Makefile* $(MYDIR)/*.sh $(MYDIR)/*.1 $(MYDIR)/COPYING $(MYDIR)/README*
	mkdir dd_rescue-$(VERSION)
	git describe --tags > dd_rescue-$(VERSION)/REL-ID
	for name in `git ls-files`; do cp -p $$name dd_rescue-$(VERSION); done
	tar cvjf dd_rescue-$(VERSION).tar.bz2 dd_rescue-$(VERSION)
	rm -rf dd_rescue-$(VERSION)

install: $(TARGETS)
	mkdir -p $(INSTALLDIR)
	$(INSTALL) $(INSTALLFLAGS) $(INSTASROOT) -m 755 $(BINTARGETS) $(INSTALLDIR)
	#$(INSTALL) $(INSTASROOT) -m 755 -d $(DOCDIR)/dd_rescue
	#$(INSTALL) $(INSTASROOT) -g root -m 644 README.dd_rescue $(DOCDIR)/dd_rescue/
	mkdir -p $(INSTALLLIBDIR)
	$(INSTALL) $(INSTALLFLAGS) $(INSTASROOT) -m 755 $(LIBTARGETS) $(INSTALLLIBDIR)
	ln -sf libddr_hash.so $(INSTALLLIBDIR)/libddr_MD5.so
	mkdir -p $(MANDIR)/man1
	$(INSTALL) $(INSTASROOT) -m 644 dd_rescue.1 ddr_lzo.1 ddr_crypt.1 $(MANDIR)/man1/
	gzip -9f $(MANDIR)/man1/dd_rescue.1 $(MANDIR)/man1/ddr_lzo.1 $(MANDIR)/man1/ddr_crypt.1

check: $(TARGETS) find_nonzero md5 sha1 sha256 sha512
	@echo "make check ... Pass VG=\"valgrind --options\" to use with valgrind"
	$(VG) ./dd_rescue --version
	@echo "***** find_nonzero tests *****"
	$(VG) ./find_nonzero 2
	@echo "***** dd_rescue tests *****"
	@rm -f dd_rescue.copy dd_rescue.copy2
	$(VG) ./dd_rescue -apP dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy 
	@rm dd_rescue.copy
	$(VG) ./dd_rescue -b16k -B16k -a dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy
	@rm dd_rescue.copy
	$(VG) ./dd_rescue -r dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy
	$(VG) ./dd_rescue -x dd_rescue dd_rescue.copy
	cat dd_rescue dd_rescue > dd_rescue.copy2
	cmp dd_rescue.copy dd_rescue.copy2
	@rm dd_rescue.copy dd_rescue.copy2
	@rm -f zero zero2
	@echo "***** dd_rescue sparse tests *****"
	$(VG) ./dd_rescue -a -m 261k /dev/zero zero
	du zero
	$(VG) ./dd_rescue -S 12k -m 4k -b 4k -Z 0 zero
	$(VG) ./dd_rescue -S 20k -m 4k -b 4k -Z 0 zero
	$(VG) ./dd_rescue -a -b 8k zero zero2
	du zero zero2
	cmp zero zero2
	@rm zero2
	$(VG) ./dd_rescue -a -b 16k zero zero2
	du zero zero2
	cmp zero zero2
	@rm zero zero2
	@rm -f TEST TEST2
	@echo "***** dd_rescue MD5 plugin tests *****"
	$(VG) ./md5 /dev/null
	$(VG) ./md5 /dev/null | md5sum -c
	$(VG) ./dd_rescue -a -b 16k -m 32k /dev/zero TEST
	$(VG) ./dd_rescue -x -a -b 16k -m32k dd_rescue TEST
	$(VG) ./dd_rescue -x -a -b 16k -m17k /dev/zero TEST
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_MD5.so=output TEST TEST2 >HASH.TEST
	md5sum -c HASH.TEST
	#MD5=$$(./dd_rescue -c0 -a -b16k -L ./libddr_MD5.so TEST TEST2 2>&1 | grep 'MD5(0)': | tail -n1 | sed 's/^dd_rescue: (info): MD5(0):[^:]*: //'); MD5S=$$(md5sum TEST | sed 's/ .*$$//'); echo $$MD5 $$MD5S; if test "$$MD5" != "$$MD5S"; then false; fi
	rm -f HASH.TEST
	$(VG) ./sha1 /dev/null
	$(VG) ./sha1 /dev/null | sha1sum -c
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=outnm=HASH.TEST:alg=sha1 TEST TEST2
	sha1sum -c HASH.TEST
	if test $(HAVE_SHA256SUM) = 1; then $(MAKE) check_sha2; fi
	$(VG) ./sha256 /dev/null
	$(VG) ./sha512 /dev/null
	rm -f TEST TEST2 HASH.TEST
	if test $(HAVE_LZO) = 1; then $(MAKE) check_lzo; fi
	if test $(HAVE_LZO) = 1; then $(MAKE) check_lzo_algos; fi
	#if test $(HAVE_LZO) = 1; then $(MAKE) check_lzo_test; fi
	if test $(HAVE_LZO) = 1; then $(MAKE) check_lzo_fuzz; fi
	# Tests for libddr_null
	$(VG) ./dd_rescue -L ./libddr_null.so=debug dd_rescue /dev/null
	# Tests with hash set_xattr and chk_xattr (with fallback as not all filesystems support xattrs ...)
	$(VG) ./dd_rescue -tL ./libddr_hash.so=sha256:set_xattr:fallback dd_rescue /tmp/dd_rescue
	$(VG) ./dd_rescue -L ./libddr_hash.so=sha256:chk_xattr:fallback /tmp/dd_rescue /dev/null
	rm -f /tmp/dd_rescue CHECKSUMS.sha256
	# Tests with prepend and append
	$(VG) ./dd_rescue -tL ./libddr_hash.so=sha512:set_xattr:fallback:prepend=abc:append=xyz dd_rescue /tmp/dd_rescue
	$(VG) ./dd_rescue  -L ./libddr_hash.so=sha512:chk_xattr:fallback /tmp/dd_rescue /dev/null && false || true
	$(VG) ./dd_rescue  -L ./libddr_hash.so=sha512:chk_xattr:fallback:prepend=abc:append=xyz /tmp/dd_rescue /dev/null
	# Tests with HMAC
	echo -n "what do ya want for nothing?" > TEST
	echo "750c783e6ab0b503eaa86e310a5db738 *TEST" > HMACS.md5
	$(VG) ./dd_rescue -L ./libddr_hash.so=md5:hmacpwd=Jefe:chknm= TEST /dev/null
	rm -f /tmp/dd_rescue CHECKSUMS.sha512 TEST HMACS.md5
	if ./calchmac.py sha1 pass dd_rescue; then make check_hmac; else echo "Sorry, no more HMAC test due to missing python-hashlib support"; true; fi
	make check_fault
	make check_aes
	make check_crypt

check_hmac: $(TARGETS)
	FILES="*.c *.h *.po dd_rescue *.so"; \
	for alg in md5 sha1 sha256 sha384; do \
		./calchmac.py $$alg pass_$$alg $$FILES > HMACS.$$alg; \
	done
	for name in *.c *.h *.po dd_rescue *.so; do \
		for alg in md5 sha1 sha256 sha384; do \
			$(VG) ./dd_rescue -L ./libddr_hash.so=$$alg:hmacpwd=pass_$$alg:chknm= $$name /dev/null || exit 1; \
		done \
	done
	rm -f HMACS.md5 HMACS.sha1 HMACS.sha256 HMACS.sha384

	
check_sha2: $(TARGETS) sha224 sha384
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=output:alg=sha224 TEST TEST2 >HASH.TEST
	sha224sum -c HASH.TEST
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=outnm=:alg=sha256 TEST TEST2 >HASH.TEST
	sha256sum -c CHECKSUMS.sha256
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=output:alg=sha384 TEST TEST2 >HASH.TEST
	sha384sum -c HASH.TEST
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=outnm=:alg=sha512 TEST TEST2
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=outnm=:alg=sha512,./libddr_null.so=change dd_rescue /dev/null
	sha512sum -c CHECKSUMS.sha512
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=sha512:chknm=CHECKSUMS.sha512 TEST2 /dev/null
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=alg=sha512:chknm= dd_rescue /dev/null
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=sha512:check dd_rescue /dev/null <CHECKSUMS.sha512
	$(VG) ./sha224 /dev/null | sha224sum -c
	$(VG) ./sha256 /dev/null | sha256sum -c
	$(VG) ./sha384 /dev/null | sha384sum -c
	$(VG) ./sha512 /dev/null | sha512sum -c
	rm -f HASH.TEST CHECKSUMS.sha256 CHECKSUMS.sha512 TEST2

check_lzo: $(TARGETS)
	@echo "***** dd_rescue lzo (and MD5) plugin tests *****"
	$(VG) ./dd_rescue -b32k -ATL ./libddr_lzo.so dd_rescue dd_rescue.ddr.lzo
	$(LZOP) -t dd_rescue.ddr.lzo
	@cp -p dd_rescue dd_rescue.ddr
	$(LZOP) -fd dd_rescue.ddr.lzo
	cmp dd_rescue dd_rescue.ddr
	@rm -f dd_rescue.ddr dd_rescue.ddr.lzo
	$(VG) ./dd_rescue -b256k -L ./libddr_MD5.so=output,./libddr_lzo.so=compress,./libddr_MD5.so=output dd_rescue dd_rescue.ddr.lzo > dd_rescue.ddr.MD5SUM
	md5sum -c dd_rescue.ddr.MD5SUM
	md5sum dd_rescue dd_rescue.ddr.lzo
	$(LZOP) -Nvl dd_rescue.ddr.lzo
	$(VG) ./dd_rescue -b256k -TL ./libddr_MD5.so=output,./libddr_lzo.so=compress,./libddr_MD5.so,./libddr_lzo.so=decompress,./libddr_MD5.so=outfd=1 dd_rescue dd_rescue.ddr > dd_rescue.ddr.MD5
	cmp dd_rescue dd_rescue.ddr
	md5sum -c dd_rescue.ddr.MD5
	$(VG) ./dd_rescue -b16k -TL ./libddr_MD5.so=output,./libddr_lzo.so=compress,./libddr_MD5.so,./libddr_lzo.so=decompress,./libddr_MD5.so=outfd=1 dd_rescue dd_rescue.ddr > dd_rescue.ddr.MD5
	cmp dd_rescue dd_rescue.ddr
	md5sum -c dd_rescue.ddr.MD5
	@cp -p dd_rescue.ddr.lzo dd_rescue.lzo
	@rm -f dd_rescue.ddr dd_rescue.ddr.lzo dd_rescue.ddr.MD5
	$(LZOP) -f dd_rescue
	$(VG) ./dd_rescue -b256k -TL ./libddr_lzo.so dd_rescue.lzo dd_rescue.cmp
	cmp dd_rescue dd_rescue.cmp
	@rm -f dd_rescue.cmp dd_rescue.lzo
	$(VG) ./dd_rescue -b16k -L ./libddr_MD5.so=output,./libddr_lzo.so,./libddr_MD5.so=output dd_rescue dd_rescue.lzo > MD5.1
	$(VG) ./dd_rescue -b 8k -L ./libddr_MD5.so=output,./libddr_lzo.so,./libddr_MD5.so=output dd_rescue.lzo dd_rescue.cmp > MD5.2
	cmp dd_rescue dd_rescue.cmp
	md5sum dd_rescue dd_rescue.lzo
	md5sum -c MD5.1
	md5sum -c MD5.2
	@rm -f dd_rescue.lzo dd_rescue.cmp MD5.1 MD5.2
	# Sparse testing and MULTIPART testing and extend
	$(VG) ./dd_rescue -ta -m 64k /dev/zero test
	$(VG) ./dd_rescue -ax dd_rescue test
	$(VG) ./dd_rescue -axm 128k /dev/zero test
	$(VG) ./dd_rescue -taL ./libddr_MD5.so test test2
	$(VG) ./dd_rescue -taL ./libddr_MD5.so=output,./libddr_lzo.so,./libddr_MD5.so=output test test.lzo > MD5
	md5sum -c MD5
	rm -f MD5 test2
	$(VG) ./dd_rescue -axL ./libddr_lzo.so,./libddr_MD5.so=output dd_rescue test.lzo > MD5
	#md5sum -c MD5
	$(LZOP) -Nvl test.lzo
	cat dd_rescue >> test
	$(VG) ./dd_rescue -aL ./libddr_lzo.so,./libddr_MD5.so=output test.lzo test.cmp > MD5
	md5sum -c MD5
	cmp test test.cmp
	rm -f MD5 test test.lzo test.cmp
	
check_lzo_algos: $(TARGETS)
	for alg in lzo1x_1 lzo1x_1_11 lzo1x_1_12 lzo1x_1_15 lzo1x_999 lzo1y_1 lzo1y_999 lzo1f_1 lzo1f_999 lzo1b_1 lzo1b_2 lzo1b_3 lzo1b_4 lzo1b_5 lzo1b_6 lzo1b_7 lzo1b_8 lzo1b_9 lzo1b_99 lzo1b_999 lzo2a_999; do ./dd_rescue -qATL ./libddr_lzo.so=algo=$$alg:benchmark dd_rescue dd_rescue.lzo || exit 1; $(LZOP) -lt dd_rescue.lzo; ./dd_rescue -qATL ./libddr_lzo.so=benchmark dd_rescue.lzo dd_rescue.cmp || exit 2; cmp dd_rescue dd_rescue.cmp || exit 3; done

check_lzo_test: $(TARGETS)
	find . -type f
	find . -type f | xargs ./test_lzo.sh

check_lzo_fuzz: $(TARGETS) fuzz_lzo
	# Do intelligent fuzzing before feeding to dd_rescue -L lzo=decompress
	# Intelligent fuzzing means starting from valid .lzo, and adding
	#  distortions, with and without fixing checksums ...
	./test_lzo_fuzz.sh


ALGS = AES128-ECB AES128-CBC AES128-CTR AES128+-ECB AES128+-CBC AES128+-CTR AES128x2-ECB AES128x2-CBC AES128x2-CTR \
	AES192-ECB AES192-CBC AES192-CTR AES192+-ECB AES192+-CBC AES192+-CTR AES192x2-ECB AES192x2-CBC AES192x2-CTR \
	AES256-ECB AES256-CBC AES256-CTR AES256+-ECB AES256+-CBC AES256+-CTR AES256x2-ECB AES256x2-CBC AES256x2-CTR 

check_aes: $(TARGETS) test_aes
	for alg in $(ALGS); do $(VG) ./test_aes $$alg 10000 || exit $$?; done

check_crypt: $(TARGETS)
	# TODO: Move previous cases into script ...
	./test_crypt.sh
	# Holes (all)
	# Reverse (CTR, ECB)
	# Chain with lzo, hash (all)
	# Various ways to pass in keys/IVs
	# Padding variations
	# OpenSSL compatibility
	# Algs and Engines
	rm -f dd_rescue.enc dd_rescue.dec dd_rescue.enc.orig dd_rescue2 KEYS.* IVS.*

check_fault: $(TARGETS)
	# Test fault injection
	# Only one fault, should be handled by retrying.
	$(VG) ./dd_rescue -tpv -F 4r/1,6r/1,22r/1 dd_rescue dd_rescue.cmp || true
	cmp dd_rescue dd_rescue.cmp
	# Incremental
	$(VG) ./dd_rescue -tp -F 4r/0,20r/0 dd_rescue dd_rescue.cmp || true
	cmp dd_rescue dd_rescue.cmp || true
	$(VG) ./dd_rescue -p -F 6r/0 dd_rescue dd_rescue.cmp || true
	cmp dd_rescue dd_rescue.cmp
	# Write errors: We recover from one of them
	$(VG) ./dd_rescue -tp -F 4w/1,22w/1 dd_rescue dd_rescue.cmp || true
	#$(VG) ./dd_rescue -p -F 6w/1 dd_rescue dd_rescue.cmp || true
	cmp dd_rescue dd_rescue.cmp
	# Write errors: Fill in ...
	$(VG) ./dd_rescue -tp -b 16k -F 4w/2,22w/2 dd_rescue dd_rescue.cmp || true
	$(VG) ./dd_rescue -p -b 16k -F 12w/2 dd_rescue dd_rescue.cmp || true
	cmp dd_rescue dd_rescue.cmp
	# TODO: More fault injection tests!
	# Test reverse, holes, ... with faults


make_check_crypt: check_crypt
	$(VG) ./dd_rescue -tp -L ./libddr_crypt.so=enc:keygen:keysfile:ivgen:ivsfile:alg=AES192+-CTR dd_rescue dd_rescue.enc
	$(VG) ./dd_rescue -tp -L ./libddr_crypt.so=dec:keysfile:ivsfile:alg=AES192+-CTR dd_rescue.enc dd_rescue.dec
	cmp dd_rescue dd_rescue.dec
	# Reverse (CTR, ECB)
	cp -p dd_rescue.enc dd_rescue.enc.orig
	$(VG) ./dd_rescue -tpr -L ./libddr_crypt.so=enc:keysfile:ivsfile:alg=AES192+-CTR dd_rescue dd_rescue.enc
	cmp dd_rescue.enc.orig dd_rescue.enc
	$(VG) ./dd_rescue -tpr -L ./libddr_crypt.so=dec:keysfile:ivsfile:alg=AES192+-CTR dd_rescue.enc dd_rescue.dec
	cmp dd_rescue dd_rescue.dec
	# Appending (CTR)
	$(VG) ./dd_rescue -px -L ./libddr_crypt.so=enc:keysfile:ivsfile:alg=AES192+-CTR dd_rescue dd_rescue.enc
	$(VG) ./dd_rescue -tp -L ./libddr_crypt.so=dec:keysfile:ivsfile:alg=AES192+-CTR dd_rescue.enc dd_rescue.dec
	cat dd_rescue dd_rescue > dd_rescue2
	cmp dd_rescue2 dd_rescue.dec


