#!/bin/bash
# Script to test crypt module

enc_dec_compare_keys()
{
	file=$1; alg=$2; keyargs=$3
	if test -n "$4"; then othargs=":$4"; else unset othargs; fi
	if test -n "$5"; then eng=":engine=$5"; else unset eng; fi
	echo "Validating enc/decryption $eng $alg $othargs"
	cp -p $file.enc $file.enc.old 2>/dev/null
	echo $VG ./dd_rescue -pt -L ./libddr_crypt.so=enc$eng:alg=$alg:$keyargs$othargs:keysfile:ivsfile $file $file.enc || exit 1
	$VG ./dd_rescue -pt -L ./libddr_crypt.so=enc$eng:alg=$alg:$keyargs$othargs:keysfile:ivsfile $file $file.enc || exit 1
	echo $VG ./dd_rescue -pt -L ./libddr_crypt.so=dec$eng:alg=$alg$othargs:keysfile:ivsfile $file.enc $file.cmp || exit 2
	$VG ./dd_rescue -pt -L ./libddr_crypt.so=dec$eng:alg=$alg$othargs:keysfile:ivsfile $file.enc $file.cmp || exit 2
	cmp $file $file.cmp || exit 3
}

enc_dec_compare_pass()
{
	file=$1; alg=$2; keyargs=$3
	if test -n "$4"; then othargs=":$4"; else unset othargs; fi
	if test -n "$5"; then eng=":engine=$5"; else unset eng; fi
	echo "Validating enc/decryption $eng $alg $othargs"
	cp -p $file.enc $file.enc.old 2>/dev/null
	echo $VG ./dd_rescue -pt -L ./libddr_crypt.so=enc$eng:alg=$alg:$keyargs$othargs $file $file.enc || exit 1
	$VG ./dd_rescue -pt -L ./libddr_crypt.so=enc$eng:alg=$alg:$keyargs$othargs $file $file.enc || exit 1
	echo $VG ./dd_rescue -pt -L ./libddr_crypt.so=dec$eng:alg=$alg$othargs $file.enc $file.cmp || exit 2
	$VG ./dd_rescue -pt -L ./libddr_crypt.so=dec$eng:alg=$alg$othargs $file.enc $file.cmp || exit 2
	cmp $file $file.cmp || exit 3
}

TESTALGS="AES192-ECB AES192+-ECB AES192x2-ECB AES192-CBC AES192+-CBC AES192x2-CBC AES128-CTR AES128+-CTR AES128x2-CTR AES192-CTR AES192+-CTR AES192x2-CTR AES256-CTR AES256+-CTR AES256x2-CTR"

for alg in $TESTALGS; do
	enc_dec_compare_keys dd_rescue $alg keygen:ivgen 
	enc_dec_compare_pass dd_rescue $alg "" pass=PWD:pbkdf2
	enc_dec_compare_pass dd_rescue $alg saltgen pass=PWD:pbkdf2:saltfile=SALT
done


