#!/bin/bash
# Script to test crypt module


enc_dec_compare()
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

enc_dec_compare_keys()
{
	enc_dec_compare $1 $2 $3 $4:keysfile:ivsfile $5 $6 $7
}

ECB_ALGS="AES192-ECB AES192+-ECB AES192x2-ECB"
CBC_ALGS="AES192-CBC AES192+-CBC AES192x2-CBC"
CTR_ALGS="AES128-CTR AES128+-CTR AES128x2-CTR AES192-CTR AES192+-CTR AES192x2-CTR AES256-CTR AES256+-CTR AES256x2-CTR"
TESTALGS="$ECB_ALGS $CBC_ALGS $CTR_ALGS"

echo "We will eat a lot of entropy ... hopefully you have some!"
echo " Otherwise we might hang :-("

for alg in $TESTALGS; do
	# Generate key+IV, save to index file and use for decryption
	enc_dec_compare_keys dd_rescue $alg keygen:ivgen
	## Generate key+IV, save to binary files 
	#enc_dec_compare dd_rescue $alg keygen:ivgen keyfile=KEY:ivfile=IV
	# Use default salt generation 
	enc_dec_compare dd_rescue $alg "" pass=PWD:pbkdf2
	# Use random numbers and write to binary file
	enc_dec_compare dd_rescue $alg saltgen pass=PWD:pbkdf2:saltfile=SALT
	# Use random numbers and write to index file
	enc_dec_compare dd_rescue $alg saltgen pass=PWD:pbkdf2:saltsfile
	# Reverse (CTR, ECB)
	# Appending (CTR, ECB only when block-aligned)
	# Holes (all), skiphole
	# Reverse (CTR, ECB)
	# Chain with lzo, hash (all)
	# Various ways to pass in keys/IVs
	# Padding variations
	# OpenSSL compatibility
	# Algs and Engines
done

