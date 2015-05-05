#!/bin/bash
# Script to test crypt module

enc_dec_compare()
{
	file=$1; alg=$2; keyargs=$3
	if test -n "$4"; then othargs=":$4"; else unset othargs; fi
	if test -n "$5"; then eng=":engine=$5"; else unset eng; fi
	if test -n "$6"; then opt="$6"; else opt="-qptA"; fi
	echo "Validating enc/decryption $eng $alg $othargs"
	cp -p $file.enc $file.enc.old 2>/dev/null
	echo $VG ./dd_rescue $opt -L ./libddr_crypt.so=enc$eng:alg=$alg:$keyargs$othargs $file $file.enc 
	$VG ./dd_rescue $opt -L ./libddr_crypt.so=enc$eng:alg=$alg:$keyargs$othargs $file $file.enc || exit 1
	echo $VG ./dd_rescue $opt -L ./libddr_crypt.so=dec$eng:alg=$alg$othargs $file.enc $file.cmp 
	$VG ./dd_rescue $opt -L ./libddr_crypt.so=dec$eng:alg=$alg$othargs $file.enc $file.cmp || exit 2
	cmp $file $file.cmp || exit 3
}

enc_dec_compare_keys()
{
	enc_dec_compare "$1" "$2" "$3" "$4:keysfile:ivsfile" "$5" "$6"
}

ECB_ALGS="AES192-ECB AES192+-ECB AES192x2-ECB"
CBC_ALGS="AES192-CBC AES192+-CBC AES192x2-CBC"
CTR_ALGS="AES128-CTR AES128+-CTR AES128x2-CTR AES192-CTR AES192+-CTR AES192x2-CTR AES256-CTR AES256+-CTR AES256x2-CTR"
TESTALGS="$ECB_ALGS $CBC_ALGS $CTR_ALGS"

echo "We will eat a lot of entropy ... hopefully you have some!"
echo " Otherwise we might hang :-("

# MAIN TEST
# Reverse (CTR, ECB)
echo "*** Reverse ***"
enc_dec_compare_keys dd_rescue AES192-CTR keygen:ivgen "" "" "-qptAr"
enc_dec_compare_keys dd_rescue AES192-ECB keygen:ivgen "" "" "-qptAr"
# Appending (CTR, ECB only when block-aligned)
# Holes (all), skiphole
# Reverse (CTR, ECB)
# Chain with lzo, hash (all)
# Various ways to pass in keys/IVs
# Padding variations
# OpenSSL compatibility
echo "*** OpenSSL compatibility ***"
openssl enc -aes-192-ctr -K 4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d -iv f61059ec2d87a410853b8f1500000000 -in dd_rescue -out dd_rescue.enc.o || exit 1
enc_dec_compare dd_rescue AES192-CTR "" keyhex=4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d:ivhex=f61059ec2d87a410853b8f1500000000
cmp dd_rescue.enc dd_rescue.enc.o || exit 4
openssl enc -aes-192-cbc -K 4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d -iv f61059ec2d87a410853b8f150752bd8f -in dd_rescue -out dd_rescue.enc.o || exit 1
enc_dec_compare dd_rescue AES192-CBC "" keyhex=4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d:ivhex=f61059ec2d87a410853b8f150752bd8f
cmp dd_rescue.enc dd_rescue.enc.o || exit 4
echo "*** Algorithms ... ***"
# Algs and Engines
for alg in $TESTALGS; do
	echo "** $alg **"
	# Generate key+IV, save to index file and use for decryption
	enc_dec_compare_keys dd_rescue $alg keygen:ivgen
	## Generate key+IV, save to binary files 
	#enc_dec_compare dd_rescue $alg keygen:ivgen keyfile=KEY:ivfile=IV
	# Use default salt generation 
	enc_dec_compare dd_rescue $alg "" pass=PWD:pbkdf2
	# Use random numbers and write to index file
	enc_dec_compare dd_rescue $alg saltgen pass=PWD:pbkdf2:saltsfile
done
# Use random numbers and write to binary file
enc_dec_compare dd_rescue AES192-CTR saltgen pass=PWD:pbkdf2:saltfile=SALT

HAVE_AESNI=`grep " aes " /proc/cpuinfo 2>/dev/null`
echo "*** Engines comparison ***"
for alg in $TESTALGS; do
	rm dd_rescue.enc.old dd_rescue.enc
	case $alg in AES???+-???)
		ENG="aes_c"
		;;
	*)
		ENG="aes_c openssl"
		;;
	esac
	if test -n "$HAVE_AESNI"; then
		ENG="$ENG aesni"
	fi
	echo "** Alg $alg engines $ENG **"
	for engine in $ENG; do
		enc_dec_compare dd_rescue $alg "" pass=PASSWORD:pbkdf2 $engine
		if test -e dd_rescue.enc.old; then cmp dd_rescue.enc dd_rescue.enc.old || exit 4; fi
	done
done


rm -f dd_rescue.enc dd_rescue.enc.o dd_rescue.enc.old dd_rescue.cmp SALT SALT.* KEYS.* IVS.*
