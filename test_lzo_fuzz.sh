#!/bin/bash

test_fuzz()
{
	ERC=$1
	PAR=$2
	EDIFF=$3
	shift; shift; shift
	./fuzz_lzo $* dd_rescue dd_rescue.lzo || exit 1
	echo ./dd_rescue -tL ./libddr_lzo.so$PAR dd_rescue.lzo dd_rescue.cmp
	./dd_rescue -tL ./libddr_lzo.so$PAR dd_rescue.lzo dd_rescue.cmp
	RC=$?
	if test $RC != $ERC; then echo "Unexpected exit value $RC (exp: $ERC)"; exit 2; fi
	echo "Exit code $RC, good"
	echo -n "# of differences: "
       	DIFF=`cmp -l dd_rescue dd_rescue.cmp | wc -l`
	echo $DIFF
	if test "$DIFF" -gt "$EDIFF"; then echo "More differences than expected ..."; exit 3; fi
}


./fuzz_lzo dd_rescue dd_rescue.lzo
lzop -vl dd_rescue.lzo
./dd_rescue -L ./libddr_lzo.so dd_rescue.lzo /dev/null

# Main tests ...
test_fuzz 0 "" 0 -m3
test_fuzz 1 "" 16384 -U2
test_fuzz 1 "=nodiscard" 0 -U2
test_fuzz 1 "=nodiscard" 0 -C3
test_fuzz 1 "" 16384 -x1:0x6fe=0x1a
test_fuzz 1 "=nodiscard" 32 -x1:0x6fe=0x1a
test_fuzz 1 "" 16384 -u2=8192
test_fuzz 2 "" 100000 -c4=8192
# TODO: A lot more tests, with and without nodiscard
# TODO: Do tests with -T, with good preexisting data and check whether nothing gets destroyed
rm -f dd_rescue.lzo dd_rescue.cmp

