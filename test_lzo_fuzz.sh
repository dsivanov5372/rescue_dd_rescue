#!/bin/bash

test_fuzz()
{
	ERC=$1
	PAR=$2
	shift; shift
	./fuzz_lzo $* dd_rescue dd_rescue.lzo || exit 1
	./dd_rescue -TL ./libddr_lzo.so$PAR dd_rescue.lzo dd_rescue.cmp
	RC=$?
	if test $RC != $ERC; then echo "Unexpected exit value $RC (exp: $ERC)"; exit 2; fi
	echo "Exit code $RC, good"
}


./fuzz_lzo dd_rescue dd_rescue.lzo
lzop -vl dd_rescue.lzo
./dd_rescue -L ./libddr_lzo.so dd_rescue.lzo /dev/null

# Main tests ...
test_fuzz 0 "" -m3
test_fuzz 1 "" -U2
test_fuzz 1 "=nodiscard" -U2


