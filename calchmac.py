#!/usr/bin/env python
import hashlib
import hmac
import sys

if len(sys.argv) < 3:
	print >>sys.stderr, "Usage: calchmac.py PASS SALT"
	sys.exit(1)

pwd = sys.argv[1]
salt = sys.argv[2]
salt1 = salt + "\0\0\0\x01"

print hmac.HMAC(pwd, salt, hashlib.sha1).hexdigest()
print hmac.HMAC(pwd, salt1, hashlib.sha1).hexdigest()
print hmac.HMAC(pwd, salt, hashlib.sha512).hexdigest()


