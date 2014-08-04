#!/usr/bin/env python
import hashlib
import hmac
import sys

print hmac.HMAC(sys.argv[1], sys.argv[2], hashlib.sha1).hexdigest()
print hmac.HMAC(sys.argv[1], sys.argv[2]+"\0\0\0\x01", hashlib.sha1).hexdigest()
print hmac.HMAC(sys.argv[1], sys.argv[2], hashlib.sha512).hexdigest()
