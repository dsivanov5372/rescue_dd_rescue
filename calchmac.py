#!/usr/bin/env python3
import hashlib
import hmac
import sys

if len(sys.argv) < 4:
    print("Usage: calchmac.py ALG PASS FILE [FILE [..]]", file=sys.stderr)
    sys.exit(1)

algtbl = (("md5", hashlib.md5),
          ("sha1", hashlib.sha1),
          ("sha256", hashlib.sha256),
          ("sha224", hashlib.sha224),
          ("sha512", hashlib.sha512),
          ("sha384", hashlib.sha384))


alg = sys.argv[1]
pwd = sys.argv[2]
# salt1 = salt + "\0\0\0\x01"
algo = None

for (anm, aob) in algtbl:
    if alg == anm:
        algo = aob
        break

if not algo:
    print("Hash algorithm {} not found!".format(alg), file=sys.stderr)
    sys.exit(2)

# hmf = open("HMACS.%s" % alg, "w")
for fnm in sys.argv[3:]:
    with open(fnm, "rb") as f:
        # print fnm
        fcont = f.read()
        hm = hmac.HMAC(pwd, fcont, algo)
        # print >>hmf, "%s *%s" % (hm.hexdigest(), fnm)
        print("{} *{}".format(hm.hexdigest(), fnm))
