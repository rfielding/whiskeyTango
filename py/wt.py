#!/usr/bin/env python3
# format automatically:
#   pip3 install git+https://github.com/psf/black; black wt.py
# install cryptography
#   pip3 install cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys
import argparse
import base64
import json
import hashlib
import math
import calendar
import datetime

def wt_prove(kpFname: str, prove: str) -> str:
    f = open(kpFname)
    kp = json.load(f)
    f.close()
    n = int.from_bytes(base64.urlsafe_b64decode(kp["publicKeyN"] + "=="), byteorder="big")
    d = int.from_bytes(base64.urlsafe_b64decode(kp["D"] + "=="), byteorder="big")
    v = int.from_bytes(base64.urlsafe_b64decode(prove+"=="), byteorder="big")
    r = pow(v,d,n)
    b = math.log2(r)
    rb = r.to_bytes(int(b+1), byteorder='big')
    return str(rb, 'utf-8')

def wt_challenge(verified: any, challenge: str) -> str:
    ep = verified["encryptPublic"]
    n = int.from_bytes(base64.urlsafe_b64decode(ep["n"] + "=="), byteorder="big")
    e = int.from_bytes(base64.urlsafe_b64decode(ep["e"] + "=="), byteorder="big")
    v = int.from_bytes(challenge.encode('utf-8'), byteorder="big")
    r = pow(v,e,n)
    b = int(math.floor(math.log2(r)))
    x = base64.urlsafe_b64encode(r.to_bytes(int((b+7)/8), byteorder="big"))
    return str(x, 'utf-8').replace('=','')

# The only plaintext in the token is the kid,
# used to look up the key that encrypted it.
# The information about the key moves into the JWK,
# not into the token; where attackers can confuse
# us into negotiating forgeries
def wt_find_trust(trust: any, kid: str) -> any:
    for i in range(0, len(trust["keys"])):
        v = trust["keys"][i]
        if v["kid"] == kid and v["kty"] == "RSA":
            return v
    return None


# Verify with date check
def wt_verify(trust: any, token: str, unixNow: int) -> any:
    claims = wt_extract_claims(trust, token)
    parsed = json.loads(claims)
    if parsed["exp"] < unixNow:
        return "ERROR: expired token"
    return parsed


# Extracting claims from the token is proof that we verified it
def wt_extract_claims(trust: any, token: str) -> str:
    # split into parts
    tokens = token.split(".")
    if len(tokens) != 3:
        return "ERROR: a WT token needs three dot separated parts of b64 url encode"
    kid = base64.urlsafe_b64decode(tokens[0] + "==").decode("utf-8")
    ciphertextunderk = base64.urlsafe_b64decode(tokens[1] + "==")
    sig = int.from_bytes(base64.urlsafe_b64decode(tokens[2] + "=="), byteorder="big")
    # hash the ciphertext
    h = hashlib.sha256()
    h.update(ciphertextunderk)
    HE = int.from_bytes(h.digest(), byteorder="big")
    # unsign the signature
    rsakey = wt_find_trust(trust, kid)
    if rsakey and trust:
        n = rsakey["Nint"]
        e = rsakey["Eint"]
        V = pow(sig, e, n)
        k = (V ^ HE).to_bytes(int(rsakey["bits"]/8-1), byteorder="big")
        # It has a 12 byte nonce when encrypted, appended
        # note that the key k is never reused
        nonce = ciphertextunderk[0:12]
        ciphertextonly = ciphertextunderk[12:]
        aesgcm = AESGCM(k[0:32])
        plaintext = aesgcm.decrypt(nonce, ciphertextonly, None).decode("utf-8")
        return plaintext  # will be valid json map
    return "ERROR: no rsakey found for %s" % (kid)


# turn base64 encoded keys to big ints to simplify verify code
def wt_trust_init(trust: any) -> None:
    keys = trust["keys"]
    for k in range(0, len(keys)):
        e = trust["keys"][k]["e"]
        trust["keys"][k]["Eint"] = int.from_bytes(
            base64.urlsafe_b64decode(e + "=="), byteorder="big"
        )
        n = trust["keys"][k]["n"]
        trust["keys"][k]["Nint"] = int.from_bytes(
            base64.urlsafe_b64decode(n + "=="), byteorder="big"
        )


# Support same cli as whiskeyTango just for verifying WT
def main() -> int:
    parser = argparse.ArgumentParser("whiskeyTango auth tokens")
    parser.add_argument("-ca")
    parser.add_argument("-verify", action="store_true")
    parser.add_argument("-challenge")
    parser.add_argument("-kp")
    parser.add_argument("-prove")
    args = parser.parse_args()
    if args.ca:
        # should only be ONE line from stdin
        token = ""
        if args.verify:
            for inp in sys.stdin:
                token = inp
                break
        # read in trusted CA
        caname = args.ca
        with open(caname) as f:
            trust = json.loads(f.read())
            wt_trust_init(trust)
        unixNow = calendar.timegm(datetime.datetime.utcnow().utctimetuple())
        verified = wt_verify(trust, token, unixNow)
        if args.challenge:
            print(wt_challenge(verified,args.challenge))
        else:
            print(json.dumps(verified))
        return 0
    if args.prove:
        print(wt_prove(args.kp, args.prove))
        return 0
    return 0


main()
