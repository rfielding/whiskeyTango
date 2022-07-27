# pip3 install cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys
import argparse
import base64
import json
import hashlib
import math

# The only plaintext in the token is the kid,
# used to look up the key that encrypted it.
# The information about the key moves into the JWK,
# not into the token; where attackers can confuse
# us into negotiating forgeries
def wt_find_trust(trust, kid):
  for i in range(0,len(trust["keys"])):
    v = trust["keys"][i]
    if v["kid"] == kid and v["kty"] == "RSA": return v
  return None                

# Extracting claims from the token is proof that we verified it
def wt_extract_claims(trust, token):
  # split into parts
  tokens = token.split(".")
  if len(tokens) != 3:
    return "ERROR: a WT token needs three dot separated parts of b64 url encode"
  kid = base64.urlsafe_b64decode(tokens[0]+"==").decode("utf-8")
  ciphertextunderk = base64.urlsafe_b64decode(tokens[1]+"==")
  sig = int.from_bytes(base64.urlsafe_b64decode(tokens[2]+"=="),byteorder="big")
  # hash the ciphertext
  h = hashlib.sha256()
  h.update(ciphertextunderk)
  HE = int.from_bytes(h.digest(),byteorder="big")
  # unsign the signature
  rsakey = wt_find_trust(trust, kid)
  if rsakey and trust:
    n = rsakey["Nint"]
    e = rsakey["Eint"]
    V = pow(sig, e, n)
    k = (V ^ HE).to_bytes(32,byteorder="big")
    # It has a 12 byte nonce when encrypted, appended
    # note that the key k is never reused
    nonce = ciphertextunderk[0:12]
    ciphertextonly = ciphertextunderk[12:]
    aesgcm = AESGCM(k)
    plaintext = aesgcm.decrypt(nonce, ciphertextonly, None).decode("utf-8")
    return plaintext # will be valid json map
  return "ERROR: no rsakey found for %s" % (kid)

# turn base64 encoded keys to bit ints to simplify verify code
def wt_trust_init(trust):
  keys = trust["keys"]
  for k in range(0, len(keys)):
    e = trust["keys"][k]["e"]
    trust["keys"][k]["Eint"] = int.from_bytes(base64.urlsafe_b64decode(e+"=="), byteorder="big")
    n = trust["keys"][k]["n"]
    trust["keys"][k]["Nint"] = int.from_bytes(base64.urlsafe_b64decode(n+"=="), byteorder="big")

# Support same cli as whiskeyTango just for verifying WT
def main():
  parser = argparse.ArgumentParser("whiskeyTango auth tokens")
  parser.add_argument("-ca")
  parser.add_argument("-verify", action="store_true")
  args = parser.parse_args()
  if len(args.ca) > 0:
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
    print(wt_extract_claims(trust, token))

main()
