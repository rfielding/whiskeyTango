#!/bin/bash

(
cd `dirname $0`

# If we don't have jq, then just use cat
if command -v jq 2>&1 /dev/null
then
  jq=jq
else
  jq=cat
fi

echo --- clean up
rm *.jwk *.wt *.kp *.json *.csr *.challenge 2>&1 > /dev/null

echo --- compile binary
go build -o wt main.go

# note that this does not mean automatically trusting it
caName=https://rfielding.net/ca-1

echo --- make ca key for signer for ${caName}
./wt -ca signer.jwk -kid ${caName} -create -bits 1024

echo --- trust signer ${caName}
./wt -ca signer.jwk -kid ${caName} -trust trusted.jwk
cat trusted.jwk | $jq
echo

echo --- make keypair for robfielding
./wt -kp robfielding.kp -bits 1024

echo --- sign token
echo '{"email":["rob.fielding@gmail.com","rrr00bb@yahoo.com"],"age":["adult"]}' > claims.csr
cat claims.csr | ./wt -ca signer.jwk -kid ${caName} -kp robfielding.kp -sign -minutes 1 > token.wt
cat token.wt
echo

echo --- verify token from golang
cat token.wt | ./wt -ca trusted.jwk -verify > claims.json
cat claims.json | $jq

echo -- challenge the owner of this token to prove ownership
cat token.wt | ./wt -ca trusted.jwk -challenge squeamishossifrage > claims.challenge
echo ---- Create a challenge to prove ownership of this token
cat claims.challenge
echo ---- Verify the challenge
./wt -kp robfielding.kp -prove $(cat claims.challenge)
echo
echo
)
