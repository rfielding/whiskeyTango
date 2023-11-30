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
rm *.jwk *.wt *.kp *.json *.csr 2>&1 > /dev/null

echo --- compile binary
go build -o wt main.go

# note that this does not mean automatically trusting it
caName=https://rfielding.net/ca-1

echo --- make ca
./wt -ca signer.jwk -kid ${caName} -create -bits 2048

echo --- trust signer ${caName}
./wt -ca signer.jwk -kid ${caName} -trust trusted.jwk
cat trusted.jwk | $jq
echo

echo --- make keypair
./wt -kp robfielding.kp -bits 2048

echo --- sign token
echo '{"email":["rob.fielding@gmail.com","rrr00bb@yahoo.com"],"age":["adult"]}' > claims.csr
cat claims.csr | ./wt -ca signer.jwk -kid ${caName} -kp robfielding.kp -sign -minutes 1 > token.wt
cat token.wt
echo

echo --- verify token from golang
cat token.wt | ./wt -ca trusted.jwk -verify > claims.json
cat claims.json | $jq
)
