#!/bin/bash

(
cd `dirname $0`

# If we don't have jq, then just use cat
if command -v jq
then
  jq=jq
else
  jq=cat
fi

echo --- compile binary
go build -o wt main.go

echo --- clean up
rm *.jwk *.wt

echo --- make ca
./wt -ca signer.jwk -kid rfielding-1 -create -bits 2048
echo

echo --- trust signer rfielding-1
./wt -ca signer.jwk -kid rfielding-1 -trust trusted.jwk
cat trusted.jwk | $jq
echo

echo --- sign token
echo '{"email":["rob.fielding@gmail.com","rrr00bb@yahoo.com"],"age":["adult"]}' | ./wt -ca signer.jwk -kid rfielding-1 -sign -minutes 1 > token.wt
cat token.wt
echo

echo --- verify token
cat token.wt | ./wt -ca trusted.jwk -verify | $jq
)
