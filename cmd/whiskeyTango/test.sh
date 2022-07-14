#!/bin/bash

(
cd `dirname $0`

echo --- compile binary
go build -o wt main.go

echo --- clean up
rm *.json

echo --- make ca
./wt -ca signer.json -kid rfielding-1 -create

echo --- trust signer rfielding-1
./wt -ca signer.json -kid rfielding-1 -trust trusted.json
cat trusted.json

echo --- sign token
echo '{"age":["adult"]}' | ./wt -ca signer.json -kid rfielding-1 -sign > token.wt
cat token.wt

echo --- verify token
cat token.wt | ./wt -ca trusted.json -verify
)
