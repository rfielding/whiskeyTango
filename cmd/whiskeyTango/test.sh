#!/bin/bash

(
cd `dirname $0`

echo --- compile binary
go build -o wt main.go

rm *.json
echo --- make ca
./wt -ca signer.json -kid rfielding-1 -create
cat signer.json

echo --- trust signer rfielding-1
./wt -ca signer.json -kid rfielding-1 -trust trusted.json

echo --- sign token
echo '{"age":["adult"]}' | ./wt -ca signer.json -kid rfielding-1 -sign > token.json
cat token.json

echo --- verify token
cat token.json | ./wt -ca trusted.json -verify
)
