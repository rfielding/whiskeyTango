#!/bin/bash

echo --- compile binary
go build -o wt main.go

echo --- make ca
./wt -ca signer.json -create -kid rfielding-1
cat signer.json

echo --- sign token
echo '{"age":["adult"]}' | ./wt -ca signer.json -kid rfielding-1 -sign > token.json
cat token.json

echo --- verify token
cat token.json | ./wt -ca signer.json -verify
