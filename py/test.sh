#!/bin/bash

(
  cd `dirname $0`
  cat ../cmd/whiskeyTango/token.wt | python3 ./wt.py -ca ../cmd/whiskeyTango/trusted.jwk -verify
)
