#!/bin/bash

(
  cd `dirname $0`
  ../cmd/whiskeyTango/test.sh

  echo -- From Python
  cat ../cmd/whiskeyTango/token.wt | python3 ./wt.py -ca ../cmd/whiskeyTango/trusted.jwk -verify
)
