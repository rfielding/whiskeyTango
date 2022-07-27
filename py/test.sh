#!/bin/bash

(
  cd `dirname $0`
  ../cmd/whiskeyTango/test.sh

  if command -v jq
  then
    jq=jq
  else
    jq=cat
  fi

  echo -- verify from Python
  cat ../cmd/whiskeyTango/token.wt | python3 ./wt.py -ca ../cmd/whiskeyTango/trusted.jwk -verify | ${jq}
)
