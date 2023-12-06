#!/bin/bash

(
  cd `dirname $0`
  ../cmd/whiskeyTango/test.sh

  if command -v jq 2>&1 > /dev/null
  then
    jq=jq
  else
    jq=cat
  fi

  echo
  echo -- verify from Python
  cat ../cmd/whiskeyTango/token.wt | python3 ./wt.py -ca ../cmd/whiskeyTango/trusted.jwk -verify > claims.json
  cat claims.json | ${jq}
  cat ../cmd/whiskeyTango/token.wt | python3 ./wt.py -ca ../cmd/whiskeyTango/trusted.jwk -verify  -challenge squeamishossifrage > claims.challenge
  echo --- create challenge from python
  cat claims.challenge
  echo  -- prove python challenge from go
  ../cmd/whiskeyTango/wt -kp ../cmd/whiskeyTango/robfielding.kp -prove $(cat claims.challenge)
  echo
  echo  -- prove python challenge from python
  ./wt.py -kp ../cmd/whiskeyTango/robfielding.kp -prove $(cat claims.challenge)
  echo
)
