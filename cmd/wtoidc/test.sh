#!/bin/bash

#echo Ensure that the tokens are setup
#../../py/test.sh 
#(echo go run main.go) & 
(
sleep 2 

rm trusted.jwk 2>&1 > /dev/null
rm response.json 2>&1 > /dev/null

echo Get the trusted.jwk file
curl -X GET http://localhost:8898/auth/openid-connect/cert > trusted.jwk

echo login and verify token
curl -X POST \
     -H "grant_type: password" \
     -H "username: rob.fielding@gmail.com" \
     -H "password: rob.fielding" \
     -H "client_id: operator" \
     http://localhost:8898/auth/openid-connect/tokens > response.json

cat response.json | jq -r '.access_token' > access.wt
cat response.json | jq -r '.refresh_token' > refresh.wt
cat access.wt | go run ../whiskeyTango/main.go -ca ./trusted.jwk -verify > claims.json

echo Show claims verified
cat claims.json | jq 

echo refresh token
curl -X POST \
     -H "grant_type: refresh" \
     -H "refresh_token: $(cat refresh.wt)" \
     http://localhost:8898/auth/openid-connect/tokens > response2.json
cat response2.json | jq -r '.access_token' > access2.wt
cat response2.json | jq -r '.refresh_token' > refresh2.wt
cat access2.wt | go run ../whiskeyTango/main.go -ca ./trusted.jwk -verify > claims2.json
cat claims2.json | jq
)
