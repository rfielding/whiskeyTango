package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rfielding/whiskeyTango/wt"
)

var authAt string
var authBind string
var authJWK string
var signJWK string
var signCA *wt.JWKeys
var authCA *wt.JWKeys
var authSigner string
var expMinutes int64
var refreshMinutes int64
var userDB map[string]map[string]interface{}

type OIDCResult struct {
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

func Setup() {
	// Limit calls to EnvDefault to here, because accesses are logged
	{
		authAt = EnvDefault("AUTH_AT", "/auth/")
		authBind = EnvDefault("AUTH_BIND", "localhost:8898")
		authJWK = EnvDefault("AUTH_JWK", "../whiskeyTango/trusted.jwk")
		signJWK = EnvDefault("SIGN_JWK", "../whiskeyTango/signer.jwk")
	}
	{
		expMinutesStr := EnvDefault("AUTH_EXP_MINUTES", "15")
		var err error
		expMinutes, err = strconv.ParseInt(expMinutesStr, 10, 64)
		if err != nil {
			log.Fatal(fmt.Sprintf("AUTH_EXP_MINUTES should be an integer: %v ", err))
		}

		refreshMinutesStr := EnvDefault("AUTH_REFRESH_MINUTES", "6000")
		refreshMinutes, err = strconv.ParseInt(refreshMinutesStr, 10, 64)
		if err != nil {
			log.Fatal(fmt.Sprintf("AUTH_REFRESH_MINUTES should be an integer: %v ", err))
		}

	}

	{
		/*
		 * The plan is to be simpler than Keycloak.
		 * - assume that the database of user attributes is not huge
		 * - run in containers that can simply be restarted with updated files
		 * - get rid of complications such as config from outside of the json
		 */
		ufile := EnvDefault("AUTH_USER_DB", "userdb.json")
		userDBFile, err := os.ReadFile(ufile)
		if err != nil {
			log.Fatal(fmt.Sprintf("Error reading user DB file %s: %v", ufile, err))
		}
		err = json.Unmarshal(userDBFile, &userDB)
		if err != nil {
			log.Fatal(fmt.Sprintf("Error parsing user DB file %s: %v", ufile, err))
		}
	}

	{
		var err error
		authCA, err = wt.LoadCA(authJWK)
		if err != nil {
			log.Fatal("Error loading CA trust JWKs: ", err)
		}
		signCA, err = wt.LoadCA(signJWK)
		if err != nil {
			log.Fatal("Error loading CA sign JWKs: ", err)
		}
		authSigner = signCA.Keys[0].Kid
		if os.Getenv("AUTH_SIGNER") != "" {
			authSigner = os.Getenv("AUTH_SIGNER")
		}
		log.Printf(
			"Loaded CA JWKs, signing with %s: %s",
			wt.AsJson(authCA),
			authSigner,
		)
	}

	{
		log.Printf("bound %sopenid-connect/cert", authAt)
		log.Printf("bound %sopenid-connect/tokens", authAt)
		http.HandleFunc(authAt, AuthHandler)
	}
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	// serve up a JWK to check tokens with
	if strings.HasPrefix(r.URL.Path, fmt.Sprintf("%sopenid-connect/cert", authAt)) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(wt.AsJson(authCA)))
		return
	}

	// implement a login token, using a trivial MD5 password hash for now
	if strings.HasPrefix(r.URL.Path, fmt.Sprintf("%sopenid-connect/tokens", authAt)) {
		grantType := r.Header.Get("grant_type")
		if grantType == "" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing grant_type"))
			return
		}

		username := r.Header.Get("username")
		password := r.Header.Get("password")
		//clientID := r.Header.Get("client_id")
		refreshToken := r.Header.Get("refresh_token")
		//clientSecret := r.Header.Get("client_secret")
		//_ = clientSecret

		var err error
		var ok bool
		var user map[string]interface{}
		var token string

		if grantType == "password" && username != "" && password != "" {
			// Look up our user, verbosely for GOOD errors
			user, ok = userDB["users"][username].(map[string]interface{})
			if user == nil || !ok {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(fmt.Sprintf("invalid userDB[\"users\"][\"%s\"]", username)))
				return
			}

			if grantType == "password" {
				// Use the password field to check it
				pwdHashedString, ok := user["_passwordMD5"].(string)
				if !ok {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("_passwordMD5 needs to be hex encoded string for user entry"))
					return
				}
				expectedPwdHash, err := hex.DecodeString(pwdHashedString)
				if err != nil {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("_passwordMD5 needs to be hex encoded string"))
					return
				}
				pwdHashed16 := md5.Sum([]byte(password))
				pwdHashed := pwdHashed16[:]
				if bytes.Compare(pwdHashed, expectedPwdHash) != 0 {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("invalid password"))
					return
				}
			}
		}
		if grantType == "refresh" && refreshToken != "" {
			// validate the refresh token. it is an unexpired wt.
			claims, err := wt.GetValidClaims(
				authCA,
				time.Now().Unix(),
				refreshToken,
			)
			if err != nil {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(fmt.Sprintf("invalid refresh token: %v", err)))
				return
			}
			// extend the expiration by re-issuing a similar token
			// Look up our user, verbosely for GOOD errors
			emailList, ok := claims["email"].([]interface{})
			if !ok {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("email field is missing"))
				return
			}
			email, ok := emailList[0].(string)
			if !ok || email == "" {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("email[0] field is not a string"))
				return
			}
			username = email
		}

		user, ok = userDB["users"][username].(map[string]interface{})
		if user == nil || !ok {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("invalid userDB[\"users\"][\"%s\"]", username)))
			return
		}
		token, err = wt.CreateToken(
			signCA,
			authSigner,
			time.Now().Add(time.Minute*time.Duration(expMinutes)).Unix(),
			user,
			nil, // todo: let users pass in a public key to make the token a certificate
			"",
		)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("error creating token for user: %v", err)))
			return
		}

		result := OIDCResult{}
		result.AccessToken = token
		result.RefreshToken = token // needs to redact password

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(wt.AsJson(result)))
		return
	}

	// not found. tell the user what is here
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("available:\n"))
	w.Write([]byte(fmt.Sprintf("%sopenid-connect/cert\n", authAt)))
	w.Write([]byte(fmt.Sprintf("%sopenid-connect/tokens\n", authAt)))
	w.Write([]byte(fmt.Sprintf("- grant_type=password, username, password, client_id, client_secret\n")))
	w.Write([]byte(fmt.Sprintf("- grant_type=password, username, password, client_id\n")))
	w.Write([]byte(fmt.Sprintf("- grant_type=refresh_token, refresh_token\n")))
	w.Write([]byte(fmt.Sprintf("- grant_type=client_credentials, client_id, client_secret\n")))
}

func EnvDefault(key, def string) string {
	if val := os.Getenv(key); val != "" {
		log.Printf("Var setting %s=%s", key, val)
		return val
	}
	log.Printf("Var default %s=%s", key, def)
	return def
}

func main() {
	Setup()
	log.Printf("run listening on %s", authBind)
	http.ListenAndServe(authBind, nil)
}
