package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"
	"time"
)

// Do not use pointers to these!  Copies will be modified to blank out CA data
type JWKey struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`

	Crv           string          `json:"crv,omitempty"`
	X             string          `json:"x,omitempty"`
	Y             string          `json:"y,omitempty"`
	D             string          `json:"d,omitempty"` // comment this out if not CA
	N             string          `json:"n,omitempty"`
	E             string          `json:"e,omitempty"`
	K             string          `json:"k,omitempty"`          // comment this out if not CA?? TODO
	RSAPublicKey  *rsa.PublicKey  `json:"rsaPublic,omitempty"`  // !!! Blank this before JWK serialization for client
	RSAPrivateKey *rsa.PrivateKey `json:"rsaPrivate,omitempty"` // !!! Blank this before JWK serialization for client
}

func (key JWKey) Redact() JWKey {
	k2 := key
	k2.RSAPrivateKey = nil
	k2.D = ""
	k2.K = "" // I assume that it's private
	return k2
}

type JWKeys struct {
	Keys   []JWKey          `json:"keys"`
	KeyMap map[string]JWKey `json:"-"`
}

// Allocate a new RSA key for kid
func (keys *JWKeys) AddRSA(kid string) error {
	jwk, err := NewRSAJWK(kid)
	if err != nil {
		return fmt.Errorf("Unable to add in JWK RSA kid %s to JWKeys: %v", kid, err)
	}
	keys.Keys = append(keys.Keys, jwk)
	if keys.KeyMap == nil {
		keys.KeyMap = make(map[string]JWKey)
	}
	keys.KeyMap[kid] = jwk
	return nil
}

func AsJson(v interface{}) string {
	j, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("Unable to marshal: %v", err)
	}
	return string(j)
}

func (key JWKey) AsJsonPrivate() string {
	k2 := key.Redact()
	k2.RSAPublicKey = nil // make it suitable for serialization
	j, err := json.MarshalIndent(k2, "", "  ")
	if err != nil {
		log.Printf("Unable to marshal redacted JWKey: %v", err)
	}
	return string(j)
}

// Generate a new RSA keypair for a kid - CA will have many of these
func NewRSAJWK(kid string) (JWKey, error) {
	k := JWKey{}
	k.Kty = "RSA"
	k.Kid = kid
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return k, fmt.Errorf("Unable to generate RSA Keypair: %v", err)
	}
	k.N = base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	k.D = base64.RawURLEncoding.EncodeToString(priv.D.Bytes())
	k.E = base64.RawURLEncoding.EncodeToString(new(big.Int).SetInt64(int64(priv.E)).Bytes())
	k.RSAPrivateKey = priv
	k.RSAPublicKey = &rsa.PublicKey{N: priv.N, E: priv.E}
	return k, nil
}

// ParseJWK reads in a JWK from the filesystem,
// either extended for use by the CA, or for a client as a standard JWK format.
func ParseJWK(b []byte) (*JWKeys, error) {
	var keys JWKeys
	json.Unmarshal(b, &keys)
	keys.KeyMap = make(map[string]JWKey)
	for _, v := range keys.Keys {
		// Set the RSAPublicKey field if it's blank
		if v.Kty == "RSA" && len(v.N) > 0 && len(v.E) > 0 && v.RSAPublicKey == nil {
			nn, err := base64.RawURLEncoding.DecodeString(v.N)
			if err != nil {
				return nil, fmt.Errorf("Cannot parse RSA N: %v", err)
			}
			ne, err := base64.RawURLEncoding.DecodeString(v.E)
			if err != nil {
				return nil, fmt.Errorf("Cannot parse RSA E: %v", err)
			}
			N := new(big.Int).SetBytes(nn)
			E := new(big.Int).SetBytes(ne)
			// A proper JWK trust for clients may only set n,e
			v.RSAPublicKey = &rsa.PublicKey{
				N: N,
				E: int(E.Int64()),
			}
		}
		keys.KeyMap[v.Kid] = v
	}
	return &keys, nil
}

func H(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// Returns claims,err
func Decrypt(k []byte, ciphertextWithNonce []byte) ([]byte, error) {
	nonce := ciphertextWithNonce[0:12]
	ciphertext := ciphertextWithNonce[12:]

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("Unable to create cipher: %s", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Unable to create block cipher: %s", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to decrypt plaintext: %v", err)
	}
	return plaintext, nil
}

// Returns ciphertextWithNonce,err
func Encrypt(k []byte, claims []byte) ([]byte, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("Cannot get a new block cipher: %v", err)
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("Cannot create a nonce: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Cannot instantiate AES GCM cipher: %v", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, claims, nil)
	return append(nonce, ciphertext...), nil
}

// Pass in e for encrypt, or d for decrypt into x.  This is raw RSA,
// because we need a WITNESS value, not a mere check.  Without a witness,
// they can simply accept the plaintext claims without verifying it.
// The point of this token format is for a verification to lead to
// a decrypt of the claims.
func RSA(b *big.Int, x *big.Int, n *big.Int) *big.Int {
	// verified = (b^x)%n
	return new(big.Int).Exp(b, x, n)
}

/*
  CreateToken with a given CA JWK (that has secret keys in it, the D value in RSA)
  - must not be an array input type
  - an exp value must be inserted, with the date calculated for us already
  - the kid value must be inserted into the claims
  - WE will create the byte array from claims.
*/
func CreateToken(keys *JWKeys, kid string, exp int64, claimsObject interface{}) (string, error) {
	// We round-trip marshalling, so that the claimsObject can be any kind of json object we like as input
	claimsMarshalled, err := json.Marshal(claimsObject)
	if err != nil {
		return "", fmt.Errorf("Unable to marshal claimsObject: %v", err)
	}
	var claims interface{}
	err = json.Unmarshal(claimsMarshalled, &claims)
	if err != nil {
		return "", fmt.Errorf("Unable to remarshal claims object into generic interface: %v", err)
	}
	c, ok := claims.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Must pass in something that serializes to a json struct at top level")
	}

	// We can set exp, kid no matter what fields exist on claimsObject
	c["exp"] = exp
	c["kid"] = kid
	j, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("Unable to marshal plaintext: %v", err)
	}

	// Create a fresh random AES key
	k := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, k)
	if err != nil {
		return "", fmt.Errorf("Unable to create a fresh random witness key: %v", err)
	}

	// Generate the ciphertext E
	E, err := Encrypt(k, j)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt plaintext claims: %s", c)
	}

	// Generate hash of ciphertext HE
	HE := H(E)

	// We xor the two required steps together of HE and V to make client produce K to decrypt
	V := new(big.Int).Xor(
		new(big.Int).SetBytes(k),
		new(big.Int).SetBytes(HE),
	)

	// Sign V
	rpk := keys.KeyMap[kid].RSAPrivateKey
	Sig := RSA(V, rpk.D, rpk.N)

	// This token is kind of similar to a JWT in appearance.
	return fmt.Sprintf(
		"%s.%s.%s",
		base64.RawURLEncoding.EncodeToString([]byte(kid)),
		base64.RawURLEncoding.EncodeToString(E),
		base64.RawURLEncoding.EncodeToString(Sig.Bytes()),
	), nil
}

// Extract claims from token.
func GetValidClaims(keys *JWKeys, now int64, token string) (interface{}, error) {
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return nil, fmt.Errorf("Expected 3 token parts, got %d", len(tokenParts))
	}

	kidBytes, err := base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return nil, fmt.Errorf("Unable to extract header which should be kid value only: %v", err)
	}
	kid := string(kidBytes)

	// will it decode ALL bytes?
	ciphertextWithNonce, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, fmt.Errorf("Unable to decode body: %v", err)
	}

	SigBytes, err := base64.RawURLEncoding.DecodeString(tokenParts[2])
	if err != nil {
		return nil, fmt.Errorf("Unable to decode signature bytes: %v", err)
	}

	rpk := keys.KeyMap[kid].RSAPublicKey
	// We need a hash of the ciphertext, as proof that we checked it
	HE := new(big.Int).SetBytes(H(ciphertextWithNonce))

	// We need the verified signature as proof that we checked it
	V := RSA(
		new(big.Int).SetBytes(SigBytes),
		new(big.Int).SetInt64(int64(rpk.E)),
		rpk.N,
	)

	// Extract the key that proves that we checked the signature
	k := make([]byte, 32)
	new(big.Int).Xor(V, HE).FillBytes(k)

	// We now can decrypt claims
	claims, err := Decrypt(k, ciphertextWithNonce)
	if err != nil {
		return nil, fmt.Errorf("Unable to decrypt claims: %v", err)
	}

	var result interface{}
	err = json.Unmarshal(claims, &result)
	if err != nil {
		return nil, fmt.Errorf("Unable to unmarshal decrypted claims: %v", err)
	}

	// check the expiration
	top, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Unable to verify claims because they are not a struct at top level: %v", err)
	}
	exp2, ok := top["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("Cannot check exp date: %v", err)
	}

	if exp2 < float64(now) {
		return nil, fmt.Errorf("Token is expired")
	}

	return result, nil
}

func SmokeTest() {
	// Create a new CA
	var err error
	keys := &JWKeys{}
	kid1 := "usa:1234:1"
	kid2 := "usa:1234:2"
	keys.AddRSA(kid1)
	keys.AddRSA(kid2)
	// re-parse it to ensure that we don't lose info
	cajson := AsJson(keys)
	keys, err = ParseJWK([]byte(cajson))
	if err != nil {
		panic(fmt.Sprintf("Unable to reparse JWK: %v", err))
	}

	log.Printf("public key 1: %s", keys.KeyMap[kid1].AsJsonPrivate())
	log.Printf("private keys: %s", AsJson(keys))

	// exp, and kid are inserted for you.
	t, err := CreateToken(
		keys,
		kid1,
		time.Now().Add(time.Minute*time.Duration(20)).Unix(),
		map[string]interface{}{
			"groups": map[string][]string{
				"email":  []string{"rob.fielding@gmail.com", "rrr00bb@yahoo.com"},
				"age":    []string{"adult"},
				"awards": []string{"cherryblossom-go-tournament", "best-dad"},
			},
		},
	)
	if err != nil {
		panic(fmt.Sprintf("Could not create token: %v", err))
	}
	log.Printf("create token: %s", t)

	validClaims, err := GetValidClaims(keys, time.Now().Unix(), t)
	if err != nil {
		panic(fmt.Sprintf("Cannot validate claims: %v", err))
	}
	log.Printf("validate claims: %s", AsJson(validClaims))
}

func main() {
	SmokeTest()
}
