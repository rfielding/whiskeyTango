package wt

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
)

// Do not use pointers to these!  Copies will be modified to blank out CA data
type JWKey struct {
	Kty  string `json:"kty"`
	Use  string `json:"use,omitempty"`
	Kid  string `json:"kid,omitempty"`
	Alg  string `json:"alg,omitempty"`
	Bits int    `json:"bits,omitempty"`

	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"` // comment this out if not CA
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	K   string `json:"k,omitempty"` // comment this out if not CA?? TODO

	// Parsed bigints
	Nint *big.Int `json:"-"`
	Dint *big.Int `json:"-"`
	Eint *big.Int `json:"-"`
}

func (key JWKey) Redact() JWKey {
	k2 := key
	k2.Dint = nil
	k2.D = ""
	k2.K = "" // I assume that it's private
	return k2
}

type JWKeys struct {
	Keys   []JWKey          `json:"keys"`
	KeyMap map[string]JWKey `json:"-"`
}

func (keys *JWKeys) Insert(kid string, k JWKey) {
	keys.Keys = append(keys.Keys, k)
	if keys.KeyMap == nil {
		keys.KeyMap = make(map[string]JWKey)
	}
	keys.KeyMap[kid] = k
}

// Allocate a new RSA key for kid
func (keys *JWKeys) AddRSA(kid string, bits int, smalle bool) error {
	k, err := NewRSAJWK(kid, bits, smalle)
	if err != nil {
		return fmt.Errorf("Unable to add in JWK RSA kid %s to JWKeys: %v", kid, err)
	}
	keys.Insert(kid, k)
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
	j, err := json.MarshalIndent(k2, "", "  ")
	if err != nil {
		log.Printf("Unable to marshal redacted JWKey: %v", err)
	}
	return string(j)
}

// Generate a new RSA keypair for a kid - CA will have many of these
func NewRSAJWK(kid string, bits int, smalle bool) (JWKey, error) {
	k := JWKey{}
	k.Kty = "RSA"
	k.Bits = bits
	k.Kid = kid
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return k, fmt.Errorf("Unable to generate RSA Keypair: %v", err)
	}

	// We need phi to make E not deterministic
	one := new(big.Int).SetInt64(1)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(priv.Primes[0], one),
		new(big.Int).Sub(priv.Primes[1], one),
	)
	maxModPhi := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bits)), nil)

	// I think some D have no inverse mod phi, but it only takes a few tries to find one randomly
	if smalle {
		k.Dint = priv.D
		k.Eint = new(big.Int).SetInt64(int64(priv.PublicKey.E))
		k.Nint = priv.PublicKey.N
	} else {
		for {
			// Generate
			D, err := rand.Int(rand.Reader, maxModPhi)
			if err != nil {
				return k, fmt.Errorf("Unable to generate random D: %v", err)
			}
			k.Dint = new(big.Int).Mod(D, phi)
			if k.Dint == nil {
				continue
			}

			if new(big.Int).GCD(nil, nil, k.Dint, phi).Cmp(one) != 0 {
				continue
			}

			k.Eint = new(big.Int).ModInverse(k.Dint, phi)
			if k.Eint == nil {
				continue
			}

			if new(big.Int).GCD(nil, nil, k.Eint, phi).Cmp(one) != 0 {
				continue
			}

			k.Nint = priv.N
			break
		}
	}
	k.D = base64.RawURLEncoding.EncodeToString(k.Dint.Bytes())
	k.E = base64.RawURLEncoding.EncodeToString(k.Eint.Bytes())
	k.N = base64.RawURLEncoding.EncodeToString(k.Nint.Bytes())
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
		if v.Kty == "RSA" && len(v.N) > 0 && len(v.E) > 0 {
			nn, err := base64.RawURLEncoding.DecodeString(v.N)
			if err != nil {
				return nil, fmt.Errorf("Cannot parse RSA N: %v", err)
			}
			nd, err := base64.RawURLEncoding.DecodeString(v.D)
			if err != nil {
				return nil, fmt.Errorf("Cannot parse RSA D: %v", err)
			}
			ne, err := base64.RawURLEncoding.DecodeString(v.E)
			if err != nil {
				return nil, fmt.Errorf("Cannot parse RSA E: %v", err)
			}
			v.Nint = new(big.Int).SetBytes(nn)
			v.Dint = new(big.Int).SetBytes(nd)
			v.Eint = new(big.Int).SetBytes(ne)
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
	theKey, ok := keys.KeyMap[kid]
	if !ok {
		return "", fmt.Errorf("Unable to find kid %s", kid)
	}
	Sig := RSA(V, theKey.Dint, theKey.Nint)

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

	theKey, ok := keys.KeyMap[kid]
	if !ok {
		return "", fmt.Errorf("Unable to find kid %s", kid)
	}
	// We need a hash of the ciphertext, as proof that we checked it
	HE := new(big.Int).SetBytes(H(ciphertextWithNonce))

	// We need the verified signature as proof that we checked it
	V := RSA(
		new(big.Int).SetBytes(SigBytes),
		theKey.Eint,
		theKey.Nint,
	)

	// If V is larger than a sha256 hash, then it can't be genuine!
	if len(V.Bytes()) > 64 {
		return nil, fmt.Errorf("Signature is invalid")
	}

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
