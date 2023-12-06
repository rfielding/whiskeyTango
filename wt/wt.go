package wt

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
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
	task := fmt.Errorf("during AddRSA %s", kid)
	k, err := NewRSAJWK(kid, bits, smalle)
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("add in JWK RSA"),
			err,
		)
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
		log.Printf("unable to marshal redacted JWKey: %v", err)
	}
	return string(j)
}

// It's big-endian, urlEncoded base64 for the numbers
var NumberEncoding = base64.RawURLEncoding

// Generate a new RSA keypair for a kid - CA will have many of these
func NewRSAJWK(kid string, bits int, smalle bool) (JWKey, error) {
	task := fmt.Errorf("during NewRSAJWK %s", kid)
	k := JWKey{}
	k.Kty = "RSA"
	k.Bits = bits
	k.Kid = kid
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return k, errors.Join(
			task,
			fmt.Errorf("gnerate RSA keypair"),
			err,
		)
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
				return k, errors.Join(
					task,
					fmt.Errorf("unable to generate random D"),
					err,
				)
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
	k.D = NumberEncoding.EncodeToString(k.Dint.Bytes())
	k.E = NumberEncoding.EncodeToString(k.Eint.Bytes())
	k.N = NumberEncoding.EncodeToString(k.Nint.Bytes())
	return k, nil
}

// ParseJWK reads in a JWK from the filesystem,
// either extended for use by the CA, or for a client as a standard JWK format.
func ParseJWK(b []byte) (*JWKeys, error) {
	task := fmt.Errorf("during ParseJWK")
	var keys JWKeys
	json.Unmarshal(b, &keys)
	keys.KeyMap = make(map[string]JWKey)
	for _, v := range keys.Keys {
		// Set the RSAPublicKey field if it's blank
		if v.Kty == "RSA" && len(v.N) > 0 && len(v.E) > 0 {
			nn, err := NumberEncoding.DecodeString(v.N)
			if err != nil {
				return nil, errors.Join(
					task,
					fmt.Errorf("cannod decode N"),
					err,
				)
			}
			nd, err := NumberEncoding.DecodeString(v.D)
			if err != nil {
				return nil, errors.Join(
					task,
					fmt.Errorf("cannod decode RSA D"),
					err,
				)
			}
			ne, err := NumberEncoding.DecodeString(v.E)
			if err != nil {
				return nil, errors.Join(
					task,
					fmt.Errorf("cannot decode RSA E"),
					err,
				)
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
	task := fmt.Errorf("during Decrypt")
	nonce := ciphertextWithNonce[0:12]
	ciphertext := ciphertextWithNonce[12:]

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("unable to create NewCipher"),
			err,
		)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("unable to create NewGCM"),
			err,
		)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("unable to decrypt"),
			err,
		)
	}
	return plaintext, nil
}

// Returns ciphertextWithNonce,err
func Encrypt(k []byte, claims []byte) ([]byte, error) {
	task := fmt.Errorf("during Encrypt")
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("cannot get a NewCipher"),
			err,
		)
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("cannot ReadFull"),
			err,
		)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("cannot create NewGCM"),
			err,
		)
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
func CreateToken(
	keys *JWKeys,
	kid string,
	exp int64,
	claimsObject interface{},
	publicKey *rsa.PublicKey,
	publicKeyName string,
) (string, error) {
	task := fmt.Errorf("during CreateToken")
	// We round-trip marshalling, so that the claimsObject can be any kind of json object we like as input
	claimsMarshalled, err := json.Marshal(claimsObject)
	if err != nil {
		return "", errors.Join(
			task,
			fmt.Errorf("unable to Marshal claims"),
			err,
		)
	}
	var claims interface{}
	err = json.Unmarshal(claimsMarshalled, &claims)
	if err != nil {
		return "", errors.Join(
			task,
			fmt.Errorf("unable to Unmarshal to claims"),
			err,
		)
	}
	c, ok := claims.(map[string]interface{})
	if !ok {
		return "", errors.Join(
			task,
			fmt.Errorf("must pass in a map[string]interface{} at the top for claims"),
		)
	}

	// We can set exp, kid no matter what fields exist on claimsObject
	c["exp"] = exp
	c["kid"] = kid
	if publicKey != nil {
		encryptPublic := make(map[string]interface{})
		encryptPublic["n"] = NumberEncoding.EncodeToString(publicKey.N.Bytes())
		encryptPublic["e"] = NumberEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())
		encryptPublic["name"] = publicKeyName
		c["encryptPublic"] = encryptPublic
	}
	j, err := json.Marshal(c)
	if err != nil {
		return "", errors.Join(
			task,
			fmt.Errorf("failed to Marshal claims"),
			err,
		)
	}

	// Sign V
	theKey, ok := keys.KeyMap[kid]
	if !ok {
		return "", errors.Join(
			task,
			fmt.Errorf("unable to find kid %s", kid),
		)
	}

	// Create a fresh random key
	k := make([]byte, theKey.Bits/8-1)
	_, err = io.ReadFull(rand.Reader, k)
	if err != nil {
		return "", errors.Join(
			task,
			fmt.Errorf("failed to ReadFull"),
			err,
		)
	}

	// Generate the ciphertext E
	E, err := Encrypt(k[0:32], j)
	if err != nil {
		return "", errors.Join(
			task,
			fmt.Errorf("failed to Encrypt claims"),
			err,
		)
	}

	// Generate hash of ciphertext HE
	HE := H(E)

	// We xor the two required steps together of HE and V to make client produce K to decrypt
	V := new(big.Int).Xor(
		new(big.Int).SetBytes(k),
		new(big.Int).SetBytes(HE),
	)

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
func GetValidClaims(keys *JWKeys, now int64, token string) (map[string]interface{}, error) {
	task := fmt.Errorf("during GetValidClaims")
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return nil, errors.Join(
			task,
			fmt.Errorf("expected 3 token parts, but got %d", len(tokenParts)),
		)
	}

	kidBytes, err := base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("unable to extract header which should be kid value"),
			err,
		)
	}
	kid := string(kidBytes)

	// will it decode ALL bytes?
	ciphertextWithNonce, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("unable to decode body"),
			err,
		)
	}

	SigBytes, err := base64.RawURLEncoding.DecodeString(tokenParts[2])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("unable to decode signature bytes"),
			err,
		)
	}

	theKey, ok := keys.KeyMap[kid]
	if !ok {
		return nil, errors.Join(
			task,
			fmt.Errorf("could not find kid %s", kid),
		)
	}
	// We need a hash of the ciphertext, as proof that we checked it
	HE := new(big.Int).SetBytes(H(ciphertextWithNonce))

	// We need the verified signature as proof that we checked it
	V := RSA(
		new(big.Int).SetBytes(SigBytes),
		theKey.Eint,
		theKey.Nint,
	)

	// Extract the key that proves that we checked the signature
	k := make([]byte, theKey.Bits/8-1)
	new(big.Int).Xor(V, HE).FillBytes(k)

	// We now can decrypt claims
	claims, err := Decrypt(k[0:32], ciphertextWithNonce)
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("unable to decrypt claims"),
			err,
		)
	}

	var result map[string]interface{}
	err = json.Unmarshal(claims, &result)
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("unable to unmarshal claims"),
			err,
		)
	}

	// check the expiration
	exp2, ok := result["exp"].(float64)
	if !ok {
		return nil, errors.Join(
			task,
			fmt.Errorf("cannot find expiration date exp"),
		)
	}

	// note that we only have 53 bits of precision
	if int64(exp2) < now {
		return nil, errors.Join(
			task,
			fmt.Errorf("token is expired at %d", int64(exp2)),
		)
	}

	return result, nil
}

func Prove(keypairName string, challenge string) error {
	challengeBytes, err := NumberEncoding.DecodeString(challenge)
	task := fmt.Errorf("prove ownership of keypair")
	if err != nil {
		return errors.Join(task, err)
	}
	var challengeInt = (&big.Int{}).SetBytes(challengeBytes)

	kPair, err := ReadKeyPair(keypairName)
	if err != nil {
		return errors.Join(task, err)
	}
	responseInt := RSA(challengeInt, kPair.D, kPair.PublicKey.N)
	fmt.Printf("%s", string(responseInt.Bytes()))
	return nil
}

func Challenge(keys *JWKeys, challenge string) error {
	task := fmt.Errorf("challenge token owner")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return errors.Join(task, scanner.Err())
	}
	input := scanner.Bytes()

	validClaims, err := GetValidClaims(keys, time.Now().Unix(), string(input))
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("cannot validate claims: %s", string(input)),
			err,
		)
	}
	// calculate: challengeInt^E mod N
	encryptPublic := validClaims["encryptPublic"].(map[string]interface{})
	publicKeyE, okE := encryptPublic["e"].(string)
	publicKeyN, okN := encryptPublic["n"].(string)
	if okE && len(publicKeyE) > 0 && okN && len(publicKeyN) > 0 {

		bE, err := NumberEncoding.DecodeString(publicKeyE)
		if err != nil {
			return errors.Join(
				task,
				fmt.Errorf("unable to unpack E"),
				err,
			)
		}
		E := (&big.Int{}).SetBytes(bE)

		bN, err := NumberEncoding.DecodeString(publicKeyN)
		if err != nil {
			return errors.Join(
				task,
				fmt.Errorf("unable to unpack N"),
				err,
			)
		}
		N := (&big.Int{}).SetBytes(bN)

		challengeInt := (&big.Int{}).SetBytes([]byte(challenge))

		C := RSA(challengeInt, E, N)
		fmt.Printf("%s\n", NumberEncoding.EncodeToString(C.Bytes()))
	}
	return nil
}

func Verify(keys *JWKeys) error {
	scanner := bufio.NewScanner(os.Stdin)
	task := fmt.Errorf("verify keys")
	if !scanner.Scan() {
		return errors.Join(
			task,
			fmt.Errorf("failed to read"),
			scanner.Err(),
		)
	}
	input := scanner.Bytes()

	validClaims, err := GetValidClaims(keys, time.Now().Unix(), string(input))
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("cannot validate claims %s", string(input)),
			err,
		)
	}
	fmt.Printf("%s\n", AsJson(validClaims))
	return nil
}

func KeyPair(bits int) (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("keypair unable to generate"),
			err,
		)
	}
	return priv, nil
}

func ReadKeyPair(name string) (*rsa.PrivateKey, error) {
	d, err := os.ReadFile(name)
	task := fmt.Errorf("ReadKeyPair %s", name)
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("read file"),
			err,
		)
	}
	j := make(map[string]string)
	err = json.Unmarshal(d, &j)
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("unable to unmarshal"),
			err,
		)
	}
	bD, err := NumberEncoding.DecodeString(j["D"])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("decode string"),
			err,
		)
	}
	D := big.NewInt(0).SetBytes(bD)

	bP, err := NumberEncoding.DecodeString(j["P"])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("could not decode P"),
			err,
		)
	}
	P := big.NewInt(0).SetBytes(bP)

	bQ, err := NumberEncoding.DecodeString(j["Q"])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("could not decode Q"),
			err,
		)
	}
	Q := big.NewInt(0).SetBytes(bQ)

	bN, err := NumberEncoding.DecodeString(j["publicKeyN"])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("could not decode N"),
			err,
		)
	}
	N := big.NewInt(0).SetBytes(bN)

	bE, err := NumberEncoding.DecodeString(j["publicKeyE"])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("decode E"),
			err,
		)
	}
	E := big.NewInt(0).SetBytes(bE)

	v := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: N,
			E: int(E.Int64()),
		},
		D:      D,
		Primes: []*big.Int{P, Q},
	}
	v.Precompute()
	return v, nil
}

func WriteNewKeyPair(name string, bits int) error {
	task := fmt.Errorf("write keypair %s %d bit", name, bits)
	kp, err := KeyPair(bits)
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("RSA keypair"),
			err,
		)
	}
	data := make(map[string]string)
	data["publicKeyE"] = NumberEncoding.EncodeToString(
		big.NewInt(int64(kp.PublicKey.E)).Bytes(),
	)
	data["publicKeyN"] = NumberEncoding.EncodeToString(
		kp.PublicKey.N.Bytes(),
	)
	data["D"] = NumberEncoding.EncodeToString(
		kp.D.Bytes(),
	)
	data["P"] = NumberEncoding.EncodeToString(
		kp.Primes[0].Bytes(),
	)
	data["Q"] = NumberEncoding.EncodeToString(
		kp.Primes[1].Bytes(),
	)
	j, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("marshal"),
			err,
		)
	}
	err = os.WriteFile(name, j, 0700)
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("write file"),
			err,
		)
	}
	return nil
}

func Sign(keys *JWKeys, kid string, minutes int64, keypairName string) error {
	task := fmt.Errorf("Sign %s", kid)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return errors.Join(
			task,
			fmt.Errorf("scan"),
			scanner.Err(),
		)
	}
	input := scanner.Bytes()
	var claims map[string]interface{}
	err := json.Unmarshal(input, &claims)
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("unmarshal"),
			err,
		)
	}

	var pub *rsa.PublicKey
	if len(keypairName) > 0 {
		priv, err := ReadKeyPair(keypairName)
		if err != nil {
			return errors.Join(
				task,
				fmt.Errorf("read key pair"),
				err,
			)
		}
		pub = &priv.PublicKey
	}

	// exp, and kid are inserted for you.
	t, err := CreateToken(
		keys,
		kid,
		time.Now().Add(time.Minute*time.Duration(minutes)).Unix(),
		claims,
		pub,
		keypairName,
	)
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("create token"),
			err,
		)
	}
	fmt.Printf("%s\n", t)
	return nil
}

func LoadCA(f string) (*JWKeys, error) {
	task := fmt.Errorf("load ca %s", f)
	keys := &JWKeys{}
	if _, err := os.Stat(f); os.IsNotExist(err) {
		return keys, nil
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return keys, errors.Join(
			task,
			fmt.Errorf("read file"),
			err,
		)
	}
	keys, err = ParseJWK(b)
	if err != nil {
		return keys, errors.Join(
			task,
			fmt.Errorf("parse jwk"),
			err,
		)
	}
	return keys, nil
}

func StoreCA(f string, keys *JWKeys) error {
	cajson := AsJson(keys)
	err := os.WriteFile(f, []byte(cajson), 0600)
	if err != nil {
		return errors.Join(
			fmt.Errorf("store ca"),
			err,
		)
	}
	return nil
}

func MakeCA(kid string, bits int, smalle bool) error {
	task := fmt.Errorf("make ca")
	keys := &JWKeys{}
	keys.AddRSA(kid, bits, smalle)

	caJson := AsJson(keys)
	f := fmt.Sprintf("%s-sign.json", kid)
	err := os.WriteFile(f, []byte(caJson), 0600)
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("write file %s", f),
			err,
		)
	}

	caJson = keys.KeyMap[kid].AsJsonPrivate()

	f = fmt.Sprintf("%s-verify.json", kid)
	err = os.WriteFile(f, []byte(caJson), 0600)
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("write file %s", f),
			err,
		)
	}
	return nil
}

func Main() error {
	task := fmt.Errorf("during Main")
	kp := flag.String("kp", "", "RSA keypair filename")
	show := flag.String("show", "", "show what is being read")
	ca := flag.String("ca", "", "CA signing json jwk")
	trust := flag.String("trust", "", "trust a CA key")
	create := flag.Bool("create", false, "Create an item")
	sign := flag.Bool("sign", false, "Sign a token")
	smalle := flag.Bool("smalle", false, "Use standard small e in RSA")
	bits := flag.Int("bits", 2048, "bits for the RSA key")
	verify := flag.Bool("verify", false, "Verify a token")
	minutes := flag.Int64("minutes", 20, "Expiration in minutes")
	kid := flag.String("kid", "", "kid to issue")
	challenge := flag.String("challenge", "", "challenge token owner to prove ownership")
	prove := flag.String("prove", "", "prove to challenger that token is owned")
	flag.Parse()

	if len(*ca) > 0 {
		keys, err := LoadCA(*ca)
		if err != nil {
			return errors.Join(
				task,
				fmt.Errorf("failed to LoadCA %s", *ca),
				err,
			)
		}
		if len(*trust) > 0 && len(*kid) > 0 {
			trusted, err := LoadCA(*trust)
			if err != nil {
				return errors.Join(
					task,
					fmt.Errorf("failed to LoadCA for %s", *trust),
					err,
				)
			}
			k := keys.KeyMap[*kid].Redact()
			trusted.Insert(*kid, k)
			err = StoreCA(*trust, trusted)
			if err != nil {
				return errors.Join(
					task,
					fmt.Errorf("failed to StoreCA at %s", *trust),
					err,
				)
			}
			return nil
		}
		if *create && len(*kid) > 0 {
			// ca [fname] create kid [kid]
			keys.AddRSA(*kid, *bits, *smalle)
			err = StoreCA(*ca, keys)
			if err != nil {
				return errors.Join(
					task,
					fmt.Errorf("failed to StoreCA at %s", *ca),
					err,
				)
			}
			return nil
		}
		if *sign && len(*kid) > 0 {
			err = Sign(keys, *kid, *minutes, *kp)
			if err != nil {
				return errors.Join(
					task,
					fmt.Errorf("failed to Sign %s into cert", *kid),
					err,
				)
			}
			return nil
		}
		if *verify {
			err = Verify(keys)
			if err != nil {
				return errors.Join(
					task,
					fmt.Errorf("failed to Verify token"),
					err,
				)
			}
			return nil
		}
		if len(*challenge) > 0 {
			err = Challenge(keys, *challenge)
			if err != nil {
				return errors.Join(
					task,
					fmt.Errorf("failed to Challenge"),
					err,
				)
			}
			return nil
		}
	}
	if len(*kp) > 0 && len(*show) > 0 {
		privateKey, err := ReadKeyPair(*kp)
		if err != nil {
			return errors.Join(
				task,
				fmt.Errorf("failed to ReadKeyPair"),
				err,
			)
		}
		fmt.Printf("%s\n", AsJson(privateKey))
		return nil
	}
	if len(*prove) > 0 && len(*kp) > 0 {
		err := Prove(*kp, *prove)
		return err
	}
	if len(*kp) > 0 {
		err := WriteNewKeyPair(*kp, *bits)
		return err
	}
	return nil
}
