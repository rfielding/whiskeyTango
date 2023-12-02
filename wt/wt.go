package wt

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// It's big-endian, urlEncoded base64 for the numbers
var NumberEncoding = base64.RawURLEncoding

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
	k.D = NumberEncoding.EncodeToString(k.Dint.Bytes())
	k.E = NumberEncoding.EncodeToString(k.Eint.Bytes())
	k.N = NumberEncoding.EncodeToString(k.Nint.Bytes())
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
			nn, err := NumberEncoding.DecodeString(v.N)
			if err != nil {
				return nil, fmt.Errorf("Cannot parse RSA N: %v", err)
			}
			nd, err := NumberEncoding.DecodeString(v.D)
			if err != nil {
				return nil, fmt.Errorf("Cannot parse RSA D: %v", err)
			}
			ne, err := NumberEncoding.DecodeString(v.E)
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
func CreateToken(
	keys *JWKeys,
	kid string,
	exp int64,
	claimsObject interface{},
	publicKey *rsa.PublicKey,
	publicKeyName string,
) (string, error) {
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
	if publicKey != nil {
		encryptPublic := make(map[string]interface{})
		encryptPublic["N"] = hex.EncodeToString(publicKey.N.Bytes())
		encryptPublic["E"] = hex.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())
		encryptPublic["name"] = publicKeyName
		c["encryptPublic"] = encryptPublic
	}
	j, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("Unable to marshal plaintext: %v", err)
	}

	// Sign V
	theKey, ok := keys.KeyMap[kid]
	if !ok {
		return "", fmt.Errorf("Unable to find kid %s", kid)
	}

	// Create a fresh random key
	k := make([]byte, theKey.Bits/8-1)
	_, err = io.ReadFull(rand.Reader, k)
	if err != nil {
		return "", fmt.Errorf("Unable to create a fresh random witness key: %v", err)
	}

	// Generate the ciphertext E
	E, err := Encrypt(k[0:32], j)
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
		return nil, fmt.Errorf("Unable to find kid %s", kid)
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
		return nil, fmt.Errorf("Unable to decrypt claims: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(claims, &result)
	if err != nil {
		return nil, fmt.Errorf("Unable to unmarshal decrypted claims: %v", err)
	}

	// check the expiration
	exp2, ok := result["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("Cannot check exp date: %v", err)
	}

	if exp2 < float64(now) {
		return nil, fmt.Errorf("Token is expired")
	}

	return result, nil
}

/*
package wt

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/rfielding/whiskeyTango/wt"
)
*/

func Prove(keypairName string, challenge string) error {
	challengeBytes, err := hex.DecodeString(challenge)
	task := fmt.Errorf("Prove ownership of keypair")
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
	task := fmt.Errorf("Challenge token owner")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return errors.Join(task, scanner.Err())
	}
	input := scanner.Bytes()

	validClaims, err := GetValidClaims(keys, time.Now().Unix(), string(input))
	if err != nil {
		return errors.Join(
			task,
			fmt.Errorf("Cannot validate claims: %s", string(input)),
			err,
		)
	}
	// calculate: challengeInt^E mod N
	encryptPublic := validClaims["encryptPublic"].(map[string]interface{})
	publicKeyE, okE := encryptPublic["E"].(string)
	publicKeyN, okN := encryptPublic["N"].(string)
	if okE && len(publicKeyE) > 0 && okN && len(publicKeyN) > 0 {

		bE, err := hex.DecodeString(publicKeyE)
		if err != nil {
			return errors.Join(
				task,
				fmt.Errorf("unable to unpack E"),
				err,
			)
		}
		E := (&big.Int{}).SetBytes(bE)

		bN, err := hex.DecodeString(publicKeyN)
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
		fmt.Printf("%s\n", hex.EncodeToString(C.Bytes()))
	}
	return nil
}

func Verify(keys *JWKeys) error {
	scanner := bufio.NewScanner(os.Stdin)
	task := fmt.Errorf("Verify keys")
	if !scanner.Scan() {
		return errors.Join(
			task,
			fmt.Errorf("Failed to read"),
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
			fmt.Errorf("Keypair unable to generate"),
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
	bD, err := hex.DecodeString(j["D"])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("decode string"),
			err,
		)
	}
	D := big.NewInt(0).SetBytes(bD)

	bP, err := hex.DecodeString(j["P"])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("could not decode P"),
			err,
		)
	}
	P := big.NewInt(0).SetBytes(bP)

	bQ, err := hex.DecodeString(j["Q"])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("could not decode Q"),
			err,
		)
	}
	Q := big.NewInt(0).SetBytes(bQ)

	bN, err := hex.DecodeString(j["publicKeyN"])
	if err != nil {
		return nil, errors.Join(
			task,
			fmt.Errorf("could not decode N"),
			err,
		)
	}
	N := big.NewInt(0).SetBytes(bN)

	bE, err := hex.DecodeString(j["publicKeyE"])
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
	data["publicKeyE"] = hex.EncodeToString(
		big.NewInt(int64(kp.PublicKey.E)).Bytes(),
	)
	data["publicKeyN"] = hex.EncodeToString(
		kp.PublicKey.N.Bytes(),
	)
	data["D"] = hex.EncodeToString(
		kp.D.Bytes(),
	)
	data["P"] = hex.EncodeToString(
		kp.Primes[0].Bytes(),
	)
	data["Q"] = hex.EncodeToString(
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
			return err
		}
		if len(*trust) > 0 && len(*kid) > 0 {
			trusted, err := LoadCA(*trust)
			if err != nil {
				return err
			}
			k := keys.KeyMap[*kid].Redact()
			trusted.Insert(*kid, k)
			err = StoreCA(*trust, trusted)
			return err
		}
		if *create && len(*kid) > 0 {
			// ca [fname] create kid [kid]
			keys.AddRSA(*kid, *bits, *smalle)
			err = StoreCA(*ca, keys)
			return err
		}
		if *sign && len(*kid) > 0 {
			err = Sign(keys, *kid, *minutes, *kp)
			return err
		}
		if *verify {
			err = Verify(keys)
			return err
		}
		if len(*challenge) > 0 {
			err = Challenge(keys, *challenge)
			return err
		}
	}
	if len(*kp) > 0 && len(*show) > 0 {
		privateKey, err := ReadKeyPair(*kp)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", AsJson(privateKey))
		return err
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
