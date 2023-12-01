package main

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

func Prove(keypairName string, challenge string) {
	challengeBytes, err := hex.DecodeString(challenge)
	if err != nil {
		panic(fmt.Sprintf("unable to hex decode challenge: %v", err))
	}
	var challengeInt = (&big.Int{}).SetBytes(challengeBytes)

	kPair := ReadKeyPair(keypairName)
	responseInt := wt.RSA(challengeInt, kPair.D, kPair.PublicKey.N)
	fmt.Printf("%s", string(responseInt.Bytes()))
}

func Challenge(keys *wt.JWKeys, challenge string) {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		log.Printf("Failed to read: %v", scanner.Err())
		return
	}
	input := scanner.Bytes()

	validClaims, err := wt.GetValidClaims(keys, time.Now().Unix(), string(input))
	if err != nil {
		panic(fmt.Sprintf("Cannot validate claims: %v\n%s", err, string(input)))
	}
	// calculate: challengeInt^E mod N
	publicKeyE, okE := validClaims["publicKeyE"].(string)
	publicKeyN, okN := validClaims["publicKeyN"].(string)
	if okE && len(publicKeyE) > 0 && okN && len(publicKeyN) > 0 {

		bE, err := hex.DecodeString(publicKeyE)
		if err != nil {
			panic(fmt.Sprintf("unable to unpack E: %v", err))
		}
		E := (&big.Int{}).SetBytes(bE)

		bN, err := hex.DecodeString(publicKeyN)
		if err != nil {
			panic(fmt.Sprintf("unable to unpack N: %v", err))
		}
		N := (&big.Int{}).SetBytes(bN)

		challengeInt := (&big.Int{}).SetBytes([]byte(challenge))

		C := wt.RSA(challengeInt, E, N)
		fmt.Printf("%s\n", hex.EncodeToString(C.Bytes()))
	}
}

func Verify(keys *wt.JWKeys) {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		log.Printf("Failed to read: %v", scanner.Err())
		return
	}
	input := scanner.Bytes()

	validClaims, err := wt.GetValidClaims(keys, time.Now().Unix(), string(input))
	if err != nil {
		panic(fmt.Sprintf("Cannot validate claims: %v\n%s", err, string(input)))
	}
	fmt.Printf("%s\n", wt.AsJson(validClaims))
}

func KeyPair(bits int) *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(fmt.Sprintf("Unable to generate RSA Keypair: %v", err))
	}
	return priv
}

func ReadKeyPair(name string) *rsa.PrivateKey {
	d, err := os.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("unable to read file %s: %v", name, err))
	}
	j := make(map[string]string)
	err = json.Unmarshal(d, &j)
	if err != nil {
		panic(fmt.Sprintf("unable to read %s: %v", name, err))
	}
	bD, err := hex.DecodeString(j["D"])
	if err != nil {
		panic(fmt.Sprintf("could not decode D from %s: %v", name, err))
	}
	D := big.NewInt(0).SetBytes(bD)

	bP, err := hex.DecodeString(j["P"])
	if err != nil {
		panic(fmt.Sprintf("could not decode P from %s: %v", name, err))
	}
	P := big.NewInt(0).SetBytes(bP)

	bQ, err := hex.DecodeString(j["Q"])
	if err != nil {
		panic(fmt.Sprintf("could not decode Q from %s: %v", name, err))
	}
	Q := big.NewInt(0).SetBytes(bQ)

	bN, err := hex.DecodeString(j["publicKeyN"])
	if err != nil {
		panic(fmt.Sprintf("could not decode N from %s: %v", name, err))
	}
	N := big.NewInt(0).SetBytes(bN)

	bE, err := hex.DecodeString(j["publicKeyE"])
	if err != nil {
		panic(fmt.Sprintf("could not decode E from %s: %v", name, err))
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
	return v
}

func WriteNewKeyPair(name string, bits int) {
	kp := KeyPair(bits)
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
		panic(fmt.Sprintf("error making keypair %s: %v", name, err))
	}
	err = os.WriteFile(name, j, 0700)
	if err != nil {
		panic(fmt.Sprintf("error writing keypair %s: %v", name, err))
	}
}

func Sign(keys *wt.JWKeys, kid string, minutes int64, keypairName string) {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		log.Printf("Failed to read: %v", scanner.Err())
		return
	}
	input := scanner.Bytes()
	var claims map[string]interface{}
	err := json.Unmarshal(input, &claims)
	if err != nil {
		panic("Could not parse claims")
	}

	var pub *rsa.PublicKey
	if len(keypairName) > 0 {
		priv := ReadKeyPair(keypairName)
		pub = &priv.PublicKey
	}

	// exp, and kid are inserted for you.
	t, err := wt.CreateToken(
		keys,
		kid,
		time.Now().Add(time.Minute*time.Duration(minutes)).Unix(),
		claims,
		pub,
		keypairName,
	)
	if err != nil {
		panic(fmt.Sprintf("Could not create token: %v", err))
	}
	fmt.Printf("%s\n", t)
}

func LoadCA(f string) *wt.JWKeys {
	keys := &wt.JWKeys{}
	if _, err := os.Stat(f); os.IsNotExist(err) {
		return keys
	}
	b, err := ioutil.ReadFile(f)
	if err != nil {
		panic(fmt.Sprintf("Could not read CA: %v", err))
	}
	keys, err = wt.ParseJWK(b)
	if err != nil {
		panic(fmt.Sprintf("Unable to parse JWK: %v", err))
	}
	return keys
}

func StoreCA(f string, keys *wt.JWKeys) {
	cajson := wt.AsJson(keys)
	err := os.WriteFile(f, []byte(cajson), 0600)
	if err != nil {
		panic(fmt.Sprintf("Could not write CA: %v", err))
	}
}

func MakeCA(kid string, bits int, smalle bool) {
	keys := &wt.JWKeys{}
	keys.AddRSA(kid, bits, smalle)

	caJson := wt.AsJson(keys)
	f := fmt.Sprintf("%s-sign.json", kid)
	err := os.WriteFile(f, []byte(caJson), 0600)
	if err != nil {
		panic(fmt.Sprintf("Could not write CA: %v", err))
	}

	caJson = keys.KeyMap[kid].AsJsonPrivate()

	f = fmt.Sprintf("%s-verify.json", kid)
	err = os.WriteFile(f, []byte(caJson), 0600)
	if err != nil {
		panic(fmt.Sprintf("Could not write CA: %v", err))
	}
}

func main() {
	/*
		WriteNewKeyPair("robfielding.kp", 1024)
		theKeys := ReadKeyPair("robfielding.kp")
		test := "hi"
		E := big.NewInt(int64(theKeys.E))
		D := theKeys.D
		N := theKeys.PublicKey.N
		R := wt.RSA(
			(&big.Int{}).SetBytes([]byte(test)),
			E,
			N,
		)
		R2 := wt.RSA(
			R,
			D,
			N,
		)
		fmt.Printf("%s vs %s", test, string(R2.Bytes()))
		if true {
			return
		}
	*/
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
		keys := LoadCA(*ca)
		if len(*trust) > 0 && len(*kid) > 0 {
			trusted := LoadCA(*trust)
			k := keys.KeyMap[*kid].Redact()
			trusted.Insert(*kid, k)
			StoreCA(*trust, trusted)
			return
		}
		if *create && len(*kid) > 0 {
			// ca [fname] create kid [kid]
			keys.AddRSA(*kid, *bits, *smalle)
			StoreCA(*ca, keys)
			return
		}
		if *sign && len(*kid) > 0 {
			Sign(keys, *kid, *minutes, *kp)
			return
		}
		if *verify {
			Verify(keys)
			return
		}
		if len(*challenge) > 0 {
			Challenge(keys, *challenge)
			return
		}
	}
	if len(*kp) > 0 && len(*show) > 0 {
		privateKey := ReadKeyPair(*kp)
		fmt.Printf("%s\n", wt.AsJson(privateKey))
		return
	}
	if len(*prove) > 0 && len(*kp) > 0 {
		Prove(*kp, *prove)
		return
	}
	if len(*kp) > 0 {
		WriteNewKeyPair(*kp, *bits)
		return
	}
}
