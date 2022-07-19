package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/rfielding/whiskeyTango/wt"
)

func Verify(keys *wt.JWKeys) {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		log.Printf("Failed to read: %v", scanner.Err())
		return
	}
	input := scanner.Bytes()

	validClaims, err := wt.GetValidClaims(keys, time.Now().Unix(), string(input))
	if err != nil {
		panic(fmt.Sprintf("Cannot validate claims: %v", err))
	}
	fmt.Printf("%s\n", wt.AsJson(validClaims))
}

func Sign(keys *wt.JWKeys, kid string, minutes int64) {
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

	// exp, and kid are inserted for you.
	t, err := wt.CreateToken(
		keys,
		kid,
		time.Now().Add(time.Minute*time.Duration(minutes)).Unix(),
		claims,
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
	err := ioutil.WriteFile(f, []byte(cajson), 0600)
	if err != nil {
		panic(fmt.Sprintf("Could not write CA: %v", err))
	}
}

func MakeCA(kid string, bits int, smalle bool) {
	keys := &wt.JWKeys{}
	keys.AddRSA(kid, bits, smalle)

	caJson := wt.AsJson(keys)
	f := fmt.Sprintf("%s-sign.json", kid)
	err := ioutil.WriteFile(f, []byte(caJson), 0600)
	if err != nil {
		panic(fmt.Sprintf("Could not write CA: %v", err))
	}

	caJson = keys.KeyMap[kid].AsJsonPrivate()

	f = fmt.Sprintf("%s-verify.json", kid)
	err = ioutil.WriteFile(f, []byte(caJson), 0600)
	if err != nil {
		panic(fmt.Sprintf("Could not write CA: %v", err))
	}

}

func SmokeTest() {
	// Create a new CA
	var err error
	keys := &wt.JWKeys{}
	kid1 := "usa:1234:1"
	kid2 := "usa:1234:2"
	keys.AddRSA(kid1, 2048, false)
	keys.AddRSA(kid2, 2048, false)

	// re-parse it to ensure that we don't lose info
	cajson := wt.AsJson(keys)
	keys, err = wt.ParseJWK([]byte(cajson))
	if err != nil {
		panic(fmt.Sprintf("Unable to reparse JWK: %v", err))
	}

	log.Printf("public key 1: %s", keys.KeyMap[kid1].AsJsonPrivate())
	log.Printf("private keys: %s", wt.AsJson(keys))

	// exp, and kid are inserted for you.
	t, err := wt.CreateToken(
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

	validClaims, err := wt.GetValidClaims(keys, time.Now().Unix(), t)
	if err != nil {
		panic(fmt.Sprintf("Cannot validate claims: %v", err))
	}
	log.Printf("validate claims: %s", wt.AsJson(validClaims))
}

func main() {
	ca := flag.String("ca", "", "CA signing json jwk")
	trust := flag.String("trust", "", "trust a CA key")
	create := flag.Bool("create", false, "Create an item")
	sign := flag.Bool("sign", false, "Sign a token")
	smalle := flag.Bool("smalle", false, "Use standard small e in RSA")
	bits := flag.Int("bits", 2048, "bits for the RSA key")
	verify := flag.Bool("verify", false, "Verify a token")
	minutes := flag.Int64("minutes", 20, "Expiration in minutes")
	kid := flag.String("kid", "", "kid to issue")
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
			Sign(keys, *kid, *minutes)
			return
		}
		if *verify {
			Verify(keys)
			return
		}
	}

	SmokeTest()
}
