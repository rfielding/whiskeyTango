package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/rfielding/whiskeyTango/wt"
)

func SmokeTest() {
	// Create a new CA
	var err error
	keys := &wt.JWKeys{}
	kid1 := "usa:1234:1"
	kid2 := "usa:1234:2"
	keys.AddRSA(kid1)
	keys.AddRSA(kid2)
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
	smokeTestFlag := flag.Bool("smokeTest", false, "run a simple smoke test")
	makeCAFlag := flag.Bool("makeCA", false, "create a new CA")
	issueToken := flag.Bool("issueToken", false, "issue a token")
	flag.Parse()
	if *smokeTestFlag || (!*makeCAFlag && !*issueToken) {
		SmokeTest()
	}
}
