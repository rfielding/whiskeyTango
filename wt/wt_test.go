package wt

import (
 "encoding/base64"
 "encoding/json"
 "math/big"
 "strings"
 "testing"
)

func TestCiphertextBinding(t *testing.T) {
 keys := &JWKeys{}
 if err := keys.AddRSA("binding-test", 2048, true); err != nil { t.Fatal(err) }
 token, err := CreateToken(keys, "binding-test", 2000000000, map[string]interface{}{"role":"reader"}, nil, "")
 if err != nil { t.Fatal(err) }
 trust := &JWKeys{}
 trust.Insert("binding-test", keys.KeyMap["binding-test"].Redact())
 claims, err := GetValidClaims(trust, 0, token)
 if err != nil || claims["role"] != "reader" { t.Fatalf("round trip: %v, %v", claims, err) }
 parts := strings.Split(token, ".")
 ciphertext, _ := base64.RawURLEncoding.DecodeString(parts[1])
 signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
 key := trust.KeyMap["binding-test"]
 witness := make([]byte, key.Bits/8-1)
 recovered := RSA(new(big.Int).SetBytes(signature), key.Eint, key.Nint)
 new(big.Int).Xor(recovered, new(big.Int).SetBytes(H(ciphertext))).FillBytes(witness)
 plaintext, _ := json.Marshal(map[string]interface{}{"role":"admin", "exp":2000000000, "kid":"binding-test"})
 replacement, err := Encrypt(witness[len(witness)-32:], plaintext)
 if err != nil { t.Fatal(err) }
 parts[1] = base64.RawURLEncoding.EncodeToString(replacement)
 if _, err := GetValidClaims(trust, 0, strings.Join(parts, ".")); err == nil { t.Fatal("accepted altered claims with reused signature") }
}
