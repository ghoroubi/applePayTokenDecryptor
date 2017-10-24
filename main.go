package main

import
(
	"crypto"


	"fmt"

	"crypto/rand"
)
type AppleSecretToken struct {
	PrivateKey crypto.PrivateKey
	PublicKey crypto.PublicKey
	SecretToken []byte
	ECDH
}
func main() {
	apple_key:=AppleSecretToken{}

	var err error

	var key1,key2 []byte
	var pri crypto.PrivateKey=rand.Reader
	var pub crypto.PublicKey=rand.Reader
/*	key1=apple_key.Marshal(pri)
	key2=apple_key.Marshal(pub)*/
	key1,err=apple_key.GenerateSharedSecret(pri,pub)
	if err!=nil {
		fmt.Println(err.Error())
	}
	fmt.Println(key1,key2)
}
/*
func GenerateSecretSharedKey(merchantPrivateKey, ephemeralPublicKey string)(string,error){
	var result string
	var err error

	return result,nil
}*/
