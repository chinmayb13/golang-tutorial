package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"log"
)

func DF_exchange() {
	clientCurve := ecdh.P256()
	clientPrivKey, err := clientCurve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	clientPubKey := clientPrivKey.PublicKey()

	serverCurve := ecdh.P256()
	serverPrivKey, err := serverCurve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serverPubKey := serverPrivKey.PublicKey()

	clientSecret, err := clientPrivKey.ECDH(serverPubKey)
	if err != nil {
		log.Fatal(err)
	}

	serverSecret, err := serverPrivKey.ECDH(clientPubKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(serverSecret)

	ExampleNewGCMEncrypter(clientSecret)
}

func ExampleNewGCMEncrypter( key []byte) {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	//key := []byte("AES256Key-32Characters1234567890")
	plaintext := []byte("exampleplaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("%x\n", ciphertext)
}
