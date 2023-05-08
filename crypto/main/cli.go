package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"github.com/wemixarchive/vrf-generator/crypto/vrf"
)

func main() {
	// Define and parse command-line flags
	privateKeyHex := flag.String("privateKey", "", "Private key in hexadecimal format (required)")
	message := flag.String("message", "", "Message to prove (required)")
	flag.Parse()

	// Check if both privateKey and message are provided
	if *privateKeyHex == "" || *message == "" {
		flag.PrintDefaults()
		return
	}

	// Decode private key from hexadecimal
	privateKeyBytes, err := hex.DecodeString(*privateKeyHex)
	if err != nil {
		log.Fatalf("Error decoding private key: %v", err)
	}

	// Generate public key from private key
	pk, sk, err := ed25519.GenerateKey(bytes.NewReader(privateKeyBytes))
	if err != nil {
		log.Fatalf("Error generating public key: %v", err)
	}
	// fmt.Println(">>> pk:", len(pk), hex.EncodeToString(pk)) // 32
	// fmt.Println(">>> sk:", len(sk), hex.EncodeToString(sk)) // 64

	// Call Prove() function with provided private key and message
	proof, hash, err := vrf.Prove(pk, sk, []byte(*message))
	if err != nil {
		log.Fatalf("Error generating proof: %v", err)
	}

	// Print results
	fmt.Printf("Proof: %x\n", proof)
	fmt.Printf("Hash: %x\n", hash)
}
