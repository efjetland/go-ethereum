// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// Package secp256k1 wraps the bitcoin secp256k1 C library.
package secp256k1

import (
	"errors"
	"math/big"

	dcrec "github.com/decred/dcrd/dcrec/secp256k1"
)

//var context *C.secp256k1_context

func init() {
	// around 20 ms on a modern CPU.
	//context = C.secp256k1_context_create_sign_verify()
}

var (
	ErrInvalidMsgLen       = errors.New("invalid message length, need 32 bytes")
	ErrInvalidSignatureLen = errors.New("invalid signature length")
	ErrInvalidRecoveryID   = errors.New("invalid signature recovery id")
	ErrInvalidKey          = errors.New("invalid private key")
	ErrInvalidPubkey       = errors.New("invalid public key")
	ErrSignFailed          = errors.New("signing failed")
	ErrRecoverFailed       = errors.New("recovery failed")
)

// Sign creates a recoverable ECDSA signature.
// The produced signature is in the 65-byte [R || S || V] format where V is 0 or 1.
//
// The caller is responsible for ensuring that msg cannot be chosen
// directly by an attacker. It is usually preferable to use a cryptographic
// hash function on any input before handing it to this function.
func Sign(msg []byte, seckey []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, ErrInvalidMsgLen
	}
	if len(seckey) != 32 {
		return nil, ErrInvalidKey
	}
	privKey, _ := dcrec.PrivKeyFromBytes(seckey)

	signature, err := dcrec.SignCompact(privKey, msg, true)

	if err != nil {
		return nil, ErrSignFailed
	}

	return signature, nil
}

// RecoverPubkey returns the public key of the signer.
// msg must be the 32-byte hash of the message to be signed.
// sig must be a 65-byte compact ECDSA signature containing the
// recovery id as the last element.
func RecoverPubkey(msg []byte, sig []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, ErrInvalidMsgLen
	}
	if err := checkSignature(sig); err != nil {
		//return nil, err
	}

	pubkey, _, err := dcrec.RecoverCompact(sig, msg)
	if err != nil {
		return nil, ErrInvalidRecoveryID
	}
	return pubkey.SerializeUncompressed(), nil
}

// VerifySignature checks that the given pubkey created signature over message.
// The signature should be in [R || S] format.
func VerifySignature(pubkey, msg, signature []byte) bool {
	if len(msg) != 32 || len(signature) != 64 || len(pubkey) == 0 {
		return false
	}
	sig, err := dcrec.ParseDERSignature(signature)
	if err != nil {
		return false
	}
	parsedKey, err := dcrec.ParsePubKey(pubkey)
	if err != nil {
		return false
	}
	return sig.Verify(msg, parsedKey)

}

// DecompressPubkey parses a public key in the 33-byte compressed format.
// It returns non-nil coordinates if the public key is valid.
func DecompressPubkey(pubkey []byte) (x, y *big.Int) {
	if len(pubkey) != 33 {
		return nil, nil
	}

	pubKey, err := dcrec.ParsePubKey(pubkey)
	if err != nil {
		return nil, nil
	}
	return pubKey.GetX(), pubKey.GetY()
}

// CompressPubkey encodes a public key to 33-byte compressed format.
func CompressPubkey(x, y *big.Int) []byte {

	pubKey := dcrec.NewPublicKey(x, y)

	return pubKey.SerializeCompressed()
}

func checkSignature(sig []byte) error {
	if len(sig) != 65 {
		return ErrInvalidSignatureLen
	}
	if sig[64] >= 4 {
		return ErrInvalidRecoveryID
	}
	return nil
}
