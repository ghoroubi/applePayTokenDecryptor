package main

import (
	"crypto"
	"io"

	"golang.org/x/crypto/curve25519"
)

type curve25519ECDH struct {
	ECDH
}

// NewCurve25519ECDH creates a new ECDH instance that uses djb's curve25519
// elliptical curve.
func NewCurve25519ECDH() ECDH {
	return &curve25519ECDH{}
}

func (e *curve25519ECDH) GenerateKey(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	var publicKey, privateKey [32]byte
	var err error

	_, err = io.ReadFull(rand, privateKey[:])
	if err != nil {
		return nil, nil, err
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &privateKey, &publicKey, nil
}

func (e *curve25519ECDH) Marshal(p crypto.PublicKey) []byte {
	pub := p.(*[32]byte)
	return pub[:]
}

func (e *curve25519ECDH) Unmarshal(data []byte) (crypto.PublicKey, bool) {
	var pub [32]byte
	if len(data) != 32 {
		return nil, false
	}

	copy(pub[:], data)
	return &pub, true
}

func (e *curve25519ECDH) GenerateSharedSecret(private_key crypto.PrivateKey, public_key crypto.PublicKey) ([]byte, error) {
	var _private, _public, _secret *[32]byte

	_private = private_key.(*[32]byte)
	_public = public_key.(*[32]byte)
	_secret = new([32]byte)

	curve25519.ScalarMult(_secret, _private, _public)
	return _secret[:], nil
}
