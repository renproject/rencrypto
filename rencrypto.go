package rencrypto

import (
	"crypto"
	"hash"
)

type Decrypter interface {
	Marshal() ([]byte, error)
	Decrypt(msg []byte) ([]byte, error)
	Encrypter() Encrypter
}

type Encrypter interface {
	Marshal() ([]byte, error)
	Hash(hash.Hash) ([]byte, error)
	Encrypt(msg []byte) ([]byte, error)
	Public() crypto.PublicKey
}

type Signer interface {
	Marshal() ([]byte, error)
	Sign(msgHash []byte) ([]byte, error)
	Verifier() Verifier
}

type Verifier interface {
	Marshal() ([]byte, error)
	Hash(hash.Hash) ([]byte, error)
	Verify(sig []byte, msgHash []byte) error
	Public() crypto.PublicKey
}
