package rencrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"hash"

	ethCrypto "github.com/ethereum/go-ethereum/crypto"
)

type ecdsaSigner struct {
	privKey *ecdsa.PrivateKey
}

type ecdsaVerifier struct {
	pubKey *ecdsa.PublicKey
}

func NewECDSASigner(key interface{}) (Signer, error) {
	var privKey *ecdsa.PrivateKey
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		privKey = key
	case ecdsa.PrivateKey:
		privKey = &key
	case []byte:
		k, err := ethCrypto.ToECDSA(key)
		if err != nil {
			return nil, err
		}
		privKey = k
	case string:
		k, err := ethCrypto.HexToECDSA(key)
		if err != nil {
			return nil, err
		}
		privKey = k
	default:
		return nil, fmt.Errorf("unknown type: %T cannot convert into an ECDSA signer", key)
	}
	return &ecdsaSigner{
		privKey: privKey,
	}, nil
}

func (signer *ecdsaSigner) Sign(msgHash []byte) ([]byte, error) {
	return ethCrypto.Sign(msgHash, signer.privKey)
}

func (signer *ecdsaSigner) Marshal() ([]byte, error) {
	return ethCrypto.FromECDSA(signer.privKey), nil
}

func (signer *ecdsaSigner) Verifier() Verifier {
	return &ecdsaVerifier{pubKey: &signer.privKey.PublicKey}
}

func NewECDSAVerifier(key interface{}) (Verifier, error) {
	var pubKey *ecdsa.PublicKey
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		pubKey = key
	case ecdsa.PublicKey:
		pubKey = &key
	case *ecdsa.PrivateKey:
		pubKey = &key.PublicKey
	case ecdsa.PrivateKey:
		pubKey = &key.PublicKey
	case []byte:
		x, y := elliptic.Unmarshal(ethCrypto.S256(), key)
		pubKey = &ecdsa.PublicKey{
			Curve: ethCrypto.S256(),
			X:     x,
			Y:     y,
		}
	case string:
		keyBytes, err := hex.DecodeString(key)
		if err != nil {
			return nil, err
		}
		x, y := elliptic.Unmarshal(ethCrypto.S256(), keyBytes)
		pubKey = &ecdsa.PublicKey{
			Curve: ethCrypto.S256(),
			X:     x,
			Y:     y,
		}
	default:
		return nil, fmt.Errorf("unknown type: %T cannot convert into an ECDSA signer", key)
	}
	return &ecdsaVerifier{
		pubKey: pubKey,
	}, nil
}

func (verifier *ecdsaVerifier) Marshal() ([]byte, error) {
	return ethCrypto.FromECDSAPub(verifier.pubKey), nil
}

func (verifier *ecdsaVerifier) Verify(sig, msgHash []byte) error {
	return ECDSAVerify(sig, msgHash, func(pubKey *ecdsa.PublicKey) error {
		pubKeyBytes, err := verifier.Marshal()
		if err != nil {
			return err
		}
		sigPubKeyBytes := ethCrypto.FromECDSAPub(pubKey)
		if !bytes.Equal(pubKeyBytes, sigPubKeyBytes) {
			return fmt.Errorf("invalid signature: pubkey generated from sig" +
				"does not match the current pubkey")
		}
		return nil
	})
}

func (verifier *ecdsaVerifier) Public() crypto.PublicKey {
	return verifier.pubKey
}

func (verifier *ecdsaVerifier) Hash(hash hash.Hash) ([]byte, error) {
	data, err := verifier.Marshal()
	if err != nil {
		return nil, err
	}
	return hash.Sum(data), nil
}

func ECDSAVerify(sig, msgHash []byte, checker func(*ecdsa.PublicKey) error) error {
	pubKey, err := ethCrypto.SigToPub(msgHash, sig)
	if err != nil {
		return err
	}
	return checker(pubKey)
}
