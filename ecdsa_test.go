package rencrypto_test

import (
	"crypto/rand"
	"reflect"
	"testing/quick"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/rencrypto"

	"github.com/ethereum/go-ethereum/crypto"
)

var _ = Describe("ECDSA", func() {
	Context("when marshalling and unmarshalling the encryptor", func() {
		It("should not change", func() {
			Expect(quick.Check(func() bool {
				key, err := crypto.GenerateKey()
				Expect(err).Should(BeNil())
				verifier, err := NewECDSAVerifier(key)
				Expect(err).Should(BeNil())
				data, err := verifier.Marshal()
				Expect(err).Should(BeNil())
				verifier2, err := NewECDSAVerifier(data)
				Expect(err).Should(BeNil())
				data2, err := verifier2.Marshal()
				Expect(err).Should(BeNil())
				return reflect.DeepEqual(data, data2)
			}, &quick.Config{
				MaxCount: 8,
			})).Should(BeNil())
		})

		It("should be able to encrypt a message", func() {
			Expect(quick.Check(func() bool {
				key, err := crypto.GenerateKey()
				Expect(err).Should(BeNil())
				hash := [32]byte{}
				rand.Read(hash[:])
				sig, err := crypto.Sign(hash[:], key)
				Expect(err).Should(BeNil())
				verifier, err := NewECDSAVerifier(key)
				Expect(err).Should(BeNil())
				data, err := verifier.Marshal()
				Expect(err).Should(BeNil())
				Expect(verifier.Verify(sig, hash[:])).Should(BeNil())
				verifier2, err := NewECDSAVerifier(data)
				Expect(err).Should(BeNil())
				Expect(verifier2.Verify(sig, hash[:])).Should(BeNil())
				return true
			}, &quick.Config{
				MaxCount: 8,
			})).Should(BeNil())
		})
	})

	Context("when marshalling and unmarshalling the decryptor", func() {
		It("should not change", func() {
			Expect(quick.Check(func() bool {
				key, err := crypto.GenerateKey()
				Expect(err).Should(BeNil())
				decryptor, err := NewECDSASigner(key)
				Expect(err).Should(BeNil())
				data, err := decryptor.Marshal()
				Expect(err).Should(BeNil())
				decryptor2, err := NewECDSASigner(data)
				Expect(err).Should(BeNil())
				data2, err := decryptor2.Marshal()
				Expect(err).Should(BeNil())
				return reflect.DeepEqual(data, data2)
			}, &quick.Config{
				MaxCount: 8,
			})).Should(BeNil())
		})

		It("should be able to decrypt a message", func() {
			Expect(quick.Check(func() bool {
				key, err := crypto.GenerateKey()
				Expect(err).Should(BeNil())
				signer, err := NewECDSASigner(key)
				Expect(err).Should(BeNil())
				hash := [32]byte{}
				rand.Read(hash[:])
				data, err := signer.Marshal()
				Expect(err).Should(BeNil())
				sig, err := signer.Sign(hash[:])
				Expect(err).Should(BeNil())
				signer2, err := NewECDSASigner(data)
				Expect(err).Should(BeNil())
				sig1, err := signer2.Sign(hash[:])
				Expect(err).Should(BeNil())
				Expect(signer.Verifier().Verify(sig, hash[:])).Should(BeNil())
				Expect(signer.Verifier().Verify(sig1, hash[:])).Should(BeNil())
				return true
			}, &quick.Config{
				MaxCount: 8,
			})).Should(BeNil())
		})
	})
})
