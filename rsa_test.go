package rencrypto_test

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing/quick"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/rencrypto"
)

var _ = Describe("RSA", func() {
	Context("when marshalling and unmarshalling the encrypter", func() {
		It("should not change", func() {
			Expect(quick.Check(func() bool {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).Should(BeNil())
				encrypter, err := NewRSAEncrypter(key)
				Expect(err).Should(BeNil())
				data, err := encrypter.Marshal()
				Expect(err).Should(BeNil())
				encrypter2, err := NewRSAEncrypter(data)
				Expect(err).Should(BeNil())
				data2, err := encrypter2.Marshal()
				Expect(err).Should(BeNil())
				return reflect.DeepEqual(data, data2)
			}, &quick.Config{
				MaxCount: 8,
			})).Should(BeNil())
		})

		It("should be able to encrypt a message", func() {
			Expect(quick.Check(func() bool {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).Should(BeNil())
				encrypter, err := NewRSAEncrypter(key)
				Expect(err).Should(BeNil())
				data, err := encrypter.Marshal()
				Expect(err).Should(BeNil())
				_, err = encrypter.Encrypt([]byte("Secret"))
				Expect(err).Should(BeNil())
				encrypter2, err := NewRSAEncrypter(data)
				Expect(err).Should(BeNil())
				_, err = encrypter2.Encrypt([]byte("Secret"))
				Expect(err).Should(BeNil())
				return true
			}, &quick.Config{
				MaxCount: 8,
			})).Should(BeNil())
		})
	})

	Context("when marshalling and unmarshalling the decrypter", func() {
		It("should not change", func() {
			Expect(quick.Check(func() bool {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).Should(BeNil())
				decrypter, err := NewRSADecrypter(key)
				Expect(err).Should(BeNil())
				data, err := decrypter.Marshal()
				Expect(err).Should(BeNil())
				decrypter2, err := NewRSADecrypter(data)
				Expect(err).Should(BeNil())
				data2, err := decrypter2.Marshal()
				Expect(err).Should(BeNil())
				return reflect.DeepEqual(data, data2)
			}, &quick.Config{
				MaxCount: 8,
			})).Should(BeNil())
		})

		It("should be able to decrypt a message", func() {
			Expect(quick.Check(func() bool {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).Should(BeNil())
				decrypter, err := NewRSADecrypter(key)
				Expect(err).Should(BeNil())
				cipherText, err := decrypter.Encrypter().Encrypt([]byte("Secret"))
				Expect(err).Should(BeNil())
				data, err := decrypter.Marshal()
				Expect(err).Should(BeNil())
				data1, err := decrypter.Decrypt(cipherText)
				Expect(err).Should(BeNil())
				decrypter2, err := NewRSADecrypter(data)
				Expect(err).Should(BeNil())
				data2, err := decrypter2.Decrypt(cipherText)
				Expect(err).Should(BeNil())
				return reflect.DeepEqual(data1, data2)
			}, &quick.Config{
				MaxCount: 8,
			})).Should(BeNil())
		})
	})
})
