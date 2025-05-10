package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

func generateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt data using AES-GCM
func encryptAES(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt data using AES-GCM

var ErrCiphertextTooShort = errors.New("ciphertext too short")

func decryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

var ErrUnsupportedKeyType = errors.New("unsupported key type")

func rsaEncrypt(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		plaintext,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// RSA decryption
func rsaDecrypt(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		ciphertext,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func marshalPrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	der := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func unmarshalPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block with type 'RSA PRIVATE KEY'")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func marshalPublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func unmarshalPublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block with type 'PUBLIC KEY'")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}
	return rsaPub, nil
}
