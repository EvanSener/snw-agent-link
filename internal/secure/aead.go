package secure

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

type KeyProvider interface {
	Key(context.Context) ([]byte, error)
}

type StaticKeyProvider []byte

func (provider StaticKeyProvider) Key(context.Context) ([]byte, error) {
	if len(provider) != 32 {
		return nil, errors.New("AES-256-GCM key must be 32 bytes")
	}
	return append([]byte(nil), provider...), nil
}

type AEAD struct {
	provider KeyProvider
}

func NewAEAD(provider KeyProvider) *AEAD {
	return &AEAD{provider: provider}
}

func (service *AEAD) Encrypt(ctx context.Context, plaintext, associatedData []byte) ([]byte, error) {
	gcm, err := service.gcm(ctx)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, associatedData), nil
}

func (service *AEAD) Decrypt(ctx context.Context, ciphertext, associatedData []byte) ([]byte, error) {
	gcm, err := service.gcm(ctx)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext is too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], associatedData)
	if err != nil {
		return nil, fmt.Errorf("decrypt sensitive field: %w", err)
	}
	return plaintext, nil
}

func (service *AEAD) gcm(ctx context.Context) (cipher.AEAD, error) {
	key, err := service.provider.Key(ctx)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return gcm, nil
}
