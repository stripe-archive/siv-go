package siv

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func TestBadKeySize(t *testing.T) {
	aead, err := New(make([]byte, 16), aes.NewCipher)
	if err == nil {
		t.Fatalf("AEAD returned instead of error: %v", aead)
	}
}

func TestNoNonceRequired(t *testing.T) {
	aead, _ := New(make([]byte, 32), aes.NewCipher)

	if v, want := aead.NonceSize(), 0; v != want {
		t.Errorf("Nonce size was %d, but expected %d", v, want)
	}
}

func TestOverhead(t *testing.T) {
	aead, _ := New(make([]byte, 32), aes.NewCipher)

	if v, want := aead.Overhead(), aes.BlockSize; v != want {
		t.Errorf("Overhead was %d, but expected %d", v, want)
	}
}

func TestDeterministicEncryption(t *testing.T) {
	// https://tools.ietf.org/html/rfc5297#appendix-A.1
	key, _ := hex.DecodeString("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	data, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f2021222324252627")
	plaintext, _ := hex.DecodeString("112233445566778899aabbccddee")
	ciphertext, _ := hex.DecodeString("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")

	aead, err := New(key, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}

	actual := aead.Seal(nil, nil, plaintext, data)
	if !bytes.Equal(actual, ciphertext) {
		t.Errorf("Ciphertext was %x, but expected %x", actual, ciphertext)
	}
}

func TestRoundTrip(t *testing.T) {
	key, _ := hex.DecodeString("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	data, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f2021222324252627")
	plaintext, _ := hex.DecodeString("112233445566778899aabbccddee")

	aead, err := New(key, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := aead.Seal(nil, nil, plaintext, data)

	actual, err := aead.Open(nil, nil, ciphertext, data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(actual, plaintext) {
		t.Errorf("Plaintext was %x, but expected %x", actual, plaintext)
	}
}

func TestRoundTripBadData(t *testing.T) {
	key, _ := hex.DecodeString("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	data, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f2021222324252627")
	plaintext, _ := hex.DecodeString("112233445566778899aabbccddee")

	aead, err := New(key, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := aead.Seal(nil, nil, plaintext, data)

	data[0] ^= 1

	actual, err := aead.Open(nil, nil, ciphertext, data)
	if err == nil {
		t.Fatalf("Plaintext returned instead of error: %x", actual)
	}
}

func TestRoundTripBadCiphertext(t *testing.T) {
	key, _ := hex.DecodeString("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	data, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f2021222324252627")
	plaintext, _ := hex.DecodeString("112233445566778899aabbccddee")

	aead, err := New(key, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := aead.Seal(nil, nil, plaintext, data)

	ciphertext[0] ^= 1

	actual, err := aead.Open(nil, nil, ciphertext, data)
	if err == nil {
		t.Fatalf("Plaintext returned instead of error: %x", actual)
	}
}

func BenchmarkSeal(b *testing.B) {
	key, _ := hex.DecodeString("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	data, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f2021222324252627")
	plaintext := make([]byte, 1024)

	aead, err := New(key, aes.NewCipher)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(1024)

	for i := 0; i < b.N; i++ {
		aead.Seal(nil, nil, plaintext, data)
	}
}
