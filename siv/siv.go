// Package siv provides an implementation of the SIV-CMAC AEAD as described in
// RFC 5297. SIV-CMAC does not require a nonce, allowing for both deterministic
// and resistance to nonce re- or misuse.
package siv

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"hash"

	"github.com/ebfe/cmac"
)

// New returns a new SIV AEAD with the given key and encryption algorithm. The
// key must be 256, 384, or 512 bits long.
func New(key []byte, alg func([]byte) (cipher.Block, error)) (cipher.AEAD, error) {
	if len(key) != 32 && len(key) != 48 && len(key) != 64 {
		return nil, errInvalidKey
	}

	k1, k2 := key[:(len(key)/2)], key[(len(key)/2):]

	mac, err := alg(k1)
	if err != nil {
		return nil, err
	}

	enc, err := alg(k2)
	if err != nil {
		return nil, err
	}

	return &siv{
		enc: enc,
		mac: mac,
	}, nil
}

type siv struct {
	enc, mac cipher.Block
}

func (*siv) NonceSize() int {
	return 0
}

func (s *siv) Overhead() int {
	return s.mac.BlockSize()
}

func (s *siv) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	v, ciphertext := ciphertext[:s.enc.BlockSize()], ciphertext[s.enc.BlockSize():]
	plaintext := make([]byte, len(ciphertext))
	ctr := cipher.NewCTR(s.enc, ctr(v, s.enc.BlockSize()))
	ctr.XORKeyStream(plaintext, ciphertext)

	h, _ := cmac.NewWithCipher(s.mac)
	vP := s2v(h, data, nonce, plaintext)

	if subtle.ConstantTimeCompare(v, vP) != 1 {
		return nil, errOpen
	}

	return plaintext, nil
}

func (s *siv) Seal(dst, nonce, plaintext, data []byte) []byte {
	h, _ := cmac.NewWithCipher(s.mac)

	v := s2v(h, data, nonce, plaintext)

	ctr := cipher.NewCTR(s.enc, ctr(v, s.enc.BlockSize()))
	result := make([]byte, len(v)+len(plaintext))
	copy(result, v)
	ctr.XORKeyStream(result[len(v):], plaintext)

	return append(dst, result...)
}

var (
	errOpen       = errors.New("message authentication failed")
	errInvalidKey = errors.New("key must be 256, 384, or 512 bits long")
)

func ctr(v []byte, n int) []byte {
	q := make([]byte, len(v))
	copy(q, v)
	q[n-4] &= 0x7f
	q[n-8] &= 0x7f
	return q
}

func s2v(h hash.Hash, data ...[]byte) []byte {
	_, _ = h.Write(make([]byte, h.BlockSize()))
	d := h.Sum(nil)
	h.Reset()

	for _, v := range data[:len(data)-1] {
		if v == nil {
			continue
		}

		_, _ = h.Write(v)
		dbl(d)
		xor(d, h.Sum(nil))
		h.Reset()
	}

	v := data[len(data)-1]

	var t []byte
	if len(v) >= h.BlockSize() {
		t = xorend(v, d)
	} else {
		dbl(d)
		padded := pad(v, h.BlockSize())
		for i, v := range d {
			padded[i] ^= v
		}
		t = padded
	}

	_, _ = h.Write(t)
	return h.Sum(nil)
}

func dbl(b []byte) {
	shifted := (b[0] >> 7) == 1
	shiftLeft(b)
	if shifted {
		b[len(b)-1] ^= 0x87
	}
}

func shiftLeft(b []byte) {
	overflow := byte(0)
	for i := int(len(b) - 1); i >= 0; i-- {
		v := b[i]
		b[i] <<= 1
		b[i] |= overflow
		overflow = (v & 0x80) >> 7
	}
}

func xor(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func pad(b []byte, n int) []byte {
	padded := make([]byte, n)
	copy(padded, b)
	padded[n-2] = 0x80
	return padded
}

func xorend(a, b []byte) []byte {
	diff := len(a) - len(b)
	result := make([]byte, len(a))
	copy(result, a[:diff]) // leftmost
	if diff < len(b) {
		copy(result[len(b):], b[diff:]) // rightmost
	}
	for i := diff; i < len(a); i++ { // xor the middle
		result[i] = a[i] ^ b[i-diff]
	}
	return result
}
