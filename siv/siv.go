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
// key must be twice the key size of the underlying algorithm.
func New(key []byte, alg func([]byte) (cipher.Block, error)) (cipher.AEAD, error) {
	mac, err := alg(key[:(len(key) / 2)])
	if err != nil {
		return nil, err
	}

	enc, err := alg(key[(len(key) / 2):])
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
	v, ciphertext := ciphertext[:s.Overhead()], ciphertext[s.Overhead():]
	plaintext := make([]byte, len(ciphertext))
	ctr := cipher.NewCTR(s.enc, ctr(v))
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

	ctr := cipher.NewCTR(s.enc, ctr(v))
	result := make([]byte, len(v)+len(plaintext))
	copy(result, v)
	ctr.XORKeyStream(result[len(v):], plaintext)

	return append(dst, result...)
}

var (
	errOpen = errors.New("message authentication failed")
)

func ctr(v []byte) []byte {
	q := make([]byte, len(v))
	copy(q, v)
	q[len(q)-4] &= 0x7f
	q[len(q)-8] &= 0x7f
	return q
}

func s2v(h hash.Hash, data ...[]byte) []byte {
	d := make([]byte, h.BlockSize())
	_, _ = h.Write(d)
	d = h.Sum(d[:0])
	h.Reset()

	for _, v := range data[:len(data)-1] {
		if v == nil {
			continue
		}

		dbl(d)

		_, _ = h.Write(v)

		for i, v := range h.Sum(nil) {
			d[i] ^= v
		}

		h.Reset()
	}

	v := data[len(data)-1]

	if len(v) >= h.BlockSize() {
		// xorend
		prefix := len(v) - len(d)
		_, _ = h.Write(v[:prefix])
		for i := range d {
			d[i] ^= v[prefix+i]
		}
		_, _ = h.Write(d)
	} else {
		dbl(d)

		// pad and xor
		for i, v := range v {
			d[i] ^= v
		}
		d[len(v)] ^= 0x80

		_, _ = h.Write(d)
	}

	return h.Sum(d[:0])
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
	for i := len(b) - 1; i >= 0; i-- {
		v := b[i]
		b[i] <<= 1
		b[i] |= overflow
		overflow = (v & 0x80) >> 7
	}
}
