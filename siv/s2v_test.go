package siv

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ebfe/cmac"
)

func TestS2V(t *testing.T) {
	// https://tools.ietf.org/html/rfc5297#appendix-A.2

	key, _ := hex.DecodeString("7f7e7d7c7b7a79787776757473727170")
	ad1, _ := hex.DecodeString("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100")
	ad2, _ := hex.DecodeString("102030405060708090a0")
	nonce, _ := hex.DecodeString("09f911029d74e35bd84156c5635688c0")
	plaintext, _ := hex.DecodeString("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553")
	expected, _ := hex.DecodeString("7bdb6e3b432667eb06f4d14bff2fbd0f") // CMAC(final)

	h, _ := cmac.New(key)
	actual := s2v(h, ad1, ad2, nonce, plaintext)

	if !bytes.Equal(actual, expected) {
		t.Errorf("S2V was %x, but expected %x", actual, expected)
	}
}
