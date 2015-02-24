package siv

import (
	"bytes"
	"testing"
)

func TestXorend(t *testing.T) {
	a := []byte{0xf0, 0xaa, 0x00}
	b := []byte{0xf0, 0x0f}
	expected := []byte{0xf0, 0x5a, 0x0f}

	actual := xorend(a, b)

	if !bytes.Equal(expected, actual) {
		t.Errorf("Was %x, but expected %x", actual, expected)
	}
}
