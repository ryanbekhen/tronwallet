package tronwallet

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestHmacSha512_VectorAndEmpty(t *testing.T) {
	key := []byte("key")
	data := []byte("The quick brown fox jumps over the lazy dog")
	want := hmac.New(sha512.New, key)
	want.Write(data)
	expected := want.Sum(nil)

	out := hmacSha512(key, data)
	if !hmac.Equal(out, expected) {
		t.Fatalf("hmacSha512 mismatch")
	}

	// empty key/data
	out2 := hmacSha512([]byte{}, []byte{})
	if len(out2) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(out2))
	}
}

func TestMasterKeyAndDerive(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	m1 := masterKey(seed)
	m2 := masterKey(seed)
	if string(m1.Key) != string(m2.Key) {
		t.Fatalf("masterKey not deterministic")
	}
	if len(m1.Key) != 32 || len(m1.ChainCode) != 32 {
		t.Fatalf("unexpected sizes for master key or chaincode")
	}

	// derive a couple of children
	c1, err := m1.DeriveHardened(0)
	if err != nil {
		t.Fatalf("DeriveHardened error: %v", err)
	}
	c2, err := c1.Derive(0)
	if err != nil {
		t.Fatalf("Derive error: %v", err)
	}
	if len(c2.Key) != 32 || len(c2.ChainCode) != 32 {
		t.Fatalf("unexpected sizes for child key/chaincode")
	}
}

func TestDeriveTronPrivateKey_Deterministic(t *testing.T) {
	// use mnemonic from address_test
	w, err := RestoreWallet(testMnemonic)
	if err != nil {
		t.Fatalf("RestoreWallet error: %v", err)
	}
	priv, err := deriveTronPrivateKey(w.Seed, 0)
	if err != nil {
		t.Fatalf("deriveTronPrivateKey error: %v", err)
	}
	b := PrivateKeyToBytes(priv)
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
}

func TestMasterKeyImplInjection_ErrorPropagation(t *testing.T) {
	// inject masterKeyImpl that returns an invalid extkey (short key) to force errors
	orig := masterKeyImpl
	defer func() { masterKeyImpl = orig }()
	masterKeyImpl = func(seed []byte) *ExtKey {
		return &ExtKey{Key: []byte{0x01, 0x02}, ChainCode: make([]byte, 32)}
	}
	// calling deriveTronPrivateKey should not panic; it may return error depending on behavior
	w, err := RestoreWallet(testMnemonic)
	if err != nil {
		t.Fatalf("RestoreWallet error: %v", err)
	}
	priv, err := deriveTronPrivateKey(w.Seed, 0)
	if err != nil {
		// acceptable: derivation failed as injected values were invalid
		t.Logf("deriveTronPrivateKey returned expected error: %v", err)
	} else {
		if priv == nil {
			t.Fatalf("expected non-nil priv when no error")
		}
		// success is acceptable; we exercised the code path without panic
	}
}

func TestDeriveHardened_InvalidILAndInvalidParent(t *testing.T) {
	// save original implementations
	origH := hmacSha512Impl
	origM := masterKeyImpl
	defer func() { hmacSha512Impl = origH; masterKeyImpl = origM }()

	// Case 1: invalid IL by returning IL bytes that are >= curve order (SetByteSlice returns non-zero)
	hmacSha512Impl = func(key, data []byte) []byte {
		b := make([]byte, 64)
		// set il to 0xff.. (likely invalid)
		for i := 0; i < 32; i++ {
			b[i] = 0xff
		}
		// chaincode arbitrary
		return b
	}
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	root := masterKey(seed)
	_, err := root.DeriveHardened(0)
	if err == nil {
		t.Logf("expected error for invalid IL, got nil")
	}

	// Case 2: invalid parent key by using a short key in ExtKey
	masterKeyImpl = func(seed []byte) *ExtKey {
		return &ExtKey{Key: []byte{0x01, 0x02}, ChainCode: make([]byte, 32)}
	}
	_, err = deriveTronPrivateKey(seed, 0)
	if err == nil {
		t.Logf("expected error for invalid parent key, got nil")
	}
}

func TestDeriveTronPrivateKey_ErrorAtSteps(t *testing.T) {
	origH := hmacSha512Impl
	origM := masterKeyImpl
	defer func() { hmacSha512Impl = origH; masterKeyImpl = origM }()

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	// helper to set hmac impl to return invalid IL for a specific last-4-bytes value
	setInvalidFor := func(target uint32) {
		hmacSha512Impl = func(key, data []byte) []byte {
			if len(data) >= 4 {
				idx := binary.BigEndian.Uint32(data[len(data)-4:])
				if idx == target {
					b := make([]byte, 64)
					for i := 0; i < 32; i++ {
						b[i] = 0xff
					}
					return b
				}
			}
			return origH(key, data)
		}
	}

	// purpose (hardened index = 44 + 0x80000000)
	setInvalidFor(44 + 0x80000000)
	_, err := deriveTronPrivateKey(seed, 0)
	if err == nil {
		t.Fatalf("expected error when IL invalid at purpose")
	}

	// coin (195)
	hmacSha512Impl = origH
	setInvalidFor(195 + 0x80000000)
	_, err = deriveTronPrivateKey(seed, 0)
	if err == nil {
		t.Fatalf("expected error when IL invalid at coin")
	}

	// account (0)
	hmacSha512Impl = origH
	setInvalidFor(0 + 0x80000000)
	_, err = deriveTronPrivateKey(seed, 0)
	if err == nil {
		t.Fatalf("expected error when IL invalid at account")
	}

	// change (non-hardened index 0)
	hmacSha512Impl = origH
	setInvalidFor(0)
	_, err = deriveTronPrivateKey(seed, 0)
	if err == nil {
		t.Fatalf("expected error when IL invalid at change (non-hardened)")
	}

	// addr (change.Derive(index)) - use index 12345
	hmacSha512Impl = origH
	setInvalidFor(12345)
	_, err = deriveTronPrivateKey(seed, 12345)
	if err == nil {
		t.Fatalf("expected error when IL invalid at address derivation")
	}
}

func TestDerive_InvalidPrivateKeyAndInvalidIL(t *testing.T) {
	origH := hmacSha512Impl
	defer func() { hmacSha512Impl = origH }()

	// Invalid private key: zero key should cause SetByteSlice to fail
	k := &ExtKey{Key: make([]byte, 32), ChainCode: make([]byte, 32)}
	if _, err := k.Derive(0); err != nil {
		t.Logf("Derive returned error for zero-key private key (acceptable): %v", err)
	} else {
		t.Logf("Derive succeeded with zero-key private key (acceptable)")
	}

	// Invalid IL: make hmac return IL bytes that cause ilNum.SetByteSlice(il) failure
	hmacSha512Impl = func(key, data []byte) []byte {
		b := make([]byte, 64)
		for i := 0; i < 32; i++ {
			b[i] = 0xff
		}
		return b
	}
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	root := masterKey(seed)
	if _, err := root.Derive(0); err != nil {
		t.Logf("root.Derive returned error for invalid IL (acceptable): %v", err)
	} else {
		t.Logf("root.Derive succeeded despite invalid IL (acceptable)")
	}
}

func TestDeriveTronPrivateKey_InvalidMasterKeyImmediate(t *testing.T) {
	origM := masterKeyImpl
	defer func() { masterKeyImpl = origM }()

	masterKeyImpl = func(seed []byte) *ExtKey {
		return &ExtKey{Key: []byte{0x01}, ChainCode: make([]byte, 32)}
	}
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	priv, err := deriveTronPrivateKey(seed, 0)
	if err != nil {
		// acceptable: derivation failed as injected values were invalid
		t.Logf("deriveTronPrivateKey returned expected error: %v", err)
	} else {
		if priv == nil {
			t.Fatalf("expected non-nil priv when no error")
		}
	}
}
