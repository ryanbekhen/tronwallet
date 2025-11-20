package tronwallet

import (
	"fmt"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestNewWallet_DefaultAnd24Words(t *testing.T) {
	w, err := NewWallet()
	if err != nil {
		t.Fatalf("NewWallet error: %v", err)
	}
	if len(strings.Split(w.Mnemonic, " ")) != 12 {
		t.Fatalf("expected 12 words, got %d", len(strings.Split(w.Mnemonic, " ")))
	}

	w2, err := NewWallet(Mnemonic24Words)
	if err != nil {
		t.Fatalf("NewWallet 24 error: %v", err)
	}
	if len(strings.Split(w2.Mnemonic, " ")) != 24 {
		t.Fatalf("expected 24 words, got %d", len(strings.Split(w2.Mnemonic, " ")))
	}
}

func TestRestoreWallet_ValidAndInvalid(t *testing.T) {
	w, err := RestoreWallet(testMnemonic)
	if err != nil {
		t.Fatalf("RestoreWallet error: %v", err)
	}
	if w.Mnemonic != testMnemonic {
		t.Fatalf("mnemonic mismatch")
	}

	_, err = RestoreWallet("invalid mnemonic phrase")
	if err == nil {
		t.Fatalf("expected error for invalid mnemonic")
	}
}

func TestWalletDeriveAndPrivateKeyHelpers(t *testing.T) {
	w, err := RestoreWallet(testMnemonic)
	if err != nil {
		t.Fatalf("RestoreWallet error: %v", err)
	}
	priv, err := w.Derive(0)
	if err != nil {
		t.Fatalf("Derive error: %v", err)
	}
	b := PrivateKeyToBytes(priv)
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
	h := PrivateKeyToHex(priv)
	if len(h) != 64 {
		t.Fatalf("expected hex length 64, got %d", len(h))
	}
}

func TestPrivateKeyToBytes_Padding(t *testing.T) {
	// create a private key whose D is small to force padding
	w, err := RestoreWallet(testMnemonic)
	if err != nil {
		t.Fatalf("RestoreWallet error: %v", err)
	}
	priv, err := w.Derive(0)
	if err != nil {
		t.Fatalf("Derive error: %v", err)
	}
	// artificially set D to small value by creating a new key from bytes with leading zeros
	b := PrivateKeyToBytes(priv)
	b[0] = 0x00
	// construct a key from the bytes via secp256k1 helper in bip32 (privkey->ecdsa)
	// We can reuse priv but it's hard to mutate D directly; instead test padding via PrivateKeyToBytes on a key with small D
	// Create a new ecdsa.PrivateKey by decoding via secp256k1
	pk := secp256k1.PrivKeyFromBytes(b).ToECDSA()
	pb := PrivateKeyToBytes(pk)
	if len(pb) != 32 {
		t.Fatalf("expected padded length 32, got %d", len(pb))
	}
}

func TestNewWallet_Bip39FailureInjection(t *testing.T) {
	origEntropy := bip39NewEntropyImpl
	origMnemonic := bip39NewMnemonicImpl
	defer func() { bip39NewEntropyImpl = origEntropy; bip39NewMnemonicImpl = origMnemonic }()

	bip39NewEntropyImpl = func(bits int) ([]byte, error) {
		return nil, fmt.Errorf("entropy failure")
	}
	_, err := NewWallet()
	if err == nil {
		t.Fatalf("expected error when entropy generation fails")
	}

	// now make entropy succeed but mnemonic fail
	bip39NewEntropyImpl = origEntropy
	bip39NewMnemonicImpl = func(ent []byte) (string, error) {
		return "", fmt.Errorf("mnemonic failure")
	}
	_, err = NewWallet()
	if err == nil {
		t.Fatalf("expected error when mnemonic generation fails")
	}
}
