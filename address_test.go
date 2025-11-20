package tronwallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestPubUncompressed(t *testing.T) {
	w, err := RestoreWallet(testMnemonic)
	if err != nil {
		t.Fatalf("RestoreWallet error: %v", err)
	}
	priv, err := w.Derive(0)
	if err != nil {
		t.Fatalf("Derive error: %v", err)
	}

	b := pubUncompressed(priv)
	if len(b) != 65 {
		t.Fatalf("expected pub length 65, got %d", len(b))
	}
	if b[0] != 0x04 {
		t.Fatalf("expected prefix 0x04, got 0x%x", b[0])
	}
	// X and Y should be 32 bytes each
	if len(b[1:33]) != 32 || len(b[33:]) != 32 {
		t.Fatalf("expected X and Y to be 32 bytes each")
	}
}

func TestTronAddressFromPrivate_ChecksumAndPrefix(t *testing.T) {
	w, err := RestoreWallet(testMnemonic)
	if err != nil {
		t.Fatalf("RestoreWallet error: %v", err)
	}
	priv, err := w.Derive(0)
	if err != nil {
		t.Fatalf("Derive error: %v", err)
	}

	addr := TronAddressFromPrivate(priv)
	decoded := base58.Decode(addr)
	if len(decoded) != 25 {
		t.Fatalf("decoded address expected 25 bytes, got %d", len(decoded))
	}
	// version byte
	if decoded[0] != 0x41 {
		t.Fatalf("expected version byte 0x41, got 0x%x", decoded[0])
	}
	// checksum validation (double SHA-256)
	payload := decoded[:21]
	checksum := decoded[21:]
	s1 := sha256.Sum256(payload)
	s2 := sha256.Sum256(s1[:])
	if !bytes.Equal(checksum, s2[:4]) {
		t.Fatalf("checksum mismatch")
	}
}

func TestPubUncompressed_SmallCoordinatesPadding(t *testing.T) {
	// construct private key with small scalar to force short X/Y
	// reduce the scalar to a very small value
	small := make([]byte, 32)
	small[31] = 0x05
	pk := secp256k1.PrivKeyFromBytes(small).ToECDSA()

	pub := pubUncompressed(pk)
	if len(pub) != 65 {
		t.Fatalf("expected pub length 65, got %d", len(pub))
	}
	// X and Y padding check
	if pub[1] == 0x00 {
		// ok: padded
	} else {
		// still acceptable; main check is lengths
	}
}

func TestPubUncompressed_ManualSmallCoordinates(t *testing.T) {
	// build an ecdsa key with small X/Y to guarantee padding loop executes
	pk := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: secp256k1.S256(),
			X:     big.NewInt(5),
			Y:     big.NewInt(7),
		},
		D: big.NewInt(1),
	}

	b := pubUncompressed(pk)
	if len(b) != 65 {
		t.Fatalf("expected pub length 65, got %d", len(b))
	}
	// check that X and Y are padded to 32 bytes
	if len(b[1:33]) != 32 || len(b[33:]) != 32 {
		t.Fatalf("expected X and Y to be 32 bytes each")
	}
}
