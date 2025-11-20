package tronwallet

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// add test seams for bip39 functions
var bip39NewEntropyImpl = bip39.NewEntropy
var bip39NewMnemonicImpl = bip39.NewMnemonic

type MnemonicLength int

const (
	Mnemonic12Words MnemonicLength = 12
	Mnemonic24Words MnemonicLength = 24
)

// TronWallet represents a TRON wallet with a mnemonic and seed.
type TronWallet struct {
	// Mnemonic is the BIP39 mnemonic phrase for the wallet.
	Mnemonic string
	// Seed is the binary seed derived from the mnemonic (BIP39 seed).
	Seed []byte
}

// NewWallet creates a new TronWallet with a randomly generated mnemonic.
// The optional length argument can be used to request a 12- or 24-word
// mnemonic (default is 12 words).
func NewWallet(length ...MnemonicLength) (*TronWallet, error) {
	l := Mnemonic12Words
	if len(length) > 0 {
		l = length[0]
	}

	entropyBits := 128
	if l == Mnemonic24Words {
		entropyBits = 256
	}

	entropy, err := bip39NewEntropyImpl(entropyBits)
	if err != nil {
		return nil, err
	}

	mn, err := bip39NewMnemonicImpl(entropy)
	if err != nil {
		return nil, err
	}

	seed := bip39.NewSeed(mn, "")
	return &TronWallet{Mnemonic: mn, Seed: seed}, nil
}

// RestoreWallet validates a BIP39 mnemonic string and returns the corresponding
// TronWallet with the derived seed.
func RestoreWallet(mnemonic string) (*TronWallet, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("invalid mnemonic")
	}
	seed := bip39.NewSeed(mnemonic, "")
	return &TronWallet{Mnemonic: mnemonic, Seed: seed}, nil
}

// Derive returns the ECDSA private key for the given account index following
// the Tron/BIP44 derivation implemented in deriveTronPrivateKey.
func (w *TronWallet) Derive(index uint32) (*ecdsa.PrivateKey, error) {
	return deriveTronPrivateKey(w.Seed, index)
}

// PrivateKeyToBytes returns the 32-byte big-endian representation of the
// private key's D value, left-padded with zeros if necessary.
func PrivateKeyToBytes(priv *ecdsa.PrivateKey) []byte {
	b := priv.D.Bytes()
	if len(b) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		return padded
	}
	return b
}

// PrivateKeyToHex returns the hexadecimal encoding of the private key.
func PrivateKeyToHex(priv *ecdsa.PrivateKey) string {
	return fmt.Sprintf("%x", PrivateKeyToBytes(priv))
}
