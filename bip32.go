package tronwallet

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ExtKey represents an extended key (private key and chain code) used in BIP32
// hierarchical deterministic wallets.
type ExtKey struct {
	Key       []byte
	ChainCode []byte
}

// hmacSha512 returns HMAC-SHA512(key, data).
func hmacSha512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// allow tests to override hmac behavior
var hmacSha512Impl = hmacSha512

// masterKey derives the master extended key from a BIP39 seed using the
// HMAC-SHA512 key "Bitcoin seed" as specified by BIP32.
func masterKey(seed []byte) *ExtKey {
	I := hmacSha512Impl([]byte("Bitcoin seed"), seed)
	k := make([]byte, 32)
	cc := make([]byte, 32)
	copy(k, I[:32])
	copy(cc, I[32:])
	return &ExtKey{Key: k, ChainCode: cc}
}

// allow tests to override masterKey behavior
var masterKeyImpl = masterKey

// DeriveHardened derives the i-th hardened child extended key from k.
// It follows BIP32 hardened derivation where the index is i + 0x80000000.
func (k *ExtKey) DeriveHardened(i uint32) (*ExtKey, error) {
	data := make([]byte, 0, 1+32+4)
	data = append(data, 0x00)
	data = append(data, k.Key...)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i+0x80000000)
	data = append(data, buf...)

	I := hmacSha512Impl(k.ChainCode, data)
	il := I[:32]
	ir := I[32:]

	parent := new(secp256k1.ModNScalar)
	if parent.SetByteSlice(k.Key) {
		return nil, errors.New("invalid parent key")
	}

	ilNum := new(secp256k1.ModNScalar)
	if ilNum.SetByteSlice(il) {
		return nil, errors.New("invalid IL")
	}

	child := new(secp256k1.ModNScalar)
	child.Set(parent)
	child.Add(ilNum)

	childArr := child.Bytes()
	childSlice := make([]byte, 32)
	copy(childSlice, childArr[:])

	chainCode := make([]byte, 32)
	copy(chainCode, ir)

	return &ExtKey{Key: childSlice, ChainCode: chainCode}, nil
}

// Derive derives the i-th non-hardened child extended key from k using the
// public key and the chain code as specified by BIP32.
func (k *ExtKey) Derive(i uint32) (*ExtKey, error) {
	privNum := new(secp256k1.ModNScalar)
	if privNum.SetByteSlice(k.Key) {
		return nil, errors.New("invalid private key")
	}

	pub := secp256k1.NewPrivateKey(privNum).PubKey().SerializeUncompressed()

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i)
	data := append(pub, buf...)

	I := hmacSha512Impl(k.ChainCode, data)
	il := I[:32]
	ir := I[32:]

	ilNum := new(secp256k1.ModNScalar)
	if ilNum.SetByteSlice(il) {
		return nil, errors.New("invalid IL")
	}

	child := new(secp256k1.ModNScalar)
	child.Set(privNum)
	child.Add(ilNum)

	childArr := child.Bytes()
	childSlice := make([]byte, 32)
	copy(childSlice, childArr[:])

	chainCode := make([]byte, 32)
	copy(chainCode, ir)

	return &ExtKey{Key: childSlice, ChainCode: chainCode}, nil
}

// deriveTronPrivateKey derives a Tron-compatible secp256k1 ECDSA private key
// from the given BIP39 seed using the BIP44 path m/44'/195'/0'/0/index.
func deriveTronPrivateKey(seed []byte, index uint32) (*ecdsa.PrivateKey, error) {
	root := masterKeyImpl(seed)
	purpose, err := root.DeriveHardened(44)
	if err != nil {
		return nil, err
	}
	coin, err := purpose.DeriveHardened(195)
	if err != nil {
		return nil, err
	}
	account, err := coin.DeriveHardened(0)
	if err != nil {
		return nil, err
	}
	change, err := account.Derive(0)
	if err != nil {
		return nil, err
	}
	addr, err := change.Derive(index)
	if err != nil {
		return nil, err
	}

	priv := secp256k1.PrivKeyFromBytes(addr.Key)
	return priv.ToECDSA(), nil
}
