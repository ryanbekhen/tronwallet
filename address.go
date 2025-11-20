package tronwallet

import (
	"crypto/ecdsa"
	"crypto/sha256"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/sha3"
)

// TronAddressFromPrivate returns the Base58-encoded Tron address for the
// provided ECDSA private key. The function computes the uncompressed public
// key, hashes the X||Y bytes with Keccak-256, takes the last 20 bytes, prefixes
// with the Tron version byte 0x41, appends a 4-byte checksum (double SHA-256),
// and encodes the result with Base58.
func TronAddressFromPrivate(priv *ecdsa.PrivateKey) string {
	pub := pubUncompressed(priv)

	h := sha3.NewLegacyKeccak256()
	h.Write(pub[1:]) // skip 0x04
	digest := h.Sum(nil)

	raw := append([]byte{0x41}, digest[12:]...)

	sum1 := sha256.Sum256(raw)
	sum2 := sha256.Sum256(sum1[:])

	full := append(raw, sum2[:4]...)
	return base58.Encode(full)
}

// pubUncompressed returns the uncompressed public key bytes for the given
// private key in the format 0x04 || X || Y, where X and Y are 32-byte big-endian
// coordinates. This utility pads coordinates with leading zeros if necessary.
func pubUncompressed(priv *ecdsa.PrivateKey) []byte {
	x := priv.PublicKey.X.Bytes()
	y := priv.PublicKey.Y.Bytes()

	for len(x) < 32 {
		x = append([]byte{0x00}, x...)
	}
	for len(y) < 32 {
		y = append([]byte{0x00}, y...)
	}

	return append([]byte{0x04}, append(x, y...)...)
}
