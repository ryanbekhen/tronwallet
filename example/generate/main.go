package main

import (
	"fmt"

	"github.com/ryanbekhen/tronwallet"
)

// This example demonstrates creating a new TronWallet, deriving the first
// private key (index 0), and printing the mnemonic, private key hex, and
// corresponding Tron address.
func main() {
	w, _ := tronwallet.NewWallet()
	fmt.Println("Mnemonic:", w.Mnemonic)

	priv, _ := w.Derive(0)
	addr := tronwallet.TronAddressFromPrivate(priv)

	fmt.Println("Private (hex):", tronwallet.PrivateKeyToHex(priv))
	fmt.Println("Address:", addr)
}
