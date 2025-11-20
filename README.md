# TronWallet

TronWallet is a small Go library for creating and restoring TRON (TRX) wallets using BIP39/BIP32/BIP44. The library provides simple helpers to:

- Generate a BIP39 mnemonic (12 or 24 words)
- Restore a wallet from a mnemonic
- Derive a secp256k1 private key using the BIP44 path for TRON (m/44'/195'/0'/0/index)
- Convert a private key into a TRON address (Base58)

## Key features

- `NewWallet(length ...)` — create a new mnemonic wallet (default 12 words; 24 words supported)
- `RestoreWallet(mnemonic)` — validate and restore a wallet from a mnemonic
- `(*TronWallet).Derive(index)` — derive the private key for an account index
- `PrivateKeyToHex(priv)` — convert a private key to a hex string
- `TronAddressFromPrivate(priv)` — convert a private key to a TRON address (Base58)

## Example

A short example is available under `example/generate`.

```go
package main

import (
    "fmt"

    "github.com/ryanbekhen/tronwallet"
)

func main() {
    w, _ := tronwallet.NewWallet()
    fmt.Println("Mnemonic:", w.Mnemonic)

    priv, _ := w.Derive(0)
    addr := tronwallet.TronAddressFromPrivate(priv)

    fmt.Println("Private (hex):", tronwallet.PrivateKeyToHex(priv))
    fmt.Println("Address:", addr)
}
```

## Installation

Make sure you have Go (1.20+) installed. Add this module to your project:

```bash
go get github.com/ryanbekhen/tronwallet
```

Or add it to your `go.mod`:

```go
require github.com/ryanbekhen/tronwallet latest
```

Then import and use the library as shown in the example.

## API Overview

- type `TronWallet`
  - `Mnemonic string`
  - `Seed []byte`
- `func NewWallet(length ...MnemonicLength) (*TronWallet, error)`
- `func RestoreWallet(mnemonic string) (*TronWallet, error)`
- `func (w *TronWallet) Derive(index uint32) (*ecdsa.PrivateKey, error)`
- `func PrivateKeyToHex(priv *ecdsa.PrivateKey) string`
- `func TronAddressFromPrivate(priv *ecdsa.PrivateKey) string`

## Security & Disclaimer

- Never store mnemonics or private keys in public repositories.
- Example code is provided for educational purposes only. Use this library with caution in production.
- The author is not responsible for any loss resulting from using this library.

## Contributing

Contributions are welcome — please open an issue or a pull request. A few guidelines:

- Add tests for new features.
- Follow Go formatting (`gofmt`).
- Keep dependencies minimal.

## License

This library is released under the MIT License. See [LICENSE](LICENSE) for details.

