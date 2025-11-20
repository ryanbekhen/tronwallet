<p align="center">
  <span style="font-size:2.4em; font-weight:700;">TronWallet</span>
  <br/>
  <a href="README.md" style="margin-right:12px; text-decoration:none;">🇬🇧 English</a>
  <strong>· Bahasa Indonesia</strong>
  <br/>
  <img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/ryanbekhen/tronwallet/coverage-badge/.badges/coverage.json" alt="coverage"/>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/ryanbekhen/tronwallet?style=flat-square" alt="license"/></a>
</p>


TronWallet adalah pustaka Go ringan untuk membuat dan memulihkan dompet TRON (TRX) berbasis BIP39/BIP32/BIP44. Pustaka
ini menyediakan cara mudah untuk:

- Membuat mnemonic BIP39 (12 atau 24 kata)
- Memulihkan dompet dari mnemonic
- Menurunkan kunci privat (secp256k1) mengikuti path BIP44 untuk TRON (m/44'/195'/0'/0/index)
- Mengubah kunci privat menjadi alamat TRON (Base58)

## Fitur utama

- NewWallet(length ...) -> buat mnemonic baru (default 12 kata, juga mendukung 24 kata)
- RestoreWallet(mnemonic) -> validasi dan pemulihan dompet dari mnemonic
- (*TronWallet).Derive(index) -> turunkan kunci privat untuk indeks akun
- PrivateKeyToHex(priv) -> konversi kunci privat ke hex
- TronAddressFromPrivate(priv) -> konversi kunci privat ke alamat TRON (Base58)

## Contoh penggunaan

Contoh singkat ada di folder `example/generate`.

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

## Instalasi

Pastikan Go (versi 1.20+) terpasang. Tambahkan modul ini ke proyek Anda:

```bash
go get github.com/ryanbekhen/tronwallet
```

Atau gunakan modul dalam `go.mod` Anda:

```go
require github.com/ryanbekhen/tronwallet latest
```

Kemudian import dan gunakan seperti contoh di atas.

## API singkat

- type TronWallet
    - Mnemonic string
    - Seed []byte
- func NewWallet(length ...MnemonicLength) (*TronWallet, error)
- func RestoreWallet(mnemonic string) (*TronWallet, error)
- func (w *TronWallet) Derive(index uint32) (*ecdsa.PrivateKey, error)
- func PrivateKeyToHex(priv *ecdsa.PrivateKey) string
- func TronAddressFromPrivate(priv *ecdsa.PrivateKey) string

## Keamanan & Disclaimer

- Jangan pernah menyimpan mnemonic atau kunci privat dalam repositori publik.
- Kode contoh hanya untuk tujuan edukasi. Gunakan pustaka ini dengan hati-hati di lingkungan produksi.
- Penulis tidak bertanggung jawab atas kehilangan aset akibat penggunaan pustaka.

## Contributing

Kontribusi sangat dihargai — buka issue atau pull request. Beberapa pedoman:

- Tambahkan test untuk fitur baru.
- Ikuti gaya kode Go standar (gofmt).
- Jaga dependensi seminimal mungkin.

## Lisensi

Pustaka ini dilisensikan di bawah Lisensi MIT. Lihat file [LICENSE](LICENSE) untuk detail lebih lanjut.