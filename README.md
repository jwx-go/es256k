# es256k

ES256K (secp256k1) extension for [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

This module adds ES256K digital signature support to jwx, enabling the secp256k1 elliptic curve and ES256K signature algorithm for use in JWK, JWS, and JWT operations. The secp256k1 curve is widely used in blockchain applications (Bitcoin, Ethereum).

## Installation

```
go get github.com/jwx-go/es256k/v4
```

## Usage

Import this package to register ES256K with jwx:

```go
import _ "github.com/jwx-go/es256k/v4"
```

This registers:

- **Elliptic curve**: secp256k1
- **Signature algorithm**: ES256K
- **JWS signing/verification** using ES256K

### Sign and verify with raw keys

```go
import (
    "crypto/ecdsa"
    "crypto/rand"

    "github.com/decred/dcrd/dcrec/secp256k1/v4"
    "github.com/jwx-go/es256k/v4"
    "github.com/lestrrat-go/jwx/v4/jws"
)

key, _ := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
signed, _ := jws.Sign(payload, jws.WithKey(es256k.ES256K(), key))
verified, _ := jws.Verify(signed, jws.WithKey(es256k.ES256K(), &key.PublicKey))
```

### Sign and verify with JWK keys

```go
import (
    "crypto/ecdsa"
    "crypto/rand"

    "github.com/decred/dcrd/dcrec/secp256k1/v4"
    "github.com/jwx-go/es256k/v4"
    "github.com/lestrrat-go/jwx/v4/jwk"
    "github.com/lestrrat-go/jwx/v4/jws"
)

key, _ := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
jwkKey, _ := jwk.Import[jwk.Key](&key.PublicKey)

signed, _ := jws.Sign(payload, jws.WithKey(es256k.ES256K(), key))
verified, _ := jws.Verify(signed, jws.WithKey(es256k.ES256K(), jwkKey))
```

## Signature Malleability (low-S)

ES256K signatures produced and accepted by this module do **not** enforce low-S
canonicalization. The underlying `crypto/ecdsa` implementation may emit either
of the two mathematically valid `(r, s)` / `(r, n-s)` pairs, and verification
accepts both. This matches the behavior of every other ECDSA algorithm in jwx
(ES256, ES384, ES512) and is appropriate for JWS, where signatures are bound to
a specific payload and are not used as unique identifiers.

If you are bridging JWS-signed material into a system that treats ECDSA
signatures as unique identifiers (e.g. Bitcoin-style transaction hashes, or
signature-equality caches), you are responsible for applying low-S
normalization yourself. Do not assume two verifiable ES256K signatures over the
same payload are byte-equal.

## License

MIT
