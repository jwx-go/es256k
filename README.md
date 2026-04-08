# es256k

ES256K (secp256k1) extension for [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

This module adds ES256K digital signature support to jwx, enabling the secp256k1 elliptic curve and ES256K signature algorithm for use in JWK, JWS, and JWT operations.

## Status

**Work in progress.**

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

### Sign and verify

```go
import (
    "crypto/ecdsa"
    "crypto/rand"

    "github.com/decred/dcrd/dcrec/secp256k1/v4"
    "github.com/jwx-go/es256k"
    "github.com/lestrrat-go/jwx/v4/jws"
)

key, _ := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
signed, _ := jws.Sign(payload, jws.WithKey(es256k.ES256K(), key))
verified, _ := jws.Verify(signed, jws.WithKey(es256k.ES256K(), &key.PublicKey))
```

## License

MIT
