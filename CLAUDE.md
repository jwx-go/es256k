# ES256K Extension for JWX

## Overview

This module (`github.com/jwx-go/es256k/v4`) provides ES256K (secp256k1) support for `github.com/lestrrat-go/jwx`.

ES256K uses the secp256k1 elliptic curve, widely used in blockchain applications. This module bridges the `github.com/decred/dcrd/dcrec/secp256k1/v4` implementation into jwx's algorithm registration system, enabling secp256k1 key types and ES256K signing/verification in JWK, JWS, and JWT workflows.

## Architecture

This module registers the secp256k1 curve and ES256K signature algorithm via jwx's extension point system. Unlike ML-DSA which requires custom key types, ES256K uses the standard EC key type (`jwa.EC()`) since secp256k1 is an elliptic curve — it just needs to be registered as an additional curve alongside P-256, P-384, and P-521.

### Registration Points

| JWX Package | Registration Function | Purpose |
|-------------|----------------------|---------|
| `jwa` | `RegisterEllipticCurveAlgorithm()` | Register secp256k1 curve |
| `jwa` | `RegisterSignatureAlgorithm()` | Register ES256K |
| `jwk/ecdsa` | `RegisterCurve()` | Map secp256k1 to `elliptic.Curve` for ECDSA key handling |
| `jws` | `RegisterAlgorithmForKeyType()` | Associate ES256K with EC key type |
| `jwsbb` | `RegisterDsigAlgorithm()` | Map ES256K to dsig algorithm |
| `jwk/jwkbb` | `RegisterX509Decoder[T](blockType, d)` | Decode secp256k1 PEM blocks (SEC1, PKCS#8, SubjectPublicKeyInfo) that Go stdlib rejects. One registration per block type; non-secp256k1 curves delegate back to stdlib. |

### secp256k1 PEM decoding

Go's `crypto/x509` hardcodes a list of four named curves (P-224, P-256, P-384, P-521) in `namedCurveFromOID`. secp256k1's OID (`1.3.132.0.10`) is not in that list, so stdlib fails any attempt to parse a secp256k1-carrying PEM block with `x509: unknown elliptic curve`.

`x509.go` registers one `X509Decoder` per block type via `jwkbb.RegisterX509Decoder[T]`, taking ownership of:

- `EC PRIVATE KEY` (SEC1 / RFC 5915)
- `PRIVATE KEY` (PKCS#8 / RFC 5958 wrapping SEC1 inside)
- `PUBLIC KEY` (SubjectPublicKeyInfo / RFC 5280)

For each, it asn1-unmarshals a cut-down struct and checks the curve OID. If the OID is secp256k1 the key is built via `github.com/decred/dcrd/dcrec/secp256k1/v4`. Any other curve (or malformed input) falls through to the stdlib parser (`x509.ParseECPrivateKey` / `x509.ParsePKCS8PrivateKey` / `x509.ParsePKIXPublicKey`), so registering this decoder does not break P-256 / P-384 / P-521 parsing.

`CERTIFICATE` blocks are out of scope for now — full cert parsing is a much larger undertaking and the current demand is key material only.

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```
GOEXPERIMENT=jsonv2 go test ./...
```

## Files

| File | Purpose |
|------|---------|
| `es256k.go` | Package doc, algorithm constants, `init()` registration |
| `x509.go` | secp256k1 PEM / X509 decoder |
| `es256k_test.go` | Signing / verification tests |
| `x509_test.go` | PEM decoding tests + stdlib-curve fallthrough check |
| `fuzz_test.go` | Fuzz harness |

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
