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

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```
GOEXPERIMENT=jsonv2 go test ./...
```

## Files

| File | Purpose |
|------|---------|
| `es256k.go` | Package doc, algorithm constants, `init()` registration |
| `es256k_test.go` | Tests |

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
