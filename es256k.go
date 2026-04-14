// Package es256k provides ES256K (secp256k1) support for jwx.
//
// Import this package for its side effects to enable ES256K signing,
// verification, and key management:
//
//	import _ "github.com/jwx-go/es256k/v4"
//
// # Signature malleability (low-S)
//
// ES256K signatures produced and accepted by this module do not enforce
// low-S canonicalization. Signing may emit either of the two mathematically
// valid (r, s) / (r, n-s) pairs, and verification accepts both. This
// matches every other ECDSA algorithm in jwx (ES256, ES384, ES512) and is
// appropriate for JWS, where signatures are bound to a specific payload
// and are not used as unique identifiers. Callers bridging JWS-signed
// material into systems that treat ECDSA signatures as unique identifiers
// (e.g. Bitcoin-style transaction hashes, signature-equality caches) must
// apply low-S normalization themselves.
//
// # Registration
//
// Registration happens in init(). If any underlying jwx Register* call
// returns an error, init() panics — importing this package will crash the
// program at load time. This is the house style across all jwx-go extension
// modules.
package es256k

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dsigsecp256k1 "github.com/lestrrat-go/dsig-secp256k1"
	"github.com/lestrrat-go/jwx/v4/jwa"
	ourecdsa "github.com/lestrrat-go/jwx/v4/jwk/ecdsa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
)

// ES256K returns the ES256K signature algorithm identifier.
func ES256K() jwa.SignatureAlgorithm {
	return jwa.NewSignatureAlgorithm("ES256K")
}

// Secp256k1 returns the secp256k1 elliptic curve algorithm identifier.
func Secp256k1() jwa.EllipticCurveAlgorithm {
	return jwa.NewEllipticCurveAlgorithm("secp256k1")
}

func init() {
	// Register the secp256k1 elliptic curve
	panicOnRegistrationError(jwa.RegisterEllipticCurveAlgorithm(Secp256k1()))

	// Register ES256K signature algorithm
	panicOnRegistrationError(jwa.RegisterSignatureAlgorithm(ES256K()))

	// Register secp256k1 curve for ECDSA key handling, with a point
	// validator backed by secp256k1.ParsePubKey — the library's own
	// non-deprecated "parse and validate an uncompressed SEC1 point"
	// entry point. This replaces the earlier fallback to the deprecated
	// elliptic.Curve.IsOnCurve method.
	panicOnRegistrationError(ourecdsa.RegisterCurve(Secp256k1(), secp256k1.S256(), secp256k1PointValidator))

	// Register ES256K in the algorithm-to-key-type mapping
	panicOnRegistrationError(jws.RegisterAlgorithmForKeyType(jwa.EC(), ES256K()))

	// Register the dsig algorithm mapping for ES256K
	panicOnRegistrationError(jwsbb.RegisterDsigAlgorithm("ES256K", dsigsecp256k1.ECDSAWithSecp256k1AndSHA256))
}

// secp256k1PointValidator implements jwk/ecdsa.PointValidator for
// secp256k1 by routing (x, y) through secp256k1.ParsePubKey. That
// function validates the SEC1 uncompressed encoding, enforces x < p
// and y < p, and rejects points not on the secp256k1 curve. It also
// rejects the point at infinity as a side effect of the format check.
//
// Coordinates are padded to 32 bytes per secp256k1 field size, so a
// legitimate jwk key whose x or y big.Int has leading zero bytes is
// still encoded correctly.
var secp256k1PointValidator = ourecdsa.PointValidatorFunc(func(x, y *big.Int) error {
	const coordSize = 32
	buf := make([]byte, 1+2*coordSize)
	buf[0] = 0x04
	x.FillBytes(buf[1 : 1+coordSize])
	y.FillBytes(buf[1+coordSize:])
	if _, err := secp256k1.ParsePubKey(buf); err != nil {
		return fmt.Errorf(`invalid secp256k1 public key: %w`, err)
	}
	return nil
})

// panicOnRegistrationError converts a non-nil error returned by a jwx
// Register* call during init() into an import-time panic. The rule
// (documented in jwx's internals.md) is that a failed Register* leaves
// the extension unusable, so we surface it immediately instead of
// letting the program continue in a broken state.
func panicOnRegistrationError(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwx-go/es256k: registration failed: %s", err))
	}
}
