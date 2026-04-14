// Package es256k provides ES256K (secp256k1) support for jwx.
//
// Import this package for its side effects to enable ES256K signing,
// verification, and key management:
//
//	import _ "github.com/jwx-go/es256k/v4"
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

	// Register secp256k1 curve for ECDSA key handling
	panicOnRegistrationError(ourecdsa.RegisterCurve(Secp256k1(), secp256k1.S256())) //nolint:staticcheck // secp256k1 requires elliptic.Curve

	// Register ES256K in the algorithm-to-key-type mapping
	panicOnRegistrationError(jws.RegisterAlgorithmForKeyType(jwa.EC(), ES256K()))

	// Register the dsig algorithm mapping for ES256K
	panicOnRegistrationError(jwsbb.RegisterDsigAlgorithm("ES256K", dsigsecp256k1.ECDSAWithSecp256k1AndSHA256))
}

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
