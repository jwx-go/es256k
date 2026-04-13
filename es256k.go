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
package es256k

import (
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
	jwa.RegisterEllipticCurveAlgorithm(Secp256k1())

	// Register ES256K signature algorithm
	jwa.RegisterSignatureAlgorithm(ES256K())

	// Register secp256k1 curve for ECDSA key handling
	ourecdsa.RegisterCurve(Secp256k1(), secp256k1.S256()) //nolint:staticcheck // secp256k1 requires elliptic.Curve

	// Register ES256K in the algorithm-to-key-type mapping
	jws.RegisterAlgorithmForKeyType(jwa.EC(), ES256K())

	// Register the dsig algorithm mapping for ES256K
	jwsbb.RegisterDsigAlgorithm("ES256K", dsigsecp256k1.ECDSAWithSecp256k1AndSHA256)
}
