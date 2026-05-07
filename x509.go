package es256k

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
)

// secp256k1 and ECDSA algorithm OIDs.
//
// Go's crypto/x509 hardcodes a list of four named curves in namedCurveFromOID
// (P-224, P-256, P-384, P-521). secp256k1's OID (1.3.132.0.10) is not in that
// list, so any stdlib attempt to parse a secp256k1-carrying PEM block fails
// with "x509: unknown elliptic curve". The decoders below fill that gap for
// the specific block shapes we care about — SEC1, PKCS#8, and
// SubjectPublicKeyInfo — when the embedded OID is secp256k1, and delegate to
// stdlib for every other curve.
var (
	oidSecp256k1      = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// ASN.1 shapes.
//
// These are cut-down versions of the structures defined alongside Go's
// stdlib crypto/x509 — just enough to extract the curve OID and the
// scalar/point bytes. Anything we don't need (attributes, unused
// certificate fields) is intentionally omitted.

// sec1ECPrivateKey is RFC 5915's ECPrivateKey.
type sec1ECPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// pkcs8PrivateKey is RFC 5208's PrivateKeyInfo.
type pkcs8PrivateKey struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// Attributes left off — asn1 will ignore trailing optional fields.
}

// pkixPublicKeyInfo is RFC 5280's SubjectPublicKeyInfo.
type pkixPublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func init() {
	// jwkbb dispatches decoders by PEM block type. To preserve
	// stdlib-curve parsing we take ownership of each block type our
	// secp256k1 handling overlaps with and delegate back to stdlib for
	// any curve other than secp256k1.
	panicOnRegistrationError(jwkbb.RegisterX509Decoder[any](
		jwkbb.ECPrivateKeyBlockType,
		jwkbb.X509DecodeFunc[any](decodeECPrivateKey),
	))
	panicOnRegistrationError(jwkbb.RegisterX509Decoder[any](
		jwkbb.PrivateKeyBlockType,
		jwkbb.X509DecodeFunc[any](decodePrivateKey),
	))
	panicOnRegistrationError(jwkbb.RegisterX509Decoder[any](
		jwkbb.PublicKeyBlockType,
		jwkbb.X509DecodeFunc[any](decodePublicKey),
	))
}

// decodeECPrivateKey handles `EC PRIVATE KEY` blocks. SEC1 keys carrying
// the secp256k1 OID are parsed via the dcred backend; anything else
// (P-256, P-384, P-521, or malformed input) is handed to stdlib.
func decodeECPrivateKey(block *pem.Block) (any, error) {
	var priv sec1ECPrivateKey
	if _, err := asn1.Unmarshal(block.Bytes, &priv); err == nil && priv.NamedCurveOID.Equal(oidSecp256k1) {
		return privateKeyFromScalar(priv.PrivateKey)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// decodePrivateKey handles `PRIVATE KEY` (PKCS#8) blocks. When the
// outer AlgorithmIdentifier is ECDSA with the secp256k1 OID we build
// the *ecdsa.PrivateKey ourselves; otherwise stdlib parses it.
func decodePrivateKey(block *pem.Block) (any, error) {
	var p8 pkcs8PrivateKey
	if _, err := asn1.Unmarshal(block.Bytes, &p8); err == nil && p8.Algo.Algorithm.Equal(oidPublicKeyECDSA) {
		if curveOID, err := parseCurveOIDParameters(p8.Algo.Parameters.FullBytes); err == nil && curveOID.Equal(oidSecp256k1) {
			// Inner SEC1 ECPrivateKey; RFC 5958 says NamedCurveOID is
			// omitted here because the outer AlgorithmIdentifier already
			// carries it.
			var inner sec1ECPrivateKey
			if _, err := asn1.Unmarshal(p8.PrivateKey, &inner); err != nil {
				return nil, fmt.Errorf(`es256k: failed to parse inner SEC1 ECPrivateKey: %w`, err)
			}
			return privateKeyFromScalar(inner.PrivateKey)
		}
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

// decodePublicKey handles `PUBLIC KEY` (SubjectPublicKeyInfo) blocks.
// secp256k1-carrying SPKI is parsed via dcred; stdlib handles the rest.
func decodePublicKey(block *pem.Block) (any, error) {
	var spki pkixPublicKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &spki); err == nil && spki.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		if curveOID, err := parseCurveOIDParameters(spki.Algorithm.Parameters.FullBytes); err == nil && curveOID.Equal(oidSecp256k1) {
			// BitString.Bytes is the SEC1 encoded point (compressed or
			// uncompressed); secp256k1.ParsePubKey accepts both and
			// validates on-curve.
			if len(spki.PublicKey.Bytes) == 0 {
				return nil, fmt.Errorf(`es256k: SPKI public key is empty`)
			}
			pub, err := secp256k1.ParsePubKey(spki.PublicKey.Bytes)
			if err != nil {
				return nil, fmt.Errorf(`es256k: invalid secp256k1 public point: %w`, err)
			}
			return pub.ToECDSA(), nil
		}
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// parseCurveOIDParameters unmarshals the Parameters field of an ECDSA
// AlgorithmIdentifier into an ObjectIdentifier. A present but malformed
// parameters value is an error.
func parseCurveOIDParameters(raw []byte) (asn1.ObjectIdentifier, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf(`es256k: ECDSA algorithm parameters are missing`)
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(raw, &oid); err != nil {
		return nil, fmt.Errorf(`es256k: failed to parse curve OID: %w`, err)
	}
	return oid, nil
}

// privateKeyFromScalar constructs an *ecdsa.PrivateKey from a raw 32-byte
// secp256k1 scalar. The public key is derived on the fly rather than
// trusting any public-key bytes carried alongside the private key, so an
// adversarial or buggy encoder cannot produce a mis-paired key.
//
// SEC1 §C.4 specifies the secp256k1 private key as a fixed 32-byte
// octet string. We therefore reject any input longer than 32 bytes:
// dcred's [secp256k1.PrivKeyFromBytes] silently truncates and reduces
// modulo N, so without this gate two distinct PEM payloads could
// deserialize to the same key and any caller hashing the encoded bytes
// for fingerprinting would be wrong. We also reject the all-zero
// scalar (and any value that reduces to zero mod N) — D = 0 is not a
// valid secp256k1 private key and downstream operations are undefined.
func privateKeyFromScalar(d []byte) (*ecdsa.PrivateKey, error) {
	if len(d) == 0 {
		return nil, fmt.Errorf(`es256k: secp256k1 private key scalar is empty`)
	}
	if len(d) > 32 {
		return nil, fmt.Errorf(`es256k: secp256k1 private key scalar is %d bytes; SEC1 §C.4 specifies 32`, len(d))
	}
	priv := secp256k1.PrivKeyFromBytes(d)
	if priv.Key.IsZero() {
		return nil, fmt.Errorf(`es256k: secp256k1 private key scalar is zero (or a multiple of curve order N)`)
	}
	return priv.ToECDSA(), nil
}
