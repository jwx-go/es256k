package es256k

import (
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// secp256k1 and ECDSA algorithm OIDs.
//
// Go's crypto/x509 hardcodes a list of four named curves in namedCurveFromOID
// (P-224, P-256, P-384, P-521). secp256k1's OID (1.3.132.0.10) is not in that
// list, so any stdlib attempt to parse a secp256k1-carrying PEM block fails
// with "x509: unknown elliptic curve". This decoder fills that gap by
// handling the specific block shapes we care about — SEC1, PKCS#8, and
// SubjectPublicKeyInfo — when the embedded OID is secp256k1.
var (
	oidSecp256k1      = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// Block types we handle.
const (
	blockECPrivateKey = "EC PRIVATE KEY"
	blockPrivateKey   = "PRIVATE KEY"
	blockPublicKey    = "PUBLIC KEY"
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

type identSecp256k1X509Decoder struct{}

func init() {
	panicOnRegistrationError(jwk.RegisterX509Decoder(
		identSecp256k1X509Decoder{},
		jwk.X509DecodeFunc(decodeSecp256k1PEM),
	))
}

// decodeSecp256k1PEM returns the *ecdsa.PrivateKey or *ecdsa.PublicKey
// carried by block when block encodes a secp256k1 key. For anything else
// (non-EC block types, or EC blocks carrying a different curve), it returns
// an error and the jwx.RegisterX509Decoder iteration tries the next
// registered decoder — typically the default stdlib-backed one.
func decodeSecp256k1PEM(block *pem.Block) (any, error) {
	switch block.Type {
	case blockECPrivateKey:
		return decodeSEC1(block.Bytes)
	case blockPrivateKey:
		return decodePKCS8(block.Bytes)
	case blockPublicKey:
		return decodeSPKI(block.Bytes)
	default:
		return nil, fmt.Errorf(`es256k: unsupported PEM block type %q`, block.Type)
	}
}

// decodeSEC1 parses a SEC1 ECPrivateKey. Returns an error (not a panic, and
// not the stdlib parse) when the embedded curve OID is anything other than
// secp256k1 so that callers can fall through to the default decoder.
func decodeSEC1(der []byte) (*ecdsa.PrivateKey, error) {
	var priv sec1ECPrivateKey
	if _, err := asn1.Unmarshal(der, &priv); err != nil {
		return nil, fmt.Errorf(`es256k: failed to parse SEC1 ECPrivateKey: %w`, err)
	}
	if !priv.NamedCurveOID.Equal(oidSecp256k1) {
		return nil, fmt.Errorf(`es256k: SEC1 key uses curve OID %v, not secp256k1`, priv.NamedCurveOID)
	}
	return privateKeyFromScalar(priv.PrivateKey)
}

// decodePKCS8 parses a PKCS#8 PrivateKeyInfo wrapping a SEC1 ECPrivateKey
// whose algorithm parameters carry the secp256k1 OID.
func decodePKCS8(der []byte) (*ecdsa.PrivateKey, error) {
	var p8 pkcs8PrivateKey
	if _, err := asn1.Unmarshal(der, &p8); err != nil {
		return nil, fmt.Errorf(`es256k: failed to parse PKCS#8 PrivateKeyInfo: %w`, err)
	}
	if !p8.Algo.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, fmt.Errorf(`es256k: PKCS#8 algorithm OID %v is not ECDSA`, p8.Algo.Algorithm)
	}
	curveOID, err := parseCurveOIDParameters(p8.Algo.Parameters.FullBytes)
	if err != nil {
		return nil, err
	}
	if !curveOID.Equal(oidSecp256k1) {
		return nil, fmt.Errorf(`es256k: PKCS#8 key uses curve OID %v, not secp256k1`, curveOID)
	}
	// Inner SEC1 ECPrivateKey; RFC 5958 says NamedCurveOID is omitted here
	// because the outer AlgorithmIdentifier already carries it.
	var inner sec1ECPrivateKey
	if _, err := asn1.Unmarshal(p8.PrivateKey, &inner); err != nil {
		return nil, fmt.Errorf(`es256k: failed to parse inner SEC1 ECPrivateKey: %w`, err)
	}
	return privateKeyFromScalar(inner.PrivateKey)
}

// decodeSPKI parses a SubjectPublicKeyInfo whose algorithm parameters
// carry the secp256k1 OID.
func decodeSPKI(der []byte) (*ecdsa.PublicKey, error) {
	var spki pkixPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf(`es256k: failed to parse SubjectPublicKeyInfo: %w`, err)
	}
	if !spki.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, fmt.Errorf(`es256k: SPKI algorithm OID %v is not ECDSA`, spki.Algorithm.Algorithm)
	}
	curveOID, err := parseCurveOIDParameters(spki.Algorithm.Parameters.FullBytes)
	if err != nil {
		return nil, err
	}
	if !curveOID.Equal(oidSecp256k1) {
		return nil, fmt.Errorf(`es256k: SPKI key uses curve OID %v, not secp256k1`, curveOID)
	}
	// BitString.Bytes is the SEC1 encoded point (compressed or uncompressed);
	// secp256k1.ParsePubKey accepts both and validates on-curve.
	if len(spki.PublicKey.Bytes) == 0 {
		return nil, fmt.Errorf(`es256k: SPKI public key is empty`)
	}
	pub, err := secp256k1.ParsePubKey(spki.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf(`es256k: invalid secp256k1 public point: %w`, err)
	}
	return pub.ToECDSA(), nil
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
func privateKeyFromScalar(d []byte) (*ecdsa.PrivateKey, error) {
	if len(d) == 0 {
		return nil, fmt.Errorf(`es256k: secp256k1 private key scalar is empty`)
	}
	priv := secp256k1.PrivKeyFromBytes(d)
	return priv.ToECDSA(), nil
}
