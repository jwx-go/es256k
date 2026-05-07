package es256k_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	es256k "github.com/jwx-go/es256k/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// OIDs matching the production decoder — kept duplicated in the test file
// rather than exported from the package because they are an implementation
// detail, not API surface.
var (
	testOIDSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	testOIDECDSA     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// generateKey returns a fresh secp256k1 keypair as an *ecdsa.PrivateKey.
// Using the library helper so the test does not depend on the production
// decoder under test.
func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err, "secp256k1.GeneratePrivateKey")
	return priv.ToECDSA()
}

// encodeSEC1 marshals an *ecdsa.PrivateKey into a SEC1 EC PRIVATE KEY PEM.
func encodeSEC1(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()

	// Pad scalar to curve field size (32 bytes for secp256k1) — leading
	// zero bytes must be preserved.
	privBytes := make([]byte, 32)
	priv.D.FillBytes(privBytes)

	pubBytes := elliptic.Marshal(priv.Curve, priv.X, priv.Y) //nolint:staticcheck // SEC1 uncompressed is the canonical form; deprecated wrapper is fine for test fixtures

	sec1 := struct {
		Version       int
		PrivateKey    []byte
		NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}{
		Version:       1,
		PrivateKey:    privBytes,
		NamedCurveOID: testOIDSecp256k1,
		PublicKey:     asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
	}

	der, err := asn1.Marshal(sec1)
	require.NoError(t, err, "asn1.Marshal(sec1)")

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// encodePKCS8 marshals an *ecdsa.PrivateKey into a PKCS#8 PRIVATE KEY PEM.
func encodePKCS8(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()

	// Inner SEC1 — per RFC 5958 omits the curve OID (it lives in the
	// outer AlgorithmIdentifier).
	privBytes := make([]byte, 32)
	priv.D.FillBytes(privBytes)
	pubBytes := elliptic.Marshal(priv.Curve, priv.X, priv.Y) //nolint:staticcheck // canonical SEC1 uncompressed; fixture-only use

	inner := struct {
		Version    int
		PrivateKey []byte
		PublicKey  asn1.BitString `asn1:"optional,explicit,tag:1"`
	}{
		Version:    1,
		PrivateKey: privBytes,
		PublicKey:  asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
	}
	innerDER, err := asn1.Marshal(inner)
	require.NoError(t, err, "asn1.Marshal(inner sec1)")

	curveOIDBytes, err := asn1.Marshal(testOIDSecp256k1)
	require.NoError(t, err, "asn1.Marshal(curveOID)")

	p8 := struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Version: 0,
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  testOIDECDSA,
			Parameters: asn1.RawValue{FullBytes: curveOIDBytes},
		},
		PrivateKey: innerDER,
	}
	der, err := asn1.Marshal(p8)
	require.NoError(t, err, "asn1.Marshal(pkcs8)")

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// encodeSPKI marshals an *ecdsa.PublicKey into a SubjectPublicKeyInfo
// PEM (PUBLIC KEY block).
func encodeSPKI(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()

	pubBytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y) //nolint:staticcheck // canonical SEC1 uncompressed; fixture-only use

	curveOIDBytes, err := asn1.Marshal(testOIDSecp256k1)
	require.NoError(t, err, "asn1.Marshal(curveOID)")

	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  testOIDECDSA,
			Parameters: asn1.RawValue{FullBytes: curveOIDBytes},
		},
		PublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
	}
	der, err := asn1.Marshal(spki)
	require.NoError(t, err, "asn1.Marshal(spki)")

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestParseSecp256k1PEM_SEC1(t *testing.T) {
	priv := generateKey(t)
	pemBytes := encodeSEC1(t, priv)

	key, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
	require.NoError(t, err, "jwk.ParseKey on SEC1 secp256k1 PEM")
	require.NotNil(t, key)

	// Export and confirm the scalar round-trips.
	raw, err := jwk.Export[*ecdsa.PrivateKey](key)
	require.NoError(t, err, "jwk.Export[*ecdsa.PrivateKey]")
	require.Equal(t, priv.D, raw.D, "private scalar")
	require.Equal(t, priv.X, raw.X, "public X")
	require.Equal(t, priv.Y, raw.Y, "public Y")
	require.Equal(t, secp256k1.S256(), raw.Curve, "curve") //nolint:staticcheck // library returns deprecated-interface *KoblitzCurve
}

func TestParseSecp256k1PEM_PKCS8(t *testing.T) {
	priv := generateKey(t)
	pemBytes := encodePKCS8(t, priv)

	key, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
	require.NoError(t, err, "jwk.ParseKey on PKCS#8 secp256k1 PEM")
	require.NotNil(t, key)

	raw, err := jwk.Export[*ecdsa.PrivateKey](key)
	require.NoError(t, err, "jwk.Export[*ecdsa.PrivateKey]")
	require.Equal(t, priv.D, raw.D, "private scalar")
	require.Equal(t, priv.X, raw.X, "public X")
	require.Equal(t, priv.Y, raw.Y, "public Y")
}

func TestParseSecp256k1PEM_SPKI(t *testing.T) {
	priv := generateKey(t)
	pemBytes := encodeSPKI(t, &priv.PublicKey)

	key, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
	require.NoError(t, err, "jwk.ParseKey on SPKI secp256k1 PEM")
	require.NotNil(t, key)

	raw, err := jwk.Export[*ecdsa.PublicKey](key)
	require.NoError(t, err, "jwk.Export[*ecdsa.PublicKey]")
	require.Equal(t, priv.X, raw.X, "public X")
	require.Equal(t, priv.Y, raw.Y, "public Y")
}

// TestStdlibCurveStillWorks confirms that adding the secp256k1 decoder
// does not break parsing of PEM blocks carrying stdlib-supported
// curves. jwkbb dispatches decoders by block type, so our decoder
// owns `EC PRIVATE KEY` / `PRIVATE KEY` / `PUBLIC KEY`; it delegates
// back to stdlib whenever the embedded curve OID is not secp256k1.
func TestStdlibCurveStillWorks(t *testing.T) {
	// Generate a P-256 key via stdlib and emit SEC1 + PKCS8 + SPKI PEMs.
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "ecdsa.GenerateKey P-256")

	t.Run("SEC1 P-256", func(t *testing.T) {
		der, err := x509.MarshalECPrivateKey(p256)
		require.NoError(t, err, "x509.MarshalECPrivateKey")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

		key, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
		require.NoError(t, err, "jwk.ParseKey should accept stdlib P-256")
		require.NotNil(t, key)
	})

	t.Run("PKCS8 P-256", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(p256)
		require.NoError(t, err, "x509.MarshalPKCS8PrivateKey")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

		key, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
		require.NoError(t, err, "jwk.ParseKey should accept stdlib PKCS8 P-256")
		require.NotNil(t, key)
	})

	t.Run("SPKI P-256", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
		require.NoError(t, err, "x509.MarshalPKIXPublicKey")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

		key, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
		require.NoError(t, err, "jwk.ParseKey should accept stdlib SPKI P-256")
		require.NotNil(t, key)
	})
}

// TestPrivateKeyScalarBounds pins the contract that
// privateKeyFromScalar rejects malformed scalars routed through the
// SEC1 / PKCS#8 PEM decoders:
//
//   - Oversized scalars (>32 bytes) — dcred would silently truncate
//     and reduce mod N, so two distinct PEMs could deserialize to
//     the same key and PEM-bytes-as-identifier would collide.
//   - All-zero scalars — D = 0 is not a valid secp256k1 key.
//
// Each subcase crafts a fresh SEC1 (or PKCS#8) DER manually with the
// hostile scalar payload so the rejection is exercised at the actual
// jwk.ParseKey entry point.
func TestPrivateKeyScalarBounds(t *testing.T) {
	t.Run("SEC1 oversized scalar (33 bytes) rejected", func(t *testing.T) {
		pemBytes := encodeSEC1WithScalar(t, append([]byte{0x01}, make([]byte, 32)...))
		_, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
		require.Error(t, err, "33-byte SEC1 scalar must be rejected")
		require.Contains(t, err.Error(), "32",
			"error must reference the 32-byte SEC1 spec size")
	})

	t.Run("SEC1 zero scalar rejected", func(t *testing.T) {
		pemBytes := encodeSEC1WithScalar(t, make([]byte, 32))
		_, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
		require.Error(t, err, "all-zero SEC1 scalar must be rejected")
		require.Contains(t, err.Error(), "zero")
	})

	t.Run("PKCS8 oversized scalar (40 bytes) rejected", func(t *testing.T) {
		pemBytes := encodePKCS8WithScalar(t, make([]byte, 40))
		_, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
		require.Error(t, err, "40-byte PKCS8 inner scalar must be rejected")
	})

	t.Run("PKCS8 zero scalar rejected", func(t *testing.T) {
		pemBytes := encodePKCS8WithScalar(t, make([]byte, 32))
		_, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
		require.Error(t, err, "all-zero PKCS8 inner scalar must be rejected")
		require.Contains(t, err.Error(), "zero")
	})

	t.Run("legitimate 32-byte non-zero scalar still accepted", func(t *testing.T) {
		pemBytes := encodeSEC1(t, generateKey(t))
		key, err := jwk.ParseKey(pemBytes, jwk.WithX509(true))
		require.NoError(t, err, "valid SEC1 must still parse")
		require.NotNil(t, key)
	})
}

// encodeSEC1WithScalar marshals a SEC1 EC PRIVATE KEY PEM whose
// PrivateKey octet string is the supplied raw bytes (no padding,
// no validation). Public key field is omitted; the production decoder
// derives the public key from the scalar.
func encodeSEC1WithScalar(t *testing.T, scalar []byte) []byte {
	t.Helper()

	sec1 := struct {
		Version       int
		PrivateKey    []byte
		NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	}{
		Version:       1,
		PrivateKey:    scalar,
		NamedCurveOID: testOIDSecp256k1,
	}

	der, err := asn1.Marshal(sec1)
	require.NoError(t, err, "asn1.Marshal(sec1)")

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// encodePKCS8WithScalar marshals a PKCS#8 PRIVATE KEY PEM whose inner
// SEC1 ECPrivateKey carries the supplied raw scalar bytes. Mirrors
// encodePKCS8 but with no padding/validation on the scalar.
func encodePKCS8WithScalar(t *testing.T, scalar []byte) []byte {
	t.Helper()

	inner := struct {
		Version    int
		PrivateKey []byte
	}{
		Version:    1,
		PrivateKey: scalar,
	}
	innerDER, err := asn1.Marshal(inner)
	require.NoError(t, err, "asn1.Marshal(inner SEC1)")

	curveOIDDER, err := asn1.Marshal(testOIDSecp256k1)
	require.NoError(t, err, "asn1.Marshal(curveOID)")

	pkcs8 := struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Version: 0,
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  testOIDECDSA,
			Parameters: asn1.RawValue{FullBytes: curveOIDDER},
		},
		PrivateKey: innerDER,
	}
	der, err := asn1.Marshal(pkcs8)
	require.NoError(t, err, "asn1.Marshal(pkcs8)")

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Sanity check: keep the package imported so init() registration runs even
// if no symbol is referenced directly.
var _ = es256k.ES256K
