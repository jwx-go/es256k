package es256k_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dsigsecp256k1 "github.com/lestrrat-go/dsig-secp256k1"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	ourecdsa "github.com/lestrrat-go/jwx/v4/jwk/ecdsa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"
	"github.com/stretchr/testify/require"

	// Import for side-effect registration
	"github.com/jwx-go/es256k/v4"
)

func TestSecp256k1Algorithm(t *testing.T) {
	t.Parallel()
	t.Run("accept jwa constant Secp256k1", func(t *testing.T) {
		t.Parallel()
		var dst jwa.EllipticCurveAlgorithm
		require.NoError(t, json.Unmarshal([]byte(`"secp256k1"`), &dst), `Unmarshal is successful`)
		require.Equal(t, es256k.Secp256k1(), dst, `accepted value should be equal to constant`)
	})
	t.Run("stringification for secp256k1", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "secp256k1", es256k.Secp256k1().String(), `stringified value matches`)
	})
}

func TestES256KCurveAvailable(t *testing.T) {
	t.Parallel()
	require.True(t, ourecdsa.IsCurveAvailable(es256k.Secp256k1()), `secp256k1 should be available`)
}

// TestSecp256k1PointValidatorRejectsOversized asserts the registered
// secp256k1 PointValidator returns a typed error rather than panicking
// when handed a coordinate larger than the curve's 256-bit field. The
// validator pads x and y into a fixed 32-byte window via
// big.Int.FillBytes; an oversized input would panic with
// "math/big: buffer too small to fit value" deep inside math/big.
//
// Newer jwx releases also bound coordinates inside validateECDSAPoint
// before calling the registered validator, but this guard inside the
// validator itself is defense-in-depth: jwk/ecdsa.PointValidator's
// previous contract did not pin the precondition, and a direct call
// site (or an older jwx release) must still not crash the process.
func TestSecp256k1PointValidatorRejectsOversized(t *testing.T) {
	t.Parallel()

	validator, err := ourecdsa.ValidatorFromCurve(es256k.Secp256k1())
	require.NoError(t, err, `secp256k1 validator should be registered`)

	// 33 bytes with non-zero leading byte → BitLen() > 256.
	oversize := make([]byte, 33)
	oversize[0] = 0xff
	bigVal := new(big.Int).SetBytes(oversize)
	smallVal := big.NewInt(1)

	t.Run("oversized x", func(t *testing.T) {
		t.Parallel()
		err := validator.ValidatePoint(bigVal, smallVal)
		require.Error(t, err, `validator must reject oversized x without panicking`)
	})

	t.Run("oversized y", func(t *testing.T) {
		t.Parallel()
		err := validator.ValidatePoint(smallVal, bigVal)
		require.Error(t, err, `validator must reject oversized y without panicking`)
	})
}

func TestES256KSign(t *testing.T) {
	t.Parallel()
	payload := []byte("Hello, World!")

	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader) //nolint:staticcheck // secp256k1 requires elliptic.Curve
	require.NoError(t, err, "ECDSA key generated")

	signed, err := jws.Sign(payload, jws.WithKey(es256k.ES256K(), key))
	require.NoError(t, err, "jws.Sign should succeed")

	// Verify with raw public key
	verified, err := jws.Verify(signed, jws.WithKey(es256k.ES256K(), &key.PublicKey))
	require.NoError(t, err, "jws.Verify with *ecdsa.PublicKey should succeed")
	require.Equal(t, payload, verified, "verified payload should match")

	// Verify with jwk.Key
	jwkKey, err := jwk.Import[jwk.Key](&key.PublicKey)
	require.NoError(t, err, "jwk.Import should succeed")

	verified, err = jws.Verify(signed, jws.WithKey(es256k.ES256K(), jwkKey))
	require.NoError(t, err, "jws.Verify with jwk.Key should succeed")
	require.Equal(t, payload, verified, "verified payload should match")
}

func TestES256KJwsbb(t *testing.T) {
	t.Parallel()
	payload := []byte("hello world")

	key, err := ecdsa.GenerateKey(dsigsecp256k1.Curve(), rand.Reader)
	require.NoError(t, err, "secp256k1 key generation should succeed")

	signature, err := jwsbb.Sign(key, "ES256K", payload, nil)
	require.NoError(t, err, "ES256K signing should not error")

	err = jwsbb.Verify(&key.PublicKey, "ES256K", payload, signature)
	require.NoError(t, err, "ES256K verification should succeed")

	// Verify that a tampered signature fails
	tamperedSig := make([]byte, len(signature))
	copy(tamperedSig, signature)
	if len(tamperedSig) > 0 {
		tamperedSig[0] ^= 1
	}
	err = jwsbb.Verify(&key.PublicKey, "ES256K", payload, tamperedSig)
	require.Error(t, err, "ES256K verification should fail for tampered signature")
}

func BenchmarkKeyInstantiation(b *testing.B) {
	const xb64 = "YAXIamcY9mIhcTp3BzxBKRzDq7_NA6pJVemytQ2_f5s"
	const yb64 = "ZnLa0NRq3mHjgveYiKc-p4mdlBm-zx1snsIIfBGI-hg"

	x, err := base64.RawURLEncoding.DecodeString(xb64)
	require.NoError(b, err, `DecodeBase64 should succeed`)
	y, err := base64.RawURLEncoding.DecodeString(yb64)
	require.NoError(b, err, `DecodeBase64 should succeed`)

	b.Run("Use json.Marshal/json.Unmarshal", func(b *testing.B) {
		for range b.N {
			serialized, err := json.Marshal(map[string]any{
				"kty": "EC",
				"crv": "secp256k1",
				"x":   xb64,
				"y":   yb64,
			})
			if err != nil {
				panic(err)
			}

			key, err := jwk.Parse(serialized)
			if err != nil {
				panic(err)
			}
			_ = key
		}
	})
	b.Run("Use jwk.Import", func(b *testing.B) {
		for range b.N {
			var raw ecdsa.PublicKey      //nolint:staticcheck // benchmark intentionally uses deprecated field access
			raw.Curve = secp256k1.S256() //nolint:staticcheck // secp256k1 requires elliptic.Curve
			raw.X = &big.Int{}           //nolint:staticcheck // benchmark intentionally uses deprecated field access
			raw.Y = &big.Int{}           //nolint:staticcheck // benchmark intentionally uses deprecated field access
			raw.X.SetBytes(x)            //nolint:staticcheck // benchmark intentionally uses deprecated field access
			raw.Y.SetBytes(y)            //nolint:staticcheck // benchmark intentionally uses deprecated field access

			key, err := jwk.Import[jwk.Key](&raw)
			if err != nil {
				panic(err)
			}
			_ = key
		}
	})
}
