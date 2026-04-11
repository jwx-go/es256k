package es256k_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"

	"github.com/jwx-go/es256k/v4"
)

func FuzzSignAndVerify(f *testing.F) {
	f.Add([]byte("Hello, World!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))
	f.Add([]byte("The true sign of intelligence is not knowledge but imagination."))

	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader) //nolint:staticcheck // secp256k1 requires elliptic.Curve
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		signed, err := jws.Sign(payload, jws.WithKey(es256k.ES256K(), key))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(es256k.ES256K(), &key.PublicKey))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})
}

func FuzzJWKRoundTrip(f *testing.F) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader) //nolint:staticcheck // secp256k1 requires elliptic.Curve
	if err != nil {
		f.Fatal(err)
	}
	jwkKey, err := jwk.Import[jwk.Key](key)
	if err != nil {
		f.Fatal(err)
	}
	seedJSON, err := json.Marshal(jwkKey)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(seedJSON)
	f.Add([]byte(""))
	f.Add([]byte("not-json"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		parsed, err := jwk.ParseKey[jwk.Key](data)
		if err != nil {
			return
		}

		buf, err := json.Marshal(parsed)
		if err != nil {
			return
		}

		_, _ = jwk.ParseKey[jwk.Key](buf)
	})
}
