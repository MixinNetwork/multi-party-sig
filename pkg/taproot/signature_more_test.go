package taproot

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingReader fails reads immediately.
type failingReader struct{}

var errFailing = errors.New("reader failure")

func (failingReader) Read([]byte) (int, error) { return 0, errFailing }

func TestSecretKey_Public_Invalid(t *testing.T) {
	// wrong length
	_, err := SecretKey(make([]byte, 31)).Public()
	assert.Error(t, err)

	// zero secret key
	_, err = SecretKey(make([]byte, 32)).Public()
	assert.Error(t, err)

	// a scalar equal to the group order is rejected
	_, err = SecretKey(curve.Secp256k1{}.Order().Bytes()).Public()
	assert.Error(t, err)
}

func TestGenKey_ReaderError(t *testing.T) {
	_, _, err := GenKey(failingReader{})
	assert.ErrorIs(t, err, errFailing)
}

func TestSign_InvalidSecretKey(t *testing.T) {
	m := sha256.Sum256([]byte("message"))

	// zero key
	_, err := SecretKey(make([]byte, 32)).Sign(nil, m[:])
	assert.Error(t, err)

	// wrong length
	_, err = SecretKey(make([]byte, 16)).Sign(nil, m[:])
	assert.Error(t, err)
}

func TestSign_ReaderError(t *testing.T) {
	sk, _, err := GenKey(rand.Reader)
	require.NoError(t, err)
	m := sha256.Sum256([]byte("message"))

	// deterministic signing works with a nil reader
	sig, err := sk.Sign(nil, m[:])
	require.NoError(t, err)
	require.Len(t, sig, SignatureLen)

	// a failing reader aborts signing
	_, err = sk.Sign(failingReader{}, m[:])
	assert.ErrorIs(t, err, errFailing)
}

func TestVerify_InvalidInputs(t *testing.T) {
	sk, pk, err := GenKey(rand.Reader)
	require.NoError(t, err)
	m := sha256.Sum256([]byte("message"))
	sig, err := sk.Sign(nil, m[:])
	require.NoError(t, err)

	// wrong signature length
	assert.False(t, pk.Verify(sig[:63], m[:]))
	assert.False(t, pk.Verify(append(sig, 0), m[:]))
	assert.False(t, pk.Verify(nil, m[:]))

	// tampered signature
	bad := append([]byte{}, sig...)
	bad[0] ^= 1
	assert.False(t, pk.Verify(bad, m[:]))
	bad = append([]byte{}, sig...)
	bad[63] ^= 1
	assert.False(t, pk.Verify(bad, m[:]))

	// wrong message
	other := sha256.Sum256([]byte("other"))
	assert.False(t, pk.Verify(sig, other[:]))

	// invalid public keys (x not on curve, or wrong length)
	assert.False(t, PublicKey(make([]byte, 32)).Verify(sig, m[:]))
	assert.False(t, PublicKey(make([]byte, 31)).Verify(sig, m[:]))
	assert.False(t, PublicKey(nil).Verify(sig, m[:]))
}

func TestSignDeterministic_Counter(t *testing.T) {
	// repeated deterministic signing must not produce identical signatures
	// (the atomic counter should increment the nonce)
	sk, pk, err := GenKey(rand.Reader)
	require.NoError(t, err)
	m := sha256.Sum256([]byte("counter test"))

	sig1, err := sk.Sign(nil, m[:])
	require.NoError(t, err)
	sig2, err := sk.Sign(nil, m[:])
	require.NoError(t, err)

	// both must verify
	assert.True(t, pk.Verify(sig1, m[:]))
	assert.True(t, pk.Verify(sig2, m[:]))
	// and with overwhelming probability they differ
	assert.NotEqual(t, sig1, sig2)
}

func TestPublicKey_RoundTripThroughPoint(t *testing.T) {
	sk, pk, err := GenKey(rand.Reader)
	require.NoError(t, err)

	// the public key must be the x coordinate of [sk]G
	group := curve.Secp256k1{}
	scalar := group.NewScalar()
	require.NoError(t, scalar.UnmarshalBinary(sk))
	assert.True(t, bytes.Equal(pk, scalar.ActOnBase().XScalar().Bytes()))
}
