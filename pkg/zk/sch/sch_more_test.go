package zksch

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var schGroups = []curve.Curve{curve.Secp256k1{}, curve.Edwards25519{}}

func TestNewProof_Verify(t *testing.T) {
	for _, group := range schGroups {
		x := sample.Scalar(rand.Reader, group)
		X := x.ActOnBase()

		proof := NewProof(hash.New(), X, x, nil)
		require.NotNil(t, proof)
		assert.True(t, proof.Verify(hash.New(), X, nil), group.Name())

		// a proof for a different public key must fail
		y := sample.Scalar(rand.Reader, group)
		Y := y.ActOnBase()
		assert.False(t, proof.Verify(hash.New(), Y, nil), group.Name())

		// verification with an explicit, non-standard generator
		G2 := group.NewBasePoint().Add(group.NewBasePoint()) // [2]G
		proofG2 := NewProof(hash.New(), x.Act(G2), x, G2)
		assert.True(t, proofG2.Verify(hash.New(), x.Act(G2), G2), group.Name())
		// verifying against the standard generator must fail
		assert.False(t, proofG2.Verify(hash.New(), x.Act(G2), nil), group.Name())

		// the identity as public key must never verify
		proofIdentity := NewProof(hash.New(), X, x, nil)
		assert.False(t, proofIdentity.Verify(hash.New(), group.NewPoint(), nil), group.Name())
	}
}

func TestProof_IsValid(t *testing.T) {
	group := curve.Secp256k1{}

	// an empty proof is invalid
	p := EmptyProof(group)
	assert.False(t, p.IsValid())

	// a nil proof is invalid
	var nilProof *Proof
	assert.False(t, nilProof.IsValid())

	// a genuine proof is valid
	x := sample.Scalar(rand.Reader, group)
	p2 := NewProof(hash.New(), x.ActOnBase(), x, nil)
	assert.True(t, p2.IsValid())

	// a proof with a zero response is invalid
	bad := EmptyProof(group)
	bad.C = p2.C
	assert.False(t, bad.IsValid())
}

func TestCommitment_IsValid(t *testing.T) {
	group := curve.Secp256k1{}
	c := EmptyCommitment(group)
	assert.False(t, c.IsValid())

	var nilCommitment *Commitment
	assert.False(t, nilCommitment.IsValid())

	// a real commitment is valid
	r := NewRandomness(rand.Reader, group, nil)
	assert.True(t, r.Commitment().IsValid())
}

func TestCommitment_WriteTo(t *testing.T) {
	group := curve.Secp256k1{}
	r := NewRandomness(rand.Reader, group, nil)

	var buf bytes.Buffer
	n, err := r.Commitment().WriteTo(&buf)
	require.NoError(t, err)
	expected, err := r.Commitment().C.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, int64(len(expected)), n)
	assert.Equal(t, expected, buf.Bytes())

	assert.Equal(t, "Schnorr Commitment", r.Commitment().Domain())
}

func TestResponse_IsNilAndInvalid(t *testing.T) {
	group := curve.Secp256k1{}
	var nilResponse *Response
	assert.False(t, nilResponse.IsValid())

	empty := EmptyResponse(group)
	assert.False(t, empty.IsValid())
}

func TestProve_Verify_NonInteractive(t *testing.T) {
	for _, group := range schGroups {
		x := sample.Scalar(rand.Reader, group)
		X := x.ActOnBase()

		r := NewRandomness(rand.Reader, group, nil)
		z := r.Prove(hash.New(), X, x, nil)
		require.NotNil(t, z)

		// verification must succeed with the same hash state
		h1 := hash.New()
		_ = h1.WriteAny(X)
		r2 := NewRandomness(rand.Reader, group, nil)
		z2 := r2.Prove(h1, X, x, nil)

		h2 := hash.New()
		_ = h2.WriteAny(X)
		assert.True(t, z2.Verify(h2, X, r2.Commitment(), nil), group.Name())

		// a wrong commitment must fail
		h3 := hash.New()
		_ = h3.WriteAny(X)
		assert.False(t, z2.Verify(h3, X, NewRandomness(rand.Reader, group, nil).Commitment(), nil), group.Name())

		// proving with the identity as public key returns nil
		assert.Nil(t, r.Prove(hash.New(), group.NewPoint(), x, nil))
		// proving with a zero secret returns nil
		assert.Nil(t, r.Prove(hash.New(), X, group.NewScalar(), nil))
	}
}

func TestResponse_Verify_InvalidInputs(t *testing.T) {
	group := curve.Secp256k1{}
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()
	r := NewRandomness(rand.Reader, group, nil)
	z := r.Prove(hash.New(), X, x, nil)
	require.NotNil(t, z)

	// a nil response must not verify
	var nilResponse *Response
	assert.False(t, nilResponse.Verify(hash.New(), X, r.Commitment(), nil))
}
