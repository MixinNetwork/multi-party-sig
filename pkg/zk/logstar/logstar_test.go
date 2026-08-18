package zklogstar

import (
	"crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/zk"
)

func TestLogStar(t *testing.T) {
	group := curve.Secp256k1{}

	verifier := zk.Pedersen
	prover := zk.ProverPaillierPublic

	G := sample.Scalar(rand.Reader, group).ActOnBase()

	x := sample.IntervalL(rand.Reader)
	C, rho := prover.Enc(x)
	X := group.NewScalar().SetNat(x.Mod(group.Order())).Act(G)
	public := Public{
		C:      C,
		X:      X,
		G:      G,
		Prover: prover,
		Aux:    verifier,
	}

	proof := NewProof(group, hash.New(), public, Private{
		X:   x,
		Rho: rho,
	})
	assert.True(t, proof.Verify(hash.New(), public))

	// responses with an oversized announced length must be rejected before
	// reaching any exponentiation (arith.MaxIntResponseBits)
	tampered := *proof
	tampered.Z3 = new(saferith.Int).SetBytes(make([]byte, 64*1024))
	assert.False(t, tampered.Verify(hash.New(), public))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := Empty(group)
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := Empty(group)
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(hash.New(), public))
}

func TestLogStarMalformedProofs(t *testing.T) {
	group := curve.Secp256k1{}
	prover := zk.ProverPaillierPublic

	x := sample.IntervalL(rand.Reader)
	C, _ := prover.Enc(x)
	X := group.NewScalar().SetNat(x.Mod(group.Order())).ActOnBase()
	public := Public{
		C:      C,
		X:      X,
		Prover: prover,
		Aux:    zk.Pedersen,
	}

	var nilProof *Proof
	assert.NotPanics(t, func() {
		assert.False(t, nilProof.Verify(hash.New(), public))
		assert.False(t, (&Proof{}).Verify(hash.New(), public))
		assert.False(t, (&Proof{Commitment: &Commitment{}}).Verify(hash.New(), public))
	})
}
