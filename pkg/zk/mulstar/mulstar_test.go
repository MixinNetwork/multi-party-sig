package zkmulstar

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

func TestMulG(t *testing.T) {
	group := curve.Secp256k1{}

	verifierPaillier := zk.VerifierPaillierPublic
	verifierPedersen := zk.Pedersen

	c := new(saferith.Int).SetUint64(12)
	C, _ := verifierPaillier.Enc(c)

	x := sample.IntervalL(rand.Reader)
	X := group.NewScalar().SetNat(x.Mod(group.Order())).ActOnBase()

	D := C.Clone().Mul(verifierPaillier, x)
	n := verifierPaillier.N()
	rho := sample.UnitModN(rand.Reader, n)
	D.Randomize(verifierPaillier, rho)

	public := Public{
		C:        C,
		D:        D,
		X:        X,
		Verifier: verifierPaillier,
		Aux:      verifierPedersen,
	}
	private := Private{
		X:   x,
		Rho: rho,
	}
	proof := NewProof(group, hash.New(), public, private)
	assert.True(t, proof.Verify(group, hash.New(), public))

	// responses with an oversized announced length must be rejected before
	// reaching any exponentiation (arith.MaxIntResponseBits)
	tampered := *proof
	tampered.Z1 = new(saferith.Int).SetBytes(make([]byte, 64*1024))
	assert.False(t, tampered.Verify(group, hash.New(), public))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := Empty(group)
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := Empty(group)
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(group, hash.New(), public))
}

func TestMulStarMalformedProofs(t *testing.T) {
	group := curve.Secp256k1{}
	verifierPaillier := zk.VerifierPaillierPublic

	c := new(saferith.Int).SetUint64(12)
	C, _ := verifierPaillier.Enc(c)
	x := sample.IntervalL(rand.Reader)
	X := group.NewScalar().SetNat(x.Mod(group.Order())).ActOnBase()
	D := C.Clone().Mul(verifierPaillier, x)
	rho := sample.UnitModN(rand.Reader, verifierPaillier.N())
	D.Randomize(verifierPaillier, rho)

	public := Public{
		C:        C,
		D:        D,
		X:        X,
		Verifier: verifierPaillier,
		Aux:      zk.Pedersen,
	}

	var nilProof *Proof
	assert.NotPanics(t, func() {
		assert.False(t, nilProof.Verify(group, hash.New(), public))
		assert.False(t, (&Proof{}).Verify(group, hash.New(), public))
		assert.False(t, (&Proof{Commitment: &Commitment{}}).Verify(group, hash.New(), public))
	})
}
