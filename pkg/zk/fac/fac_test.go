package zkfac

import (
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/paillier"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFac(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	aux, _ := paillier.NewSecretKey(pl).GeneratePedersen()
	sk := paillier.NewSecretKey(pl)

	public := Public{
		N:   sk.Modulus().Modulus,
		Aux: aux,
	}

	proof := NewProof(Private{
		P: sk.P(),
		Q: sk.Q(),
	}, hash.New(), public)
	assert.True(t, proof.Verify(public, hash.New()))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(public, hash.New()))
}

func TestFacSigmaBound(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	aux, _ := paillier.NewSecretKey(pl).GeneratePedersen()
	sk := paillier.NewSecretKey(pl)
	public := Public{N: sk.Modulus().Modulus, Aux: aux}

	proof := NewProof(Private{P: sk.P(), Q: sk.Q()}, hash.New(), public)

	// sigma is part of the prover's first message: replacing it must invalidate
	// the proof (the Fiat-Shamir challenge binds it)
	tampered := *proof
	tampered.Sigma = new(saferith.Int).SetUint64(1)
	assert.False(t, tampered.Verify(public, hash.New()), "proof with a replaced sigma must be rejected")
}

func TestFacOversizedResponsesRejected(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	aux, _ := paillier.NewSecretKey(pl).GeneratePedersen()
	sk := paillier.NewSecretKey(pl)
	public := Public{N: sk.Modulus().Modulus, Aux: aux}

	proof := NewProof(Private{P: sk.P(), Q: sk.Q()}, hash.New(), public)

	// Responses with an announced size far beyond any legitimate value must be
	// rejected before feeding any exponentiation — even when the value itself
	// is small (a large zero-filled input has true length 0 but still drives
	// the cost of constant-time arithmetic).
	oversized := func() *saferith.Int { return new(saferith.Int).SetBytes(make([]byte, 64*1024)) }
	for name, mutate := range map[string]func(p *Proof){
		"Sigma": func(p *Proof) { p.Sigma = oversized() },
		"Z1":    func(p *Proof) { p.Z1 = oversized() },
		"W1":    func(p *Proof) { p.W1 = oversized() },
		"V":     func(p *Proof) { p.V = oversized() },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := *proof
			mutate(&tampered)
			assert.False(t, tampered.Verify(public, hash.New()))
		})
	}
}
