package zkfac

import (
	"math/big"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/paillier"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func facSetup(t *testing.T) (*Proof, Public) {
	t.Helper()
	pl := pool.NewPool(0)
	t.Cleanup(pl.TearDown)

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
	require.True(t, proof.Verify(public, hash.New()))
	return proof, public
}

func TestFac_Malformed(t *testing.T) {
	proof, public := facSetup(t)

	// nil proof
	var nilProof *Proof
	assert.False(t, nilProof.Verify(public, hash.New()))

	// nil public fields
	assert.False(t, proof.Verify(Public{}, hash.New()))
	assert.False(t, proof.Verify(Public{N: public.N}, hash.New()))

	// nil proof fields
	nilFields := *proof
	nilFields.Sigma = nil
	assert.False(t, nilFields.Verify(public, hash.New()))
	nilFields = *proof
	nilFields.Comm.P = nil
	assert.False(t, nilFields.Verify(public, hash.New()))

	// oversized responses
	oversized := new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 20*256), 20*257)
	for name, mutate := range map[string]func(p *Proof){
		"Sigma": func(p *Proof) { p.Sigma = oversized },
		"Z1":    func(p *Proof) { p.Z1 = oversized },
		"Z2":    func(p *Proof) { p.Z2 = oversized },
		"W1":    func(p *Proof) { p.W1 = oversized },
		"W2":    func(p *Proof) { p.W2 = oversized },
		"V":     func(p *Proof) { p.V = oversized },
	} {
		t.Run("oversized "+name, func(t *testing.T) {
			tampered := *proof
			mutate(&tampered)
			assert.False(t, tampered.Verify(public, hash.New()))
		})
	}

	// values outside ±2^(1+L+ε)√N
	outside := new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 20000), 20001)
	for name, mutate := range map[string]func(p *Proof){
		"Z1": func(p *Proof) { p.Z1 = outside },
		"Z2": func(p *Proof) { p.Z2 = outside },
	} {
		t.Run("outside interval "+name, func(t *testing.T) {
			tampered := *proof
			mutate(&tampered)
			assert.False(t, tampered.Verify(public, hash.New()))
		})
	}

	// wrong commitments break the aux verifications and the final equation
	wrongP := *proof
	wrongP.Comm.P = new(saferith.Nat).SetUint64(12345)
	assert.False(t, wrongP.Verify(public, hash.New()))

	wrongT := *proof
	wrongT.Comm.T = new(saferith.Nat).SetUint64(12345)
	assert.False(t, wrongT.Verify(public, hash.New()))

	wrongV := *proof
	wrongV.V = new(saferith.Int).SetUint64(1)
	assert.False(t, wrongV.Verify(public, hash.New()))
}
