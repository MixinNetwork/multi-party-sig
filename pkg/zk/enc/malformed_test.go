package zkenc

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/paillier"
	"github.com/MixinNetwork/multi-party-sig/pkg/zk"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tamperSetup(t *testing.T) (*Proof, Public) {
	t.Helper()
	group := curve.Secp256k1{}

	prover := zk.ProverPaillierPublic
	k := sample.IntervalL(rand.Reader)
	K, rho := prover.Enc(k)
	public := Public{
		K:      K,
		Prover: prover,
		Aux:    zk.Pedersen,
	}

	proof := NewProof(group, hash.New(), public, Private{
		K:   k,
		Rho: rho,
	})
	require.True(t, proof.Verify(group, hash.New(), public))
	return proof, public
}

func cloneProof(p *Proof) *Proof {
	return &Proof{
		Commitment: &Commitment{
			S: p.S,
			A: p.A,
			C: p.C,
		},
		Z1: p.Z1,
		Z2: p.Z2,
		Z3: p.Z3,
	}
}

func TestEnc_MalformedFields(t *testing.T) {
	group := curve.Secp256k1{}
	proof, public := tamperSetup(t)

	cases := map[string]func(p *Proof){
		"nil commitment": func(p *Proof) { p.Commitment = nil },
		"nil S":          func(p *Proof) { p.S = nil },
		"nil A":          func(p *Proof) { p.A = nil },
		"nil C":          func(p *Proof) { p.C = nil },
		"nil Z1":         func(p *Proof) { p.Z1 = nil },
		"nil Z2":         func(p *Proof) { p.Z2 = nil },
		"nil Z3":         func(p *Proof) { p.Z3 = nil },
		"oversized Z1": func(p *Proof) {
			p.Z1 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 20*256), 20*257)
		},
		"A out of range": func(p *Proof) {
			nSquared := new(big.Int).Mul(public.Prover.N().Big(), public.Prover.N().Big())
			buf := make([]byte, 512)
			nSquared.FillBytes(buf)
			ct := new(paillier.Ciphertext)
			require.NoError(t, ct.UnmarshalBinary(buf))
			p.A = ct
		},
		"Z2 out of range": func(p *Proof) {
			p.Z2 = public.Prover.N().Nat()
		},
		"Z1 outside interval": func(p *Proof) {
			p.Z1 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 1000), 1001)
		},
		"wrong S": func(p *Proof) {
			p.S = new(saferith.Nat).SetUint64(12345)
		},
		"wrong C": func(p *Proof) {
			p.C = new(saferith.Nat).SetUint64(12345)
		},
		"wrong Z2": func(p *Proof) {
			p.Z2 = sample.UnitModN(rand.Reader, public.Prover.N())
		},
		"wrong A": func(p *Proof) {
			a, _ := public.Prover.Enc(new(saferith.Int).SetUint64(999))
			p.A = a
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := cloneProof(proof)
			mutate(tampered)
			assert.False(t, tampered.Verify(group, hash.New(), public))
		})
	}

	var nilProof *Proof
	assert.False(t, nilProof.Verify(group, hash.New(), public))
}
