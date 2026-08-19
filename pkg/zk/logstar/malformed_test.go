package zklogstar

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
	require.True(t, proof.Verify(hash.New(), public))
	return proof, public
}

func cloneProof(p *Proof) *Proof {
	return &Proof{
		group: p.group,
		Commitment: &Commitment{
			S: p.S,
			A: p.A,
			Y: p.Y,
			D: p.D,
		},
		Z1: p.Z1,
		Z2: p.Z2,
		Z3: p.Z3,
	}
}

func TestLogStar_MalformedFields(t *testing.T) {
	group := curve.Secp256k1{}
	proof, public := tamperSetup(t)

	cases := map[string]func(p *Proof){
		"nil commitment": func(p *Proof) { p.Commitment = nil },
		"nil S":          func(p *Proof) { p.S = nil },
		"nil A":          func(p *Proof) { p.A = nil },
		"nil Y":          func(p *Proof) { p.Y = nil },
		"nil D":          func(p *Proof) { p.D = nil },
		"nil Z1":         func(p *Proof) { p.Z1 = nil },
		"nil Z2":         func(p *Proof) { p.Z2 = nil },
		"nil Z3":         func(p *Proof) { p.Z3 = nil },
		"identity Y":     func(p *Proof) { p.Y = group.NewPoint() },
		"oversized Z1": func(p *Proof) {
			p.Z1 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 20*256), 20*257)
		},
		"oversized Z3": func(p *Proof) {
			p.Z3 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 20*256), 20*257)
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
		"wrong D": func(p *Proof) {
			p.D = new(saferith.Nat).SetUint64(12345)
		},
		"wrong A": func(p *Proof) {
			a, _ := public.Prover.Enc(new(saferith.Int).SetUint64(999))
			p.A = a
		},
		"wrong Y": func(p *Proof) {
			p.Y = group.NewScalar().SetNat(new(saferith.Nat).SetUint64(999)).Act(public.G)
		},
		"wrong Z2": func(p *Proof) {
			p.Z2 = sample.UnitModN(rand.Reader, public.Prover.N())
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := cloneProof(proof)
			mutate(tampered)
			assert.False(t, tampered.Verify(hash.New(), public))
		})
	}

	var nilProof *Proof
	assert.False(t, nilProof.Verify(hash.New(), public))
}

func TestLogStar_NilGUsesBasePoint(t *testing.T) {
	group := curve.Secp256k1{}
	prover := zk.ProverPaillierPublic

	x := sample.IntervalL(rand.Reader)
	C, rho := prover.Enc(x)
	// G is nil in the public parameters: NewProof must fall back to the base point
	public := Public{
		C:      C,
		Prover: prover,
		Aux:    zk.Pedersen,
	}
	X := group.NewScalar().SetNat(x.Mod(group.Order())).ActOnBase()
	public.X = X

	proof := NewProof(group, hash.New(), public, Private{
		X:   x,
		Rho: rho,
	})
	assert.True(t, proof.Verify(hash.New(), public))
}
