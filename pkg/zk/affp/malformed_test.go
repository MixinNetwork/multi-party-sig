package zkaffp

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
	verifierPaillier := zk.VerifierPaillierPublic
	verifierPedersen := zk.Pedersen
	prover := zk.ProverPaillierPublic

	c := new(saferith.Int).SetUint64(12)
	C, _ := verifierPaillier.Enc(c)

	x := sample.IntervalL(rand.Reader)
	X, rhoX := prover.Enc(x)

	y := sample.IntervalL(rand.Reader)
	Y, rhoY := prover.Enc(y)

	tmp := C.Clone().Mul(verifierPaillier, x)
	D, rho := verifierPaillier.Enc(y)
	D.Add(verifierPaillier, tmp)

	public := Public{
		Kv:       C,
		Dv:       D,
		Fp:       Y,
		Xp:       X,
		Prover:   prover,
		Verifier: verifierPaillier,
		Aux:      verifierPedersen,
	}
	private := Private{
		X:  x,
		Y:  y,
		S:  rho,
		Rx: rhoX,
		R:  rhoY,
	}
	group := curve.Secp256k1{}
	proof := NewProof(group, hash.New(), public, private)
	require.True(t, proof.Verify(group, hash.New(), public))
	return proof, public
}

func cloneProof(p *Proof) *Proof {
	return &Proof{
		Commitment: &Commitment{
			A:  p.A,
			Bx: p.Bx,
			By: p.By,
			E:  p.E,
			S:  p.S,
			F:  p.F,
			T:  p.T,
		},
		Z1: p.Z1,
		Z2: p.Z2,
		Z3: p.Z3,
		Z4: p.Z4,
		W:  p.W,
		Wx: p.Wx,
		Wy: p.Wy,
	}
}

func TestAffP_MalformedFields(t *testing.T) {
	group := curve.Secp256k1{}
	proof, public := tamperSetup(t)

	cases := map[string]func(p *Proof){
		"nil commitment": func(p *Proof) { p.Commitment = nil },
		"nil S":          func(p *Proof) { p.S = nil },
		"nil T":          func(p *Proof) { p.T = nil },
		"nil A":          func(p *Proof) { p.A = nil },
		"nil Bx":         func(p *Proof) { p.Bx = nil },
		"nil By":         func(p *Proof) { p.By = nil },
		"nil E":          func(p *Proof) { p.E = nil },
		"nil F":          func(p *Proof) { p.F = nil },
		"nil Z1":         func(p *Proof) { p.Z1 = nil },
		"nil Z2":         func(p *Proof) { p.Z2 = nil },
		"nil Z3":         func(p *Proof) { p.Z3 = nil },
		"nil Z4":         func(p *Proof) { p.Z4 = nil },
		"nil W":          func(p *Proof) { p.W = nil },
		"nil Wx":         func(p *Proof) { p.Wx = nil },
		"nil Wy":         func(p *Proof) { p.Wy = nil },
		"oversized Z1": func(p *Proof) {
			p.Z1 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 20*256), 20*257)
		},
		"oversized Z2": func(p *Proof) {
			p.Z2 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 20*256), 20*257)
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
	assert.False(t, nilProof.Verify(curve.Secp256k1{}, hash.New(), public))
}

func TestAffP_DeepTampering(t *testing.T) {
	group := curve.Secp256k1{}
	proof, public := tamperSetup(t)

	cases := map[string]func(p *Proof){
		"wrong E": func(p *Proof) { p.E = new(saferith.Nat).SetUint64(12345) },
		"wrong S": func(p *Proof) { p.S = new(saferith.Nat).SetUint64(12345) },
		"wrong F": func(p *Proof) { p.F = new(saferith.Nat).SetUint64(12345) },
		"wrong T": func(p *Proof) { p.T = new(saferith.Nat).SetUint64(12345) },
		"wrong A": func(p *Proof) {
			a, _ := public.Verifier.Enc(new(saferith.Int).SetUint64(999))
			p.A = a
		},
		"wrong Bx": func(p *Proof) {
			bx, _ := public.Prover.Enc(new(saferith.Int).SetUint64(999))
			p.Bx = bx
		},
		"wrong By": func(p *Proof) {
			by, _ := public.Prover.Enc(new(saferith.Int).SetUint64(999))
			p.By = by
		},
		"wrong Z1": func(p *Proof) {
			p.Z1 = new(saferith.Int).SetUint64(1)
		},
		"wrong W": func(p *Proof) {
			p.W = sample.UnitModN(rand.Reader, public.Verifier.N())
		},
		"wrong Wx": func(p *Proof) {
			p.Wx = sample.UnitModN(rand.Reader, public.Prover.N())
		},
		"Z1 outside interval": func(p *Proof) {
			p.Z1 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 1000), 1001)
		},
		"Z2 outside interval": func(p *Proof) {
			p.Z2 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 2000), 2001)
		},
		"A out of range": func(p *Proof) {
			nSquared := new(big.Int).Mul(public.Verifier.N().Big(), public.Verifier.N().Big())
			buf := make([]byte, 512)
			nSquared.FillBytes(buf)
			ct := new(paillier.Ciphertext)
			require.NoError(t, ct.UnmarshalBinary(buf))
			p.A = ct
		},
		"W out of range": func(p *Proof) {
			p.W = public.Verifier.N().Nat()
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := cloneProof(proof)
			mutate(tampered)
			assert.False(t, tampered.Verify(group, hash.New(), public))
		})
	}
}
