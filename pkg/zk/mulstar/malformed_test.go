package zkmulstar

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/zk"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tamperSetup(t *testing.T) (*Proof, Public) {
	t.Helper()
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
	require.True(t, proof.Verify(group, hash.New(), public))
	return proof, public
}

func cloneProof(p *Proof) *Proof {
	return &Proof{
		group: p.group,
		Commitment: &Commitment{
			A:  p.A,
			Bx: p.Bx,
			E:  p.E,
			S:  p.S,
		},
		Z1: p.Z1,
		Z2: p.Z2,
		W:  p.W,
	}
}

func TestMulStar_MalformedFields(t *testing.T) {
	group := curve.Secp256k1{}
	proof, public := tamperSetup(t)

	cases := map[string]func(p *Proof){
		"nil commitment": func(p *Proof) { p.Commitment = nil },
		"nil A":          func(p *Proof) { p.A = nil },
		"nil Bx":         func(p *Proof) { p.Bx = nil },
		"nil E":          func(p *Proof) { p.E = nil },
		"nil S":          func(p *Proof) { p.S = nil },
		"nil Z1":         func(p *Proof) { p.Z1 = nil },
		"nil Z2":         func(p *Proof) { p.Z2 = nil },
		"nil W":          func(p *Proof) { p.W = nil },
		"identity Bx":    func(p *Proof) { p.Bx = group.NewPoint() },
		"oversized Z1": func(p *Proof) {
			p.Z1 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 20*256), 20*257)
		},
		"oversized Z2": func(p *Proof) {
			p.Z2 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 20*256), 20*257)
		},
		"W out of range": func(p *Proof) {
			p.W = public.Verifier.N().Nat()
		},
		"Z1 outside interval": func(p *Proof) {
			p.Z1 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 1000), 1001)
		},
		"wrong E": func(p *Proof) {
			p.E = new(saferith.Nat).SetUint64(12345)
		},
		"wrong Bx": func(p *Proof) {
			p.Bx = group.NewScalar().SetNat(new(saferith.Nat).SetUint64(999)).ActOnBase()
		},
		"wrong W": func(p *Proof) {
			p.W = sample.UnitModN(rand.Reader, public.Verifier.N())
		},
		"wrong A": func(p *Proof) {
			a, _ := public.Verifier.Enc(new(saferith.Int).SetUint64(999))
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
