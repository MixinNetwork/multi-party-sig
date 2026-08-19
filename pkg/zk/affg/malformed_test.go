package zkaffg

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

	verifierPaillier := zk.VerifierPaillierPublic
	verifierPedersen := zk.Pedersen
	prover := zk.ProverPaillierPublic

	c := new(saferith.Int).SetUint64(12)
	C, _ := verifierPaillier.Enc(c)

	x := sample.IntervalL(rand.Reader)
	X := group.NewScalar().SetNat(x.Mod(group.Order())).ActOnBase()

	y := sample.IntervalLPrime(rand.Reader)
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
		X: x,
		Y: y,
		S: rho,
		R: rhoY,
	}
	proof := NewProof(group, hash.New(), public, private)
	require.True(t, proof.Verify(hash.New(), public))
	return proof, public
}

// invalidCiphertext returns a ciphertext whose value is N², i.e. out of the
// valid range, to exercise the ValidateCiphertexts rejection path.
func invalidCiphertext(t *testing.T, pk *paillier.PublicKey) *paillier.Ciphertext {
	t.Helper()
	nBig := pk.N().Big()
	nSquared := new(big.Int).Mul(nBig, nBig)
	buf := make([]byte, 512)
	nSquared.FillBytes(buf)
	ct := new(paillier.Ciphertext)
	require.NoError(t, ct.UnmarshalBinary(buf))
	return ct
}

// cloneProof returns a deep copy so that tampering does not leak into the
// original proof (the embedded *Commitment is shared by shallow copies).
func cloneProof(p *Proof) *Proof {
	return &Proof{
		group: p.group,
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
		Wy: p.Wy,
	}
}

func TestAffG_MalformedFields(t *testing.T) {
	proof, public := tamperSetup(t)
	group := curve.Secp256k1{}

	cases := map[string]func(p *Proof){
		"nil commitment":  func(p *Proof) { p.Commitment = nil },
		"nil S":           func(p *Proof) { p.S = nil },
		"nil T":           func(p *Proof) { p.T = nil },
		"nil A":           func(p *Proof) { p.A = nil },
		"nil Bx":          func(p *Proof) { p.Bx = nil },
		"nil By":          func(p *Proof) { p.By = nil },
		"nil E":           func(p *Proof) { p.E = nil },
		"nil F":           func(p *Proof) { p.F = nil },
		"nil Z1":          func(p *Proof) { p.Z1 = nil },
		"nil Z2":          func(p *Proof) { p.Z2 = nil },
		"nil Z3":          func(p *Proof) { p.Z3 = nil },
		"nil Z4":          func(p *Proof) { p.Z4 = nil },
		"nil W":           func(p *Proof) { p.W = nil },
		"nil Wy":          func(p *Proof) { p.Wy = nil },
		"identity Bx":     func(p *Proof) { p.Bx = group.NewPoint() },
		"oversized Z1":    func(p *Proof) { p.Z1 = new(saferith.Int).SetBytes(make([]byte, 64*1024)) },
		"oversized Z2":    func(p *Proof) { p.Z2 = new(saferith.Int).SetBytes(make([]byte, 64*1024)) },
		"oversized Z4":    func(p *Proof) { p.Z4 = new(saferith.Int).SetBytes(make([]byte, 64*1024)) },
		"invalid A range": func(p *Proof) { p.A = invalidCiphertext(t, public.Verifier) },
		"invalid W range": func(p *Proof) { p.W = public.Verifier.N().Nat() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := cloneProof(proof)
			mutate(tampered)
			assert.False(t, tampered.Verify(hash.New(), public))
		})
	}

	// a nil proof must not panic
	var nilProof *Proof
	assert.False(t, nilProof.Verify(hash.New(), public))
}

// TestAffG_DeepTampering mutates proof values in ways that pass the
// structural IsValid checks but break the verification equations.
func TestAffG_DeepTampering(t *testing.T) {
	proof, public := tamperSetup(t)
	group := curve.Secp256k1{}

	// Z1 outside ±2^(L+ε) but with a valid announced length
	tooBig := new(big.Int).Lsh(big.NewInt(1), 2000)
	cases := map[string]func(p *Proof){
		"Z1 outside interval": func(p *Proof) {
			p.Z1 = new(saferith.Int).SetBig(tooBig, tooBig.BitLen())
		},
		"Z2 outside interval": func(p *Proof) {
			p.Z2 = new(saferith.Int).SetBig(new(big.Int).Lsh(big.NewInt(1), 2000), 2001)
		},
		"wrong E": func(p *Proof) {
			p.E = new(saferith.Nat).SetUint64(12345)
		},
		"wrong S": func(p *Proof) {
			p.S = new(saferith.Nat).SetUint64(12345)
		},
		"wrong F": func(p *Proof) {
			p.F = new(saferith.Nat).SetUint64(12345)
		},
		"wrong T": func(p *Proof) {
			p.T = new(saferith.Nat).SetUint64(12345)
		},
		"wrong A": func(p *Proof) {
			a, _ := public.Verifier.Enc(new(saferith.Int).SetUint64(999))
			p.A = a
		},
		"wrong By": func(p *Proof) {
			by, _ := public.Prover.Enc(new(saferith.Int).SetUint64(999))
			p.By = by
		},
		"wrong Bx": func(p *Proof) {
			p.Bx = group.NewScalar().SetNat(new(saferith.Nat).SetUint64(999)).ActOnBase()
		},
		"wrong Z1 value": func(p *Proof) {
			p.Z1 = new(saferith.Int).SetNat(p.Z1.Abs()).Add(new(saferith.Int).SetUint64(1), new(saferith.Int).SetUint64(0), 5120)
		},
		"wrong W": func(p *Proof) {
			p.W = sample.UnitModN(rand.Reader, public.Verifier.N())
		},
		"wrong Wy": func(p *Proof) {
			p.Wy = sample.UnitModN(rand.Reader, public.Prover.N())
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := cloneProof(proof)
			mutate(tampered)
			assert.False(t, tampered.Verify(hash.New(), public))
		})
	}
}
