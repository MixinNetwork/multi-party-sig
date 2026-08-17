package zkfac

import (
	"crypto/rand"

	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/arith"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/pedersen"
	"github.com/cronokirby/saferith"
)

type Public struct {
	// N is the modulus whose factorization is being proven (N = p⋅q, with p, q large).
	N *saferith.Modulus
	// Aux are the verifier's Pedersen parameters (N̂, s, t), used to commit to the factors.
	Aux *pedersen.Parameters
}

type Private struct {
	P, Q *saferith.Nat
}

type Commitment struct {
	P *saferith.Nat
	Q *saferith.Nat
	A *saferith.Nat
	B *saferith.Nat
	T *saferith.Nat
}

type Proof struct {
	Comm  Commitment
	Sigma *saferith.Int
	Z1    *saferith.Int
	Z2    *saferith.Int
	W1    *saferith.Int
	W2    *saferith.Int
	V     *saferith.Int
}

func NewProof(private Private, hash *hash.Hash, public Public) *Proof {
	Nhat := public.Aux.NArith()

	// Figure 28, point 1.
	alpha := sample.IntervalLEpsRootN(rand.Reader)
	beta := sample.IntervalLEpsRootN(rand.Reader)
	mu := sample.IntervalLN(rand.Reader)
	nu := sample.IntervalLN(rand.Reader)
	sigma := sample.IntervalLN2(rand.Reader)
	r := sample.IntervalLEpsN2(rand.Reader)
	x := sample.IntervalLEpsN(rand.Reader)
	y := sample.IntervalLEpsN(rand.Reader)

	pInt := new(saferith.Int).SetNat(private.P)
	qInt := new(saferith.Int).SetNat(private.Q)
	P := public.Aux.Commit(pInt, mu)
	Q := public.Aux.Commit(qInt, nu)
	A := public.Aux.Commit(alpha, x)
	B := public.Aux.Commit(beta, y)
	T := Nhat.ExpI(Q, alpha)
	T.ModMul(T, Nhat.ExpI(public.Aux.T(), r), Nhat.Modulus)

	comm := Commitment{P, Q, A, B, T}

	// Figure 28, point 2:
	e, _ := challenge(hash, public, comm)

	// Figure 28, point 3:
	// "..., and sends (z, u, v) to the verifier, where"
	// DEVIATION:
	// This seems like another typo, because there's no "u",
	// so I assume they meant "sends (z1, z2, w1, w2, v)".
	z1 := new(saferith.Int).Mul(e, pInt, -1)
	z1.Add(z1, alpha, -1)
	z2 := new(saferith.Int).Mul(e, qInt, -1)
	z2.Add(z2, beta, -1)
	w1 := new(saferith.Int).Mul(e, mu, -1)
	w1.Add(w1, x, -1)
	w2 := new(saferith.Int).Mul(e, nu, -1)
	w2.Add(w2, y, -1)
	sigmaHat := new(saferith.Int).Mul(nu, pInt, -1)
	sigmaHat = sigmaHat.Neg(1)
	sigmaHat.Add(sigmaHat, sigma, -1)
	v := new(saferith.Int).Mul(e, sigmaHat, -1)
	v.Add(v, r, -1)

	return &Proof{
		Comm:  comm,
		Sigma: sigma,
		Z1:    z1,
		Z2:    z2,
		W1:    w1,
		W2:    w2,
		V:     v,
	}
}

func (p *Proof) Verify(public Public, hash *hash.Hash) bool {
	if p == nil {
		return false
	}
	// guard against malformed (e.g. CBOR-decoded) proofs and statements
	if public.N == nil || public.Aux == nil {
		return false
	}
	if p.Comm.P == nil || p.Comm.Q == nil || p.Comm.A == nil || p.Comm.B == nil || p.Comm.T == nil ||
		p.Sigma == nil || p.Z1 == nil || p.Z2 == nil || p.W1 == nil || p.W2 == nil || p.V == nil {
		return false
	}

	e, err := challenge(hash, public, p.Comm)
	if err != nil {
		return false
	}

	N0 := public.N
	NhatArith := public.Aux.NArith()
	Nhat := NhatArith.Modulus

	if !public.Aux.Verify(p.Z1, p.W1, e, p.Comm.A, p.Comm.P) {
		return false
	}

	if !public.Aux.Verify(p.Z2, p.W2, e, p.Comm.B, p.Comm.Q) {
		return false
	}

	// Setting R this way avoid issues with the other exponent functions which
	// might try and apply the CRT.
	R := new(saferith.Nat).SetNat(public.Aux.S())
	R = NhatArith.Exp(R, N0.Nat())
	R.ModMul(R, NhatArith.ExpI(public.Aux.T(), p.Sigma), Nhat)

	lhs := NhatArith.ExpI(p.Comm.Q, p.Z1)
	lhs.ModMul(lhs, NhatArith.ExpI(public.Aux.T(), p.V), Nhat)
	rhs := NhatArith.ExpI(R, e)
	rhs.ModMul(rhs, p.Comm.T, Nhat)
	if lhs.Eq(rhs) != 1 {
		return false
	}

	// DEVIATION: for the bounds to work, we add an extra bit, to ensure that we don't have spurious failures.
	return arith.IsInIntervalLEpsPlus1RootN(p.Z1) && arith.IsInIntervalLEpsPlus1RootN(p.Z2)
}

func challenge(hash *hash.Hash, public Public, commitment Commitment) (*saferith.Int, error) {
	err := hash.WriteAny(public.N, public.Aux, commitment.P, commitment.Q, commitment.A, commitment.B, commitment.T)
	if err != nil {
		return nil, err
	}
	// Figure 26, point 2:
	// "Verifier replies with e <- ±2ˡ"
	return sample.IntervalL(hash.Digest()), nil
}
