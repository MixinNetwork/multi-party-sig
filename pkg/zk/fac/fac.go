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
	N := public.Aux.NArith()

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
	T := N.ExpI(Q, alpha)
	T.ModMul(T, N.ExpI(public.Aux.T(), r), N.Modulus)

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

	e, err := challenge(hash, public, p.Comm)
	if err != nil {
		return false
	}

	N := public.Aux.N()
	NArith := public.Aux.NArith()
	// Setting R this way avoid issues with the other exponent functions which
	// might try and apply the CRT.
	R := new(saferith.Nat).SetNat(public.Aux.S())
	R.ExpI(R, new(saferith.Int).SetNat(N.Nat()), N)
	R.ModMul(R, NArith.ExpI(public.Aux.T(), p.Sigma), N)

	lhs := public.Aux.Commit(p.Z1, p.W1)
	rhs := NArith.ExpI(p.Comm.P, e)
	rhs.ModMul(rhs, p.Comm.A, N)
	if lhs.Eq(rhs) != 1 {
		return false
	}

	lhs = public.Aux.Commit(p.Z2, p.W2)
	rhs = NArith.ExpI(p.Comm.Q, e)
	rhs.ModMul(rhs, p.Comm.B, N)
	if lhs.Eq(rhs) != 1 {
		return false
	}

	lhs = NArith.ExpI(p.Comm.Q, p.Z1)
	lhs.ModMul(lhs, NArith.ExpI(public.Aux.T(), p.V), N)
	rhs = NArith.ExpI(R, e)
	rhs.ModMul(rhs, p.Comm.T, N)
	if lhs.Eq(rhs) != 1 {
		return false
	}

	// DEVIATION: for the bounds to work, we add an extra bit, to ensure that we don't have spurious failures.
	return arith.IsInIntervalLEpsPlus1RootN(p.Z1) && arith.IsInIntervalLEpsPlus1RootN(p.Z2)
}

func challenge(hash *hash.Hash, public Public, commitment Commitment) (*saferith.Int, error) {
	err := hash.WriteAny(public.Aux, commitment.P, commitment.Q, commitment.A, commitment.B, commitment.T)
	if err != nil {
		return nil, err
	}
	// Figure 28, point 2:
	// "Verifier replies with e <- +-q"
	// DEVIATION:
	// This doesn't make any sense, since we don't know the secret factor q,
	// and involving the size of scalars doesn't make sense.
	// I think that this is a typo in the paper, and instead it should
	// be +-2^eps.
	return sample.IntervalEps(hash.Digest()), nil
}
