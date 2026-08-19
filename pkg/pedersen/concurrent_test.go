package pedersen

import (
	"sync"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/arith"
	"github.com/cronokirby/saferith"
)

// concurrentParameters returns parameters over 2²⁵⁶ − 189, a prime ≡ 3 mod 4,
// with s = 4 and t = 9: two non-trivial quadratic residues. Commit and Verify
// do not require s ∈ ⟨t⟩ (that is what Π^prm proves), so this suffices to
// exercise their arithmetic.
func concurrentParameters(t *testing.T) *Parameters {
	t.Helper()
	n, err := new(saferith.Nat).SetHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43")
	if err != nil {
		t.Fatalf("test setup: %v", err)
	}
	N := saferith.ModulusFromNat(n)
	params := New(arith.ModulusFromN(N), new(saferith.Nat).SetUint64(4), new(saferith.Nat).SetUint64(9))
	if err := ValidateParameters(N, params.S(), params.T()); err != nil {
		t.Fatalf("test setup: %v", err)
	}
	return params
}

// Concurrent protocol sessions share the Config's Pedersen parameters, so
// Commit and Verify must not mutate them in place (saferith's arithmetic
// mutates receivers, and its comparisons mutate both operands). Results are
// compared through private clones for the same reason. Run under -race.
func TestCommitConcurrentSharedParameters(t *testing.T) {
	params := concurrentParameters(t)
	x := new(saferith.Int).SetUint64(11)
	y := new(saferith.Int).SetUint64(13)
	expected := params.Commit(x, y)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				got := params.Commit(x, y)
				if _, eq, _ := got.Clone().Cmp(expected.Clone()); eq != 1 {
					t.Error("Commit returned an inconsistent result")
				}
			}
		}()
	}
	wg.Wait()
}

func TestVerifyConcurrentSharedParameters(t *testing.T) {
	params := concurrentParameters(t)
	a := new(saferith.Int).SetUint64(3)
	b := new(saferith.Int).SetUint64(5)
	e := new(saferith.Int).SetUint64(7)
	S := params.Commit(a, b)
	T := params.Commit(b, a)
	expected := params.Verify(a, b, e, S, T)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if got := params.Verify(a, b, e, S, T); got != expected {
					t.Error("Verify returned an inconsistent result")
				}
			}
		}()
	}
	wg.Wait()
}
