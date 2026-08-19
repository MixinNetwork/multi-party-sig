package arith

import (
	"sync"
	"testing"

	"github.com/cronokirby/saferith"
)

func TestIsValidIntLen(t *testing.T) {
	if IsValidIntLen(nil) {
		t.Error("IsValidIntLen accepted nil")
	}
	// a small value is fine
	if !IsValidIntLen(new(saferith.Int).SetUint64(42)) {
		t.Error("IsValidIntLen rejected a small value")
	}
	// the largest legitimate proof response (Πfac's v, ~4865 bits) is fine
	if !IsValidIntLen(new(saferith.Int).SetBytes(make([]byte, 609))) {
		t.Errorf("IsValidIntLen rejected %d announced bits", 609*8)
	}
	// exactly at the cap is fine
	if !IsValidIntLen(new(saferith.Int).SetBytes(make([]byte, MaxIntResponseBits/8))) {
		t.Error("IsValidIntLen rejected the maximum allowed size")
	}
	// anything larger must be rejected — crucially, even when the value is
	// zero: the announced size alone drives the cost of exponentiations.
	big := new(saferith.Int).SetBytes(make([]byte, MaxIntResponseBits/8+1))
	if big.TrueLen() != 0 {
		t.Fatal("test setup: expected a zero value")
	}
	if IsValidIntLen(big) {
		t.Error("IsValidIntLen accepted an oversized zero value (announced-size DoS)")
	}
}

func TestIsValidNatModNRejectsOverAnnounced(t *testing.T) {
	n := saferith.ModulusFromNat(new(saferith.Nat).SetUint64(0xFFFFFF01)) // ~2^32, odd
	// an honest unit mod N is accepted
	if !IsValidNatModN(n, new(saferith.Nat).SetUint64(42)) {
		t.Error("IsValidNatModN rejected an honest unit")
	}
	// the same value zero-padded to a large announced length must be rejected:
	// the announced length drives the cost of the constant-time checks.
	padded := make([]byte, 4096)
	padded[len(padded)-1] = 42
	if IsValidNatModN(n, new(saferith.Nat).SetBytes(padded)) {
		t.Error("IsValidNatModN accepted a zero-padded value (announced-size DoS)")
	}
}

// IsValidNatModN must not mutate the modulus or the values it checks:
// saferith's Cmp mutates both operands in place, and these inputs are shared
// between concurrent protocol sessions (e.g. via a Config), where such
// mutation is a data race. Run under -race.
func TestIsValidNatModNConcurrent(t *testing.T) {
	// 2²⁵⁶ − 189, a prime, so every non-zero value below it is a unit.
	n, _ := new(saferith.Nat).SetHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43")
	N := saferith.ModulusFromNat(n)
	shared := new(saferith.Nat).SetUint64(42)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !IsValidNatModN(N, shared) {
				t.Error("IsValidNatModN rejected a valid shared value")
			}
		}()
	}
	wg.Wait()
}
