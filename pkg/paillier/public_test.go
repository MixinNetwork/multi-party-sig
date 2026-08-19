package paillier

import (
	"sync"
	"testing"

	"github.com/cronokirby/saferith"
)

// 2²⁵⁶ − 189, a prime; any non-zero value below it is a unit.
const testModulusHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43"

// ValidateCiphertexts and Equal must not mutate the public key's cached
// moduli: saferith's comparisons mutate their operands in place, and a
// *PublicKey from a Config can be shared between concurrent protocol
// sessions, where such mutation is a data race. Run under -race.
func TestValidateCiphertextsConcurrent(t *testing.T) {
	n, _ := new(saferith.Nat).SetHex(testModulusHex)
	pk := NewPublicKey(saferith.ModulusFromNat(n))
	ct := &Ciphertext{c: new(saferith.Nat).SetUint64(2)}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !pk.ValidateCiphertexts(ct) {
				t.Error("ValidateCiphertexts rejected a valid shared ciphertext")
			}
		}()
	}
	wg.Wait()
}

func TestEqualConcurrent(t *testing.T) {
	n, _ := new(saferith.Nat).SetHex(testModulusHex)
	pk := NewPublicKey(saferith.ModulusFromNat(n))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !pk.Equal(pk) {
				t.Error("Equal rejected a key compared with itself")
			}
		}()
	}
	wg.Wait()
}
