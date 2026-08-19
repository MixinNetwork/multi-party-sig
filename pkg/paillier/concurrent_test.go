package paillier

import (
	"crypto/rand"
	"sync"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
)

// Concurrent protocol sessions share the Config's Paillier keys, so every
// operation reading them must not mutate shared state in place: saferith's
// arithmetic mutates its receiver, and some functions (the comparison family,
// Nat.Add/Sub/Mul, shifts) mutate their operands as well. The tests below
// hammer the read paths reached by concurrent sign sessions. Run under -race.
//
// They share the fixed keys from the package fixtures, and compare results
// through private clones for the same reason: Equal/Eq mutate both operands.
func TestEncWithNonceConcurrentSharedKey(t *testing.T) {
	m := new(saferith.Int).SetUint64(42)
	nonce := sample.UnitModN(rand.Reader, paillierPublic.N())
	expected := paillierPublic.EncWithNonce(m, nonce)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				got := paillierPublic.EncWithNonce(m, nonce)
				if !got.Equal(expected.Clone()) {
					t.Error("EncWithNonce returned an inconsistent result")
				}
			}
		}()
	}
	wg.Wait()
}

func TestDecConcurrentSharedKey(t *testing.T) {
	m := new(saferith.Int).SetUint64(1234)
	ct, _ := paillierPublic.Enc(m)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				got, err := paillierSecret.Dec(ct)
				if err != nil {
					t.Errorf("Dec failed on a valid shared ciphertext: %v", err)
					return
				}
				if got.Eq(m.Clone()) != 1 {
					t.Error("Dec returned an inconsistent plaintext")
				}
			}
		}()
	}
	wg.Wait()
}

func TestCiphertextCloneMulConcurrentShared(t *testing.T) {
	ct, _ := paillierPublic.Enc(new(saferith.Int).SetUint64(7))
	k := new(saferith.Int).SetUint64(9)
	expected := ct.Clone().Mul(paillierPublic, k)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				got := ct.Clone().Mul(paillierPublic, k)
				if !got.Equal(expected.Clone()) {
					t.Error("Clone().Mul returned an inconsistent result")
				}
			}
		}()
	}
	wg.Wait()
}
