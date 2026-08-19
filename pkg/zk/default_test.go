package zk

import (
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/pedersen"
)

// TestGenerate simply exercises the debug helper that regenerates the
// fixed test keys; its output can be copy-pasted into default.go.
func TestGenerate(t *testing.T) {
	if testing.Short() {
		t.Skip("generates two fresh Paillier keys")
	}
	generate()

	// the package-level fixtures must be initialized and consistent
	if ProverPaillierPublic == nil || VerifierPaillierPublic == nil || Pedersen == nil {
		t.Fatal("package fixtures not initialized")
	}
	if !ProverPaillierPublic.Equal(ProverPaillierSecret.PublicKey) {
		t.Fatal("prover public key does not match its secret key")
	}
	if !VerifierPaillierPublic.Equal(VerifierPaillierSecret.PublicKey) {
		t.Fatal("verifier public key does not match its secret key")
	}
	if err := pedersen.ValidateParameters(VerifierPaillierPublic.N(), Pedersen.S(), Pedersen.T()); err != nil {
		t.Fatal("pedersen parameters invalid:", err)
	}
}
