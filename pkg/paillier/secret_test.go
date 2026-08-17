package paillier

import (
	"testing"

	"github.com/cronokirby/saferith"
)

func TestValidatePrime(t *testing.T) {
	// a valid 1024-bit safe prime must be accepted (from TestCiphertextValidate's init)
	if err := ValidatePrime(paillierSecret.P()); err != nil {
		t.Error("ValidatePrime rejected a valid safe prime:", err)
	}

	// pComposite = 2q+1 with q prime, q ≡ 1 (mod 12): pComposite is 1024-bit,
	// pComposite ≡ 3 (mod 4), and (pComposite-1)/2 = q is prime, but pComposite
	// is divisible by 3 and therefore composite.
	// A previous version of ValidatePrime failed to check the primality of p
	// itself and accepted this value.
	pComposite, _ := new(saferith.Nat).SetHex("C4AE6F2915E500544D5870E7537398FAA2FBA30F66B8A68AD5F7C851287A6AA2A744E7A43ADF7222B1164467E03789DEF66B9466049AF0BD125571AA61568A53DFB02FAF11459E5E618E5D6E2D56741007678FB0FB5C932A455E66B47860FA3197A34616C74451DC7F1C56FF4A1311E25EF536F656FBEF89052FCF56D1440D1B")
	if err := ValidatePrime(pComposite); err == nil {
		t.Error("ValidatePrime accepted a composite factor")
	}
}
