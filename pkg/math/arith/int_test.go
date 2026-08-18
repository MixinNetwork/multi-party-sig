package arith

import (
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
