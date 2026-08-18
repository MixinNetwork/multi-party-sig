package curve

import (
	"testing"

	"github.com/cronokirby/saferith"
)

func TestSecp256k1PointUnmarshalCanonicalPrefix(t *testing.T) {
	group := Secp256k1{}
	p := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(42)).ActOnBase()
	canonical, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// the canonical encoding round-trips
	q := group.NewPoint()
	if err := q.UnmarshalBinary(canonical); err != nil {
		t.Fatalf("canonical encoding rejected: %v", err)
	}
	if !q.Equal(p) {
		t.Error("round-trip changed the point")
	}

	// any prefix other than 0x02 (even Y) and 0x03 (odd Y) must be rejected,
	// even though it would decode to a valid point otherwise
	for _, prefix := range []byte{0x00, 0x01, 0x04, 0x06, 0x07, 0xff} {
		mut := make([]byte, len(canonical))
		copy(mut, canonical)
		mut[0] = prefix
		if err := group.NewPoint().UnmarshalBinary(mut); err == nil {
			t.Errorf("prefix 0x%02x: non-canonical encoding accepted", prefix)
		}
	}
}
