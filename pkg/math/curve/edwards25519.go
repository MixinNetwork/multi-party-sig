package curve

import (
	"errors"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/cronokirby/saferith"
)

var (
	// l = 2 ^ 252 + 27742317777372353535851937790883648493
	b, _              = new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	l                 = new(big.Int).Add(b, new(big.Int).Exp(big.NewInt(2), big.NewInt(252), nil))
	edwards25519Order = saferith.ModulusFromNat(new(saferith.Nat).SetBig(l, 512))
)

type Edwards25519 struct{}

func (Edwards25519) NewPoint() Point {
	return &Edwards25519Point{*edwards25519.NewIdentityPoint()}
}

func (Edwards25519) NewBasePoint() Point {
	out := new(Edwards25519Point)
	out.value = *edwards25519.NewGeneratorPoint()
	return out
}

func (Edwards25519) NewScalar() Scalar {
	return &Edwards25519Scalar{*edwards25519.NewScalar()}
}

func (Edwards25519) ScalarBits() int {
	return 256
}

func (Edwards25519) SafeScalarBytes() int {
	return 64
}

func (Edwards25519) Order() *saferith.Modulus {
	return edwards25519Order
}

func (Edwards25519) Name() string {
	return "edwards25519"
}

type Edwards25519Scalar struct {
	value edwards25519.Scalar
}

func edwards25519CastScalar(generic Scalar) *Edwards25519Scalar {
	return generic.(*Edwards25519Scalar)
}

func (*Edwards25519Scalar) Curve() Curve {
	return Edwards25519{}
}

func (s *Edwards25519Scalar) MarshalBinary() ([]byte, error) {
	data := s.value.Bytes()
	return data[:], nil
}

func (s *Edwards25519Scalar) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for edwards25519 scalar: %d", len(data))
	}
	value, err := s.value.SetCanonicalBytes(data)
	if err != nil {
		return errors.New("invalid bytes for edwards25519 scalar")
	}
	s.value = *value
	return nil
}

func (s *Edwards25519Scalar) Add(that Scalar) Scalar {
	other := edwards25519CastScalar(that)
	s.value.Add(&s.value, &other.value)
	return s
}

func (s *Edwards25519Scalar) Sub(that Scalar) Scalar {
	other := edwards25519CastScalar(that)
	s.value.Subtract(&s.value, &other.value)
	return s
}

func (s *Edwards25519Scalar) Mul(that Scalar) Scalar {
	other := edwards25519CastScalar(that)
	s.value.Multiply(&s.value, &other.value)
	return s
}

func (s *Edwards25519Scalar) Invert() Scalar {
	s.value.Invert(&s.value)
	return s
}

func (s *Edwards25519Scalar) Negate() Scalar {
	s.value.Negate(&s.value)
	return s
}

func (s *Edwards25519Scalar) Equal(that Scalar) bool {
	other := edwards25519CastScalar(that)

	return s.value.Equal(&other.value) == 1
}

func (s *Edwards25519Scalar) IsZero() bool {
	return s.value.Equal(edwards25519.NewScalar()) == 1
}

func (s *Edwards25519Scalar) Set(that Scalar) Scalar {
	other := edwards25519CastScalar(that)

	s.value.Set(&other.value)
	return s
}

func (s *Edwards25519Scalar) SetNat(x *saferith.Nat) Scalar {
	buf := make([]byte, 64)
	buf = x.FillBytes(buf)
	if len(buf) != 64 {
		panic(len(buf))
	}
	s.value.SetUniformBytes(buf)
	return s
}

func (s *Edwards25519Scalar) Act(that Point) Point {
	other := edwards25519CastPoint(that)
	out := new(Edwards25519Point)
	out.value.ScalarMult(&s.value, &other.value)
	return out
}

func (s *Edwards25519Scalar) ActOnBase() Point {
	out := new(Edwards25519Point)
	out.value.ScalarBaseMult(&s.value)
	return out
}

func (s *Edwards25519Scalar) Bytes() []byte {
	b, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

type Edwards25519Point struct {
	value edwards25519.Point
}

func edwards25519CastPoint(generic Point) *Edwards25519Point {
	return generic.(*Edwards25519Point)
}

func (*Edwards25519Point) Curve() Curve {
	return Edwards25519{}
}

func (p *Edwards25519Point) MarshalBinary() ([]byte, error) {
	return p.value.Bytes(), nil
}

func (p *Edwards25519Point) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid edwards25519 point length: %d", len(data))
	}
	_, err := p.value.SetBytes(data)
	return err
}

func (p *Edwards25519Point) Add(that Point) Point {
	other := edwards25519CastPoint(that)

	out := new(Edwards25519Point)
	out.value.Add(&p.value, &other.value)
	return out
}

func (p *Edwards25519Point) Sub(that Point) Point {
	other := edwards25519CastPoint(that)

	out := new(Edwards25519Point)
	out.value.Subtract(&p.value, &other.value)
	return out
}

func (p *Edwards25519Point) Set(that Point) Point {
	other := edwards25519CastPoint(that)
	p.value.Set(&other.value)
	return p
}

func (p *Edwards25519Point) Negate() Point {
	out := new(Edwards25519Point)
	out.value.Negate(&p.value)
	return out
}

func (p *Edwards25519Point) Equal(that Point) bool {
	other := edwards25519CastPoint(that)
	return p.value.Equal(&other.value) == 1
}

func (p *Edwards25519Point) IsIdentity() bool {
	return p.value.Equal(edwards25519.NewIdentityPoint()) == 1
}

func (p *Edwards25519Point) HasEvenY() bool {
	return false
}

func (p *Edwards25519Point) XScalar() Scalar {
	return nil
}

func (p *Edwards25519Point) YScalar() Scalar {
	return nil
}
