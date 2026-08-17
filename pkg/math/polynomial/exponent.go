package polynomial

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
)

type rawExponentData struct {
	IsConstant   bool
	Coefficients []curve.Point
}

// Exponent represent a polynomial F(X) whose coefficients belong to a group 𝔾.
type Exponent struct {
	group curve.Curve
	// IsConstant indicates that the constant coefficient is the identity.
	// We do this so that we never need to send an encoded Identity point, and thus consider it invalid
	IsConstant bool
	// coefficients is a list of curve.Point representing the coefficients of a polynomial over an elliptic curve.
	coefficients []curve.Point
}

// NewPolynomialExponent generates an Exponent polynomial F(X) = [secret + a₁•X + … + aₜ•Xᵗ]•G,
// with coefficients in 𝔾, and degree t.
func NewPolynomialExponent(polynomial *Polynomial) *Exponent {
	p := &Exponent{
		group:        polynomial.group,
		IsConstant:   polynomial.coefficients[0].IsZero(),
		coefficients: make([]curve.Point, 0, len(polynomial.coefficients)),
	}

	for i, c := range polynomial.coefficients {
		if p.IsConstant && i == 0 {
			continue
		}
		p.coefficients = append(p.coefficients, c.ActOnBase())
	}

	return p
}

// Evaluate returns F(x) = [secret + a₁•x + … + aₜ•xᵗ]•G.
func (p *Exponent) Evaluate(x curve.Scalar) curve.Point {
	result := p.group.NewPoint()

	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// Bₙ₋₁ = [x]Bₙ  + Aₙ₋₁
		result = x.Act(result).Add(p.coefficients[i])
	}

	if p.IsConstant {
		// result is B₁
		// we want B₀ = [x]B₁ + A₀ = [x]B₁
		result = x.Act(result)
	}

	return result
}

// evaluateClassic evaluates a polynomial in a given variable index
// We do the classic method, where we compute all powers of x.
func (p *Exponent) evaluateClassic(x curve.Scalar) curve.Point {
	var tmp curve.Point

	xPower := p.group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	result := p.group.NewPoint()

	if p.IsConstant {
		// since we start at index 1 of the polynomial, x must be x and not 1
		xPower.Mul(x)
	}

	for i := 0; i < len(p.coefficients); i++ {
		// tmp = [xⁱ]Aᵢ
		tmp = xPower.Act(p.coefficients[i])
		// result += [xⁱ]Aᵢ
		result = result.Add(tmp)
		// x = xⁱ⁺¹
		xPower.Mul(x)
	}
	return result
}

// Degree returns the degree t of the polynomial.
func (p *Exponent) Degree() int {
	if p.IsConstant {
		return len(p.coefficients)
	}
	return len(p.coefficients) - 1
}

func (p *Exponent) add(q *Exponent) error {
	if len(p.coefficients) != len(q.coefficients) {
		return errors.New("q is not the same length as p")
	}

	if p.IsConstant != q.IsConstant {
		return errors.New("p and q differ in 'IsConstant'")
	}

	for i := 0; i < len(p.coefficients); i++ {
		p.coefficients[i] = p.coefficients[i].Add(q.coefficients[i])
	}

	return nil
}

// Sum creates a new Polynomial in the Exponent, by summing a slice of existing ones.
func Sum(polynomials []*Exponent) (*Exponent, error) {
	var err error

	// Create the new polynomial by copying the first one given
	summed := polynomials[0].copy()

	// we assume all polynomials have the same degree as the first
	for j := 1; j < len(polynomials); j++ {
		err = summed.add(polynomials[j])
		if err != nil {
			return nil, err
		}
	}
	return summed, nil
}

func (p *Exponent) copy() *Exponent {
	q := &Exponent{
		group:        p.group,
		IsConstant:   p.IsConstant,
		coefficients: make([]curve.Point, 0, len(p.coefficients)),
	}
	for i := 0; i < len(p.coefficients); i++ {
		q.coefficients = append(q.coefficients, p.coefficients[i])
	}
	return q
}

// Equal returns true if p ≡ other.
func (p *Exponent) Equal(other Exponent) bool {
	if p.IsConstant != other.IsConstant {
		return false
	}
	if len(p.coefficients) != len(other.coefficients) {
		return false
	}
	for i := 0; i < len(p.coefficients); i++ {
		if !p.coefficients[i].Equal(other.coefficients[i]) {
			return false
		}
	}
	return true
}

// Constant returns the constant coefficient of the polynomial 'in the exponent'.
func (p *Exponent) Constant() curve.Point {
	c := p.group.NewPoint()
	if p.IsConstant {
		return c
	}
	return p.coefficients[0]
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (p *Exponent) WriteTo(w io.Writer) (int64, error) {
	data, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	total, err := w.Write(data)
	return int64(total), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (*Exponent) Domain() string {
	return "Exponent"
}

func EmptyExponent(group curve.Curve) *Exponent {
	// TODO create custom marshaller
	return &Exponent{group: group}
}

func (e *Exponent) UnmarshalBinary(data []byte) error {
	if e == nil || e.group == nil {
		return errors.New("can't unmarshal Exponent with no group")
	}
	if len(data) < 4 {
		return errors.New("can't unmarshal Exponent: data too short")
	}
	group := e.group
	size := binary.BigEndian.Uint32(data)
	// Every serialized coefficient occupies at least 32 bytes, so a well-formed
	// message can never contain more than len(data)/32 of them. Enforcing this
	// bound before allocating prevents memory exhaustion from a malformed or
	// malicious length prefix.
	const minSerializedPointSize = 32
	if uint64(size) > uint64(len(data))/minSerializedPointSize {
		return fmt.Errorf("can't unmarshal Exponent: claimed %d coefficients in %d bytes", size, len(data))
	}
	e.coefficients = make([]curve.Point, int(size))
	for i := 0; i < len(e.coefficients); i++ {
		e.coefficients[i] = group.NewPoint()
	}
	rawExponent := rawExponentData{Coefficients: e.coefficients}
	if err := cbor.Unmarshal(data[4:], &rawExponent); err != nil {
		return err
	}
	e.group = group
	e.coefficients = rawExponent.Coefficients
	e.IsConstant = rawExponent.IsConstant
	return nil
}

func (e *Exponent) MarshalBinary() ([]byte, error) {
	enc, _ := cbor.CanonicalEncOptions().EncMode()
	data, err := enc.Marshal(rawExponentData{
		IsConstant:   e.IsConstant,
		Coefficients: e.coefficients,
	})
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(data))
	size := len(e.coefficients)
	binary.BigEndian.PutUint32(out, uint32(size))
	copy(out[4:], data)
	return out, nil
}
