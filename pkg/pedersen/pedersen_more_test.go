package pedersen

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestError_Error(t *testing.T) {
	err := ErrNilFields
	assert.Equal(t, "pedersen: contains nil field", err.Error())

	// each sentinel must produce a distinct message
	sentinels := []Error{ErrNilFields, ErrSEqualT, ErrNotValidModN, ErrNEven, ErrTrivial, ErrNotQR}
	seen := map[string]bool{}
	for _, s := range sentinels {
		msg := s.Error()
		assert.NotEmpty(t, msg)
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}

func TestValidateParameters_Nil(t *testing.T) {
	p := benchParams
	assert.ErrorIs(t, ValidateParameters(nil, p.s, p.t), ErrNilFields)
	assert.ErrorIs(t, ValidateParameters(p.n.Modulus, nil, p.t), ErrNilFields)
	assert.ErrorIs(t, ValidateParameters(p.n.Modulus, p.s, nil), ErrNilFields)
}

func TestParameters_Accessors(t *testing.T) {
	p := benchParams
	assert.Equal(t, p.n.Modulus, p.N())
	assert.Equal(t, p.n, p.NArith())
	assert.Equal(t, p.s, p.S())
	assert.Equal(t, p.t, p.T())
}

func TestParameters_CommitVerify(t *testing.T) {
	p := benchParams

	x := sample.IntervalL(rand.Reader)
	y := sample.IntervalL(rand.Reader)
	S := p.Commit(x, y)

	e := sample.IntervalL(rand.Reader)
	// a correct opening must verify: sˣtʸ = S⋅T⁰ with e = 0
	zero := new(saferith.Int).SetUint64(0)
	assert.True(t, p.Verify(x, y, zero, S, benchParams.t))

	// a correct randomized opening must verify: with S' = sˣtʸ T⁻ᵉ and
	// challenge e, we get sˣtʸ = S' Tᵉ
	eNeg := e.Clone().Neg(1)
	te := p.n.ExpI(p.t, eNeg)
	S2 := S.ModMul(S, te, p.n.Modulus)
	assert.True(t, p.Verify(x, y, e, S2, p.t))

	// incorrect openings must not verify
	assert.False(t, p.Verify(x, y, zero, S2, p.t))
	wrongX := new(saferith.Int).SetUint64(1)
	assert.False(t, p.Verify(wrongX, y, zero, S, p.t))
}

func TestParameters_VerifyNilAndRange(t *testing.T) {
	p := benchParams
	x := sample.IntervalL(rand.Reader)
	y := sample.IntervalL(rand.Reader)
	S := p.Commit(x, y)
	e := new(saferith.Int).SetUint64(0)

	// nil arguments must be rejected
	assert.False(t, p.Verify(nil, y, e, S, p.t))
	assert.False(t, p.Verify(x, nil, e, S, p.t))
	assert.False(t, p.Verify(x, y, nil, S, p.t))
	assert.False(t, p.Verify(x, y, e, nil, p.t))
	assert.False(t, p.Verify(x, y, e, S, nil))

	// S, T must be in range
	bigS := new(saferith.Nat).SetNat(p.n.Nat())
	assert.False(t, p.Verify(x, y, e, bigS, p.t))
	zero := new(saferith.Nat).SetUint64(0)
	assert.False(t, p.Verify(x, y, e, S, zero))
}

func TestParameters_WriteTo(t *testing.T) {
	p := benchParams
	var buf bytes.Buffer
	n, err := p.WriteTo(&buf)
	require.NoError(t, err)
	// three fixed-width numbers
	bufLen := int64(len(buf.Bytes()))
	assert.Equal(t, bufLen, n)
	assert.Equal(t, int64(3*params.BytesIntModN), bufLen)

	// a nil receiver must error
	var nilParams *Parameters
	_, err = nilParams.WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestParameters_Domain(t *testing.T) {
	assert.Equal(t, "Pedersen Parameters", Parameters{}.Domain())
}
