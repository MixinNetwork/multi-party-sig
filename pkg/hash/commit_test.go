package hash

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHash_CommitDecommit(t *testing.T) {
	h := New()
	c, d, err := h.Commit([]byte("data"))
	require.NoError(t, err)
	assert.Len(t, c, DigestLengthBytes)
	assert.Len(t, d, 32)

	// the commitment must verify against the original data
	assert.True(t, h.Decommit(c, d, []byte("data")))

	// wrong data must not verify
	assert.False(t, h.Decommit(c, d, []byte("other data")))

	// a tampered decommitment must not verify
	bad := Decommitment(bytes.Clone(d))
	bad[0] ^= 1
	assert.False(t, h.Decommit(c, bad, []byte("data")))

	// a different commitment must not verify
	badc := Commitment(bytes.Clone(c))
	badc[0] ^= 1
	assert.False(t, h.Decommit(badc, d, []byte("data")))
}

func TestCommitment_Validate(t *testing.T) {
	valid := make(Commitment, DigestLengthBytes)
	valid[0] = 1
	assert.NoError(t, valid.Validate())

	zero := make(Commitment, DigestLengthBytes)
	assert.Error(t, zero.Validate())

	assert.Error(t, make(Commitment, DigestLengthBytes-1).Validate())
	assert.Error(t, make(Commitment, DigestLengthBytes+1).Validate())
}

func TestDecommitment_Validate(t *testing.T) {
	valid := make(Decommitment, 32)
	valid[0] = 1
	assert.NoError(t, valid.Validate())

	zero := make(Decommitment, 32)
	assert.Error(t, zero.Validate())

	assert.Error(t, make(Decommitment, 31).Validate())
	assert.Error(t, make(Decommitment, 33).Validate())
}

func TestCommitment_WriteTo(t *testing.T) {
	c := make(Commitment, DigestLengthBytes)
	c[0] = 3
	var buf bytes.Buffer
	n, err := c.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(len(c)), n)
	assert.Equal(t, []byte(c), buf.Bytes())

	_, err = Commitment(nil).WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

	d := make(Decommitment, 32)
	n, err = d.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(32), n)

	_, err = Decommitment(nil).WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestDomains(t *testing.T) {
	assert.Equal(t, "Commitment", Commitment{}.Domain())
	assert.Equal(t, "Decommitment", Decommitment{}.Domain())
}

func TestHash_CloneForkSum(t *testing.T) {
	h := New()
	h.WriteAny([]byte("one"))
	forked := h.Fork([]byte("two"))
	cloned := h.Clone()

	// the original must be unaffected by the fork
	origSum := h.Sum()
	assert.Equal(t, origSum, cloned.Sum())
	assert.NotEqual(t, origSum, forked.Sum())

	// writing to a clone must not affect the original
	cloned.WriteAny([]byte("mutated"))
	assert.Equal(t, origSum, h.Sum())

	// Sum must return the documented digest length
	assert.Len(t, h.Sum(), DigestLengthBytes)
	assert.Equal(t, 64, DigestLengthBytes)
}

func TestHash_Digest(t *testing.T) {
	h := New()
	h.WriteAny([]byte("digest me"))
	r := h.Digest()
	out := make([]byte, 10)
	n, err := io.ReadFull(r, out)
	require.NoError(t, err)
	assert.Equal(t, 10, n)

	// the stream must be extendable to arbitrary lengths
	long := make([]byte, 300)
	r2 := New().Digest()
	n, err = io.ReadFull(r2, long)
	require.NoError(t, err)
	assert.Equal(t, 300, n)
}

func TestBytesWithDomain(t *testing.T) {
	b := BytesWithDomain{TheDomain: "D", Bytes: []byte{1, 2, 3}}
	var buf bytes.Buffer
	n, err := b.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
	assert.Equal(t, "D", b.Domain())

	_, err = BytesWithDomain{TheDomain: "D"}.WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestHash_WriteAnyNilByteSlice(t *testing.T) {
	h := New()
	var nilBytes []byte
	assert.Error(t, h.WriteAny(nilBytes))
}

func TestHash_InitialData(t *testing.T) {
	h1 := New(BytesWithDomain{TheDomain: "a", Bytes: []byte{1}})
	h2 := New()
	h2.WriteAny(BytesWithDomain{TheDomain: "a", Bytes: []byte{1}})
	assert.Equal(t, h1.Sum(), h2.Sum())
	// different initial data must give a different digest
	h3 := New(BytesWithDomain{TheDomain: "b", Bytes: []byte{1}})
	assert.NotEqual(t, h1.Sum(), h3.Sum())
}

// failingMarshaler implements encoding.BinaryMarshaler but always fails.
type failingMarshaler struct{}

func (failingMarshaler) MarshalBinary() ([]byte, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestHash_WriteAny_MarshalFailure(t *testing.T) {
	h := New()
	assert.Error(t, h.WriteAny(failingMarshaler{}))
}

func TestHash_Decommit_WriteFailure(t *testing.T) {
	h := New()
	c, d, err := h.Commit([]byte("data"))
	require.NoError(t, err)
	// a data element that cannot be written must make Decommit fail
	assert.False(t, h.Decommit(c, d, 42))
}
