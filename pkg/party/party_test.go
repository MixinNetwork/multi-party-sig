package party

import (
	"bytes"
	"io"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIDSlice_NewSorted(t *testing.T) {
	ids := NewIDSlice([]ID{"c", "a", "b"})
	assert.Equal(t, IDSlice{"a", "b", "c"}, ids)
	assert.True(t, ids.Valid())
}

func TestIDSlice_Valid(t *testing.T) {
	assert.True(t, IDSlice{}.Valid())
	assert.True(t, IDSlice{"a"}.Valid())
	assert.True(t, IDSlice{"a", "b"}.Valid())

	// unsorted
	assert.False(t, IDSlice{"b", "a"}.Valid())
	// duplicates
	assert.False(t, IDSlice{"a", "a"}.Valid())
}

func TestIDSlice_Contains(t *testing.T) {
	ids := NewIDSlice([]ID{"a", "b", "c"})
	assert.True(t, ids.Contains("a"))
	assert.True(t, ids.Contains("a", "b", "c"))
	assert.False(t, ids.Contains("d"))
	assert.False(t, ids.Contains("a", "d"))
	assert.False(t, ids.Contains(""))
}

func TestIDSlice_Copy(t *testing.T) {
	ids := IDSlice{"a", "b"}
	copied := ids.Copy()
	assert.Equal(t, ids, copied)
	require.Len(t, copied, 2)
	copied[0] = "z"
	assert.Equal(t, IDSlice{"a", "b"}, ids, "Copy must return an independent slice")
}

func TestIDSlice_Remove(t *testing.T) {
	ids := IDSlice{"a", "b", "c"}
	assert.Equal(t, IDSlice{"b", "c"}, ids.Remove("a"))
	assert.Equal(t, IDSlice{"a", "b", "c"}, ids.Remove("d"))
	assert.Equal(t, IDSlice{}, IDSlice{}.Remove("a"))
}

func TestIDSlice_SortInterface(t *testing.T) {
	ids := IDSlice{"c", "a", "b"}
	assert.Equal(t, 3, ids.Len())
	assert.True(t, ids.Less(1, 0))
	assert.False(t, ids.Less(0, 1))
	ids.Swap(0, 2)
	assert.Equal(t, IDSlice{"b", "a", "c"}, ids)
	ids.sort()
	assert.Equal(t, IDSlice{"a", "b", "c"}, ids)
}

func TestIDSlice_WriteTo(t *testing.T) {
	ids := IDSlice{"a", "bc", "def"}
	var buf bytes.Buffer
	n, err := ids.WriteTo(&buf)
	require.NoError(t, err)

	// 8 bytes of length + the IDs themselves
	expected := int64(8 + 1 + 2 + 3)
	if n != expected {
		t.Errorf("WriteTo reported %d bytes, expected %d", n, expected)
	}

	// the encoding must start with the big-endian count
	written := buf.Bytes()
	assert.Equal(t, uint8(3), written[7])

	// nil must error
	_, err = IDSlice(nil).WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestIDSlice_String(t *testing.T) {
	ids := IDSlice{"a", "b"}
	assert.Equal(t, "a, b", ids.String())
	assert.Equal(t, "", IDSlice{}.String())
}

func TestID_Scalar(t *testing.T) {
	group := curve.Secp256k1{}
	id := ID("a")
	s := id.Scalar(group)
	require.NotNil(t, s)
	assert.False(t, s.IsZero())

	// distinct IDs must map to distinct scalars
	s2 := ID("b").Scalar(group)
	assert.False(t, s.Equal(s2))

	// the empty ID maps to the zero scalar
	assert.True(t, ID("").Scalar(group).IsZero())

	// same ID maps to the same scalar
	assert.True(t, id.Scalar(group).Equal(ID("a").Scalar(group)))
}

func TestID_WriteTo(t *testing.T) {
	var buf bytes.Buffer
	id := ID("test")
	n, err := id.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(4), n)
	assert.Equal(t, []byte("test"), buf.Bytes())

	// the empty ID must error
	_, err = ID("").WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestID_Domain(t *testing.T) {
	assert.Equal(t, "ID", ID("a").Domain())
	assert.Equal(t, "IDSlice", IDSlice{}.Domain())
}

func TestPointMap_RoundTrip(t *testing.T) {
	group := curve.Secp256k1{}
	X := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(42)).ActOnBase()
	Y := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(77)).ActOnBase()

	points := map[ID]curve.Point{"a": X, "b": Y}
	m := NewPointMap(points)
	require.NotNil(t, m.group)

	data, err := m.MarshalBinary()
	require.NoError(t, err)

	m2 := EmptyPointMap(group)
	require.NoError(t, m2.UnmarshalBinary(data))
	assert.Len(t, m2.Points, 2)
	assert.True(t, m2.Points["a"].Equal(X))
	assert.True(t, m2.Points["b"].Equal(Y))
}

func TestPointMap_UnmarshalWithoutGroup(t *testing.T) {
	m := &PointMap{}
	err := m.UnmarshalBinary([]byte{0xa0})
	assert.Error(t, err, "unmarshalling without a group must fail")
}

func TestPointMap_Empty(t *testing.T) {
	group := curve.Secp256k1{}
	m := EmptyPointMap(group)
	require.NotNil(t, m)

	// an empty point map has no group inferred
	m2 := NewPointMap(map[ID]curve.Point{})
	assert.Nil(t, m2.group)

	// marshal/unmarshal of an empty map works when a group is set
	data, err := m.MarshalBinary()
	require.NoError(t, err)
	m3 := EmptyPointMap(group)
	require.NoError(t, m3.UnmarshalBinary(data))
	assert.Empty(t, m3.Points)
}
