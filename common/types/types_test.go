package types

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRID_EmptyAndNew(t *testing.T) {
	rid := EmptyRID()
	assert.Len(t, rid, params.SecBytes)
	for _, b := range rid {
		assert.Equal(t, byte(0), b)
	}

	// NewRID reads from a reader
	r := make([]byte, params.SecBytes)
	_, err := rand.Read(r)
	require.NoError(t, err)
	rid2, err := NewRID(bytes.NewReader(r))
	require.NoError(t, err)
	assert.Equal(t, RID(r), rid2)

	// a short reader must error
	short := make([]byte, params.SecBytes-1)
	_, err = NewRID(bytes.NewReader(short))
	assert.Error(t, err)
}

func TestRID_XOR(t *testing.T) {
	a := RID(make([]byte, params.SecBytes))
	b := RID(make([]byte, params.SecBytes))
	a[0] = 0x0f
	b[0] = 0xff
	a.XOR(b)
	assert.Equal(t, byte(0xf0), a[0])
	assert.Equal(t, byte(0xff), b[0], "XOR must not modify the argument")
	a.XOR(b)
	assert.Equal(t, byte(0x0f), a[0], "XOR twice must restore the original")
}

func TestRID_WriteTo(t *testing.T) {
	rid := EmptyRID()
	rid[0] = 0x42
	var buf bytes.Buffer
	n, err := rid.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(params.SecBytes), n)
	assert.Equal(t, []byte(rid), buf.Bytes())

	// nil must error
	_, err = RID(nil).WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestRID_Domain(t *testing.T) {
	assert.Equal(t, "RID", RID{}.Domain())
}

func TestRID_Validate(t *testing.T) {
	// all-zero is invalid
	rid := EmptyRID()
	assert.Error(t, rid.Validate())

	// correct length and non-zero is valid
	rid[0] = 1
	assert.NoError(t, rid.Validate())

	// wrong lengths are invalid
	assert.Error(t, RID{}.Validate())
	assert.Error(t, RID(make([]byte, params.SecBytes-1)).Validate())
	assert.Error(t, RID(make([]byte, params.SecBytes+1)).Validate())
}

func TestRID_Copy(t *testing.T) {
	rid := EmptyRID()
	rid[0] = 0x24
	copied := rid.Copy()
	assert.Equal(t, rid, copied)
	require.Len(t, copied, params.SecBytes)
	copied[0] = 0
	assert.Equal(t, byte(0x24), rid[0], "Copy must return an independent RID")
}

func TestThresholdWrapper_WriteTo(t *testing.T) {
	var buf bytes.Buffer
	n, err := ThresholdWrapper(0x01020304).WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(4), n)
	assert.Equal(t, []byte{1, 2, 3, 4}, buf.Bytes())
}

func TestThresholdWrapper_Domain(t *testing.T) {
	assert.Equal(t, "Threshold", ThresholdWrapper(0).Domain())
}

func TestSigningMessage_WriteTo(t *testing.T) {
	var buf bytes.Buffer
	n, err := SigningMessage("abc").WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
	assert.Equal(t, []byte("abc"), buf.Bytes())
}

func TestSigningMessage_Domain(t *testing.T) {
	assert.Equal(t, "Empty Message", SigningMessage(nil).Domain())
	assert.Equal(t, "Signature Message", SigningMessage{}.Domain())
	assert.Equal(t, "Signature Message", SigningMessage("x").Domain())
}
