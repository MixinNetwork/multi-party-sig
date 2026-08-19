package config

import (
	"errors"
	"io"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failAfterWriter fails once the given number of bytes have been written.
type failAfterWriter struct {
	remaining int
	err       error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, w.err
	}
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, w.err
	}
	w.remaining -= len(p)
	return len(p), nil
}

func TestConfig_WriteToWriterFailures(t *testing.T) {
	pl := pool.NewPool(1)
	defer pl.TearDown()
	c := testConfig(t, pl)

	// determine the full length first
	full := &countingWriter{}
	_, err := c.WriteTo(full)
	require.NoError(t, err)

	// failing at a range of offsets must surface the error, not panic
	testErr := errors.New("writer failed")
	for _, offset := range []int{0, 1, 3, 5, 10, full.total - 1} {
		w := &failAfterWriter{remaining: offset, err: testErr}
		_, err := c.WriteTo(w)
		assert.Error(t, err, "expected error after %d bytes", offset)
	}

	// the Public.WriteTo failure path
	pub := c.Public[c.ID]
	for _, offset := range []int{0, 20, 100} {
		w := &failAfterWriter{remaining: offset, err: testErr}
		_, err := pub.WriteTo(w)
		assert.Error(t, err, "expected public write error after %d bytes", offset)
	}
}

type countingWriter struct {
	total int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.total += len(p)
	return len(p), nil
}

var _ io.Writer = (*countingWriter)(nil)

func TestConfig_UnmarshalNilGroup(t *testing.T) {
	pl := pool.NewPool(1)
	defer pl.TearDown()
	c := testConfig(t, pl)
	data, err := c.MarshalBinary()
	require.NoError(t, err)

	// a config without a group set must be rejected
	fresh := &Config{}
	assert.Error(t, fresh.UnmarshalBinary(data))

	// invalid cbor must be rejected
	fresh = EmptyConfig(curve.Secp256k1{})
	assert.Error(t, fresh.UnmarshalBinary([]byte{0xff}))
}
