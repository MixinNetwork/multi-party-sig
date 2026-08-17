package hash

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
)

func TestHash_WriteAny(t *testing.T) {
	var err error

	testFunc := func(vs ...any) error {
		h := New()
		for _, v := range vs {
			err = h.WriteAny(v)
			if err != nil {
				return err
			}
		}
		return nil
	}
	b := big.NewInt(35)
	i := new(saferith.Int).SetBig(b, b.BitLen())
	n := new(saferith.Nat).SetBig(b, b.BitLen())
	m := saferith.ModulusFromBytes(b.Bytes())

	assert.NoError(t, testFunc(i, n, m))
	assert.NoError(t, testFunc(sample.Scalar(rand.Reader, curve.Secp256k1{})))
	assert.NoError(t, testFunc(sample.Scalar(rand.Reader, curve.Secp256k1{}).ActOnBase()))
	assert.NoError(t, testFunc([]byte{1, 4, 6}))
}

func TestHash_WriteAny_UnsupportedType(t *testing.T) {
	// Unsupported types must produce an error rather than being silently
	// skipped, which would corrupt the transcript.
	h := New()
	assert.Error(t, h.WriteAny(42))
	assert.Error(t, h.WriteAny(nil))
	assert.Error(t, h.WriteAny(struct{}{}))
	// a nil interface of a supported kind must also fail cleanly
	var p curve.Point
	assert.Error(t, h.WriteAny(p))
}

func TestHash_WriteAny_Collision(t *testing.T) {
	var err error

	testFunc := func(vs ...any) ([]byte, error) {
		h := New()
		for _, v := range vs {
			err = h.WriteAny(v)
			if err != nil {
				return nil, err
			}
		}
		return h.Sum(), nil
	}
	b1 := []byte("1)(big.Int\x02*data_added*")
	b2 := []byte("3")
	n2 := new(big.Int)
	n2.SetString(hex.EncodeToString(b2), 16)
	h1, err := testFunc(b1, n2)
	assert.NoError(t, err)

	b1 = []byte("1")
	b2 = []byte("*data_added*)(big.Int\x023")
	n2 = new(big.Int)
	n2.SetString(hex.EncodeToString(b2), 16)
	h2, err := testFunc(b1, n2)
	assert.NoError(t, err)

	assert.NotEqual(t, h1, h2)
}
