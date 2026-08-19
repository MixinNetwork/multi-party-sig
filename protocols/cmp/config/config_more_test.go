package config

import (
	"bytes"
	"crypto/rand"
	"io"
	"math"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_WriteTo(t *testing.T) {
	pl := pool.NewPool(1)
	defer pl.TearDown()
	c := testConfig(t, pl)

	var buf bytes.Buffer
	n, err := c.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(buf.Len()), n)
	assert.Positive(t, buf.Len())

	// deterministic: the same config serializes identically
	var buf2 bytes.Buffer
	_, err = c.WriteTo(&buf2)
	require.NoError(t, err)
	assert.Equal(t, buf.Bytes(), buf2.Bytes())

	// nil must error
	var nilConfig *Config
	_, err = nilConfig.WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

	// nil Public must error
	var nilPublic *Public
	_, err = nilPublic.WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestConfig_Domains(t *testing.T) {
	assert.Equal(t, "CMP Config", (&Config{}).Domain())
	assert.Equal(t, "Public Data", (&Public{}).Domain())
}

func TestConfig_PublicPointAndPartyIDs(t *testing.T) {
	pl := pool.NewPool(1)
	defer pl.TearDown()
	c := testConfig(t, pl)

	// PublicPoint must be the Lagrange interpolation of the shares
	pk := c.PublicPoint()
	require.NotNil(t, pk)

	ids := c.PartyIDs()
	assert.Len(t, ids, 2)
	assert.True(t, ids.Valid())
	assert.Contains(t, ids, party.ID("a"))
	assert.Contains(t, ids, party.ID("b"))
}

func TestConfig_CanSign(t *testing.T) {
	pl := pool.NewPool(1)
	defer pl.TearDown()
	c := testConfig(t, pl)

	a := party.ID("a")
	b := party.ID("b")

	// valid: both signers, sorted, including self
	assert.True(t, c.CanSign(party.NewIDSlice([]party.ID{a, b})))

	// too few signers (threshold 1 requires at least 2)
	assert.False(t, c.CanSign(party.NewIDSlice([]party.ID{a})))

	// unsorted (bypassing NewIDSlice's sorting)
	assert.False(t, c.CanSign(party.IDSlice{b, a}))

	// does not include self (two signers so the threshold check passes)
	assert.False(t, c.CanSign(party.NewIDSlice([]party.ID{b, "c"})))

	// unknown signer
	assert.False(t, c.CanSign(party.NewIDSlice([]party.ID{a, "zz"})))

	// duplicates
	assert.False(t, c.CanSign(party.NewIDSlice([]party.ID{a, a, b})))

	// nil slice
	assert.False(t, c.CanSign(nil))
}

func TestValidThreshold(t *testing.T) {
	assert.True(t, ValidThreshold(0, 1))
	assert.True(t, ValidThreshold(1, 2))
	assert.True(t, ValidThreshold(2, 5))

	assert.False(t, ValidThreshold(-1, 5))
	assert.False(t, ValidThreshold(0, 0))
	assert.False(t, ValidThreshold(5, 5))
	assert.False(t, ValidThreshold(3, 2))
}

func TestConfig_Derive(t *testing.T) {
	pl := pool.NewPool(1)
	defer pl.TearDown()
	c := testConfig(t, pl)

	adjust := sample.Scalar(rand.Reader, c.Group)
	newChainKey := make([]byte, params.SecBytes)
	_, err := rand.Read(newChainKey)
	require.NoError(t, err)

	derived, err := c.Derive(adjust, newChainKey)
	require.NoError(t, err)

	// the public key must be adjusted
	assert.True(t, derived.PublicPoint().Equal(c.PublicPoint().Add(adjust.ActOnBase())))
	// the private share must be adjusted
	assert.True(t, derived.ECDSA.Equal(c.Group.NewScalar().Set(c.ECDSA).Add(adjust)))
	// the paillier keys and rid stay
	assert.True(t, bytes.Equal(c.RID, derived.RID))
	// the chain key is new
	assert.True(t, bytes.Equal(newChainKey, derived.ChainKey))

	// no new chain key keeps the old
	derived2, err := c.Derive(adjust, nil)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(c.ChainKey, derived2.ChainKey))

	// zero adjust is a no-op
	derived3, err := c.Derive(c.Group.NewScalar(), nil)
	require.NoError(t, err)
	assert.True(t, derived3.PublicPoint().Equal(c.PublicPoint()))

	// wrong chain key length errors
	_, err = c.Derive(adjust, []byte{1, 2, 3})
	assert.Error(t, err)
}

func TestConfig_DeriveBIP32(t *testing.T) {
	pl := pool.NewPool(1)
	defer pl.TearDown()
	c := testConfig(t, pl)

	child, err := c.DeriveBIP32(1)
	require.NoError(t, err)
	require.NotNil(t, child)
	assert.Len(t, child.ChainKey, params.SecBytes)

	// the same index gives the same result
	child2, err := c.DeriveBIP32(1)
	require.NoError(t, err)
	assert.True(t, child.PublicPoint().Equal(child2.PublicPoint()))
	assert.True(t, bytes.Equal(child.ChainKey, child2.ChainKey))

	// a hardened index panics
	assert.Panics(t, func() {
		_, _ = c.DeriveBIP32(math.MaxUint32)
	})
}

func TestConfig_DeriveBIP32_EdwardsFails(t *testing.T) {
	// a config whose public points live on edwards25519 cannot use BIP32
	group := curve.Edwards25519{}
	secret := sample.Scalar(rand.Reader, group)
	c := &Config{
		Group:     group,
		ID:        "a",
		Threshold: 0,
		ECDSA:     secret,
		ElGamal:   group.NewScalar(),
		RID:       make([]byte, params.SecBytes),
		ChainKey:  make([]byte, params.SecBytes),
		Public: map[party.ID]*Public{
			"a": {ECDSA: secret.ActOnBase(), ElGamal: group.NewBasePoint()},
		},
	}
	_, err := c.DeriveBIP32(0)
	assert.Error(t, err)
}
