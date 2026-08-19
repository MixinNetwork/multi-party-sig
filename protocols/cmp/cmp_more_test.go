package cmp

import (
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmptyConfig(t *testing.T) {
	for _, group := range []curve.Curve{curve.Secp256k1{}, curve.Edwards25519{}} {
		c := EmptyConfig(group)
		require.NotNil(t, c)
		assert.Equal(t, group.Name(), c.Group.Name())
		// the rest of the config is empty
		assert.Nil(t, c.ECDSA)
		assert.Nil(t, c.Paillier)
		assert.Empty(t, c.Public)
	}
}
