package config

import (
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigUnmarshalRejectsMoreTampering(t *testing.T) {
	pl := pool.NewPool(1)
	defer pl.TearDown()
	c := testConfig(t, pl)

	t.Run("composite prime Q", func(t *testing.T) {
		data := remarshal(t, c, func(cm *configMarshal, _ []*publicMarshal) {
			// 2q+1 with q prime: 1024-bit, ≡ 3 (mod 4), but composite
			cm.Q, _ = new(saferith.Nat).SetHex("C4AE6F2915E500544D5870E7537398FAA2FBA30F66B8A68AD5F7C851287A6AA2A744E7A43ADF7222B1164467E03789DEF66B9466049AF0BD125571AA61568A53DFB02FAF11459E5E618E5D6E2D56741007678FB0FB5C932A455E66B47860FA3197A34616C74451DC7F1C56FF4A1311E25EF536F656FBEF89052FCF56D1440D1B")
		})
		err := EmptyConfig(c.Group).UnmarshalBinary(data)
		assert.ErrorContains(t, err, "prime Q")
	})

	t.Run("invalid other-party modulus length", func(t *testing.T) {
		data := remarshal(t, c, func(cm *configMarshal, pms []*publicMarshal) {
			for _, pm := range pms {
				if pm.ID != cm.ID {
					// a far too small modulus
					pm.N = saferith.ModulusFromUint64(101)
				}
			}
		})
		assert.Error(t, EmptyConfig(c.Group).UnmarshalBinary(data))
	})

	t.Run("identity public point", func(t *testing.T) {
		data := remarshal(t, c, func(cm *configMarshal, pms []*publicMarshal) {
			for _, pm := range pms {
				if pm.ID != cm.ID {
					pm.ECDSA = curve.Secp256k1{}.NewPoint()
				}
			}
		})
		assert.Error(t, EmptyConfig(c.Group).UnmarshalBinary(data))
	})

	t.Run("duplicate public entries", func(t *testing.T) {
		data := remarshal(t, c, func(cm *configMarshal, pms []*publicMarshal) {
			require.Len(t, pms, 2)
			// two entries with the same ID
			pms[1].ID = pms[0].ID
		})
		assert.Error(t, EmptyConfig(c.Group).UnmarshalBinary(data))
	})

	t.Run("missing own public entry", func(t *testing.T) {
		data := remarshal(t, c, func(cm *configMarshal, pms []*publicMarshal) {
			// rename our own entry so only the other party remains
			for _, pm := range pms {
				if pm.ID == cm.ID {
					pm.ID = "renamed"
				}
			}
		})
		assert.Error(t, EmptyConfig(c.Group).UnmarshalBinary(data))
	})

	t.Run("invalid threshold", func(t *testing.T) {
		data := remarshal(t, c, func(cm *configMarshal, _ []*publicMarshal) {
			cm.Threshold = 5
		})
		assert.Error(t, EmptyConfig(c.Group).UnmarshalBinary(data))
	})
}
