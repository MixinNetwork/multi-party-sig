package config

import (
	"crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/MixinNetwork/multi-party-sig/common/types"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/paillier"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
)

func testConfig(t *testing.T, pl *pool.Pool) *Config {
	t.Helper()
	group := curve.Secp256k1{}
	id, other := party.ID("a"), party.ID("b")

	sk := paillier.NewSecretKey(pl)
	ped, _ := sk.GeneratePedersen()
	otherSK := paillier.NewSecretKey(pl)
	otherPed, _ := otherSK.GeneratePedersen()

	ecdsaShare := sample.Scalar(rand.Reader, group)
	elGamalShare := sample.Scalar(rand.Reader, group)
	otherECDSAShare := sample.Scalar(rand.Reader, group)
	otherElGamalShare := sample.Scalar(rand.Reader, group)

	rid, err := types.NewRID(rand.Reader)
	require.NoError(t, err)
	chainKey, err := types.NewRID(rand.Reader)
	require.NoError(t, err)

	return &Config{
		Group:     group,
		ID:        id,
		Threshold: 1,
		ECDSA:     ecdsaShare,
		ElGamal:   elGamalShare,
		Paillier:  sk,
		RID:       rid,
		ChainKey:  chainKey,
		Public: map[party.ID]*Public{
			id: {
				ECDSA:    ecdsaShare.ActOnBase(),
				ElGamal:  elGamalShare.ActOnBase(),
				Paillier: sk.PublicKey,
				Pedersen: ped,
			},
			other: {
				ECDSA:    otherECDSAShare.ActOnBase(),
				ElGamal:  otherElGamalShare.ActOnBase(),
				Paillier: otherSK.PublicKey,
				Pedersen: otherPed,
			},
		},
	}
}

// remarshal round-trips c through its serialized form, allowing the test to
// tamper with the decoded fields before re-encoding.
func remarshal(t *testing.T, c *Config, mutate func(cm *configMarshal, pms []*publicMarshal)) []byte {
	t.Helper()
	data, err := c.MarshalBinary()
	require.NoError(t, err)

	cm := &configMarshal{ECDSA: c.Group.NewScalar(), ElGamal: c.Group.NewScalar()}
	require.NoError(t, cbor.Unmarshal(data, cm))

	pms := make([]*publicMarshal, 0, len(cm.Public))
	for _, raw := range cm.Public {
		pm := &publicMarshal{ECDSA: c.Group.NewPoint(), ElGamal: c.Group.NewPoint()}
		require.NoError(t, cbor.Unmarshal(raw, pm))
		pms = append(pms, pm)
	}

	mutate(cm, pms)

	enc, _ := cbor.CanonicalEncOptions().EncMode()
	cm.Public = make([]cbor.RawMessage, 0, len(pms))
	for _, pm := range pms {
		d, err := enc.Marshal(pm)
		require.NoError(t, err)
		cm.Public = append(cm.Public, d)
	}
	out, err := enc.Marshal(cm)
	require.NoError(t, err)
	return out
}

func TestConfigMarshalRoundTrip(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	c := testConfig(t, pl)

	data, err := c.MarshalBinary()
	require.NoError(t, err)

	c2 := EmptyConfig(c.Group)
	require.NoError(t, c2.UnmarshalBinary(data))
	require.True(t, c2.PublicPoint().Equal(c.PublicPoint()))
}

func TestConfigUnmarshalRejectsTampering(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	c := testConfig(t, pl)

	cases := map[string]func(cm *configMarshal, pms []*publicMarshal){
		"short RID": func(cm *configMarshal, _ []*publicMarshal) {
			cm.RID = types.RID{1, 2, 3}
		},
		"zero RID": func(cm *configMarshal, _ []*publicMarshal) {
			cm.RID = types.EmptyRID()
		},
		"zero ChainKey": func(cm *configMarshal, _ []*publicMarshal) {
			cm.ChainKey = types.EmptyRID()
		},
		"self Pedersen S == T": func(cm *configMarshal, pms []*publicMarshal) {
			for _, pm := range pms {
				if pm.ID == cm.ID {
					pm.T = pm.S
				}
			}
		},
		"composite prime P": func(cm *configMarshal, _ []*publicMarshal) {
			// 2q+1 with q prime: 1024-bit, ≡ 3 (mod 4), (P-1)/2 prime, but composite (divisible by 3)
			cm.P, _ = new(saferith.Nat).SetHex("C4AE6F2915E500544D5870E7537398FAA2FBA30F66B8A68AD5F7C851287A6AA2A744E7A43ADF7222B1164467E03789DEF66B9466049AF0BD125571AA61568A53DFB02FAF11459E5E618E5D6E2D56741007678FB0FB5C932A455E66B47860FA3197A34616C74451DC7F1C56FF4A1311E25EF536F656FBEF89052FCF56D1440D1B")
		},
		"P equal to Q": func(cm *configMarshal, _ []*publicMarshal) {
			// N = P² is trivially factorable
			cm.Q = cm.P
		},
		"own N is 2047 bits": func(cm *configMarshal, _ []*publicMarshal) {
			// Two distinct, valid 1024-bit safe Blum primes whose product is
			// only 2047 bits: the modulus invariant must also be enforced for
			// our own key, like it is for the other parties.
			cm.P, _ = new(saferith.Nat).SetHex("9b89ebdb03b220b53081c29bbdce2b26647d3e7574b2f12d2f4cc5de409595a2a7fdfa838d3d9189b12ca5c9f2423b8eb2628bd6c4ab6c247178d1c02471ae047b4207839191e59213b470e7f7475a825aa46a2acf1f4e1a28302a45e328c2c10a8c3edb6017ae73d6250eddfdd0b5df38faf7efa4454aeb769beb63c28f13e3")
			cm.Q, _ = new(saferith.Nat).SetHex("9b89ebdb03b220b53081c29bbdce2b26647d3e7574b2f12d2f4cc5de409595a2a7fdfa838d3d9189b12ca5c9f2423b8eb2628bd6c4ab6c247178d1c02471ae047b4207839191e59213b470e7f7475a825aa46a2acf1f4e1a28302a45e328c2c10a8c3edb6017ae73d6250eddfdd0b5df38faf7efa4454aeb769beb63c291af63")
		},
		"colliding scalar party IDs": func(cm *configMarshal, pms []*publicMarshal) {
			// "a" and "\x00a" both map to the scalar 0x61: the duplicate-string
			// check passes, but Lagrange interpolation over them would panic.
			for _, pm := range pms {
				if pm.ID != cm.ID {
					pm.ID = "\x00a"
				}
			}
		},
		"zero scalar party ID": func(cm *configMarshal, pms []*publicMarshal) {
			for _, pm := range pms {
				if pm.ID != cm.ID {
					pm.ID = "\x00"
				}
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			data := remarshal(t, c, mutate)
			c2 := EmptyConfig(c.Group)
			if err := c2.UnmarshalBinary(data); err == nil {
				t.Error("tampered config was accepted")
			}
		})
	}
}
