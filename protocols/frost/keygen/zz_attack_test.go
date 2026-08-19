package keygen

// AUDIT regression test — small-subgroup (torsion) injection into VSS
// commitments on edwards25519.
//
// A malicious keygen participant can embed order-8 components into its VSS
// polynomial commitments Phi_i (built through the wire format below), and
// grind the Schnorr proof of knowledge so that it verifies for the polluted
// constant coefficient. Before the fix, incoming points were never checked
// for prime-order subgroup membership (RFC 9591, Section 6.1 requires such
// checks): the VSS check f_l(i)*G == Phi_l(i) runs over the full curve group,
// and the Schnorr PoK only binds the prime-order component, so both passed
// for every honest party while the derived verification shares / group key
// carried an attacker-chosen 8-torsion component.
//
// round2.StoreBroadcastMessage now rejects any Phi_i whose coefficients lie
// outside the prime-order subgroup, so the crafted broadcast below is
// rejected by every honest party and keygen aborts before any key material
// is derived.

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/common/types"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/polynomial"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	zksch "github.com/MixinNetwork/multi-party-sig/pkg/zk/sch"
)

// canonical encoding of an order-8 edwards25519 point
const order8PointHex = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"

func u64Scalar(group curve.Curve, v uint64) curve.Scalar {
	return group.NewScalar().SetNat(new(saferith.Nat).SetUint64(v))
}

func torsionPoint(t *testing.T) curve.Point {
	b, err := hex.DecodeString(order8PointHex)
	require.NoError(t, err)
	p := curve.Edwards25519{}.NewPoint()
	require.NoError(t, p.UnmarshalBinary(b), "order-8 point must deserialize (this is the bug)")
	eight := u64Scalar(p.Curve(), 8)
	four := u64Scalar(p.Curve(), 4)
	require.True(t, eight.Act(p).IsIdentity())
	require.False(t, four.Act(p).IsIdentity())
	return p
}

// buildMalicious creates a Phi with coefficients C_k = a_k*G + t_k*T8 and a
// Schnorr PoK that verifies for C_0 despite the torsion (grinding on the
// Fiat-Shamir challenge), exactly as an attacker would.
func buildMalicious(t *testing.T, group curve.Curve, threshold int, malID party.ID, malHelper *round.Helper, torsion []int, T8 curve.Point) *broadcast2 {
	require.Len(t, torsion, threshold+1)

	a := make([]curve.Scalar, threshold+1)
	a[0] = sample.ScalarUnit(rand.Reader, group)
	for k := 1; k <= threshold; k++ {
		a[k] = sample.Scalar(rand.Reader, group)
	}

	// exponent coefficients with embedded torsion, built through the wire format
	coeffBytes := make([][]byte, threshold+1)
	for k := range a {
		p := a[k].ActOnBase()
		if tk := torsion[k] % 8; tk != 0 {
			p = p.Add(u64Scalar(group, uint64(tk)).Act(T8))
		}
		b, err := p.MarshalBinary()
		require.NoError(t, err)
		coeffBytes[k] = b
	}
	payload, err := cbor.Marshal(struct {
		IsConstant   bool
		Coefficients [][]byte
	}{false, coeffBytes})
	require.NoError(t, err)
	wire := make([]byte, 4+len(payload))
	wire[3] = byte(threshold + 1)
	copy(wire[4:], payload)
	exp := polynomial.EmptyExponent(group)
	require.NoError(t, exp.UnmarshalBinary(wire))
	require.Equal(t, threshold, exp.Degree())

	C0 := exp.Constant()
	a0 := a[0]

	// Grind the Schnorr PoK: pick random a, C = a*G, need e*t_0 == 0 (mod 8).
	t0 := torsion[0] % 8
	var proof *zksch.Proof
	for tries := 0; ; tries++ {
		require.Less(t, tries, 10000)
		a := sample.ScalarUnit(rand.Reader, group)
		C := a.ActOnBase()
		h := malHelper.HashForID(malID)
		require.NoError(t, h.WriteAny(C, C0, group.NewBasePoint()))
		e := sample.Scalar(h.Digest(), group)
		// e mod 2 via little-endian encoding of edwards25519 scalar
		par := e.Bytes()[0] & 1
		if (t0*int(par))%8 == 0 && (t0 == 0 || (t0*int(e.Bytes()[0]&7))%8 == 0) {
			Z := group.NewScalar().Set(e).Mul(a0).Add(a)
			proof = zksch.EmptyProof(group)
			proof.C.C = C
			proof.Z.Z = Z
			break
		}
	}

	c_m, err := types.NewRID(rand.Reader)
	require.NoError(t, err)
	commitment, _, err := malHelper.HashForID(malID).Commit(c_m)
	require.NoError(t, err)

	return &broadcast2{Phi_i: exp, Sigma_i: proof, Commitment: commitment}
}

// TestAttackTorsionRejected drives the crafted broadcasts of two attack
// variants through honest parties and asserts that the small-subgroup check
// rejects them:
//
//   - "group key pollution": the torsion polynomial tau(x) = 4 + 4x vanishes
//     mod 8 at every honest evaluation point but tau(0) = 4, so the group
//     public key would be polluted by 4*T8 while every honest VSS check passes.
//   - "verification share framing": a torsion polynomial vanishing at every
//     honest point except one victim's, polluting only the victim's
//     verification share so that the victim is blamed during signing.
func TestAttackTorsionRejected(t *testing.T) {
	group := curve.Edwards25519{}
	T8 := torsionPoint(t)

	variants := []struct {
		name      string
		threshold int
		honest    []party.ID
		malID     party.ID
		all       []party.ID
		torsion   []int
	}{
		{
			name:      "group key pollution",
			threshold: 3,
			honest:    []party.ID{"\x01", "\x03", "\x05"},
			malID:     "\x02",
			all:       []party.ID{"\x01", "\x02", "\x03", "\x05"},
			torsion:   []int{4, 4, 0, 0},
		},
		{
			name:      "verification share framing",
			threshold: 4,
			honest:    []party.ID{"a", "b", "c", "d"},
			malID:     "e",
			all:       []party.ID{"a", "b", "c", "d", "e"},
			torsion:   []int{0, 2, 1, 0, 5},
		},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			sessionID := []byte("audit-small-subgroup-attack")
			malSess, err := StartKeygenCommon(false, group, v.all, v.threshold, v.malID)(sessionID)
			require.NoError(t, err)
			malB2 := buildMalicious(t, group, v.threshold, v.malID, malSess.(*round1).Helper, v.torsion, T8)

			for _, id := range v.honest {
				s, err := StartKeygenCommon(false, group, v.all, v.threshold, id)(sessionID)
				require.NoError(t, err)
				out := make(chan *round.Message, 4)
				r2, err := s.Finalize(out)
				require.NoError(t, err)
				close(out)

				// the torsion-carrying VSS commitments must be rejected
				// before any key material is derived
				err = r2.(*round2).StoreBroadcastMessage(round.Message{From: v.malID, Content: malB2, Broadcast: true})
				require.Error(t, err, "honest party %q accepted torsion-carrying VSS commitments", id)
				assert.Contains(t, err.Error(), "prime-order subgroup")
			}

			t.Logf("ATTACK BLOCKED: all honest parties rejected the malicious Phi at round 2")
		})
	}
}
