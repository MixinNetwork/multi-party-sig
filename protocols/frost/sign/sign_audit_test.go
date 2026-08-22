package sign

// AUDIT regression tests — nonce generation hygiene, nonce commitment
// validation, and per-share signature verification.
//
// These tests exercise the checks that prevent the classic FROST failure
// modes: nonce reuse across identical executions (key recovery), identity or
// torsion-carrying nonce commitments (share recovery / key pollution, see
// RFC 9591 Section 6.1), and forged signature shares (identifiable abort).

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/keygen"
)

// canonical encoding of an order-8 edwards25519 point
const signOrder8PointHex = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"

func auditConfig(group curve.Curve, ids []party.ID, self party.ID, threshold int) *keygen.Config {
	priv := sample.ScalarUnit(rand.Reader, group)
	shares := make(map[party.ID]curve.Point, len(ids))
	for _, id := range ids {
		shares[id] = sample.ScalarUnit(rand.Reader, group).ActOnBase()
	}
	shares[self] = priv.ActOnBase()
	return &keygen.Config{
		ID:                 self,
		Threshold:          threshold,
		PrivateShare:       priv,
		PublicKey:          priv.ActOnBase(),
		VerificationShares: party.NewPointMap(shares),
	}
}

// TestAuditNonceHedgedFresh runs round 1 repeatedly with identical inputs
// (same session ID, same message, same key share) and asserts that the nonce
// commitments differ every time. Deterministic nonces in the multi-party
// setting allow complete key-recovery (RFC 9591, Section 1), so the hedged
// construction must randomize every execution.
func TestAuditNonceHedgedFresh(t *testing.T) {
	group := curve.Edwards25519{}
	ids := []party.ID{"a", "b", "c"}
	cfg := auditConfig(group, ids, "a", 1)
	sessionID := []byte("audit-nonce-hedging-test")
	msg := []byte("the same message signed over and over")

	seen := make(map[string]bool)
	for i := 0; i < 8; i++ {
		sess, err := StartSignCommon(cfg, ids, msg, ProtocolDefault)(sessionID)
		require.NoError(t, err)
		out := make(chan *round.Message, 4)
		_, err = sess.Finalize(out)
		require.NoError(t, err)
		close(out)
		var d, e curve.Point
		for m := range out {
			body := m.Content.(*broadcast2)
			d, e = body.D_i, body.E_i
		}
		db, err := d.MarshalBinary()
		require.NoError(t, err)
		eb, err := e.MarshalBinary()
		require.NoError(t, err)
		key := string(db) + string(eb)
		require.False(t, seen[key], "nonce commitment pair reused across identical executions")
		seen[key] = true
	}
}

// TestAuditNonceCommitmentValidation asserts that identity and
// torsion-carrying nonce commitments are rejected before any binding factor
// is computed.
func TestAuditNonceCommitmentValidation(t *testing.T) {
	group := curve.Edwards25519{}
	ids := []party.ID{"a", "b", "c"}
	cfg := auditConfig(group, ids, "a", 1)
	sess, err := StartSignCommon(cfg, ids, []byte("m"), ProtocolDefault)([]byte("audit-commit-validation"))
	require.NoError(t, err)
	out := make(chan *round.Message, 4)
	r2sess, err := sess.Finalize(out)
	require.NoError(t, err)
	close(out)
	r2 := r2sess.(*round2)

	// identity commitments must be rejected
	err = r2.StoreBroadcastMessage(round.Message{
		From:      "b",
		Content:   &broadcast2{D_i: group.NewPoint(), E_i: group.NewBasePoint()},
		Broadcast: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity")

	// commitments outside the prime-order subgroup must be rejected
	tb, err := hex.DecodeString(signOrder8PointHex)
	require.NoError(t, err)
	T8 := group.NewPoint()
	require.NoError(t, T8.UnmarshalBinary(tb))
	eight := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(8))
	require.True(t, eight.Act(T8).IsIdentity(), "test point must have order 8")
	badD := sample.ScalarUnit(rand.Reader, group).ActOnBase().Add(T8)
	err = r2.StoreBroadcastMessage(round.Message{
		From:      "b",
		Content:   &broadcast2{D_i: badD, E_i: group.NewBasePoint()},
		Broadcast: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prime-order subgroup")

	// a clean commitment passes
	good := sample.ScalarUnit(rand.Reader, group)
	err = r2.StoreBroadcastMessage(round.Message{
		From:      "b",
		Content:   &broadcast2{D_i: good.ActOnBase(), E_i: good.ActOnBase()},
		Broadcast: true,
	})
	require.NoError(t, err)
}

// TestAuditSignatureShareVerification drives rounds 1-3 locally with
// fabricated peers and asserts that a correctly formed signature share is
// accepted while a tampered one is rejected and attributed to its sender.
func TestAuditSignatureShareVerification(t *testing.T) {
	group := curve.Edwards25519{}
	ids := party.NewIDSlice([]party.ID{"a", "b", "c"})
	cfg := auditConfig(group, ids, "a", 1)
	M := []byte("audit share verification")
	sess, err := StartSignCommon(cfg, ids, M, ProtocolDefault)([]byte("audit-share-verification"))
	require.NoError(t, err)
	out := make(chan *round.Message, 4)
	r2sess, err := sess.Finalize(out)
	require.NoError(t, err)
	close(out)
	r2 := r2sess.(*round2)

	type peer struct{ d, e, s curve.Scalar }
	peers := make(map[party.ID]*peer)
	for _, id := range []party.ID{"b", "c"} {
		p := &peer{
			d: sample.ScalarUnit(rand.Reader, group),
			e: sample.ScalarUnit(rand.Reader, group),
			s: sample.ScalarUnit(rand.Reader, group),
		}
		peers[id] = p
		r2.YShares[id] = p.s.ActOnBase()
		err = r2.StoreBroadcastMessage(round.Message{
			From:      id,
			Content:   &broadcast2{D_i: p.d.ActOnBase(), E_i: p.e.ActOnBase()},
			Broadcast: true,
		})
		require.NoError(t, err)
	}

	out2 := make(chan *round.Message, 4)
	r3sess, err := r2.Finalize(out2)
	require.NoError(t, err)
	close(out2)
	r3 := r3sess.(*round3)

	// recompute the binding factors exactly as round 2 does
	rhoPreHash := hash.New()
	require.NoError(t, rhoPreHash.WriteAny(r2.Y, messageHash(M)))
	for _, l := range r2.PartyIDs() {
		require.NoError(t, rhoPreHash.WriteAny(r2.D[l], r2.E[l]))
	}
	rho := func(l party.ID) curve.Scalar {
		h := rhoPreHash.Clone()
		require.NoError(t, h.WriteAny(l))
		return sample.Scalar(h.Digest(), group)
	}
	share := func(id party.ID) curve.Scalar {
		p := peers[id]
		z := group.NewScalar().Set(r3.Lambda[id]).Mul(p.s).Mul(r3.c)
		z.Add(p.d)
		z.Add(rho(id).Mul(p.e))
		return z
	}

	// a well-formed share from b verifies
	require.NoError(t, r3.StoreBroadcastMessage(round.Message{
		From:      "b",
		Content:   &broadcast3{Z_i: share("b")},
		Broadcast: true,
	}))

	// a tampered share from c is rejected and names c
	forged := share("c")
	forged.Add(group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1)))
	err = r3.StoreBroadcastMessage(round.Message{
		From:      "c",
		Content:   &broadcast3{Z_i: forged},
		Broadcast: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify response from c")
}
