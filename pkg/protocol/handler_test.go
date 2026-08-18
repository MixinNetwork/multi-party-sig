package protocol_test

import (
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/protocol"
	"github.com/MixinNetwork/multi-party-sig/protocols/cmp"
)

// A broadcast message with a non-empty To field is a unicast in disguise: it
// would be stored (and folded into the broadcast verification hash) by only a
// subset of the participants. CanAccept must reject it.
func TestCanAcceptRejectsBroadcastWithDestination(t *testing.T) {
	group := curve.Secp256k1{}
	ids := []party.ID{"a", "b"}
	sessionID := []byte("handler-test-12345")

	hB, err := protocol.NewMultiHandler(cmp.Keygen(group, "b", ids, 1, nil), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	hA, err := protocol.NewMultiHandler(cmp.Keygen(group, "a", ids, 1, nil), sessionID)
	if err != nil {
		t.Fatal(err)
	}

	// take a genuine broadcast message from A's outbox
	var bcast *protocol.Message
	for m := range hA.Listen() {
		if m.Broadcast {
			bcast = m
		}
		break
	}
	if bcast == nil {
		t.Fatal("expected a broadcast message")
	}
	if bcast.To != "" {
		t.Fatal("test setup: broadcasts must have an empty To field")
	}

	if !hB.CanAccept(bcast) {
		t.Fatal("a genuine broadcast message must be acceptable")
	}

	evil := *bcast
	evil.To = "b"
	if hB.CanAccept(&evil) {
		t.Error("broadcast message with a specific destination must not be accepted")
	}
}
