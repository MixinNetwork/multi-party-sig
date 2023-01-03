package keygen

import (
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/stretchr/testify/require"
)

func TestKeygenEdwards25519(t *testing.T) {
	group := curve.Edwards25519{}
	N := 5
	partyIDs := test.PartyIDs(N)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		r, err := StartKeygenCommon(false, group, partyIDs, N-1, partyID)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutput(t, group, rounds, partyIDs)
}
