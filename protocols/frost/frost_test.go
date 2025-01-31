package frost

import (
	"fmt"
	"sync"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/protocol"
	"github.com/MixinNetwork/multi-party-sig/pkg/taproot"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, group curve.Curve, variant int) {
	defer wg.Done()
	h, err := protocol.NewMultiHandler(Keygen(group, id, ids, threshold), nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c0 := r.(*Config)

	h, err = protocol.NewMultiHandler(KeygenTaproot(id, ids, threshold), nil)
	require.NoError(t, err)
	test.HandlerLoop(c0.ID, h, n)

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &TaprootConfig{}, r)

	c0Taproot := r.(*TaprootConfig)

	h, err = protocol.NewMultiHandler(Sign(c0, ids, message, variant), nil)
	require.NoError(t, err)
	test.HandlerLoop(c0.ID, h, n)

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Signature{}, signResult)
	signature := signResult.(*Signature)
	switch variant {
	case sign.ProtocolEd25519SHA512:
		assert.True(t, signature.VerifyEd25519(c0.PublicKey, message))
	default:
		assert.True(t, signature.Verify(c0.PublicKey, message))
	}

	h, err = protocol.NewMultiHandler(SignTaproot(c0Taproot, ids, message), nil)
	require.NoError(t, err)

	test.HandlerLoop(c0.ID, h, n)

	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, taproot.Signature{}, signResult)
	taprootSignature := signResult.(taproot.Signature)
	assert.True(t, c0Taproot.PublicKey.Verify(taprootSignature, message))
}

func testFrost(t *testing.T, group curve.Curve, variant int) {
	N := 5
	T := N - 1
	message := []byte("hello")

	partyIDs := test.PartyIDs(N)
	fmt.Println(partyIDs)

	n := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(N)
	for _, id := range partyIDs {
		go do(t, id, partyIDs, T, message, n, &wg, group, variant)
	}
	wg.Wait()
}

func TestFrost(t *testing.T) {
	testFrost(t, curve.Edwards25519{}, sign.ProtocolEd25519SHA512)
	testFrost(t, curve.Edwards25519{}, sign.ProtocolDefault)
	testFrost(t, curve.Secp256k1{}, sign.ProtocolDefault)
}
