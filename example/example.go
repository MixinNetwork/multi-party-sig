package main

import (
	"errors"
	"fmt"
	"sync"

	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/ecdsa"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/MixinNetwork/multi-party-sig/pkg/protocol"
	"github.com/MixinNetwork/multi-party-sig/pkg/taproot"
	"github.com/MixinNetwork/multi-party-sig/protocols/cmp"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
)

func CMPKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPSign(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool) error {
	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}

func FrostKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network) (*frost.Config, error) {
	h, err := protocol.NewMultiHandler(frost.Keygen(curve.Secp256k1{}, id, ids, threshold), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*frost.Config), nil
}

func FrostSign(c *frost.Config, id party.ID, m []byte, signers party.IDSlice, n *test.Network) error {
	h, err := protocol.NewMultiHandler(frost.Sign(c, signers, m), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return err
	}

	signature := r.(frost.Signature)
	if !signature.Verify(c.PublicKey, m) {
		return errors.New("failed to verify frost signature")
	}
	return nil
}

func FrostKeygenTaproot(id party.ID, ids party.IDSlice, threshold int, n *test.Network) (*frost.TaprootConfig, error) {
	h, err := protocol.NewMultiHandler(frost.KeygenTaproot(id, ids, threshold), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*frost.TaprootConfig), nil
}
func FrostSignTaproot(c *frost.TaprootConfig, id party.ID, m []byte, signers party.IDSlice, n *test.Network) error {
	h, err := protocol.NewMultiHandler(frost.SignTaproot(c, signers, m), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return err
	}

	signature := r.(taproot.Signature)
	if !c.PublicKey.Verify(signature, m) {
		return errors.New("failed to verify frost signature")
	}
	return nil
}

func All(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()

	// CMP KEYGEN
	keygenConfig, err := CMPKeygen(id, ids, threshold, n, pl)
	if err != nil {
		return err
	}

	// FROST KEYGEN
	frostResult, err := FrostKeygen(id, ids, threshold, n)
	if err != nil {
		return err
	}

	// FROST KEYGEN TAPROOT
	frostResultTaproot, err := FrostKeygenTaproot(id, ids, threshold, n)
	if err != nil {
		return err
	}

	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

	// CMP SIGN
	err = CMPSign(keygenConfig, message, signers, n, pl)
	if err != nil {
		return err
	}

	// FROST SIGN
	err = FrostSign(frostResult, id, message, signers, n)
	if err != nil {
		return err
	}

	// FROST SIGN TAPROOT
	err = FrostSignTaproot(frostResultTaproot, id, message, signers, n)
	if err != nil {
		return err
	}

	return nil
}

func main() {

	ids := party.IDSlice{"a", "b", "c", "d", "e", "f"}
	threshold := 4
	messageToSign := []byte("hello")

	net := test.NewNetwork(ids)

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()
			if err := All(id, ids, threshold, messageToSign, net, &wg, pl); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()
}
