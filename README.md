# multi-party-sig

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Go implementation of multi-party threshold signing for:

- ECDSA, using the CGGMP protocol by [Canetti et al.](https://eprint.iacr.org/2021/060).
  The implementation provides distributed key generation and threshold signing on secp256k1.
  Implementation details are documented in [docs/CMP.md](docs/CMP.md).
- Schnorr signatures, using [FROST](https://eprint.iacr.org/2020/852.pdf).
  FROST supports secp256k1 and Edwards25519, including standard Ed25519-compatible signatures on Edwards25519 and Bitcoin Taproot/BIP-340 signatures on secp256k1.
  Nonces are generated during the three-round signing protocol, which does not require a central signing coordinator. See [docs/FROST.md](docs/FROST.md) for protocol-specific details.

> **Disclaimer:** Use at your own risk. This project needs further testing and auditing before it is production-ready.

## Features

- **[BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) key derivation.**
  [`cmp.Config.DeriveBIP32`](protocols/cmp/config/config.go), [`frost.Config.DeriveChild`](protocols/frost/keygen/config.go), and [`frost.TaprootConfig.DeriveChild`](protocols/frost/keygen/config.go) derive new shares without reconstructing the private key. Only unhardened secp256k1 derivation is supported.
- **Constant-time modular arithmetic.**
  CMP's Paillier operations and related zero-knowledge proofs use [saferith](https://github.com/cronokirby/saferith) to mitigate timing leaks.
- **Parallel CMP operations.**
  Expensive CMP computations can use a reusable [`pool.Pool`](pkg/pool/pool.go). Passing `nil` runs them on the calling goroutine.
- **Application-compatible signature formats.**
  CMP signatures support the library's native encoding, DER, and Ethereum's recoverable `r || s || v` form through [`Serialize`, `SerializeDER`, and `SerializeEthereum`](pkg/ecdsa/signature.go). FROST can produce native Schnorr signatures, Ed25519-compatible signatures, BIP-340 signatures, and a Mixin-specific public-key variant.

## Usage

Protocol initializers return a [`protocol.StartFunc`](pkg/protocol/handler.go). Pass that function to `protocol.NewMultiHandler`; once the handler completes, `Handler.Result` returns the value shown below.

### CMP (threshold ECDSA)

| Initializer | Handler result | Description |
| --- | --- | --- |
| [`cmp.Keygen(group, selfID, participants, threshold, pl)`](protocols/cmp/cmp.go) | [`*cmp.Config`](protocols/cmp/config/config.go) | Generates a new ECDSA key shared by all participants. CMP currently supports secp256k1. |
| [`cmp.Sign(config, signers, messageHash, pl)`](protocols/cmp/cmp.go) | [`*ecdsa.Signature`](pkg/ecdsa/signature.go) | Generates an ECDSA signature for `messageHash` with at least `threshold + 1` signers. |

### FROST (threshold Schnorr)

| Initializer | Handler result | Description |
| --- | --- | --- |
| [`frost.Keygen(group, selfID, participants, threshold)`](protocols/frost/frost.go) | [`*frost.Config`](protocols/frost/keygen/config.go) | Generates a shared Schnorr key on secp256k1 or Edwards25519. |
| [`frost.Sign(config, signers, messageHash, variant)`](protocols/frost/frost.go) | Usually [`*frost.Signature`](protocols/frost/sign/types.go) | Generates a signature using one of the variants below. |
| [`frost.KeygenTaproot(selfID, participants, threshold)`](protocols/frost/frost.go) | [`*frost.TaprootConfig`](protocols/frost/keygen/config.go) | Generates a secp256k1 key normalized for Taproot/BIP-340. |
| [`frost.SignTaproot(config, signers, messageHash)`](protocols/frost/frost.go) | [`taproot.Signature`](pkg/taproot/signature.go) | Generates a 64-byte Taproot/BIP-340 signature. |

The `variant` passed to `frost.Sign` is defined in [`protocols/frost/sign`](protocols/frost/sign/sign.go):

| Variant | Curve | Result and compatibility |
| --- | --- | --- |
| `sign.ProtocolDefault` | secp256k1 or Edwards25519 | `*frost.Signature`, verified with `Signature.Verify`. |
| `sign.ProtocolEd25519SHA512` | Edwards25519 | `*frost.Signature` whose 64-byte serialization is Ed25519-compatible; verify with `Signature.VerifyEd25519` or `crypto/ed25519`. |
| `sign.ProtocolMixinPublic` | Edwards25519 | `*frost.Signature` for Mixin's adjusted-public-key signing flow. |
| `sign.ProtocolTaproot` | secp256k1 with a BIP-340-normalized key | `taproot.Signature`; this is the internal variant used by `frost.SignTaproot`, which applications should normally call instead. |

The main arguments have the following requirements:

- [`party.ID`](pkg/party/id.go) is a string identifying a participant. IDs must be unique and must map to distinct, non-zero curve scalars. Every party must use the same participant and signer sets.
- [`curve.Curve`](pkg/math/curve/curve.go) selects the group. CMP supports [`curve.Secp256k1`](pkg/math/curve/secp256k1.go); FROST supports secp256k1 and [`curve.Edwards25519`](pkg/math/curve/edwards25519.go).
- `threshold` is the maximum number of corrupt participants tolerated. A signing set must contain at least `threshold + 1` participants.
- [`*pool.Pool`](pkg/pool/pool.go) is optional and used only by CMP's top-level API. `pool.NewPool(0)` uses one worker per available CPU. A pool must not be used concurrently by multiple protocol executions, and it must be closed with `TearDown`.
- `messageHash` is supplied by the application. For ECDSA and BIP-340, pass the digest required by the surrounding protocol.

### Creating a handler

Each party creates its own handler with the same protocol parameters and session ID. The session ID is mandatory, must contain at least 16 bytes, and must never be reused for another protocol execution.

```go
group := curve.Secp256k1{}
participants := []party.ID{"a", "b", "c", "d", "e"}
selfID := participants[0]
threshold := 3 // at least four participants are required to sign

// All parties use the same value for this execution. Use a different value for
// every subsequent key generation or signing session.
sessionID := []byte("keygen-session-0001")

pl := pool.NewPool(0)
defer pl.TearDown()

start := cmp.Keygen(group, selfID, participants, threshold, pl)
handler, err := protocol.NewMultiHandler(start, sessionID)
if err != nil {
	panic(err) // invalid participants, threshold, curve, or session ID
}
```

### Exchanging messages

Read outgoing messages from `Handler.Listen`, deliver them to every matching recipient, and pass accepted incoming messages to `Handler.Accept`. The transport functions in this sketch are application-defined:

```go
func runProtocol(handler protocol.Handler, participants []party.ID) {
	for {
		select {
		case msgOut, ok := <-handler.Listen():
			if !ok {
				return // the protocol succeeded or aborted
			}

			if msgOut.Broadcast {
				// Deliver through a reliable broadcast channel.
				reliablyBroadcast(msgOut)
				continue
			}

			for _, recipient := range participants {
				if msgOut.IsFor(recipient) {
					send(recipient, msgOut)
				}
			}

		case msgIn := <-receive():
			if handler.CanAccept(msgIn) {
				handler.Accept(msgIn)
			}
		}
	}
}
```

`runProtocol` blocks until the handler succeeds or aborts. Retrieve and type-assert the result afterward:

```go
runProtocol(handler, participants)

result, err := handler.Result()
if err != nil {
	var protocolError protocol.Error
	if errors.As(err, &protocolError) {
		// protocolError.Culprits contains any parties whose misbehavior was
		// locally verified. It may be empty when attribution is impossible.
	}
	return
}

config := result.(*cmp.Config)
```

Call `Handler.Stop` to cancel an unfinished local execution and notify the other parties.

### Configuration storage

The `Config` values returned by key generation contain secret key shares. Store them with confidentiality and integrity protection; in particular, authenticate serialized configurations with a MAC or signature so that tampering is detected.

Configurations implement binary marshaling. Before unmarshaling a generic CMP or FROST configuration, initialize its curve-dependent fields with `cmp.EmptyConfig(group)` or `frost.EmptyConfig(group)`.

### Network requirements

Point-to-point protocol messages require authentication, integrity, and confidentiality. The application is responsible for delivering each message to all participants for which [`Message.IsFor`](pkg/protocol/message.go) returns `true`.

Messages with `Message.Broadcast == true` require reliable broadcast, meaning all honest participants agree on the value sent by each party. The handler includes the [Goldwasser-Lindell echo-broadcast](https://eprint.iacr.org/2002/040) consistency check and aborts if participants received inconsistent broadcasts. When that check fails, the library cannot identify the culprit without additional guarantees from the transport.

## Intellectual property

This code is copyright (c) Adrian Hamelink and Taurus SA, 2021, and under Apache 2.0 license.

On potential patents: the company that sponsored the development of the CMP
protocol [stated](https://apnews.com/press-release/pr-newswire/26aab91e254bc254d331ceafc20b9859)
that it "will not be applying for patents on this technology."
