---
title: FROST threshold Schnorr signatures
author:
  - J.-P. Aumasson
  - A. Hamelink
  - L. C. Meier
date: 20-08-2026
---

This document describes the [FROST](https://eprint.iacr.org/2020/852.pdf) implementation in this repository. It supports secp256k1 and Edwards25519, performs distributed key generation, and produces signatures without a central signing coordinator.

The public entry points are [`frost.Keygen`](../protocols/frost/frost.go), [`frost.Sign`](../protocols/frost/frost.go), [`frost.KeygenTaproot`](../protocols/frost/frost.go), and [`frost.SignTaproot`](../protocols/frost/frost.go).

## Protocol model

Let $P_1, \ldots, P_n$ be the key holders and let $t$ be the maximum number of corrupt participants tolerated. Key generation creates a Shamir sharing of one Schnorr key. Any subset $S$ with $|S| > t$ can sign.

Every participant runs the same protocol state machine. Commitments and response shares are broadcast directly among the signers, so each participant verifies the other signers and independently constructs the result. Messages marked for broadcast use the consistency mechanism described in [Broadcast.md](Broadcast.md).

The session context binds the protocol identifier, session ID, curve, participant set, and threshold. During signing, nonce derivation also includes that context and the application input, while the binding-factor and challenge hashes include the group public key and application input. Session IDs must contain at least 16 bytes and be unique to each execution.

## Distributed key generation

Key generation follows Figure 1 of the FROST paper and uses three concrete rounds.

### Round 1: polynomial commitments

Each participant $P_i$ samples a degree-$t$ polynomial

$$
f_i(X) = a_{i,0} + a_{i,1}X + \cdots + a_{i,t}X^t
$$

and publishes the coefficient commitments

$$
\Phi_i = (a_{i,0}G, a_{i,1}G, \ldots, a_{i,t}G).
$$

It also creates a Schnorr proof of knowledge of $a_{i,0}$ and commits to a random 32-byte chain-key contribution $c_i$. The VSS commitments, proof, and chain-key commitment are broadcast together.

### Round 2: shares and chain-key opening

Each participant checks that every VSS commitment has degree $t$, contains only prime-order subgroup points, and has a valid proof of knowledge for its constant coefficient.

It then sends $f_i(j)$ privately to each $P_j$ and broadcasts $(c_i, u_i)$, where $u_i$ opens the chain-key commitment.

### Round 3: verification and output

Participant $P_j$ verifies every received share using

$$
f_i(j)G = \Phi_i(j).
$$

It computes its private signing share, verification shares, group public key, and chain key as

$$
s_j = \sum_i f_i(j),
\qquad
Y_j = s_jG,
\qquad
Y = \sum_i a_{i,0}G,
\qquad
c = \bigoplus_i c_i.
$$

The handler result is a [`*frost.Config`](../protocols/frost/keygen/config.go), or a `*frost.TaprootConfig` when using the Taproot entry point.

## Three-round signing

The implementation generates nonce commitments within the signing execution and merges the roles assigned to the signing authority in the paper into the participant state machines.

Let $m$ be the application-supplied message or digest, $Y$ the group public key, and $Y_i$ the verification share of signer $P_i$.

### Round 1: hedged nonce commitments

Each signer generates two nonces $d_i$ and $e_i$ with a hedged construction:

$$
\begin{aligned}
h_i &\leftarrow \mathrm{BLAKE3\text{-}KDF}(\mathrm{enc}(s_i)), \\
a_i &\xleftarrow{R} \{0,1\}^{256}, \\
(d_i,e_i) &\leftarrow \mathrm{ExpandToNonzeroScalars}(\mathrm{BLAKE3}_{h_i}(\mathsf{SSID} \mathbin\| m \mathbin\| a_i)).
\end{aligned}
$$

The secret share makes the nonce unpredictable if the random input is weak, while the random input ensures repeated signatures of the same message use different nonces. The signer reliably broadcasts

$$
D_i = d_iG,
\qquad
E_i = e_iG.
$$

### Round 2: binding factors and response shares

After rejecting identity or non-prime-order nonce commitments, every signer computes the ordered commitment list

$$
B = ((D_1,E_1), \ldots, (D_s,E_s))
$$

and one binding factor per signer:

$$
\rho_i = H(Y, m, B, i).
$$

Including $Y$ binds the signing execution to the group public key, matching the related-key guidance in [RFC 9591, Section 4.4](https://www.rfc-editor.org/rfc/rfc9591.html#section-4.4).

The group commitment and each signer's contribution are

$$
R_i = D_i + \rho_iE_i,
\qquad
R = \sum_i R_i.
$$

For challenge $c$ and Lagrange coefficient $\lambda_i$, signer $P_i$ broadcasts

$$
z_i = d_i + \rho_i e_i + \lambda_i s_i c.
$$

The exact challenge function depends on the selected signature variant.

### Round 3: verify and aggregate

Every participant verifies each response independently:

$$
z_iG = R_i + c\lambda_iY_i.
$$

Valid responses are aggregated as $z = \sum_i z_i$. The implementation constructs the variant-specific signature, verifies it against the public key and message, and only then returns it.

## Signature variants

The variants are defined in [`protocols/frost/sign`](../protocols/frost/sign/sign.go).

### Native Schnorr

`sign.ProtocolDefault` works with secp256k1 and Edwards25519. It computes

$$
c = H(R,Y,m)
$$

with the library's domain-separated hash and returns a `*frost.Signature`. Use `Signature.Verify` for verification.

### Ed25519-compatible

`sign.ProtocolEd25519SHA512` requires Edwards25519 and computes

$$
c = \mathrm{reduce}(\mathrm{SHA\text{-}512}(\mathrm{enc}(R) \mathbin\| \mathrm{enc}(Y) \mathbin\| m)).
$$

The serialized result is 64 bytes and verifies with `crypto/ed25519` or `Signature.VerifyEd25519`.

### Taproot/BIP-340

`frost.KeygenTaproot` creates a secp256k1 sharing whose x-only public key represents the even-y point required by [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki). If the generated group point has odd y, every private and verification share is negated consistently before output.

During signing, the effective group commitment is similarly normalized to even y. The challenge is

$$
c = \mathrm{taggedHash}(\texttt{BIP0340/challenge}, x(R) \mathbin\| x(Y) \mathbin\| m),
$$

and `frost.SignTaproot` returns a 64-byte `taproot.Signature` containing $x(R) \mathbin\| z$.

### Mixin adjusted public key

`sign.ProtocolMixinPublic` requires Edwards25519. The first 32 input bytes must be a canonical encoding of an adjustment scalar $m_s$; the remaining bytes are the signed message $m$. Signing uses the effective public key

$$
P = Y + m_sG
$$

and the Ed25519 challenge over $(R,P,m)$. Before output, the aggregate response is adjusted by $cm_s$, producing an Ed25519-compatible signature for $P$.

## Key derivation

Every key-generation result includes a jointly generated chain key. `Config.Derive` applies an arbitrary public scalar adjustment to all private and verification shares. On secp256k1, `Config.DeriveChild` implements unhardened BIP-32 derivation.

`TaprootConfig.Derive` and `TaprootConfig.DeriveChild` apply the same adjustment and then normalize the derived key back to its even-y representative. Including $Y$ in the signing binding-factor hash ensures signatures are bound to the selected derived key.

On valid secp256k1 configurations, both `DeriveChild` methods panic for a hardened index greater than or equal to `2^31`.

## Point and configuration validation

Edwards25519 has cofactor 8, so decoded points may contain small-order components. Key generation rejects VSS commitments outside the prime-order subgroup, and signing rejects identity or non-prime-order nonce commitments. Generic `Config.UnmarshalBinary` rejects identity or non-prime-order group public keys and verification shares.

Configurations contain private shares and must be stored confidentially with integrity protection. Use `frost.EmptyConfig(group)` before unmarshaling a generic configuration so its curve-dependent fields are initialized. To unmarshal a secp256k1-only `TaprootConfig`, initialize its private share first:

```go
config := &frost.TaprootConfig{
	PrivateShare: curve.Secp256k1{}.NewScalar(),
}
err := config.UnmarshalBinary(data)
```

`TaprootConfig.UnmarshalBinary` reconstructs the verification-share map, and `frost.SignTaproot` checks that the x-only public key lifts to a secp256k1 point when the signing handler starts. Unmarshaling validates an encoding; it does not authenticate the stored configuration.
