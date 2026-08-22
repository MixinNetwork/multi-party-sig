---
title: CMP threshold ECDSA
author:
  - J.-P. Aumasson
  - A. Hamelink
  - L. C. Meier
date: 20-08-2026
---

This document describes the threshold ECDSA implementation in this repository. It follows the final 2021 revision of the CGGMP protocol by [Canetti et al.](https://eprint.iacr.org/archive/2021/060/1634824619.pdf), with a threshold distributed key-generation protocol, a coordinatorless network model, and an echo-broadcast consistency check. A local copy of that 2021-10-21 revision is kept at [CGGMP21.pdf](CGGMP21.pdf). The 2024 protocol rewrite is not the implementation target, although selected verifier hardenings have been backported.

The public entry points are [`cmp.Keygen`](../protocols/cmp/cmp.go) and [`cmp.Sign`](../protocols/cmp/cmp.go). The supported group is secp256k1. Both functions return a `protocol.StartFunc` for use with `protocol.NewMultiHandler`.

## Protocol model

Let $P_1, \ldots, P_n$ be the participants and let $t$ be the maximum number of corrupt participants tolerated. Key generation gives each $P_i$ a Shamir share of one ECDSA key. Any signing set $S$ with $|S| > t$ can produce a signature.

Each execution is bound to a session context containing the application-provided session ID, protocol identifier, curve, participant set, and threshold. Signing also binds the message digest and the configuration's common transcript—the threshold, party IDs, RID, and public parameters—into that context. The session ID must be shared by the participants, contain at least 16 bytes, and be unique to the execution.

There is no central coordinator. Every participant runs the same state machine, sends point-to-point or broadcast messages, verifies the messages it receives, and independently computes the final result. Broadcast consistency is described in [Broadcast.md](Broadcast.md).

## Key configuration

Successful key generation returns one [`cmp.Config`](../protocols/cmp/config/config.go) per participant. A configuration contains:

- the participant's ECDSA, ElGamal, and Paillier secret material;
- every participant's ECDSA and ElGamal public shares;
- every participant's Paillier key and Pedersen parameters;
- the threshold, participant identifiers, joint RID, and joint chain key.

The group public key is reconstructed from the public ECDSA shares with Lagrange interpolation. Configurations contain secret material and must be stored with confidentiality and integrity protection. Initialize a configuration with `cmp.EmptyConfig(curve.Secp256k1{})` before unmarshaling it.

The chain key enables unhardened BIP-32 derivation. `Config.DeriveBIP32(i)` derives the same child adjustment at every participant and applies it to the private and public ECDSA shares without reconstructing the signing key. An index greater than or equal to `2^31` is a hardened index and causes the method to panic.

## Distributed key generation

Each participant $P_i$ samples a degree-$t$ polynomial

$$
f_i(X) = a_{i,0} + a_{i,1}X + \cdots + a_{i,t}X^t
$$

and publishes the coefficient commitments

$$
F_i(X) = f_i(X)G.
$$

After all shares are validated, participant $P_j$ holds

$$
x_j = \sum_{i=1}^{n} f_i(j),
$$

with verification share $X_j = x_jG$. The group public key is

$$
X = \sum_{i=1}^{n} F_i(0).
$$

The implementation uses five concrete rounds.

### Round 1: commit to key material

Each participant generates:

- its degree-$t$ VSS polynomial and coefficient commitments;
- a Paillier secret key and corresponding Pedersen parameters;
- a proof $\Pi_{\mathsf{prm}}$ that the Pedersen parameters are correctly related;
- an ElGamal key pair;
- random contributions $\mathsf{rid}_i$ and $c_i$ to the joint RID and chain key;
- randomness for a Schnorr proof of knowledge of its eventual ECDSA share.

It broadcasts a commitment to the RID, chain-key contribution, VSS commitments, Schnorr commitment, ElGamal public key, public Paillier/Pedersen parameters, and $\Pi_{\mathsf{prm}}$. Committing to this proof before seeing the other openings follows the October 2021 revision.

### Round 2: open commitments

After collecting every commitment, each participant broadcasts the committed values, $\Pi_{\mathsf{prm}}$, and decommitment. Recipients validate the RID and chain-key contributions, VSS degree and subgroup membership, Paillier modulus, Pedersen parameters, and ElGamal public key; verify $\Pi_{\mathsf{prm}}$; and then verify the commitment opening. The ElGamal key must be non-identity and in the curve's prime-order subgroup. No participant produces a factor proof using a peer's Pedersen parameters until this verification has passed.

### Round 3: prove parameters and distribute shares

The joint values are computed as

$$
\mathsf{rid} = \bigoplus_i \mathsf{rid}_i,
\qquad
c = \bigoplus_i c_i.
$$

Each participant broadcasts a proof for its Paillier modulus. For every other participant $P_j$, it also sends:

- an encryption under $P_j$'s Paillier key of $f_i(j)$; and
- a factorization proof constructed with $P_j$'s verified Pedersen parameters and transcript-bound to the encrypted share.

### Round 4: validate and combine shares

Each recipient verifies the proofs, validates the ciphertext, decrypts its share together with its Paillier randomness, checks its range, and verifies

$$
f_i(j)G = F_i(j).
$$

If the plaintext is out of range or does not satisfy this equation, the recipient reliably broadcasts a public `Dec Error` containing the accused sender, ciphertext, ciphertext-bound factor proof, plaintext, and Paillier randomness, and aborts. Every other participant can authenticate the ciphertext's sender, verify its opening, reproduce the failed range/VSS check, and assign the same culprit.

Figure 6 of the 2021 paper lists the sender, ciphertext, plaintext, and Paillier opening in `Dec Error`. This implementation additionally binds the sender's $\Pi_{\mathsf{fac}}$ challenge to that ciphertext and includes the proof in the report. The protocol message API does not itself provide a transferable signature for point-to-point messages, so this binding supplies the sender authentication that a third-party verifier needs; it does not add a refresh or presigning feature.

Otherwise, it sums the received shares, constructs the group public key and all verification shares, and builds its `cmp.Config`. Finally, it broadcasts the response for a Schnorr proof of knowledge of its resulting ECDSA share. The proof transcript is bound to the configuration's common transcript: its threshold, party IDs, RID, and public parameters.

### Round 5: confirm the result

Every participant verifies either a final Schnorr response or a public `Dec Error` from each peer. A valid `Dec Error` aborts with its proven sender as culprit; an invalid report blames the reporting party. If all Schnorr proofs pass, the local configuration is returned.

## Threshold signing

For a signing set $S$, each participant first computes the Lagrange coefficient $\lambda_i$ for its identifier and scales its share:

$$
\widetilde{x}_i = \lambda_i x_i.
$$

The scaled shares form an additive sharing of the same ECDSA secret, allowing the CGGMP signing protocol to run among any subset with more than $t$ participants.

The implementation uses five concrete rounds.

### Round 1: nonce encryptions

Each signer samples $k_i$ and $\gamma_i$, computes $\Gamma_i = \gamma_iG$, and encrypts both scalars under its Paillier key:

$$
K_i = \mathrm{Enc}_i(k_i),
\qquad
G_i = \mathrm{Enc}_i(\gamma_i).
$$

It broadcasts $(K_i, G_i)$ and sends each peer a proof that $K_i$ encrypts a value known to the sender.

### Round 2: multiplication-to-addition

After validating the encryptions, each signer broadcasts $\Gamma_i$ and performs two multiplication-to-addition exchanges with every peer. These exchanges produce additive shares for the products involving $k$, $\gamma$, and the scaled ECDSA secret. Affine-group and discrete-log proofs bind the encrypted values to the corresponding curve points.

### Round 3: nonce consistency shares

Each signer verifies the proofs, decrypts its incoming multiplication shares, and computes shares $\delta_i$ and $\chi_i$ such that their sums represent

$$
\delta = k\gamma,
\qquad
\chi = kx.
$$

It broadcasts $\delta_i$ and $\Delta_i = k_i\Gamma$, together with per-recipient proofs linking $K_i$, $\Delta_i$, and the aggregate $\Gamma = \sum_i \Gamma_i$.

### Round 4: signature shares

The signers aggregate

$$
\delta = \sum_i \delta_i,
\qquad
\Delta = \sum_i \Delta_i
$$

and require $\Delta = \delta G$. They then compute

$$
R = \delta^{-1}\Gamma
$$

and broadcast their response shares

$$
\sigma_i = r\chi_i + k_i m,
$$

where $r$ is the x-coordinate of $R$ and $m$ is the ECDSA scalar derived from the supplied message digest.

### Round 5: aggregate and verify

Each signer computes $\sigma = \sum_i \sigma_i$, constructs the ECDSA signature $(R, \sigma)$, and verifies it against the group public key before returning it.

The resulting [`ecdsa.Signature`](../pkg/ecdsa/signature.go) supports the library's native encoding, DER serialization, and Ethereum's recoverable `r || s || v` representation.

## Validation and aborts

The round handlers perform the structural and cryptographic checks described above before accepting peer data. If a sender-specific check fails, the handler aborts and records that sender in `protocol.Error.Culprits`. A valid public `Dec Error` instead records the sender proven by the evidence, not the party forwarding the report. A broadcast-transcript mismatch also aborts, but cannot be attributed to one party without additional evidence from the transport. `Config.UnmarshalBinary` separately validates its secret and public key material, thresholds, party-ID evaluation points, RID, chain key, and Paillier/Pedersen parameters; successful unmarshaling does not replace storage authentication.
