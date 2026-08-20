---
title: Broadcast consistency
author:
  - J.-P. Aumasson
  - A. Hamelink
  - L. Meier
date: 20-08-2026
---

Threshold signing must remain safe when a signing set contains a dishonest majority. A malicious sender can equivocate over ordinary point-to-point connections by sending different versions of a broadcast message to different participants. The protocol handler therefore distinguishes ordinary messages from messages that require broadcast consistency.

## Message types

[`protocol.Message`](../pkg/protocol/message.go) contains the session identifier, sender, optional recipient, protocol identifier, round number, encoded content, broadcast flag, and the verification hash for the preceding broadcast round.

- A point-to-point message has `Broadcast == false` and is normally addressed to one participant through `To`.
- A broadcast message has `Broadcast == true`, an empty `To` field, and must be delivered to every other participant.
- An abort notification uses round number 0 and informs peers that the sender's local handler stopped with an error.

`Message.IsFor(id)` reports whether the application should deliver a message to a participant. `Handler.CanAccept` checks the destination, protocol, session, sender, and round before `Handler.Accept` processes it.

All transports must provide peer authentication and message integrity. Point-to-point protocol payloads also require confidentiality. Applications may serialize messages with `Message.MarshalBinary`; authenticating the serialized message or `Message.Hash()` binds both its headers and content.

## Echo-broadcast check

The handler implements the broadcast-with-abort technique used by Goldwasser and Lindell. Suppose a protocol round requires every $P_i$ to broadcast $x_i$.

1. Each participant receives and stores one $x_i$ for every sender.
2. It computes an ordered transcript hash

   $$
   V = H(x_1, \ldots, x_n).
   $$

3. Every message it sends in the following round includes $V$ in `BroadcastVerification`.
4. After receiving the following-round messages, it compares every attached value with its own $V$.
5. If any value differs, the handler aborts with a broadcast-verification error.

The transcript hash uses the sorted participant order and hashes the complete protocol messages, including their session and round headers. A participant that sends inconsistent broadcast values therefore causes honest recipients to compute different verification hashes and abort in the next round.

This mechanism guarantees consistency or abort; it does not guarantee delivery or fairness. A malicious participant can deliberately force an abort by equivocating or withholding a message.

## Fault attribution

A locally invalid proof, point, scalar, ciphertext, or other message value is attributable to the sender whose message failed verification. In that case, `protocol.Error.Culprits` identifies the sender.

A mismatched echo hash proves that honest parties saw inconsistent broadcast transcripts, but the hash alone does not show which sender equivocated. Such an abort therefore has no culprit unless the transport provides independently verifiable evidence, such as authenticated copies of both conflicting messages.

Abort notifications are also not accusations. A peer may be honestly reporting a failure that another participant has not yet observed, so receiving a round-0 abort does not add its sender to the culprit list.

## Application responsibilities

For every protocol execution, the application must:

- use the same participant set and a common, unique session ID of at least 16 bytes;
- deliver every broadcast message to all other participants without changing it;
- deliver point-to-point messages only to their intended recipients;
- preserve authentication, integrity, and confidentiality as required;
- continue processing until `Handler.Listen()` closes, or call `Handler.Stop()` when cancelling locally.

A transport with a native reliable-broadcast primitive can use it for messages marked `Broadcast`. Over authenticated point-to-point channels, delivering the same outgoing message to every recipient allows the handler's echo check to detect equivocation.
