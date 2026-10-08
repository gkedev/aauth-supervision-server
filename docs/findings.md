# Findings from implementing an SS for Supervision -00

What building and testing this SS showed about the drafts, at AAuth commit `70d6737`.
Each finding cites the test that demonstrates it.

## F1. The `auth_token` request does not carry the R3 per-call proposal ([AAuth #256](https://github.com/dickhardt/AAuth/issues/256), filed)

- **Draft:** Supervision L462 says "the SS sees what the PS saw". R3 L734 says the SS
  cannot fetch the proposal ("Any other signer MUST be rejected").
- **Effect:** under the as-written transport, the SS has no resource-asserted
  `operations`, `parameters` or `result`. A conservative policy therefore asks the person
  in 7 of 10 adversarial scenarios. One of them is T5, where the agent lies about the
  recipient and the person sees only the agent's claim. The same policy decides 9 of 10
  when the PS forwards the proposal bytes it hash-verified.
- **Tests:** `tests/test_adversarial.py::test_critical_decisions`, the `apc/current` and
  `apc/forwarded` columns of `docs/adversarial-results.md`;
  `tests/test_policy.py::test_justification_never_turns_an_ask_into_allow`.
- **Implementation:** with the extension enabled (`r3_member` in the policy; off by
  default, so the server is spec-only unless you opt in), the SS accepts `r3_proposal`
  (base64url of the exact bytes) in the decision request and checks it against the
  resource token's `r3_s256`
  (`tests/test_conformance.py::test_forwarded_proposal_must_match_r3_s256`,
  `tests/test_r3_extension_optin.py`).
- **Wider than per-call:** the same holds for the R3 document an ordinary R3 resource
  token references. R3 Issuer Processing has the issuer fetch it and "Use the
  `operations` section for policy evaluation" (R3 L549), and the SS cannot fetch
  it either. [#256](https://github.com/dickhardt/AAuth/issues/256) asks only for the per-call proposal. The member here carries either,
  checked against the same `r3_s256`; a document gives operations but no parameters
  (`tests/test_r3_extension_optin.py::test_forwarded_r3_document_gives_operations_but_no_parameters`).

## F2. A released `result` does not reach later decisions or a replacement SS ([AAuth #257](https://github.com/dickhardt/AAuth/issues/257), filed)

- **Draft:** `auth_token.issued` (L540) has no member for the proposal or its `result`.
  On replay (L619) a new SS rebuilds history from those events.
- **Effect:** even with F1 fixed, after a routing change a sensitive release replays as an
  uncertain read. The new SS can then only ask about an external send that the old SS
  would have denied.
- **Tests:** T9 (`apc/forwarded` = ask, `apc/forwarded+issued` = deny);
  `tests/test_adversarial.py::test_request_forwarding_alone_does_not_survive_a_routing_change`;
  `tests/test_policy.py::test_replay_without_the_proposal_loses_certainty` versus
  `test_replay_gives_the_same_history`.
- **Issue:** [AAuth #257](https://github.com/dickhardt/AAuth/issues/257). T9 gives it an
  executable case, so it does not rest only on reading the drafts.

## F3. What an SS does when an `sdi` is reused for a different request is unspecified ([AAuth #258](https://github.com/dickhardt/AAuth/issues/258), filed with F6)

- **Draft:** L196 makes the `sdi` unique within the PS. L316 says a repeated request
  under an answered `sdi` gets the same signed response. Neither says what the SS does
  when a PS (buggy or compromised) sends a *different* request under an `sdi` it already
  answered.
- **Risk:** an SS that keys its replay on `(iss, sdi)` alone hands one act's `allow` to
  another act. A review of this implementation found exactly this in an earlier version: a
  composition deny became an allow.
- **This SS:** binds each `sdi` to a digest of the request that opened it, and answers a
  mismatch with `invalid_request`
  (`tests/test_hardening_replay.py::test_sdi_reuse_for_a_different_act_is_refused`).
- **Issue:** [AAuth #258](https://github.com/dickhardt/AAuth/issues/258), as the
  "Also:" of F6, asking for one sentence in Idempotence: "A request under an `sdi` the
  SS has answered that differs from the request it answered MUST be rejected with
  `invalid_request`".

## F4. `auth_token.issued` after an `ask`, with no `decision.resolved` (implementation choice)

- **Draft:** the draft orders resolution before issuance, but an SS still receives
  issuance events for acts it asked about and never saw answered. One example is the SS
  being unavailable during the act (L611).
- **This SS:**
  - It records the issued act as a fact for composition and budgets, so issuing past an
    `ask` or a `deny` cannot hide it from later decisions.
  - It never treats issuance as the person's answer: reach (`apply`) comes only from
    `decision.resolved`.
- **Tests:** `tests/test_policy.py::test_issued_past_a_deny_still_counts`,
  `tests/test_hardening_replay.py::test_issuance_does_not_answer_an_ask`.

## F5. Connect has an `id` but no stated deduplication (implementation choice)

- **Draft:** a connect carries `id` (L238), and L197 makes `(iss, id)` the deduplication
  key "on an event and on a report". Whether a connect is a report is not said.
- **This SS:** acts on each connect or disconnect once per `(iss, id)`. Without that, a
  captured `connect` replayed inside the signature window would undo the person's later
  `disconnect` (`tests/test_hardening_replay.py::test_captured_connect_or_disconnect_cannot_replay`).

## F6. "The same signed response" on a retry outlives any freshness check on it ([AAuth #258](https://github.com/dickhardt/AAuth/issues/258), filed)

- **Draft:** Idempotence (L316): a repeated request under an answered `sdi` "MUST be
  answered with the same decision, and where the SS signs, the same signed response".
  Signed Decisions (L342) says what the PS MUST verify (the key set, and the `id` against
  the SS called) and says nothing about the signature's `created`.
- **Effect:** the replayed signature carries the `created` of the first answer. A PS that
  applies its request-signature window to responses too (core, Verification, which bounds
  `created` for requests) rejects the retried answer as stale once the window has passed,
  and per L342 treats it as `server_error`. A PS retrying after an outage, the case
  idempotence exists for, is the one that hits it. The two plausible readings disagree:
  either the PS must not apply a window to a decision response, or the SS should re-sign
  the stored decision for the delivery (same body, fresh `created`), which is not "the
  same signed response".
- **This SS:** follows L316 literally and replays the stored signature, so the PS's log
  entry for the `sdi` is one signature however often it retried
  (`tests/test_service_semantics.py::test_a_retry_long_after_is_still_byte_identical`).
  The simulated PS's verifier does apply a 300 s window, and the model-based lifecycle
  test found the conflict by retrying 301 s after an answer
  (`tests/test_properties_lifecycle.py`, which verifies retries without the window).
- **Issue:** [AAuth #258](https://github.com/dickhardt/AAuth/issues/258), asking for
  one sentence in Signed Decisions: "The PS does not apply a freshness window to a
  decision response: a retried request is answered with the original signed response
  (#idempotence)."

## F7. The clarification `timeout` binds the SS that states it (implementation note)

- **Draft:** Supervision L292-308 reuses core Clarification Required, whose `timeout` is
  "Seconds until the server times out the request" and whose recipient "MUST respond
  before this deadline". The example states `"timeout": 120`.
- **This SS:** an earlier version stated 120 and enforced nothing; an unanswered pending
  request lived forever. It now enforces the value it states (`408` `expired` after it,
  per core Polling Error Codes), restates the full time on each round, and states no
  timeout when configured with 0 (SUP-P15, `tests/test_service_branches.py`). Nothing for
  the draft: recorded because a second implementation could make the same mistake, and
  the matrix had no row for it until a curated one was added.



## F8. Supervision gives the SS no way to size a Budgets allocation ([AAuth #259](https://github.com/dickhardt/AAuth/issues/259), filed)

- **Draft:** Budgets L485: "Sizing the allocation is where the PS's supervision happens",
  with responses that include "Grant less" (L507) and "Decline with a figure" (L510,
  `suggested_budget`). With an SS configured the PS "makes no supervision decision of its
  own" (Supervision L79), yet an SS `allow` "MAY narrow it, with members the endpoint
  defines: a `scope` narrower than requested, an `exp` earlier" (L264), with no `budget`;
  `auth_token.issued` (L540) does not say what budget was granted; and the SS "calls no
  one" (L647), so it cannot read the usage counters Budgets lists as an input (L494).
  Supervision does not mention Budgets.
- **Effect:** the SS sees the resource's offer and its signed consumption record, because
  they ride in the forwarded resource token, but cannot answer with an allocation. A
  ceiling can only allow the whole offer, ask, or deny; who sizes the allocation when an
  SS is configured is unspecified.
- **This SS:** holds a per-mission ceiling per metered resource (`resource_budgets`),
  counts each allocation as fully consumed until a `budget_consumed` for its token
  arrives (Budgets L831, Unreported Allocations), and puts an offer past the headroom to
  the person with the headroom stated (`tests/test_budgets.py`, adversarial T10, and
  `aauth-ss demo`).
- **Issue:** [AAuth #259](https://github.com/dickhardt/AAuth/issues/259), asking to let
  an SS `allow` carry a `budget` no larger than the resource token's, and a `deny` carry
  `suggested_budget`, as Budgets defines them; and to add the granted `budget` to
  `auth_token.issued` so the SS's ledger holds what was issued, not the offer.
- **Same shape in R3:** the issuer populates `r3_granted` and `r3_per_call` "per policy"
  (R3 L537, L550), and R3 claims may replace `scope` in the resource token (R3 L415). An
  SS `allow` can name neither, so where R3 replaces `scope` the SS has no narrowing member
  at all, and it cannot move an operation from granted to per-call. `auth_token.issued`
  carries `scope` but not `r3_granted`. This SS never narrows `scope` (its `allow`
  carries only `exp`), so it is not affected, but a policy that wanted to cannot.
