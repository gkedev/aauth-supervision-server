# Findings from implementing an SS for Supervision -00

What building and testing this SS showed about the drafts, at AAuth commit `70d67375`.
F1 to F10 and F14 to F17 cite the tests that demonstrate them; F11 to F13 record points
of the drafts and what this SS does.

## F1. The `auth_token` request does not carry the R3 per-call proposal ([AAuth #256](https://github.com/dickhardt/AAuth/issues/256), filed)

- **Draft:** Supervision L462 says "the SS sees what the PS saw". R3 L734 says the SS
  cannot fetch the proposal ("Any other signer MUST be rejected"). The core has the PS
  convey the line between resource-asserted and agent-asserted content to a supervision
  server "in whatever form that context takes" (Protocol L1041); for R3 content, -00
  gives it none.
- **Effect:** under the as-written transport, the SS has no resource-asserted
  `operations`, `parameters` or `result`. A conservative policy therefore asks the
  person in 7 of 10 adversarial scenarios. One of them is T5, where the agent lies about
  the recipient: the SS cannot check the claim, so its `summary` can rest only on it,
  while only the PS, which renders the proposal's `display` for consent (R3 L676), holds
  the resource's account. The same policy decides 9 of 10 when the PS forwards the
  proposal bytes it hash-verified.
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
  it either. [#256](https://github.com/dickhardt/AAuth/issues/256), as its comment of
  2026-10-08 widened it, asks for the R3 document or the per-call proposal. The member
  here carries either, checked against the same `r3_s256`; a document gives operations but no parameters
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
- **Issue:** [AAuth #257](https://github.com/dickhardt/AAuth/issues/257), asking that
  the PS report the resource-asserted released `result` to the SS as replayable state,
  for example as a member of `auth_token.issued`. T9 gives it an executable case, so it
  does not rest only on reading the drafts.

## F3. What an SS does when an `sdi` is reused for a different request is unspecified ([AAuth #258](https://github.com/dickhardt/AAuth/issues/258), filed with F6)

- **Draft:** L196 makes the `sdi` unique within the PS. L316 says a repeated request
  under an answered `sdi` gets the same signed response. Neither says what the SS does
  when a PS (buggy or compromised) sends a *different* request under an `sdi` it already
  answered.
- **Risk:** an SS that keys its replay on `(iss, sdi)` alone hands one act's `allow` to
  another act: a composition `deny` can become an `allow`.
- **This SS:** binds each `sdi` to a digest of the request that opened it, and answers a
  mismatch with `invalid_request`
  (`tests/test_hardening_replay.py::test_sdi_reuse_for_a_different_act_is_refused`).
- **Issue:** [AAuth #258](https://github.com/dickhardt/AAuth/issues/258), as the
  "Also:" of F6, asking for one sentence in Idempotence: "A request under an `sdi` the
  SS has answered that differs from the request it answered MUST be rejected with
  `invalid_request`".

## F4. `auth_token.issued` after an `ask`, with no `decision.resolved` (implementation choice)

- **Draft:** the draft orders resolution before issuance (requests for one person in the
  order the acts occurred, L211, each under its `sdi`, L207), and the PS reports the
  person's answer even after the SS was unavailable (L551, L611). An SS can still receive
  an issuance for an act it asked about with no answer before it: from a PS that issues
  past an `ask` without reporting an answer, or that reports it only after the issuance,
  against L211. A `decision.resolved` the SS refuses is another case: the PS logs an
  `invalid_request` and treats the SS as unavailable for that act (L631), and the draft
  does not say whether it reports the answer again.
- **This SS:**
  - It records the issued act as a fact for composition and budgets, so issuing past an
    `ask` or a `deny` cannot hide it from later decisions.
  - It never treats issuance as the person's answer: reach (`apply`) comes only from
    `decision.resolved`.
- **Tests:** `tests/test_policy.py::test_issued_past_a_deny_still_counts`,
  `tests/test_hardening_replay.py::test_issuance_does_not_answer_an_ask`.

## F5. Connect has an `id` but no stated deduplication (implementation choice)

- **Draft:** a connect carries `id` (the example at L231). L197 requires `id` on an
  event and on a report, and makes `(iss, id)` the deduplication key. Whether a connect
  is a report is not said.
- **This SS:** acts on each connect or disconnect once per `(iss, id)`. Without that, a
  captured `connect` replayed inside the signature window would undo the person's later
  `disconnect` (`tests/test_hardening_replay.py::test_captured_connect_or_disconnect_cannot_replay`).

## F6. "The same signed response" on a retry outlives any freshness check on it ([AAuth #258](https://github.com/dickhardt/AAuth/issues/258), filed)

- **Draft:** Idempotence (L316): a repeated request under an answered `sdi` "MUST be
  answered with the same decision, and where the SS signs, the same signed response".
  Signed Decisions (L342) says what the PS MUST verify (the key set, and the `id` against
  the SS called) and says nothing about the signature's `created`. Protocol L2274
  leaves the `created`-to-verification skew a verifier accepts for a signed artifact it
  first sees after a delay to that verifier's own policy, and Signed Decisions does not
  say that a retried decision is such an artifact.
- **Effect:** the replayed signature carries the `created` of the first answer. A PS that
  applies its request-signature window to responses too (core, Verification, which bounds
  `created` for requests) rejects the retried answer as stale once the window has passed,
  and, counting that as a signature that fails verification, treats it as `server_error`
  (L342). A PS retrying after an outage, the case
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

## F7. The clarification `timeout` is the SS's own deadline (implementation note)

- **Draft:** Supervision L292-308 reuses core Clarification Required, whose `timeout` is
  "Seconds until the server times out the request" and whose recipient "MUST respond
  before this deadline". The example states `"timeout": 120`.
- **Effect:** an SS that copies the example's `timeout` without enforcing it leaves an
  unanswered pending request open for ever.
- **This SS:** enforces the value it states (`408` `expired` after it, per core Polling
  Error Codes), states the time left on a poll or a retry (rounded down, never later
  than it enforces) and the full time again on each new round, and states no timeout
  when configured with 0 (matrix row SUP-P15, `tests/test_service_branches.py`). Nothing for
  the draft; recorded because a second implementation could make the same mistake.

## F8. Supervision gives the SS no way to size a Budgets allocation ([AAuth #259](https://github.com/dickhardt/AAuth/issues/259), filed)

- **Draft:** Budgets L485: "Sizing the allocation is where the PS's supervision
  happens", with responses that include "Grant less" (L507) and "Decline with a figure"
  (L510, `suggested_budget`). With an SS configured the PS "makes no supervision
  decision of its own" (Supervision L79), yet an SS `allow` "MAY narrow it, with members
  the endpoint defines: a `scope` narrower than requested, an `exp` earlier" (L264),
  with no `budget`; `auth_token.issued` (L540) does not say what budget was granted; and
  the SS "calls no one" (L647), so it cannot read the usage counters Budgets lists as an
  input (L494). Supervision does not reference the Budgets draft; it says only that the
  forwarded resource token carries "any budget or other requirement the resource
  attached" (L504).
- **Effect:** the SS sees the resource's offer and its signed consumption record, because
  they ride in the forwarded resource token, but cannot answer with an allocation. A
  ceiling can only allow the whole offer, ask, or deny; who sizes the allocation when an
  SS is configured is unspecified.
- **This SS:** holds a per-mission ceiling per metered resource (`resource_budgets`) and
  counts each allocation as fully consumed (Budgets L831, Unreported Allocations). A
  `budget_consumed` record for its token can only raise that figure: a record "settles
  nothing" (L841), and the SS, which calls no one, never gets the usage reading that
  would settle it (L847). An offer past the headroom, or a request it cannot compare (no
  offer, or one in another unit or scale), is put to the person with the headroom stated
  (`tests/test_budgets.py` and `aauth-ss demo`), and a "yes" lets that one act pass the
  ceiling. Once the ceiling is spent, such a request is denied, as is any offer above 0
  (adversarial T10); an offer of 0 in the ceiling's unit and scale spends nothing and
  fits (Budgets L344, L913; `tests/test_budget_texts.py`).
- **Issue:** [AAuth #259](https://github.com/dickhardt/AAuth/issues/259), asking to let
  an SS `allow` carry a `budget` no larger than the resource token's, and a `deny` carry
  `suggested_budget`, as Budgets defines them; and to add the granted `budget` to
  `auth_token.issued` so the SS's ledger holds what was issued, not the offer.
- **Related:** [AAuth #261](https://github.com/dickhardt/AAuth/issues/261) (opened after
  the pinned commit) proposes one explanation member and optional guidance, modelled on
  `suggested_budget`, for every agent-facing denial, including the SS `deny`. The
  `suggested_budget` part of #259 would fit there.
- **Same shape in R3:** the issuer populates `r3_granted` and `r3_per_call` from its
  policy evaluation (R3 L537, L550), and R3 claims may replace `scope` in the resource
  token (R3 L415). An SS `allow` can name neither, so where R3 replaces `scope` the SS
  has no narrowing member at all, and it cannot move an operation from granted to
  per-call. `auth_token.issued` carries `scope` but not `r3_granted`. This SS never
  narrows `scope` (its `allow` carries only `exp`), so it is not affected, but a policy
  that wanted to cannot.

## F9. A permission grant has no lifetime and no event (not filed)

- **Draft:** core L1238: "`granted`: The agent MAY proceed with the action", with no time
  bound. Supervision L531 turns an SS `allow` into that grant, the event table (L535-545)
  has no event for it, and replay after a routing change (L619) sends missions, their
  logs and outstanding tokens, so a new SS never learns a grant.
- **Effect:** an SS that composes acts must treat a grant as able to take effect at any
  later moment, for good; read as one moment, a permission for the last step of a
  prohibited sequence, taken first, lets the earlier steps through. After a routing
  change the grant is gone.
- **This SS:** counts a grant as never expiring (`tests/test_history_timing.py`), and
  records a grant that `decision.resolved` reports for a request it holds
  (`tests/test_unavailable_supervisor.py`).
- **Possible ask:** an `exp` on a permission `allow` (or a statement that a grant is for
  one immediate use), and a `permission.granted` event with the action, so that replay
  can carry it.

## F10. Delivery order lets a request arrive while another act is still open (not filed)

- **Draft:** L211: "The PS delivers requests for one `(sub, SS)` pair in the order the
  acts occurred." An agent's second request can occur after the SS answered the first
  but before the PS reports its issuance, or while the person is still deciding an
  `ask`, so the SS decides it without the first act in history.
- **This SS:** counts an open act (an `ask` the person is deciding, an open
  clarification, an `allow` not yet reported issued, whose `exp` it caps an hour after
  the decision, Supervision L508) as an uncertain act: an `allow` from that answer on,
  the others from now on. It can make the second request be asked, never denied, and
  spends no budget, though the second request is asked about where the two together
  would, or may, take a budget past its limit (`tests/test_open_acts.py`,
  `tests/test_properties_open_acts.py`). The cost is more asks when requests overlap.
- **Possible ask:** say whether a PS may relay a new request for an agent while another
  of its acts awaits the person or its issuance report, and how long an `allow` stays
  usable before the PS issues on it.

## F11. `decision.resolved` carries no act, and reach does not survive replay (not filed)

- **Draft:** L551 and L611: after the SS was unavailable the PS reports the person's
  answer in `decision.resolved`. L617 lists "the reach the person has given earlier
  answers" among the SS's state, and L619 rebuilds the state by replay.
- **Effect:** an SS that never received the request learns nothing from the resolution;
  a replayed resolution names an `sdi` a new SS never decided, so the reach it carried is
  lost and the person is asked again.
- **Possible ask:** carry the act (or the original request) in `decision.resolved`, or
  replay supervision requests with their resolutions.

## F12. Two small tensions in the error rules (not filed)

- **Unsigned errors:** L320 has an SS with a `jwks_uri` sign "the terminal response to
  every supervision request", and L342 treats "an unsigned terminal response from an SS
  that publishes a `jwks_uri`" as `server_error`. The draft does not say whether an error
  answer such as `unknown_mission` or `unknown_sub` is terminal. This SS signs decisions
  (200), not error answers; a PS that read "terminal" as any non-202 answer would treat
  those as `server_error` and never run the recovery of the Errors table (L633-634).
  Signing error answers too would satisfy either reading.
- **Polls from another PS:** L286 says the SS "MUST answer `unknown_pending` (#errors)
  to a poll from any other" identity, and the Errors table gives `unknown_pending` where
  "the poller is not the requester" (L635); L188 says the SS answers a PS it does not
  accept with `unsupported_iss`. This SS answers an untrusted poller `unsupported_iss`,
  following L188 for that case (matrix row SUP-027).


## F13. Points the draft leaves open, and what this SS does (not filed)

- **An `updated_request` and a retry of the original.** After the agent narrows its
  request through `updated_request` (L310), the SS decides the narrower request. A retry
  of the original request under the same `sdi` then gets that decision (L316: "the same
  decision"), signed against the original body it repeats. Whether a decision about the
  updated request may be bound to the original request's body is not said; a PS that
  checks the `sdi` in the body, as L340 has it do for pending answers, sees the right
  decision.
- **A retry after the clarification deadline.** Once an unanswered clarification times
  out, its pending URL answers `408 expired` once and then `410 Gone` (Protocol L2623,
  L2840). The draft does not say whether a retry of the request under its `sdi` is
  "already answered" or opens a new decision. Answered with the old `Location`, the PS's
  next poll would get `410`, which is not in the Errors table, so it would treat the SS
  as unavailable (L639) and the `sdi` could never be decided. This SS decides such a
  retry again, as it does after a withdrawn question: the question answered nothing, so
  the request gets a new answer, a new question at a new pending URL if it still needs
  one.
- **The body of a `410 Gone`.** Protocol L2840 requires the status only, and neither
  error table has a code for it, so the SS sends `410` with no body.
- **A path the SS does not serve.** No Supervision request names one, and the table pairs
  `invalid_request` with 400 (L631), so the SS answers HTTP's own `404` with an RFC 9457
  body and no AAuth `error` code; the PS reads an unlisted status as `server_error`
  (L639).

## F14. Fetching the PS's published keys is not "a request of the PS" (not filed)

- **Draft:** L190: "The SS never makes a request of the PS". L181: the PS signs "under the
  `jwks_uri` Signature-Key scheme", which the verifier resolves by fetching the signer's
  metadata and JWKS (Signature-Key, `jwks_uri`).
- **This SS:** fetches the PS's `aauth-person.json` and the JWKS it names, under egress
  admission, and nothing else (`tests/test_conformance.py::test_ss_only_fetches_keying_material`).
- **Possible ask:** say in L190 that fetching the PS's published metadata and keys to
  verify its signature is not a request of the PS in the sense of
  #why-ss-never-calls (L723).

## F15. A person token can be access, and the SS cannot tell (not filed)

- **Draft:** Supervision puts a person token request to the SS like any act (L464-L485)
  and reports its issuance (`person_token.issued`, L539). Core Person Identity Access
  (L326-L346): a resource may serve on the person token alone, with "No resource token,
  no auth token", and the PS issues one for each resource it approves with a mission
  (L1415).
- **Effect:** whether a person token is an identity check or access depends on the
  resource, which the SS cannot see. An SS that composes acts has to either treat every
  person token as possible access to the resource or leave identity-served access out.
- **This SS:** takes it from configuration: for a resource the policy lists in
  `serves_on_identity`, a person token joins history as an uncertain act, usable until
  60 seconds past its `exp`, as any token is (`tests/test_identity_access.py`; the
  margin, `tests/test_token_lifetime_sequences.py`); for any other it changes nothing
  (`tests/test_service_branches.py::test_acknowledged_events_change_nothing_but_dedup`).
- **Possible ask:** let resource metadata, or the person token request, say whether the
  resource serves on identity alone, so a supervisor can tell the two apart.

## F16. Agent words in an ask reach the person as the supervisor's (not filed)

- **Draft:** an ask's `summary` is "a Markdown string the PS presents alongside the
  request" (Supervision L266) and each `apply_options` `label` is Markdown the PS shows
  the person (L584). The core requires a PS to "visually distinguish resource-asserted
  content from agent-asserted content" and to attribute the latter to the agent
  (Protocol L1037-L1039), to convey the same distinction to a supervision server "in
  whatever form that context takes" (L1041), and to sanitize Markdown before rendering
  (L215).
- **Effect:** an SS that quotes the agent's justification, or a tool name the agent
  chose, in its `summary` or a `label` hands agent words to the PS as the supervisor's,
  where the distinction the core asks for no longer reaches them. Unescaped, they can
  also be Markdown of their own: an image the PS would load, carrying what the agent
  has read, or a line that reads as the supervisor's verdict. Sanitizing is not defined,
  and need not stop either.
- **This SS:** quotes agent words in a code span or a fenced block that nothing inside
  can close, after "the agent says", with control and format characters removed, and
  quotes a resource's budget unit the same way unless it is a short word of ASCII
  letters (`tests/test_person_facing_text.py`, `tests/test_properties_markdown.py`).
- **Possible ask:** say in Supervision that an SS quoting agent-asserted content in a
  `summary` or `label` marks it as such, or give the ask a member for it, so the PS can
  apply Consent Presentation to it.

## F17. A per-call approval reapplied on resubmission meets "the PS applies none" (not filed)

- **Draft:** R3 L680: when the auth token presented on the call expires before the
  person approves, the PS answers `expired_presented_token`, the agent refreshes and
  resubmits the call, and "The PS SHOULD apply the approval it already recorded rather
  than ask the person again". Supervision L282: with an SS configured, "The PS applies
  none", and every act goes to the SS.
- **Effect:** with an SS configured, the resubmitted call reaches the SS as a new act,
  under a new `sdi`. Nothing in the request ties it to the approval the person gave, so
  an SS cannot tell it from any other call of the same kind.
- **This SS:** decides the resubmission as a new act. An answer the person gave with
  reach `mission` or `always` covers it, as it covers any later act it reaches; one
  given `once` covers only the act it answered, so the person is asked again
  (`tests/test_policy.py::test_reach_of_an_answer`). Matrix row R3-011 is n/a for this
  reason.
- **Possible ask:** say in R3 L680 that with an SS configured the recorded approval is
  the SS's to apply, and give the SS a way to tie the resubmission to the act it
  answered (for example the original `sdi`).
- **Issue:** [AAuth #108](https://github.com/dickhardt/AAuth/issues/108) ("Pending grant
  lifetime, and key rotation across a pending grant") is open. Its comment of
  2026-09-28 names R3 per-call approvals as a case of it: R3 -00 has the agent refresh
  and resubmit and the PS apply the approval it already recorded, and the consent record
  and `stale_evidence` code proposed in its comment of 2026-09-20 (held for -12) would
  let the approval survive instead. It does not discuss an SS.
