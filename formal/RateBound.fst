module RateBound

/// Machine-checked (F*) model of the QUANTITATIVE side of invariant I4 (plan 0005): the
/// join/relay token bucket (`TokenBucket` in engine.rs) bounds how much work a flood can
/// force. In a burst (no refill) the number of ADMITTED operations is at most the bucket's
/// token count — hence at most its capacity — and with a refill of `r` (modeling
/// elapsed*rate) at most tokens+r, i.e. LINEAR in elapsed time, never unbounded. This is the
/// part of I4 that was previously stated as an assumption backed by unit tests; it is now
/// proven. (The invite-MAC admission pre-filter that gates WHICH requests reach the bucket is
/// the separate EngineAuth THEOREMs 10/16.)

/// Integer bucket: each `try_take` consumes one whole token, admitting iff tokens > 0.
let try_take (tokens:nat) : (bool & nat) =
  if tokens > 0 then (true, tokens - 1) else (false, 0)

/// Admitted count over `n` attempts against a bucket with `tokens` and NO refill (a burst).
let rec admitted (tokens:nat) (n:nat) : Tot nat (decreases n) =
  if n = 0 then 0
  else
    let (ok, t') = try_take tokens in
    (if ok then 1 else 0) + admitted t' (n - 1)

/// THEOREM 1 (BURST BOUND — I4). For a burst of ANY length, the number of admitted
/// operations is at most the initial token count — a flood cannot force more work than the
/// bucket holds.
let rec thm_burst_bounded (tokens:nat) (n:nat)
  : Lemma (ensures admitted tokens n <= tokens) (decreases n)
  = if n = 0 then ()
    else
      // One step: admitted tokens n == (if ok then 1 else 0) + admitted t' (n-1), and the IH
      // bounds admitted t' (n-1) <= t'. Holds in BOTH cases (t' = tokens-1 when admitted,
      // else t' = 0), so the recursive lemma is invoked unconditionally.
      let (_ok, t') = try_take tokens in
      thm_burst_bounded t' (n - 1)

/// THEOREM 2 (BOUNDED BY CAPACITY). Since the bucket never holds more than its capacity, any
/// burst admits at most `capacity` operations regardless of how many attempts arrive.
let thm_burst_bounded_by_capacity (tokens capacity n:nat)
  : Lemma (requires tokens <= capacity)
          (ensures admitted tokens n <= capacity)
  = thm_burst_bounded tokens n

/// THEOREM 3 (LINEAR IN REFILL / ELAPSED TIME). With `r` tokens refilled before a burst
/// (r == floor(elapsed * refill_rate)), the admitted count is at most tokens+r — so admitted
/// work grows only LINEARLY with elapsed time, never unbounded under a sustained flood.
let thm_admitted_linear_in_refill (tokens r n:nat)
  : Lemma (ensures admitted (tokens + r) n <= tokens + r)
  = thm_burst_bounded (tokens + r) n

/// THEOREM 4 (AN EMPTY BUCKET ADMITS NOTHING). Once drained, every further attempt in the
/// burst is rejected — the hard stop that makes the bound bite under a flood.
let rec thm_empty_bucket_rejects_all (n:nat)
  : Lemma (ensures admitted 0 n == 0) (decreases n)
  = if n = 0 then () else thm_empty_bucket_rejects_all (n - 1)
