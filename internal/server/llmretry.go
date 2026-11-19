package server

import (
	"time"

	"github.com/Aiz9/ripple/internal/agent"
	"github.com/Aiz9/ripple/internal/db"
)

// Server retry-policy resolution across five layers:
// - Connection/empty/safe-window settings follow endpoints; profile overrides global,
//   unspecified profile inherits global, unspecified global uses built-ins.
// - Breaker and intent reruns have one process-wide policy.
//
// Read one settings row on low-frequency provider construction, work completion, and config save;
// no cache needed. Breaker checks occur on each failure, so applyRetryPolicy stores their
// resolved values in Registry.

// retryPolicy reads the global policy; a nil DB yields the zero policy (all
// layers on their built-in defaults).
func (s *Server) retryPolicy() db.LLMRetryPolicy {
	if s.m == nil || s.m.pg == nil {
		return db.LLMRetryPolicy{}
	}
	return s.m.pg.LLMRetryPolicy()
}

// resolveRetry layers one profile's override on top of the global policy and
// converts the result into the form agent.Config carries. Rules combine field by
// field, so a profile that only pins an interval still inherits the global count.
func resolveRetry(o db.RetryOverride, pol db.LLMRetryPolicy) agent.RetryConfig {
	connect := o.Connect.Or(pol.Connect)
	empty := o.Empty.Or(pol.Empty)
	stream := o.Stream.Or(pol.Stream)
	return agent.RetryConfig{
		// Preserve SDK count semantics 0/default and negative/disabled; MaxRetries/EmptyResponseRetries
		// resolve those values themselves.
		ConnectAttempts: connect.Attempts, ConnectInterval: connect.Interval(),
		EmptyAttempts: empty.Attempts, EmptyInterval: empty.Interval(),
		StreamAttempts: stream.Attempts, StreamInterval: stream.Interval(),
	}
}

// applyProfileRetry fills cfg.Retry for a profile read from the DB.
func (s *Server) applyProfileRetry(cfg *agent.Config, p *db.LLMProfile) {
	if p == nil {
		return
	}
	cfg.Retry = resolveRetry(p.Retry, s.retryPolicy())
}

// Breaker cooldown defaults match llmpool and are overridden only for configured values.
// Intent rerun defaults are engine.go modelErrorRetries/modelErrorRetryBackoff.

// applyRetryPolicy pushes the process-wide layers of the policy into the objects
// that consume them on a hot path: the circuit-breaker registry. Called at
// startup and whenever the policy is saved.
func (s *Server) applyRetryPolicy() {
	pol := s.retryPolicy()
	if s.llmHealth != nil {
		s.llmHealth.SetPolicy(pol.Breaker.Attempts, pol.Breaker.Interval())
	}
}

// modelErrorRetryPolicy resolves the intent-level replay knobs (layer ⑤): how
// many times a model_error work is re-run and how long to back off between runs.
func (e *Engine) modelErrorRetryPolicy() (retries int, backoff time.Duration) {
	retries, backoff = modelErrorRetries, modelErrorRetryBackoff
	if e == nil || e.m == nil || e.m.pg == nil {
		return retries, backoff
	}
	rule := e.m.pg.LLMRetryPolicy().Intent
	if rule.Attempts != 0 {
		retries = max(rule.Attempts, 0)
	}
	if d := rule.Interval(); d > 0 {
		backoff = d
	}
	return retries, backoff
}

// emptyTurnNudgeLimit resolves how many empty-turn continuations one work may
// inject (steerHooks.Stop), sharing layer 2's empty-response retry setting:
// SDK retries requests with no content blocks unchanged; this layer handles reasoning-only
// turns by appending a continuation, because identical prompt replay repeats the same idle
// behavior. SDK considers any yielded event content, including reasoning deltas; users instead
// mean retry when no substantive output occurred, so both mechanisms share the same count.
// Different detection boundaries implement one user-facing retry intention.
// Keep their configuration aligned.
//
// Read global policy rather than profile overrides because failover can change profiles mid-run;
// this whole-intent cap must not reset with endpoints. Match SDK emptyRetries semantics:
// 0=defaultEmptyTurnNudges; negative=disabled; positive=explicit count.
func (e *Engine) emptyTurnNudgeLimit() int {
	if e == nil || e.m == nil || e.m.pg == nil {
		return defaultEmptyTurnNudges
	}
	switch n := e.m.pg.LLMRetryPolicy().Empty.Attempts; {
	case n == 0:
		return defaultEmptyTurnNudges
	case n < 0:
		return 0
	default:
		return n
	}
}
