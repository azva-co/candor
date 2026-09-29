/*
Copyright 2026 Albert Asawaroengchai.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

func TestHMACKeyCache_SetThenGet_ReturnsCachedValue(t *testing.T) {
	var c hmacKeyCache
	key := client.ObjectKey{Namespace: testNamespace, Name: testSecretName}

	if _, ok := c.get(key); ok {
		t.Fatal("get() on an empty cache returned ok = true, want false")
	}

	c.set(key, []byte(testHMACKey))
	got, ok := c.get(key)
	if !ok || string(got) != testHMACKey {
		t.Fatalf("get() = (%q, %v), want (%q, true)", got, ok, testHMACKey)
	}
}

func TestHMACKeyCache_ExpiredEntry_NotReturned(t *testing.T) {
	var c hmacKeyCache
	key := client.ObjectKey{Namespace: testNamespace, Name: testSecretName}

	c.set(key, []byte(testHMACKey))
	// Reach into the unexported entry directly to simulate TTL expiry without a real sleep -
	// hmacKeyCacheTTL is 20s, too long to wait out in a unit test.
	entry := c.entries[key]
	entry.expires = time.Now().Add(-time.Second)
	c.entries[key] = entry

	if _, ok := c.get(key); ok {
		t.Fatal("get() returned ok = true for an expired entry, want false")
	}
	if _, stillThere := c.entries[key]; stillThere {
		t.Error("expired entry was left in the map after get() - it must be deleted, not just ignored, or the map never sheds stale keys for the life of the process")
	}
}

// TestHMACKeyCache_Set_SweepsExpiredEntriesEvenForOtherKeys is the regression test for a real
// finding from a fourth /code-review high pass: get()'s own expiry check only cleans up the exact
// key that was looked up. A key that stops being queried entirely (a deleted/renamed SignalPolicy,
// a Secret rotated under a new name) would otherwise never be swept and stay in the map for the
// life of the process. set() must also sweep, so any key's activity cleans up every other expired
// entry too, not just its own.
func TestHMACKeyCache_Set_SweepsExpiredEntriesEvenForOtherKeys(t *testing.T) {
	var c hmacKeyCache
	staleKey := client.ObjectKey{Namespace: testNamespace, Name: "stale-secret"}
	freshKey := client.ObjectKey{Namespace: testNamespace, Name: testSecretName}

	c.set(staleKey, []byte("stale-value"))
	entry := c.entries[staleKey]
	entry.expires = time.Now().Add(-time.Second)
	c.entries[staleKey] = entry

	// staleKey is never queried again - only freshKey is set from here on.
	c.set(freshKey, []byte(testHMACKey))

	if _, stillThere := c.entries[staleKey]; stillThere {
		t.Error("a different key's set() left an unrelated expired entry in the map - it must sweep every expired entry, not just the one it's writing")
	}
}

func TestHMACKeyCache_GetOrResolve_CachesSuccess(t *testing.T) {
	var c hmacKeyCache
	key := client.ObjectKey{Namespace: testNamespace, Name: testSecretName}

	var resolveCalls atomic.Int32
	resolve := func() ([]byte, error) {
		resolveCalls.Add(1)
		return []byte(testHMACKey), nil
	}

	for range 3 {
		got, err := c.getOrResolve(context.Background(), key, resolve)
		if err != nil {
			t.Fatalf("getOrResolve() error = %v, want nil", err)
		}
		if string(got) != testHMACKey {
			t.Fatalf("getOrResolve() = %q, want %q", got, testHMACKey)
		}
	}
	if got := resolveCalls.Load(); got != 1 {
		t.Errorf("resolve calls = %d, want 1 - a successful result must be cached, not re-resolved", got)
	}
}

func TestHMACKeyCache_GetOrResolve_NeverCachesFailure(t *testing.T) {
	var c hmacKeyCache
	key := client.ObjectKey{Namespace: testNamespace, Name: testSecretName}

	var resolveCalls atomic.Int32
	resolve := func() ([]byte, error) {
		resolveCalls.Add(1)
		return nil, errors.New("boom")
	}

	for range 2 {
		if _, err := c.getOrResolve(context.Background(), key, resolve); err == nil {
			t.Fatal("getOrResolve() error = nil, want the resolve error to propagate")
		}
	}
	if got := resolveCalls.Load(); got != 2 {
		t.Errorf("resolve calls = %d, want 2 - a failed resolve must never be cached", got)
	}
}

// TestHMACKeyCache_GetOrResolve_ConcurrentMisses_ResolveCalledOnce is the regression test for a
// real finding from /code-review high: without coalescing, N goroutines that all miss the cache
// at the same moment (e.g. right after one entry's TTL expires) would each call resolve
// independently, each doing its own apiserver round trip - defeating the point of caching at
// exactly the moment (a concurrent burst) it matters most.
func TestHMACKeyCache_GetOrResolve_ConcurrentMisses_ResolveCalledOnce(t *testing.T) {
	var c hmacKeyCache
	key := client.ObjectKey{Namespace: testNamespace, Name: testSecretName}

	const goroutines = 20
	release := make(chan struct{})
	leaderStarted := make(chan struct{})
	var resolveCalls atomic.Int32
	// nolint:unparam // matches the resolve func(([]byte, error)) signature getOrResolve requires;
	// this test only exercises the success path.
	resolve := func() ([]byte, error) {
		resolveCalls.Add(1)
		<-release
		return []byte(testHMACKey), nil
	}

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	// Establish the leader call first, deterministically, before any follower can race it -
	// singleflight marks a call in-flight before invoking its function, so once leaderStarted
	// fires, every follower's own getOrResolve below is guaranteed to coalesce onto it regardless
	// of scheduling delay, rather than relying on a fixed sleep to make that likely.
	wg.Go(func() {
		if _, err := c.getOrResolve(context.Background(), key, func() ([]byte, error) {
			close(leaderStarted)
			return resolve()
		}); err != nil {
			errs <- err
		}
	})
	<-leaderStarted

	for range goroutines - 1 {
		wg.Go(func() {
			if _, err := c.getOrResolve(context.Background(), key, resolve); err != nil {
				errs <- err
			}
		})
	}
	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("getOrResolve() error = %v, want nil", err)
	}
	if got := resolveCalls.Load(); got != 1 {
		t.Errorf("resolve calls = %d, want 1 - concurrent misses for the same key must be coalesced into a single resolve", got)
	}
}

// TestHMACKeyCache_GetOrResolve_FollowerContextDeadlineExceeded_ReturnsEarly is the regression test
// for a real finding from a fourth /code-review high pass: a follower coalesced onto another
// caller's in-flight resolve must still respect its OWN context's deadline, not be held hostage
// until whichever request happens to be the singleflight leader's own call finishes - Do blocks
// unconditionally with no way for one particular waiter to bail out early; DoChan (what
// getOrResolve actually uses) is required to make that possible.
func TestHMACKeyCache_GetOrResolve_FollowerContextDeadlineExceeded_ReturnsEarly(t *testing.T) {
	var c hmacKeyCache
	key := client.ObjectKey{Namespace: testNamespace, Name: testSecretName}

	leaderStarted := make(chan struct{})
	release := make(chan struct{})
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = c.getOrResolve(context.Background(), key, func() ([]byte, error) {
			close(leaderStarted)
			<-release // never closed until this test is done - the leader outlives the follower below
			return []byte(testHMACKey), nil
		})
	}()
	t.Cleanup(func() {
		close(release)
		<-leaderDone
	})
	<-leaderStarted

	followerCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.getOrResolve(followerCtx, key, func() ([]byte, error) {
		t.Fatal("follower's own resolve must never run - it should coalesce onto the in-flight leader instead of starting its own")
		return nil, nil
	})
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("getOrResolve() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("getOrResolve() took %v to return after its own context's deadline, want it to return promptly rather than waiting for the still-in-flight leader to finish", elapsed)
	}
}

// newCountingTestReceiver is newTestReceiver plus a live count of Get calls against corev1.Secret
// specifically, so a test can assert the cache actually avoids apiserver round trips rather than
// just returning the right value incidentally. Builds on the same newTestFakeClient every other
// test Receiver in this package uses, rather than duplicating its scheme/client construction.
func newCountingTestReceiver(t *testing.T, objs ...client.Object) (*Receiver, *atomic.Int32) {
	t.Helper()
	inner, scheme := newTestFakeClient(t, objs...)

	var secretGets atomic.Int32
	c := interceptor.NewClient(inner, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				secretGets.Add(1)
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	return &Receiver{Client: c, Scheme: scheme}, &secretGets
}

func TestReceiver_RepeatedRequests_ReuseCachedHMACKey(t *testing.T) {
	r, secretGets := newCountingTestReceiver(t, withWebhookReceiver(), testSecret())

	body := []byte(validBody)
	sig := sign([]byte(testHMACKey), body)
	for i := range 3 {
		rec := doRequest(t, r, testPolicyName, body, sig)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, http.StatusAccepted)
		}
	}

	if got := secretGets.Load(); got != 1 {
		t.Errorf("Secret Get calls = %d, want 1 - later requests within the TTL should reuse the cached HMAC key", got)
	}
}

// TestReceiver_ConcurrentMisses_OneRequestCanceled_OtherStillSucceeds is the regression test for a
// real finding from a second /code-review high pass: the resolve closure receiver.go passes to
// getOrResolve must build its own context, not reuse the calling request's own ctx - singleflight
// invokes that closure at most once per set of concurrent misses and shares its result with every
// caller waiting on it, so a shared closure keyed to one particular request's context would let
// that request's own cancellation (client disconnect, its own deadline) fail every other request
// coalesced onto it, even though their contexts are still perfectly healthy.
func TestReceiver_ConcurrentMisses_OneRequestCanceled_OtherStillSucceeds(t *testing.T) {
	inner, scheme := newTestFakeClient(t, withWebhookReceiver(), testSecret())

	blockedInGet := make(chan struct{}, 1)
	release := make(chan struct{})
	var secretGets atomic.Int32
	c := interceptor.NewClient(inner, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				if secretGets.Add(1) == 1 {
					blockedInGet <- struct{}{}
					<-release
				}
				// The fake client's own Get doesn't check ctx cancellation the way a real
				// apiserver round trip would - checked explicitly here so this test can actually
				// simulate what canceling the leader's context is meant to simulate.
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	r := &Receiver{Client: c, Scheme: scheme}

	// Different payload IDs so A's and B's own signal.Ingest calls target different Findings -
	// this test is about secret-resolution coalescing, not about two concurrent Ingest calls
	// racing on one object, which is an unrelated concern.
	bodyA := []byte(`{"severity":"HIGH","kind":"Deployment","name":"api","summary":"a","id":"issue-a"}`)
	bodyB := []byte(`{"severity":"HIGH","kind":"Deployment","name":"api","summary":"b","id":"issue-b"}`)

	// Request A becomes the singleflight leader and blocks inside the Secret Get above.
	ctxA, cancelA := context.WithCancel(context.Background())
	reqA := httptest.NewRequest(http.MethodPost, "/webhook/"+testNamespace+"/"+testPolicyName, bytes.NewReader(bodyA)).WithContext(ctxA)
	reqA.Header.Set(signatureHeader, sign([]byte(testHMACKey), bodyA))
	recA := httptest.NewRecorder()
	doneA := make(chan struct{})
	go func() {
		r.Handler().ServeHTTP(recA, reqA)
		close(doneA)
	}()
	<-blockedInGet

	// Request B joins the same in-flight resolve as a follower - deterministically, not just
	// probably: release (below) isn't closed until after B is launched here, and the cache can
	// only be populated once the leader's own resolve returns, which can't happen until release
	// is closed. So whenever B's goroutine actually gets scheduled, it must still find the leader
	// in-flight rather than a populated cache - no sleep needed to make this likely.
	doneB := make(chan *httptest.ResponseRecorder, 1)
	go func() { doneB <- doRequest(t, r, testPolicyName, bodyB, sign([]byte(testHMACKey), bodyB)) }()

	cancelA()      // A's own request context is canceled...
	close(release) // ...then the shared, leader-triggered Get is allowed to complete.
	<-doneA
	recB := <-doneB

	if recB.Code != http.StatusAccepted {
		t.Errorf("request B status = %d, want %d, body: %s - request A's context being canceled must not fail request B, which shares A's coalesced Secret resolve but has its own healthy context",
			recB.Code, http.StatusAccepted, recB.Body.String())
	}
	if got := secretGets.Load(); got != 1 {
		t.Errorf("Secret Get calls = %d, want 1 - request B must have joined request A's in-flight resolve, not started its own", got)
	}
}

// TestReceiver_HMACKeyResolve_UsesFixedTimeoutIndependentOfOuterCtx is the regression test for a
// real finding from a fifth /code-review high pass: an earlier fix derived the resolve closure's
// deadline from the calling (leader) request's own remaining ctx budget, to avoid doubling this
// handler's worst-case latency. But singleflight coalesces concurrent misses onto whichever
// request happens to become the leader - tying the shared call's deadline to that one arbitrary
// request's own remaining time would make every other request coalesced onto it succeed or fail
// based on a completely unrelated request's timeline, not its own (e.g. a follower with a fresh,
// generous budget failing because it joined a leader whose own SignalPolicy Get had already eaten
// most of its budget). The fix is a fixed, independent secretResolveTimeout instead: this test
// proves the Secret Get's own deadline does NOT shrink as the SignalPolicy Get ahead of it in the
// same request takes longer, which a ctx-derived deadline would.
func TestReceiver_HMACKeyResolve_UsesFixedTimeoutIndependentOfOuterCtx(t *testing.T) {
	inner, scheme := newTestFakeClient(t, withWebhookReceiver(), testSecret())

	const policyGetDelay = 1 * time.Second
	var secretDeadline time.Time
	var haveDeadline bool
	c := interceptor.NewClient(inner, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			switch obj.(type) {
			case *candorv1alpha1.SignalPolicy:
				time.Sleep(policyGetDelay)
			case *corev1.Secret:
				secretDeadline, haveDeadline = ctx.Deadline()
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	r := &Receiver{Client: c, Scheme: scheme}

	body := []byte(validBody)
	rec := doRequest(t, r, testPolicyName, body, sign([]byte(testHMACKey), body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if !haveDeadline {
		t.Fatal("Secret Get's context had no deadline at all")
	}

	const tolerance = 300 * time.Millisecond
	if remaining := time.Until(secretDeadline); remaining < secretResolveTimeout-tolerance || remaining > secretResolveTimeout {
		t.Errorf("Secret Get's remaining deadline = %v, want close to secretResolveTimeout (%v) regardless of the %v already spent on the SignalPolicy Get - deriving it from the outer request's own remaining budget would make a coalesced follower's success depend on a completely unrelated request's timeline",
			remaining, secretResolveTimeout, policyGetDelay)
	}
}

func TestReceiver_MisconfiguredSecret_NeverCached(t *testing.T) {
	// The Secret doesn't exist yet: the first two requests must both hit the apiserver, not cache
	// a failure - a fix (creating the Secret) must take effect on the very next request rather
	// than waiting out hmacKeyCacheTTL.
	r, secretGets := newCountingTestReceiver(t, withWebhookReceiver())

	body := []byte(validBody)
	sig := sign([]byte(testHMACKey), body)
	doRequest(t, r, testPolicyName, body, sig)
	doRequest(t, r, testPolicyName, body, sig)

	if got := secretGets.Load(); got != 2 {
		t.Errorf("Secret Get calls = %d, want 2 - a missing/misconfigured secret must never be cached", got)
	}
}
