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

package controller

import (
	"context"
	"testing"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/llm"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// sanitizeRecommendedAction is the backend-agnostic brake for slice 10 (issue #53): whichever LLM
// backend produced a Hypothesis, an out-of-catalog RecommendedAction must never reach the CRD
// field, since the API server would reject the *whole* status update over the field's
// +kubebuilder:validation:Enum marker, not just drop the bad value.
func TestSanitizeRecommendedAction(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty stays empty - a valid no-recommendation", "", ""},
		{"Notify passes through", candorv1alpha1.ActionNotify, candorv1alpha1.ActionNotify},
		{"ProposePullRequest passes through", candorv1alpha1.ActionProposePullRequest, candorv1alpha1.ActionProposePullRequest},
		{"an out-of-catalog value is dropped to empty, not passed through", "DeleteEverything", ""},
		{"case must match exactly - no case-insensitive leniency", "notify", ""},
		{"whitespace is not trimmed - exact match only", " Notify", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeRecommendedAction(tt.in); got != tt.want {
				t.Errorf("sanitizeRecommendedAction(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestFindingReconciler_MaliciousRecommendedAction_NeverPersisted exercises the same path a real
// reconcile takes: a fake LLM (standing in for any backend, not just Anthropic) returns an
// out-of-catalog RecommendedAction, and the Finding's persisted status must never carry it -
// proving toHypotheses's sanitization is actually wired into the reconcile path, not just correct
// in isolation.
func TestFindingReconciler_MaliciousRecommendedAction_NeverPersisted(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	finding := newTestFinding("f1")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(finding).WithStatusSubresource(&candorv1alpha1.Finding{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{
		{Cause: testCauseOutdatedImage, Confidence: 0.9, Rationale: "injected via untrusted scanner data", RecommendedAction: "DeleteEverything"},
	}}}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}

	got := &candorv1alpha1.Finding{}
	if err := c.Get(context.Background(), namespacedName(finding), got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Hypotheses) != 1 {
		t.Fatalf("got %d hypotheses, want 1", len(got.Status.Hypotheses))
	}
	if action := got.Status.Hypotheses[0].RecommendedAction; action != "" {
		t.Errorf("RecommendedAction = %q, want empty - the malicious value must never be persisted", action)
	}
	// The rest of the hypothesis must still land - sanitizing one field must not discard the whole
	// hypothesis.
	if got.Status.Hypotheses[0].Cause != testCauseOutdatedImage {
		t.Errorf("Cause = %q, want %q - sanitizing RecommendedAction must not affect other fields", got.Status.Hypotheses[0].Cause, testCauseOutdatedImage)
	}
}
