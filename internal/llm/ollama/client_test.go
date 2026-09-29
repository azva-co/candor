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

package ollama

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/azva-co/candor/internal/llm"
)

const (
	testProvider = "trivy"
	testKind     = "Deployment"
	testName     = "api"
)

func TestEnrich_SendsExpectedRequest(t *testing.T) {
	var gotBody chatRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("path = %q, want /api/chat", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"message":{"role":"assistant","content":"{\"hypotheses\":[{\"cause\":\"outdated base image\",\"confidence\":0.8,\"rationale\":\"CVE fixed in a newer base\",\"recommendedAction\":\"Notify\"}]}"}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, WithModel("llama3.2:3b"))

	resp, err := c.Enrich(context.Background(), llm.Request{
		Provider: testProvider, Severity: "CRITICAL", Summary: "3 critical vulns", Kind: testKind, Name: testName,
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody.Model != "llama3.2:3b" {
		t.Errorf("model = %q, want %q", gotBody.Model, "llama3.2:3b")
	}
	if gotBody.Stream {
		t.Error("stream = true, want false - streaming would break the single-response parsing this client does")
	}
	// The core verified property (issue #52's comments): format must be the full schema object,
	// never the bare "json" string, which does not constrain the action enum at all.
	if _, ok := gotBody.Format.(string); ok {
		t.Fatalf("format = %#v, want a JSON schema object, not a bare string", gotBody.Format)
	}
	schema, ok := gotBody.Format.(map[string]any)
	if !ok {
		t.Fatalf("format = %#v (%T), want map[string]any", gotBody.Format, gotBody.Format)
	}
	if schema[schemaType] != "object" {
		t.Errorf("format.type = %v, want %q", schema[schemaType], "object")
	}
	if len(gotBody.Messages) != 1 || gotBody.Messages[0].Role != "user" {
		t.Errorf("messages = %+v, want one user message", gotBody.Messages)
	}

	if len(resp.Hypotheses) != 1 {
		t.Fatalf("got %d hypotheses, want 1", len(resp.Hypotheses))
	}
	if resp.Hypotheses[0].RecommendedAction != "Notify" {
		t.Errorf("RecommendedAction = %q, want %q", resp.Hypotheses[0].RecommendedAction, "Notify")
	}
}

func TestEnrich_UsesDefaultHostAndModelWhenUnset(t *testing.T) {
	c := New("")
	if c.host != DefaultHost {
		t.Errorf("host = %q, want DefaultHost %q", c.host, DefaultHost)
	}
	if c.model != DefaultModel {
		t.Errorf("model = %q, want DefaultModel %q", c.model, DefaultModel)
	}
}

func TestEnrich_ErrorField_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"model 'llama3.2:3b' not found"}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Enrich(context.Background(), llm.Request{Provider: testProvider, Kind: testKind, Name: testName})
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to surface Ollama's own error message", err.Error())
	}
}

func TestEnrich_MalformedContent_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"message":{"role":"assistant","content":"not json at all"}}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.Enrich(context.Background(), llm.Request{Provider: testProvider, Kind: testKind, Name: testName})
	if err == nil {
		t.Fatal("want an error when the model's content isn't valid JSON, got nil")
	}
}
