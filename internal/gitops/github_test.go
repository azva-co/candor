package gitops

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-github/v76/github"

	candorv1alpha1 "github.com/teerakarna/candor/api/v1alpha1"
)

const (
	originalYAML   = "image:\n  repository: ghcr.io/foo/bar\n  tag: v1.0.0\n"
	testBaseBranch = "main"
	testBaseSHA    = "base-commit-sha"
	testRepository = "ghcr.io/foo/bar"
	testCurrentTag = "v1.0.0"
	testNewTag     = "v1.2.0"
	testPRURL      = "https://github.com/acme/gitops/pull/42"
)

// fakeGitHub stands in for the real GitHub REST API, returning just enough of each real response
// shape for go-github to parse - the same "fake but interface-real" posture
// internal/llm/anthropic's tests use against a real httptest.Server, so GitHubOpener's actual HTTP
// call sequence is exercised for real without ever reaching the live API in CI.
type fakeGitHub struct {
	t              *testing.T
	baseSHA        string
	gotBranchRef   string
	gotUpdatedYAML string
	gotPRHead      string
	gotPRBase      string

	// refAlreadyExists makes CreateRef respond the way the real API does when the branch is
	// already there (a retry after an earlier attempt got partway through) - 422 with exactly
	// this message, not a dedicated error type.
	refAlreadyExists bool
}

func (f *fakeGitHub) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/ref/heads/"):
			_, _ = fmt.Fprintf(w, `{"ref":"refs/heads/main","object":{"sha":%q,"type":"commit"}}`, f.baseSHA)

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			var body struct{ Ref, SHA string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.gotBranchRef = body.Ref
			if f.refAlreadyExists {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = fmt.Fprint(w, `{"message":"Reference already exists"}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"ref":%q,"object":{"sha":%q,"type":"commit"}}`, body.Ref, body.SHA)

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			content := base64.StdEncoding.EncodeToString([]byte(originalYAML))
			_, _ = fmt.Fprintf(w, `{"type":"file","encoding":"base64","content":%q,"sha":"base-file-sha","path":"values.yaml"}`, content)

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			var body struct {
				Content []byte `json:"content"`
				Branch  string `json:"branch"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.gotUpdatedYAML = string(body.Content)
			_, _ = fmt.Fprint(w, `{"content":{"sha":"new-file-sha"},"commit":{"sha":"new-commit-sha"}}`)

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			var body struct{ Head, Base string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.gotPRHead, f.gotPRBase = body.Head, body.Base
			_, _ = fmt.Fprintf(w, `{"number":42,"html_url":%q}`, testPRURL)

		default:
			f.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func testRepo() *candorv1alpha1.GitOpsRepo {
	return &candorv1alpha1.GitOpsRepo{
		Owner: "acme", Repo: "gitops", BaseBranch: testBaseBranch,
		Path: "values.yaml", YAMLPath: "image.tag",
	}
}

func testFindingForPR() *candorv1alpha1.Finding {
	return &candorv1alpha1.Finding{
		Name: "trivy-abc123", Namespace: "team-a",
		Spec: candorv1alpha1.FindingSpec{Summary: "3 critical vulnerabilities in ghcr.io/foo/bar:v1.0.0"},
		Status: candorv1alpha1.FindingStatus{
			Fingerprint: "0123456789abcdef",
			Hypotheses: []candorv1alpha1.Hypothesis{
				{Cause: "outdated base image", Confidence: 80, Rationale: "fix is in a newer tag", RecommendedAction: candorv1alpha1.ActionProposePullRequest},
			},
		},
	}
}

func TestGitHubOpener_Open_OpensExpectedPullRequest(t *testing.T) {
	fake := &fakeGitHub{t: t, baseSHA: testBaseSHA}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	opener := &GitHubOpener{BaseURL: srv.URL + "/"}
	fix := Fix{Repository: testRepository, CurrentTag: testCurrentTag, NewTag: testNewTag}

	url, err := opener.Open(t.Context(), "test-token", testRepo(), fix, testFindingForPR())
	if err != nil {
		t.Fatal(err)
	}

	if url != testPRURL {
		t.Errorf("Open() url = %q, want the created PR's html_url", url)
	}
	if want := "refs/heads/candor/trivy-abc123-0123456789ab"; fake.gotBranchRef != want {
		t.Errorf("branch ref created = %q, want %q (fingerprint-suffixed, so a later fix doesn't collide)", fake.gotBranchRef, want)
	}
	if !strings.Contains(fake.gotUpdatedYAML, "tag: v1.2.0") {
		t.Errorf("updated file content = %q, want it to contain the new tag", fake.gotUpdatedYAML)
	}
	if !strings.Contains(fake.gotUpdatedYAML, "repository: ghcr.io/foo/bar") {
		t.Errorf("updated file content lost an unrelated field: %q", fake.gotUpdatedYAML)
	}
	if fake.gotPRHead != strings.TrimPrefix(fake.gotBranchRef, "refs/heads/") {
		t.Errorf("PR head = %q, want it to match the branch just created (%q)", fake.gotPRHead, fake.gotBranchRef)
	}
	if fake.gotPRBase != testBaseBranch {
		t.Errorf("PR base = %q, want %q", fake.gotPRBase, testBaseBranch)
	}
}

func TestGitHubOpener_Open_DefaultsBaseBranchToMain(t *testing.T) {
	fake := &fakeGitHub{t: t, baseSHA: testBaseSHA}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	opener := &GitHubOpener{BaseURL: srv.URL + "/"}
	repo := testRepo()
	repo.BaseBranch = "" // unset - GitOpsRepo.BaseBranch's kubebuilder default only applies via the API server, not a plain Go struct in tests

	if _, err := opener.Open(t.Context(), "test-token", repo, Fix{Repository: "r", CurrentTag: "v1", NewTag: "v2"}, testFindingForPR()); err != nil {
		t.Fatal(err)
	}
	if fake.gotPRBase != testBaseBranch {
		t.Errorf("PR base = %q, want the hardcoded fallback %q", fake.gotPRBase, testBaseBranch)
	}
}

// TestGitHubOpener_Open_UsesRepoHost is the regression test for a real finding from
// /code-review medium: Open only ever consulted GitHubOpener.BaseURL (a test-only field), never
// GitOpsRepo.Host, so a GitHub Enterprise repo's Host setting silently did nothing despite the
// field's own doc comment promising it. The opener here has BaseURL left unset entirely - proving
// the fake server is reached only because repo.Host was honored, not the test-only field.
func TestGitHubOpener_Open_UsesRepoHost(t *testing.T) {
	fake := &fakeGitHub{t: t, baseSHA: testBaseSHA}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	opener := &GitHubOpener{}
	repo := testRepo()
	repo.Host = srv.URL + "/"
	fix := Fix{Repository: testRepository, CurrentTag: testCurrentTag, NewTag: testNewTag}

	url, err := opener.Open(t.Context(), "test-token", repo, fix, testFindingForPR())
	if err != nil {
		t.Fatal(err)
	}
	if url != testPRURL {
		t.Errorf("Open() url = %q, want the created PR's html_url", url)
	}
}

// TestGitHubOpener_Open_HostGetsEnterpriseAPIPrefix is the regression test for a real finding from
// a second /code-review medium pass: repo.Host was applied straight to client.BaseURL via a raw
// url.Parse, bypassing go-github's WithEnterpriseURLs/NewEnterpriseClient normalization that
// appends "/api/v3/" - GitHub Enterprise's REST API 406s on every call without it. A plain
// fakeGitHub.handler() test can't catch this (it matches request paths with strings.Contains,
// which is satisfied with or without the prefix); this asserts the prefix is actually there.
func TestGitHubOpener_Open_HostGetsEnterpriseAPIPrefix(t *testing.T) {
	var gotPath string
	fake := &fakeGitHub{t: t, baseSHA: testBaseSHA}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fake.handler()(w, r)
	}))
	defer srv.Close()

	opener := &GitHubOpener{}
	repo := testRepo()
	repo.Host = srv.URL
	fix := Fix{Repository: testRepository, CurrentTag: testCurrentTag, NewTag: testNewTag}

	if _, err := opener.Open(t.Context(), "test-token", repo, fix, testFindingForPR()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotPath, "/api/v3/") {
		t.Errorf("last request path = %q, want it prefixed with /api/v3/ - GitHub Enterprise's REST API otherwise returns 406 for every call", gotPath)
	}
}

// TestGitHubOpener_Open_BranchAlreadyExists_ProceedsAnyway is the regression for a retry after an
// earlier attempt on this exact fingerprint created the branch but didn't get as far as opening
// the pull request (see tryProposePullRequest's doc comment: that's the only way this function
// runs twice for the same fingerprint). Treating GitHub's "already exists" as fatal here would
// fail every subsequent retry permanently, since the branch name is deterministic.
func TestGitHubOpener_Open_BranchAlreadyExists_ProceedsAnyway(t *testing.T) {
	fake := &fakeGitHub{t: t, baseSHA: testBaseSHA, refAlreadyExists: true}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	opener := &GitHubOpener{BaseURL: srv.URL + "/"}
	fix := Fix{Repository: testRepository, CurrentTag: testCurrentTag, NewTag: testNewTag}

	url, err := opener.Open(t.Context(), "test-token", testRepo(), fix, testFindingForPR())
	if err != nil {
		t.Fatalf("expected Open to proceed past an already-existing branch, got error: %v", err)
	}
	if url != testPRURL {
		t.Errorf("Open() url = %q, want the created PR's html_url", url)
	}
	if !strings.Contains(fake.gotUpdatedYAML, "tag: v1.2.0") {
		t.Errorf("updated file content = %q, want it to still contain the new tag", fake.gotUpdatedYAML)
	}
}

func TestIsRefAlreadyExists(t *testing.T) {
	alreadyExists := &github.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusUnprocessableEntity},
		Message:  "Reference already exists",
	}
	if !isRefAlreadyExists(alreadyExists) {
		t.Error("isRefAlreadyExists() = false for GitHub's own already-exists response, want true")
	}

	otherUnprocessable := &github.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusUnprocessableEntity},
		Message:  "Validation Failed",
	}
	if isRefAlreadyExists(otherUnprocessable) {
		t.Error("isRefAlreadyExists() = true for an unrelated 422, want false - it must not swallow other failures")
	}

	if isRefAlreadyExists(errors.New("some other error")) {
		t.Error("isRefAlreadyExists() = true for a non-GitHub error, want false")
	}
}
