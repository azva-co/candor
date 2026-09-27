package gitops

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	candorv1alpha1 "github.com/teerakarna/candor/api/v1alpha1"
)

// fakeGitLab stands in for the real GitLab REST API, returning just enough of each real response
// shape for the client library to parse - the same "fake but interface-real" posture
// fakeGitHub's own doc comment describes, so GitLabOpener's actual HTTP call sequence is exercised
// for real without ever reaching a live GitLab instance in CI.
type fakeGitLab struct {
	t               *testing.T
	gotBranchName   string
	gotBranchRef    string
	gotUpdatedYAML  string
	gotLastCommitID string
	gotMRSource     string
	gotMRTarget     string

	// branchAlreadyExists makes CreateBranch respond the way the real API does when the branch is
	// already there (a retry after an earlier attempt got partway through) - 400 naming the
	// branch, not a dedicated error type.
	branchAlreadyExists bool
}

func (f *fakeGitLab) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/repository/branches"):
			var body struct{ Branch, Ref string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.gotBranchName, f.gotBranchRef = body.Branch, body.Ref
			if f.branchAlreadyExists {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, `{"message":"Branch %s already exists"}`, f.gotBranchName)
				return
			}
			_, _ = fmt.Fprintf(w, `{"name":%q,"commit":{"id":"new-branch-commit-sha"}}`, f.gotBranchName)

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repository/files/"):
			content := base64.StdEncoding.EncodeToString([]byte(originalYAML))
			_, _ = fmt.Fprintf(w, `{"file_name":"values.yaml","file_path":"values.yaml","encoding":"base64","content":%q,"blob_id":"base-file-sha","last_commit_id":%q}`, content, testBaseSHA)

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/repository/files/"):
			var body struct {
				Content      string
				Branch       string
				LastCommitID string `json:"last_commit_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.gotUpdatedYAML, f.gotLastCommitID = body.Content, body.LastCommitID
			_, _ = fmt.Fprint(w, `{"file_path":"values.yaml","branch":"candor"}`)

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/merge_requests"):
			var body struct {
				SourceBranch string `json:"source_branch"`
				TargetBranch string `json:"target_branch"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.gotMRSource, f.gotMRTarget = body.SourceBranch, body.TargetBranch
			_, _ = fmt.Fprint(w, `{"iid":42,"web_url":"https://gitlab.com/acme/gitops/-/merge_requests/42"}`)

		default:
			f.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func testGitLabRepo() *candorv1alpha1.GitOpsRepo {
	return &candorv1alpha1.GitOpsRepo{
		Provider: candorv1alpha1.GitOpsProviderGitLab,
		Owner:    "acme", Repo: "gitops", BaseBranch: testBaseBranch,
		Path: "values.yaml", YAMLPath: "image.tag",
	}
}

func TestGitLabOpener_Open_OpensExpectedMergeRequest(t *testing.T) {
	fake := &fakeGitLab{t: t}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	opener := &GitLabOpener{}
	repo := testGitLabRepo()
	repo.Host = srv.URL
	fix := Fix{Repository: testRepository, CurrentTag: testCurrentTag, NewTag: testNewTag}

	url, err := opener.Open(t.Context(), "test-token", repo, fix, testFindingForPR())
	if err != nil {
		t.Fatal(err)
	}

	if url != "https://gitlab.com/acme/gitops/-/merge_requests/42" {
		t.Errorf("Open() url = %q, want the created MR's web_url", url)
	}
	if want := "candor/trivy-abc123-0123456789ab"; fake.gotBranchName != want {
		t.Errorf("branch created = %q, want %q (fingerprint-suffixed, so a later fix doesn't collide)", fake.gotBranchName, want)
	}
	if fake.gotBranchRef != testBaseBranch {
		t.Errorf("branch ref = %q, want the base branch name %q (GitLab's CreateBranch Ref accepts a name directly, no separate GetBranch call needed)", fake.gotBranchRef, testBaseBranch)
	}
	if !strings.Contains(fake.gotUpdatedYAML, "tag: v1.2.0") {
		t.Errorf("updated file content = %q, want it to contain the new tag", fake.gotUpdatedYAML)
	}
	if !strings.Contains(fake.gotUpdatedYAML, "repository: ghcr.io/foo/bar") {
		t.Errorf("updated file content lost an unrelated field: %q", fake.gotUpdatedYAML)
	}
	if fake.gotLastCommitID != testBaseSHA {
		t.Errorf("update's last_commit_id = %q, want the fetched file's own last_commit_id %q (the optimistic-concurrency guard)", fake.gotLastCommitID, testBaseSHA)
	}
	if fake.gotMRSource != fake.gotBranchName {
		t.Errorf("MR source branch = %q, want it to match the branch just created (%q)", fake.gotMRSource, fake.gotBranchName)
	}
	if fake.gotMRTarget != testBaseBranch {
		t.Errorf("MR target branch = %q, want %q", fake.gotMRTarget, testBaseBranch)
	}
}

func TestGitLabOpener_Open_DefaultsBaseBranchToMain(t *testing.T) {
	fake := &fakeGitLab{t: t}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	opener := &GitLabOpener{}
	repo := testGitLabRepo()
	repo.Host = srv.URL
	repo.BaseBranch = "" // unset - GitOpsRepo.BaseBranch's kubebuilder default only applies via the API server

	if _, err := opener.Open(t.Context(), "test-token", repo, Fix{Repository: "r", CurrentTag: "v1", NewTag: "v2"}, testFindingForPR()); err != nil {
		t.Fatal(err)
	}
	if fake.gotMRTarget != testBaseBranch {
		t.Errorf("MR target branch = %q, want the hardcoded fallback %q", fake.gotMRTarget, testBaseBranch)
	}
}

// TestGitLabOpener_Open_BranchAlreadyExists_ProceedsAnyway mirrors
// TestGitHubOpener_Open_BranchAlreadyExists_ProceedsAnyway - same retry-after-partial-failure
// reasoning, GitLab's own error shape for it (400, not a dedicated error type).
func TestGitLabOpener_Open_BranchAlreadyExists_ProceedsAnyway(t *testing.T) {
	fake := &fakeGitLab{t: t, branchAlreadyExists: true}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	opener := &GitLabOpener{}
	repo := testGitLabRepo()
	repo.Host = srv.URL
	fix := Fix{Repository: testRepository, CurrentTag: testCurrentTag, NewTag: testNewTag}

	url, err := opener.Open(t.Context(), "test-token", repo, fix, testFindingForPR())
	if err != nil {
		t.Fatalf("expected Open to proceed past an already-existing branch, got error: %v", err)
	}
	if url != "https://gitlab.com/acme/gitops/-/merge_requests/42" {
		t.Errorf("Open() url = %q, want the created MR's web_url", url)
	}
	if !strings.Contains(fake.gotUpdatedYAML, "tag: v1.2.0") {
		t.Errorf("updated file content = %q, want it to still contain the new tag", fake.gotUpdatedYAML)
	}
}

// TestGitLabOpener_Open_DoesNotRetryOnServerError is the regression test for a real finding from
// /code-review medium: the client library wraps every call in retryablehttp, which retries a
// failing request up to 5 times with backoff by default - httpTimeout would then bound each
// individual attempt, not the call as a whole, so a degraded GitLab instance returning 503
// repeatedly could hold Open() open for several minutes instead of ~httpTimeout. Disabled via
// gitlab.WithoutRetries() to match GitHubOpener's own behavior (go-github doesn't retry).
func TestGitLabOpener_Open_DoesNotRetryOnServerError(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	opener := &GitLabOpener{}
	repo := testGitLabRepo()
	repo.Host = server.URL

	start := time.Now()
	_, err := opener.Open(t.Context(), "test-token", repo, Fix{}, testFindingForPR())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Open() error = nil, want an error from the failing CreateBranch call")
	}
	if got := requestCount.Load(); got != 1 {
		t.Errorf("requests received = %d, want exactly 1 - retries must be disabled, or a degraded instance could hold this call open for minutes instead of failing fast", got)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Open() took %v, want it to fail fast - with retries disabled there's no backoff to wait through", elapsed)
	}
}

func TestIsBranchAlreadyExists(t *testing.T) {
	alreadyExists := &gitlab.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusBadRequest},
		Message:  "Branch candor/foo already exists",
	}
	if !isBranchAlreadyExists(alreadyExists) {
		t.Error("isBranchAlreadyExists() = false for GitLab's own already-exists response, want true")
	}

	otherBadRequest := &gitlab.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusBadRequest},
		Message:  "Branch name is invalid",
	}
	if isBranchAlreadyExists(otherBadRequest) {
		t.Error("isBranchAlreadyExists() = true for an unrelated 400, want false - it must not swallow other failures")
	}

	if isBranchAlreadyExists(errors.New("some other error")) {
		t.Error("isBranchAlreadyExists() = true for a non-GitLab error, want false")
	}
}
