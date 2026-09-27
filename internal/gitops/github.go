package gitops

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-github/v76/github"

	candorv1alpha1 "github.com/teerakarna/candor/api/v1alpha1"
)

// httpTimeout bounds every GitHub REST call Open makes. Without it, go-github's default client has
// none at all - a hung or slow response during any of the five sequential calls in Open would
// block the calling reconcile indefinitely, and FindingReconciler runs with controller-runtime's
// default of one worker, so that stalls every Finding in every namespace, not just this one.
// Matches internal/llm/anthropic's own client timeout.
const httpTimeout = 30 * time.Second

// Opener opens a pull request carrying fix against repo. GitHubOpener is the real implementation;
// tests substitute a fake pointed at an httptest.Server (see github_test.go) - the same
// "fake but interface-real" posture internal/llm.Client already uses, so the reconciler wiring is
// exercised for real without ever making a live GitHub call in CI.
type Opener interface {
	Open(ctx context.Context, token string, repo *candorv1alpha1.GitOpsRepo, fix Fix, finding *candorv1alpha1.Finding) (prURL string, err error)
}

// GitHubOpener implements Opener against the GitHub REST API via go-github. It authenticates
// per-call with the token the caller supplies (resolved from SignalPolicy.Spec.GitOpsRepo.SecretRef
// by internal/controller.FindingReconciler, which owns all Secret reads) rather than holding one
// fixed client, since different SignalPolicies can name different repos and tokens.
type GitHubOpener struct {
	// BaseURL overrides the GitHub API base URL for tests, pointed at an httptest.Server -
	// repo.Host is the real, user-facing equivalent (GitHub Enterprise), checked first; this field
	// only exists because tests construct a GitHubOpener directly, with no GitOpsRepo in hand yet
	// at that point. Empty means the real public GitHub API.
	BaseURL string
}

func (o *GitHubOpener) Open(ctx context.Context, token string, repo *candorv1alpha1.GitOpsRepo, fix Fix, finding *candorv1alpha1.Finding) (string, error) {
	client := github.NewClient(&http.Client{Timeout: httpTimeout}).WithAuthToken(token)
	apiBaseURL := repo.Host
	if apiBaseURL == "" {
		apiBaseURL = o.BaseURL
	}
	if apiBaseURL != "" {
		// WithEnterpriseURLs, not a raw url.Parse into client.BaseURL: GitHub Enterprise's REST API
		// is only reachable at http(s)://[hostname]/api/v3/ (a plain host or api root gets a 406),
		// and this normalizes that suffix on rather than requiring every repo.Host value to already
		// include it.
		var err error
		client, err = client.WithEnterpriseURLs(apiBaseURL, apiBaseURL)
		if err != nil {
			return "", fmt.Errorf("parsing base URL: %w", err)
		}
	}

	base := repo.BaseBranch
	if base == "" {
		base = defaultBaseBranch
	}

	baseRef, _, err := client.Git.GetRef(ctx, repo.Owner, repo.Repo, "heads/"+base)
	if err != nil {
		return "", fmt.Errorf("getting base ref heads/%s: %w", base, err)
	}

	// Fingerprint-suffixed, not just the Finding name: NeedsEnrichment only lets this run once per
	// distinct fingerprint, but a Finding can go through several fixes over its lifetime (content
	// changes, gets fixed, recurs differently) and each needs its own branch rather than colliding
	// with a leftover one from a prior attempt.
	//
	// Creation is treated as idempotent: if the branch already exists, that's expected on a retry
	// after an earlier attempt for this exact fingerprint got partway through (e.g. the branch was
	// created but the pull request wasn't, because that's the only way this function runs twice
	// for the same fingerprint - see FindingReconciler.tryProposePullRequest, which only marks a
	// fingerprint done once Open returns a URL). Treating "already exists" as fatal would fail
	// every subsequent retry permanently, forcing a human to delete the stray branch by hand.
	branch := branchName(finding)
	if _, _, err := client.Git.CreateRef(ctx, repo.Owner, repo.Repo, github.CreateRef{
		Ref: "refs/heads/" + branch,
		SHA: baseRef.GetObject().GetSHA(),
	}); err != nil && !isRefAlreadyExists(err) {
		return "", fmt.Errorf("creating branch %s: %w", branch, err)
	}

	content, _, _, err := client.Repositories.GetContents(ctx, repo.Owner, repo.Repo, repo.Path, &github.RepositoryContentGetOptions{Ref: base})
	if err != nil {
		return "", fmt.Errorf("getting %s: %w", repo.Path, err)
	}
	raw, err := content.GetContent()
	if err != nil {
		return "", fmt.Errorf("decoding %s: %w", repo.Path, err)
	}

	patched, err := setYAMLPath([]byte(raw), repo.YAMLPath, fix.NewTag)
	if err != nil {
		return "", fmt.Errorf("patching %s at %s: %w", repo.Path, repo.YAMLPath, err)
	}

	title := prTitle(fix)
	if _, _, err := client.Repositories.UpdateFile(ctx, repo.Owner, repo.Repo, repo.Path, &github.RepositoryContentFileOptions{
		Message: new(title),
		Content: patched,
		SHA:     content.SHA,
		Branch:  new(branch),
	}); err != nil {
		return "", fmt.Errorf("updating %s on %s: %w", repo.Path, branch, err)
	}

	pr, _, err := client.PullRequests.Create(ctx, repo.Owner, repo.Repo, &github.NewPullRequest{
		Title: new(title),
		Head:  new(branch),
		Base:  new(base),
		Body:  new(prBody(fix, finding)),
	})
	if err != nil {
		return "", fmt.Errorf("creating pull request: %w", err)
	}

	return pr.GetHTMLURL(), nil
}

// isRefAlreadyExists reports whether err is GitHub's "Reference already exists" response to
// creating a ref - the real API returns 422 Unprocessable Entity with exactly that message (not a
// dedicated error type), so matching on it is the only way to distinguish "this branch is already
// there" from every other reason CreateRef can fail.
func isRefAlreadyExists(err error) bool {
	var ghErr *github.ErrorResponse
	return errors.As(err, &ghErr) &&
		ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusUnprocessableEntity &&
		strings.Contains(strings.ToLower(ghErr.Message), "already exists")
}
