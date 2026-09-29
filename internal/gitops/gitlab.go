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

package gitops

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

// GitLabOpener implements Opener against the GitLab REST API. Same per-call authentication and
// idempotent-branch-creation posture as GitHubOpener - see its own doc comments, which this
// mirrors deliberately rather than inventing a different shape for the second backend.
type GitLabOpener struct{}

func (o *GitLabOpener) Open(ctx context.Context, token string, repo *candorv1alpha1.GitOpsRepo, fix Fix, finding *candorv1alpha1.Finding) (string, error) {
	opts := []gitlab.ClientOptionFunc{
		gitlab.WithHTTPClient(&http.Client{Timeout: httpTimeout}),
		// The client library wraps every call in retryablehttp, which retries a failing request
		// up to 5 times with backoff by default - httpTimeout would then bound each individual
		// attempt, not the call as a whole, so a degraded GitLab instance returning 5xx/429
		// repeatedly could hold Open() open for several minutes rather than ~httpTimeout, exactly
		// what httpTimeout's own doc comment (github.go) says it exists to prevent. Disabled to
		// match GitHubOpener's own behavior (go-github doesn't retry), not because retries are
		// never useful - keeps this handler's single-bounded-call assumption true for both
		// backends alike, matching how the rest of this project treats a slow apiserver-adjacent
		// call (one bounded attempt, no built-in retry) rather than introducing new resilience
		// semantics for only one of the two.
		gitlab.WithoutRetries(),
	}
	if repo.Host != "" {
		opts = append(opts, gitlab.WithBaseURL(repo.Host))
	}
	client, err := gitlab.NewClient(token, opts...)
	if err != nil {
		return "", fmt.Errorf("building GitLab client: %w", err)
	}

	// GitLab's project path, not a numeric ID - Owner may itself be a multi-segment namespace path
	// for a project nested in a subgroup (see GitOpsRepo.Owner's own doc comment). The client
	// library url-encodes this internally (gitlab.PathEscape), so a plain "owner/repo" string is
	// the correct thing to pass, not something this code needs to encode itself.
	project := repo.Owner + "/" + repo.Repo

	base := repo.BaseBranch
	if base == "" {
		base = defaultBaseBranch
	}

	// Fingerprint-suffixed and treated as idempotent - see GitHubOpener.Open's own comment on this
	// branch name for the full reasoning (a retry after an earlier attempt got partway through must
	// proceed past an already-existing branch, not fail permanently).
	//
	// Ref takes a branch name directly (GitLab API docs: "Branch name or commit SHA to create
	// branch from"), so there's no need for a separate GetBranch call to resolve base to a commit
	// SHA first - one fewer round trip, and one fewer place a self-hosted/proxied instance
	// returning an unexpected response shape could crash this call.
	branch := branchName(finding)
	if _, _, err := client.Branches.CreateBranch(project, &gitlab.CreateBranchOptions{
		Branch: &branch,
		Ref:    &base,
	}, gitlab.WithContext(ctx)); err != nil && !isBranchAlreadyExists(err) {
		return "", fmt.Errorf("creating branch %s: %w", branch, err)
	}

	file, _, err := client.RepositoryFiles.GetFile(project, repo.Path, &gitlab.GetFileOptions{Ref: &base}, gitlab.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("getting %s: %w", repo.Path, err)
	}
	raw, err := decodeFileContent(file)
	if err != nil {
		return "", fmt.Errorf("decoding %s: %w", repo.Path, err)
	}

	patched, err := setYAMLPath(raw, repo.YAMLPath, fix.NewTag)
	if err != nil {
		return "", fmt.Errorf("patching %s at %s: %w", repo.Path, repo.YAMLPath, err)
	}

	title := prTitle(fix)
	patchedStr := string(patched)
	if _, _, err := client.RepositoryFiles.UpdateFile(project, repo.Path, &gitlab.UpdateFileOptions{
		Branch:        &branch,
		Content:       &patchedStr,
		CommitMessage: &title,
		// LastCommitID is GitLab's optimistic-concurrency guard, mirroring GitHubOpener's own use
		// of content.SHA in its UpdateFile call - without it, a write between GetFile and here
		// (a human edit, an overlapping reconcile) is silently overwritten instead of rejected.
		LastCommitID: &file.LastCommitID,
	}, gitlab.WithContext(ctx)); err != nil {
		return "", fmt.Errorf("updating %s on %s: %w", repo.Path, branch, err)
	}

	body := prBody(fix, finding)
	mr, _, err := client.MergeRequests.CreateMergeRequest(project, &gitlab.CreateMergeRequestOptions{
		Title:        &title,
		SourceBranch: &branch,
		TargetBranch: &base,
		Description:  &body,
	}, gitlab.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("creating merge request: %w", err)
	}

	return mr.WebURL, nil
}

// decodeFileContent returns file's content as raw bytes - GitLab's default GetFile encoding is
// base64 (file.Encoding is "base64" in every observed real response), but decoding only when the
// API actually says so avoids silently mangling content on the day that default ever changes.
func decodeFileContent(file *gitlab.File) ([]byte, error) {
	if file.Encoding != "base64" {
		return []byte(file.Content), nil
	}
	return base64.StdEncoding.DecodeString(file.Content)
}

// isBranchAlreadyExists reports whether err is GitLab's response to creating a branch that already
// exists - a 400 Bad Request naming the branch, not a dedicated error type, mirroring
// isRefAlreadyExists's own GitHub equivalent for the identical retry-after-partial-failure reason.
func isBranchAlreadyExists(err error) bool {
	var glErr *gitlab.ErrorResponse
	return errors.As(err, &glErr) &&
		glErr.HasStatusCode(http.StatusBadRequest) &&
		strings.Contains(strings.ToLower(glErr.Message), "already exists")
}
