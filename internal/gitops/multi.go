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
	"fmt"

	candorv1alpha1 "github.com/teerakarna/candor/api/v1alpha1"
)

// MultiOpener implements Opener by dispatching to one of several concrete Openers based on
// repo.Provider - keeps FindingReconciler.GitOps as a single gitops.Opener field, as it is today,
// rather than the reconciler itself needing to know how many backends exist or how to pick one.
type MultiOpener struct {
	GitHub Opener
	GitLab Opener
}

func (m *MultiOpener) Open(ctx context.Context, token string, repo *candorv1alpha1.GitOpsRepo, fix Fix, finding *candorv1alpha1.Finding) (string, error) {
	switch repo.Provider {
	case "", candorv1alpha1.GitOpsProviderGitHub:
		if m.GitHub == nil {
			return "", fmt.Errorf("MultiOpener has no GitHub backend configured for provider %q", repo.Provider)
		}
		return m.GitHub.Open(ctx, token, repo, fix, finding)
	case candorv1alpha1.GitOpsProviderGitLab:
		if m.GitLab == nil {
			return "", fmt.Errorf("MultiOpener has no GitLab backend configured for provider %q", repo.Provider)
		}
		return m.GitLab.Open(ctx, token, repo, fix, finding)
	default:
		// Unreachable through the API server (Provider is a closed CRD enum), but a plain Go
		// struct in a test or a future caller isn't bound by that - failing loudly here is safer
		// than silently falling back to GitHub for an unrecognised value.
		return "", fmt.Errorf("unknown GitOpsRepo provider %q", repo.Provider)
	}
}
