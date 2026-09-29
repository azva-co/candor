package gitops

import (
	"context"
	"errors"
	"testing"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

type recordingOpener struct {
	called bool
	url    string
	err    error
}

func (o *recordingOpener) Open(context.Context, string, *candorv1alpha1.GitOpsRepo, Fix, *candorv1alpha1.Finding) (string, error) {
	o.called = true
	return o.url, o.err
}

func TestMultiOpener_Open_DispatchesByProvider(t *testing.T) {
	tests := []struct {
		name       string
		provider   candorv1alpha1.GitOpsProvider
		wantGitHub bool
		wantGitLab bool
	}{
		{"empty defaults to GitHub", "", true, false},
		{"explicit github", candorv1alpha1.GitOpsProviderGitHub, true, false},
		{"gitlab", candorv1alpha1.GitOpsProviderGitLab, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gh := &recordingOpener{url: "https://github.example/pr/1"}
			gl := &recordingOpener{url: "https://gitlab.example/mr/1"}
			m := &MultiOpener{GitHub: gh, GitLab: gl}

			repo := &candorv1alpha1.GitOpsRepo{Provider: tt.provider}
			url, err := m.Open(t.Context(), "token", repo, Fix{}, &candorv1alpha1.Finding{})
			if err != nil {
				t.Fatal(err)
			}

			if gh.called != tt.wantGitHub {
				t.Errorf("GitHub opener called = %v, want %v", gh.called, tt.wantGitHub)
			}
			if gl.called != tt.wantGitLab {
				t.Errorf("GitLab opener called = %v, want %v", gl.called, tt.wantGitLab)
			}
			switch {
			case tt.wantGitHub && url != gh.url:
				t.Errorf("Open() url = %q, want the GitHub opener's own %q", url, gh.url)
			case tt.wantGitLab && url != gl.url:
				t.Errorf("Open() url = %q, want the GitLab opener's own %q", url, gl.url)
			}
		})
	}
}

func TestMultiOpener_Open_UnknownProvider_Errors(t *testing.T) {
	gh := &recordingOpener{}
	gl := &recordingOpener{}
	m := &MultiOpener{GitHub: gh, GitLab: gl}

	repo := &candorv1alpha1.GitOpsRepo{Provider: "bitbucket"}
	if _, err := m.Open(t.Context(), "token", repo, Fix{}, &candorv1alpha1.Finding{}); err == nil {
		t.Fatal("Open() error = nil, want an error for an unrecognised provider")
	}
	if gh.called || gl.called {
		t.Error("neither opener should be called for an unrecognised provider")
	}
}

func TestMultiOpener_Open_PropagatesUnderlyingError(t *testing.T) {
	wantErr := errors.New("boom")
	gh := &recordingOpener{err: wantErr}
	m := &MultiOpener{GitHub: gh, GitLab: &recordingOpener{}}

	_, err := m.Open(t.Context(), "token", &candorv1alpha1.GitOpsRepo{}, Fix{}, &candorv1alpha1.Finding{})
	if !errors.Is(err, wantErr) {
		t.Errorf("Open() error = %v, want %v propagated from the underlying opener", err, wantErr)
	}
}
