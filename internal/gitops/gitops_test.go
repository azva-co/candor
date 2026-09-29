package gitops

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/provider/trivy"
)

const (
	testNamespace = "team-a"
	testRefName   = "api-abc123"
)

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	// Registers the unstructured VulnerabilityReport GVK against the fake client's scheme, the
	// same technique real controller-runtime clients need for any type it doesn't have a compiled
	// Go struct for - matching internal/provider/trivy's own "read as unstructured, no compile-time
	// dependency on Trivy Operator's Go module" posture.
	scheme.AddKnownTypeWithName(trivy.GroupVersionKind, &unstructured.Unstructured{})
	listGVK := trivy.GroupVersionKind
	listGVK.Kind += "List"
	scheme.AddKnownTypeWithName(listGVK, &unstructured.UnstructuredList{})

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func vulnReport(repository, tag string, fixedVersions ...string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(trivy.GroupVersionKind)
	u.SetName(testRefName)
	u.SetNamespace(testNamespace)
	_ = unstructured.SetNestedField(u.Object, repository, "report", "artifact", "repository")
	_ = unstructured.SetNestedField(u.Object, tag, "report", "artifact", "tag")

	vulns := make([]any, 0, len(fixedVersions))
	for _, fv := range fixedVersions {
		v := map[string]any{}
		if fv != "" {
			v["fixedVersion"] = fv
		}
		vulns = append(vulns, v)
	}
	_ = unstructured.SetNestedSlice(u.Object, vulns, "report", "vulnerabilities")
	return u
}

func testFinding(refKind, refName string) *candorv1alpha1.Finding {
	return &candorv1alpha1.Finding{
		Name: "finding", Namespace: testNamespace,
		Spec: candorv1alpha1.FindingSpec{
			Source: candorv1alpha1.FindingSource{RefKind: refKind, RefName: refName},
		},
	}
}

func TestComputeFix_NonTrivySource_NotOK(t *testing.T) {
	c := newFakeClient(t)
	finding := testFinding("FalcoEvent", "whatever")

	_, ok, err := ComputeFix(context.Background(), c, finding)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false for a non-Trivy source - ComputeFix only understands VulnerabilityReport so far")
	}
}

func TestComputeFix_SourceObjectMissing_NotOK(t *testing.T) {
	c := newFakeClient(t)
	finding := testFinding("VulnerabilityReport", "does-not-exist")

	_, ok, err := ComputeFix(context.Background(), c, finding)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false when the source VulnerabilityReport no longer exists")
	}
}

func TestComputeFix_UniformFixedVersion_ComputesFix(t *testing.T) {
	report := vulnReport(testRepository, "v1.0.0", "v1.2.0", "v1.2.0")
	c := newFakeClient(t, report)
	finding := testFinding("VulnerabilityReport", testRefName)

	fix, ok, err := ComputeFix(context.Background(), c, finding)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok=true - every vulnerability agrees on fixedVersion v1.2.0")
	}
	want := Fix{Repository: testRepository, CurrentTag: testCurrentTag, NewTag: testNewTag}
	if fix != want {
		t.Errorf("ComputeFix() = %+v, want %+v", fix, want)
	}
}

func TestComputeFix_DisagreeingFixedVersions_NotOK(t *testing.T) {
	report := vulnReport(testRepository, "v1.0.0", "v1.2.0", "v1.3.0")
	c := newFakeClient(t, report)
	finding := testFinding("VulnerabilityReport", testRefName)

	_, ok, err := ComputeFix(context.Background(), c, finding)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false - a single tag bump cannot resolve two vulnerabilities with different fixes")
	}
}

func TestComputeFix_NoFixedVersionReported_NotOK(t *testing.T) {
	report := vulnReport(testRepository, "v1.0.0", "")
	c := newFakeClient(t, report)
	finding := testFinding("VulnerabilityReport", testRefName)

	_, ok, err := ComputeFix(context.Background(), c, finding)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false - no vulnerability names a fix at all")
	}
}

func TestComputeFix_FixedVersionMatchesCurrentTag_NotOK(t *testing.T) {
	report := vulnReport(testRepository, "v1.2.0", "v1.2.0")
	c := newFakeClient(t, report)
	finding := testFinding("VulnerabilityReport", testRefName)

	_, ok, err := ComputeFix(context.Background(), c, finding)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false - the reported fix is already deployed, nothing to patch")
	}
}

func TestComputeFix_MissingArtifactInfo_NotOK(t *testing.T) {
	report := vulnReport("", "", "v1.2.0")
	c := newFakeClient(t, report)
	finding := testFinding("VulnerabilityReport", testRefName)

	_, ok, err := ComputeFix(context.Background(), c, finding)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false when the report names no repository/tag")
	}
}
