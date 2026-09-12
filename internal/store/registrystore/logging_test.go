/*
Copyright The Ratify Authors.
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

package registrystore

import (
	"context"
	"errors"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

type stubStore struct {
	desc      ocispec.Descriptor
	referrers [][]ocispec.Descriptor
	payload   []byte
	err       error
}

func (s *stubStore) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	return s.desc, s.err
}

func (s *stubStore) ListReferrers(_ context.Context, _ string, _ []string, fn func([]ocispec.Descriptor) error) error {
	if s.err != nil {
		return s.err
	}
	for _, page := range s.referrers {
		if err := fn(page); err != nil {
			return err
		}
	}
	return nil
}

func (s *stubStore) FetchBlob(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	return s.payload, s.err
}

func (s *stubStore) FetchManifest(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	return s.payload, s.err
}

// findEntry returns the first entry at the given level whose message contains
// want. The logrus hook is global, so tests match on their own message rather
// than assuming they are the only writer.
func findEntry(hook *test.Hook, level logrus.Level, want string) *logrus.Entry {
	for _, entry := range hook.AllEntries() {
		if entry.Level == level && strings.Contains(entry.Message, want) {
			return entry
		}
	}
	return nil
}

func newHook(t *testing.T) *test.Hook {
	t.Helper()
	base := logrus.StandardLogger()
	previous := base.GetLevel()
	base.SetLevel(logrus.DebugLevel)
	hook := test.NewLocal(base)
	t.Cleanup(func() {
		base.SetLevel(previous)
		hook.Reset()
	})
	return hook
}

func TestLoggingStore_Resolve(t *testing.T) {
	hook := newHook(t)
	store := &loggingStore{inner: &stubStore{desc: ocispec.Descriptor{Digest: "sha256:abc"}}}

	desc, err := store.Resolve(context.Background(), "registry.example/app:v1")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if desc.Digest != "sha256:abc" {
		t.Errorf("Resolve() digest = %s, want sha256:abc", desc.Digest)
	}
	if findEntry(hook, logrus.DebugLevel, "resolved registry.example/app:v1 to sha256:abc") == nil {
		t.Error("expected the resolved digest to be logged at debug level")
	}
}

func TestLoggingStore_ResolveError(t *testing.T) {
	hook := newHook(t)
	store := &loggingStore{inner: &stubStore{err: errors.New("manifest unknown")}}

	if _, err := store.Resolve(context.Background(), "registry.example/app:v1"); err == nil {
		t.Fatal("expected the underlying error to be returned")
	}
	if findEntry(hook, logrus.ErrorLevel, "failed to resolve registry.example/app:v1") == nil {
		t.Error("expected the resolve failure to be logged at error level")
	}
}

// The referrer count is only known after pagination finishes, so it must be
// accumulated across every callback rather than taken from the first page.
func TestLoggingStore_ListReferrersCountsAllPages(t *testing.T) {
	hook := newHook(t)
	store := &loggingStore{inner: &stubStore{referrers: [][]ocispec.Descriptor{
		{{Digest: "sha256:1"}, {Digest: "sha256:2"}},
		{{Digest: "sha256:3"}},
	}}}

	var seen int
	err := store.ListReferrers(context.Background(), "registry.example/app:v1", nil, func(referrers []ocispec.Descriptor) error {
		seen += len(referrers)
		return nil
	})
	if err != nil {
		t.Fatalf("ListReferrers() error = %v", err)
	}
	if seen != 3 {
		t.Errorf("caller received %d referrer(s), want 3", seen)
	}
	if findEntry(hook, logrus.DebugLevel, "listed 3 referrer(s)") == nil {
		t.Error("expected the total referrer count across pages to be logged")
	}
}

func TestLoggingStore_ListReferrersError(t *testing.T) {
	hook := newHook(t)
	store := &loggingStore{inner: &stubStore{err: errors.New("referrers not supported")}}

	err := store.ListReferrers(context.Background(), "registry.example/app:v1", nil, func([]ocispec.Descriptor) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected the underlying error to be returned")
	}
	if findEntry(hook, logrus.ErrorLevel, "failed to list referrers") == nil {
		t.Error("expected the list failure to be logged at error level")
	}
}

func TestLoggingStore_FetchBlob(t *testing.T) {
	hook := newHook(t)
	store := &loggingStore{inner: &stubStore{payload: []byte("signature")}}

	blob, err := store.FetchBlob(context.Background(), "registry.example/app", ocispec.Descriptor{
		Digest:    "sha256:blob",
		MediaType: "application/octet-stream",
	})
	if err != nil {
		t.Fatalf("FetchBlob() error = %v", err)
	}
	if string(blob) != "signature" {
		t.Errorf("FetchBlob() = %q, want %q", blob, "signature")
	}
	entry := findEntry(hook, logrus.DebugLevel, "fetched blob sha256:blob")
	if entry == nil {
		t.Fatal("expected the blob fetch to be logged at debug level")
	}
	if !strings.Contains(entry.Message, "9 bytes") {
		t.Errorf("expected the blob size in the message, got: %s", entry.Message)
	}
}

func TestLoggingStore_FetchBlobError(t *testing.T) {
	hook := newHook(t)
	store := &loggingStore{inner: &stubStore{err: errors.New("blob unknown")}}

	if _, err := store.FetchBlob(context.Background(), "registry.example/app", ocispec.Descriptor{Digest: "sha256:blob"}); err == nil {
		t.Fatal("expected the underlying error to be returned")
	}
	if findEntry(hook, logrus.ErrorLevel, "failed to fetch blob sha256:blob") == nil {
		t.Error("expected the blob failure to be logged at error level")
	}
}

func TestLoggingStore_FetchManifest(t *testing.T) {
	hook := newHook(t)
	store := &loggingStore{inner: &stubStore{payload: []byte(`{"schemaVersion":2}`)}}

	manifest, err := store.FetchManifest(context.Background(), "registry.example/app", ocispec.Descriptor{
		Digest:    "sha256:manifest",
		MediaType: ocispec.MediaTypeImageManifest,
	})
	if err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if string(manifest) != `{"schemaVersion":2}` {
		t.Errorf("FetchManifest() = %q", manifest)
	}
	if findEntry(hook, logrus.DebugLevel, "fetched manifest sha256:manifest") == nil {
		t.Error("expected the manifest fetch to be logged at debug level")
	}
}

func TestLoggingStore_FetchManifestError(t *testing.T) {
	hook := newHook(t)
	store := &loggingStore{inner: &stubStore{err: errors.New("manifest unknown")}}

	if _, err := store.FetchManifest(context.Background(), "registry.example/app", ocispec.Descriptor{Digest: "sha256:manifest"}); err == nil {
		t.Fatal("expected the underlying error to be returned")
	}
	if findEntry(hook, logrus.ErrorLevel, "failed to fetch manifest sha256:manifest") == nil {
		t.Error("expected the manifest failure to be logged at error level")
	}
}
