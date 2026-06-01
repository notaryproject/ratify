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

package truststore

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewWatcher_NoPaths(t *testing.T) {
	_, err := NewWatcher(nil, func() {})
	if err == nil {
		t.Fatal("expected error for nil paths")
	}
}

func TestNewWatcher_NilCallback(t *testing.T) {
	dir := t.TempDir()
	_, err := NewWatcher([]string{dir}, nil)
	if err == nil {
		t.Fatal("expected error for nil callback")
	}
}

func TestWatcher_FileWriteTriggersCallback(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certFile, []byte("initial-cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	watcher, err := NewWatcher([]string{dir}, func() { calls.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(certFile, []byte("rotated-cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(3 * time.Second)
	if calls.Load() == 0 {
		t.Fatal("expected callback after cert write")
	}
}

func TestWatcher_PollDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certFile, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	watcher, err := NewWatcher([]string{dir}, func() {})
	if err != nil {
		t.Fatal(err)
	}

	watcher.snapshotHashes()
	if err := os.WriteFile(certFile, []byte("modified"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !watcher.certsChanged() {
		t.Fatal("expected poller to detect modified cert")
	}
}

func TestWatcher_AddPathAndStop(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	watcher, err := NewWatcher([]string{dir1}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatal(err)
	}

	if err := watcher.AddPath(dir2); err != nil {
		t.Fatalf("failed to add path: %v", err)
	}
	if err := watcher.AddPath(dir2); err != nil {
		t.Fatalf("duplicate add should not error: %v", err)
	}
	if len(watcher.paths) != 2 {
		t.Fatalf("expected 2 watched paths, got %d", len(watcher.paths))
	}

	watcher.Stop()
	watcher.Stop()
}
