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
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
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
	setWatcherIntervals(t, 10*time.Millisecond, pollInterval)

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

	waitFor(t, time.Second, func() bool { return calls.Load() > 0 }, "expected callback after cert write")
}

func TestWatcher_WatchHandlesEventsAndErrors(t *testing.T) {
	setWatcherIntervals(t, 10*time.Millisecond, pollInterval)

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
	defer watcher.Stop()

	go watcher.watch()
	watcher.watcher.Errors <- errors.New("synthetic watcher error")
	watcher.watcher.Events <- fsnotify.Event{Name: dir, Op: fsnotify.Remove}

	waitFor(t, time.Second, func() bool { return calls.Load() > 0 }, "expected callback after synthetic watcher event")
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

func TestWatcher_PollDetectsRemovedFile(t *testing.T) {
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
	if err := os.Remove(certFile); err != nil {
		t.Fatal(err)
	}
	if !watcher.certsChanged() {
		t.Fatal("expected poller to detect removed cert")
	}
}

func TestWatcher_CurrentHashesHandlesRemovedDirectFile(t *testing.T) {
	certFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(certFile, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	watcher, err := NewWatcher([]string{certFile}, func() {})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(certFile); err != nil {
		t.Fatal(err)
	}
	if hashes := watcher.currentHashes(); len(hashes) != 0 {
		t.Fatalf("expected no hashes after removing direct file, got %d", len(hashes))
	}
}

func TestSnapshotPathHashes_File(t *testing.T) {
	certFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(certFile, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	hashes := make(map[string][32]byte)
	if err := snapshotPathHashes(certFile, hashes); err != nil {
		t.Fatal(err)
	}
	if _, ok := hashes[certFile]; !ok {
		t.Fatal("expected file hash to be captured")
	}
}

func TestSnapshotPathHashes_MissingPath(t *testing.T) {
	hashes := make(map[string][32]byte)
	if err := snapshotPathHashes(filepath.Join(t.TempDir(), "missing.crt"), hashes); err == nil {
		t.Fatal("expected missing path error")
	}
}

func TestWatcher_PollLoopTriggersCallback(t *testing.T) {
	setWatcherIntervals(t, debounceInterval, 10*time.Millisecond)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certFile, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	watcher, err := NewWatcher([]string{dir}, func() { calls.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	watcher.snapshotHashes()
	if err := os.WriteFile(certFile, []byte("modified"), 0o644); err != nil {
		t.Fatal(err)
	}

	go watcher.pollLoop()
	waitFor(t, time.Second, func() bool { return calls.Load() > 0 }, "expected callback after polling detected change")
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

func TestWatcher_AddPathMissingPath(t *testing.T) {
	dir := t.TempDir()

	watcher, err := NewWatcher([]string{dir}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()

	if err := watcher.AddPath(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected error adding missing path")
	}
}

func setWatcherIntervals(t *testing.T, debounce, poll time.Duration) {
	t.Helper()

	originalDebounce := debounceInterval
	originalPoll := pollInterval
	debounceInterval = debounce
	pollInterval = poll
	t.Cleanup(func() {
		debounceInterval = originalDebounce
		pollInterval = originalPoll
	})
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message)
}
