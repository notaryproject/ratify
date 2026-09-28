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
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

var (
	debounceInterval = 2 * time.Second
	pollInterval     = 30 * time.Second
)

type ChangeCallback func()

type Watcher struct {
	watcher  *fsnotify.Watcher
	paths    []string
	callback ChangeCallback
	done     chan struct{}
	hashes   map[string][32]byte

	mu       sync.Mutex
	stopOnce sync.Once
}

func NewWatcher(paths []string, callback ChangeCallback) (*Watcher, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one path must be provided")
	}
	if callback == nil {
		return nil, fmt.Errorf("callback must not be nil")
	}

	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	w := &Watcher{
		watcher:  fsWatcher,
		paths:    append([]string(nil), paths...),
		callback: callback,
		done:     make(chan struct{}),
		hashes:   make(map[string][32]byte),
	}
	w.snapshotHashes()
	return w, nil
}

func (w *Watcher) Start() error {
	for _, path := range w.paths {
		if err := w.addPath(path); err != nil {
			logrus.WithError(err).Warnf("failed to watch path %s", path)
		}
	}

	go w.watch()
	go w.pollLoop()
	return nil
}

func (w *Watcher) Stop() {
	w.stopOnce.Do(func() {
		close(w.done)
		if err := w.watcher.Close(); err != nil && !errors.Is(err, fsnotify.ErrClosed) {
			logrus.WithError(err).Error("error closing trust store watcher")
		}
	})
}

func (w *Watcher) AddPath(path string) error {
	w.mu.Lock()
	for _, existing := range w.paths {
		if existing == path {
			w.mu.Unlock()
			return nil
		}
	}
	w.mu.Unlock()

	if err := w.addPath(path); err != nil {
		return err
	}

	w.mu.Lock()
	w.paths = append(w.paths, path)
	w.mu.Unlock()
	w.snapshotHashes()
	return nil
}

func (w *Watcher) addPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat path %s: %w", path, err)
	}
	if err := w.watcher.Add(path); err != nil {
		return fmt.Errorf("failed to watch path %s: %w", path, err)
	}
	if info.IsDir() {
		parent := filepath.Dir(path)
		if parent != path {
			_ = w.watcher.Add(parent)
		}
	}
	return nil
}

func (w *Watcher) watch() {
	var debounceTimer *time.Timer
	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			logrus.Debugf("trust store watcher event: %s %s", event.Op, event.Name)
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				_ = w.watcher.Add(event.Name)
			}
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			eventName := event.Name
			debounceTimer = time.AfterFunc(debounceInterval, func() {
				logrus.Infof("trust store cert change detected: %s", eventName)
				w.callback()
				w.snapshotHashes()
			})
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			logrus.WithError(err).Error("trust store watcher error")
		case <-w.done:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return
		}
	}
}

func (w *Watcher) pollLoop() {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if w.certsChanged() {
				logrus.Info("trust store cert change detected via polling")
				w.callback()
				w.snapshotHashes()
			}
		case <-w.done:
			return
		}
	}
}

func (w *Watcher) certsChanged() bool {
	currentHashes := w.currentHashes()

	w.mu.Lock()
	defer w.mu.Unlock()

	if len(currentHashes) != len(w.hashes) {
		return true
	}
	for path, currentHash := range currentHashes {
		previousHash, ok := w.hashes[path]
		if !ok || previousHash != currentHash {
			return true
		}
	}
	return false
}

func (w *Watcher) currentHashes() map[string][32]byte {
	w.mu.Lock()
	paths := append([]string(nil), w.paths...)
	w.mu.Unlock()

	hashes := make(map[string][32]byte)
	for _, path := range paths {
		if err := snapshotPathHashes(path, hashes); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logrus.WithError(err).Warnf("failed to snapshot trust store path %s", path)
		}
	}
	return hashes
}

func snapshotPathHashes(path string, hashes map[string][32]byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return snapshotDirHashes(path, hashes)
	}

	hash, err := hashFile(path)
	if err != nil {
		return err
	}
	hashes[path] = hash
	return nil
}

func snapshotDirHashes(path string, hashes map[string][32]byte) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return fmt.Errorf("failed to open root %s: %w", path, err)
	}
	defer root.Close()

	return fs.WalkDir(root.FS(), ".", func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		data, err := root.ReadFile(filePath)
		if err != nil {
			return err
		}
		hashes[filepath.Join(path, filePath)] = sha256.Sum256(data)
		return nil
	})
}

func hashFile(path string) ([32]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

func (w *Watcher) snapshotHashes() {
	currentHashes := w.currentHashes()

	w.mu.Lock()
	defer w.mu.Unlock()
	w.hashes = currentHashes
}
