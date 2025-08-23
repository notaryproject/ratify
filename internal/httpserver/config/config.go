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

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"github.com/notaryproject/ratify/v2/internal/executor"
	"github.com/sirupsen/logrus"
)

const (
	configFileName = "config.json"
	configFileDir  = ".ratify"
)

var (
	initConfigDir         = new(sync.Once)
	configDir             string
	defaultConfigFilePath string
	homeDir               string
)

// Watcher monitors changes to the executor configuration file and reloads
// the executor when changes are detected.
type Watcher struct {
	watcher            *fsnotify.Watcher
	executor           atomic.Pointer[executor.ScopedExecutor]
	executorConfigPath string
	maxConcurrency     int
}

// NewWatcher creates a new Watcher instance.
func NewWatcher(configPath string, maxConcurrency int) (*Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	configWatcher := &Watcher{
		watcher:            watcher,
		executorConfigPath: getConfigurationFile(configPath),
		maxConcurrency:     maxConcurrency,
	}
	if err = configWatcher.loadExecutor(); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	return configWatcher, nil
}

// loadExecutor reads the configuration file from the specified path and creates
// a new executor instance.
func (w *Watcher) loadExecutor() error {
	body, err := os.ReadFile(w.executorConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %w", err)
	}

	var opts executor.Options
	if err = json.Unmarshal(body, &opts); err != nil {
		return fmt.Errorf("failed to unmarshal configuration: %w", err)
	}
	opts.MaxConcurrency = w.maxConcurrency
	e, err := executor.NewScopedExecutor(opts)
	if err != nil {
		return fmt.Errorf("failed to create executor: %w", err)
	}
	w.executor.Store(e)
	return nil
}

// GetExecutor returns the current executor instance.
// It is safe to call this method concurrently.
func (w *Watcher) GetExecutor() *executor.ScopedExecutor {
	return w.executor.Load()
}

// Start begins watching the executor configuration file for changes.
func (w *Watcher) Start() error {
	logrus.Infof("Starting executor configuration watcher at %s", w.executorConfigPath)
	if err := w.watcher.Add(w.executorConfigPath); err != nil {
		return fmt.Errorf("failed to add watcher for file %s: %w", w.executorConfigPath, err)
	}
	go func() {
		for {
			select {
			case event, ok := <-w.watcher.Events:
				// if the watcher is closed, exit the loop
				if !ok {
					return
				}
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove) != 0 {
					logrus.Infof("config file changed: %s", w.executorConfigPath)
					if event.Op&fsnotify.Remove != 0 {
						if err := w.watcher.Add(event.Name); err != nil {
							logrus.Errorf("error re-watching file: %v", err)
						}
					}
					if err := w.loadExecutor(); err != nil {
						logrus.Errorf("failed to reload config: %v", err)
					}
				}
			case err, ok := <-w.watcher.Errors:
				// If the watcher is closed, exit the loop.
				if !ok {
					return
				}
				logrus.Errorf("error watching file: %v", err)
			}
		}
	}()
	return nil
}

// Stop stops the watcher and closes the underlying fsnotify watcher.
func (w *Watcher) Stop() {
	if err := w.watcher.Close(); err != nil {
		logrus.Errorf("failed to close watcher: %v", err)
	}
}

func getConfigurationFile(configFilePath string) string {
	if configFilePath == "" {
		if configDir == "" {
			initConfigDir.Do(initDefaultPaths)
		}
		return defaultConfigFilePath
	}
	return configFilePath
}

func initDefaultPaths() {
	configDir = os.Getenv("RATIFY_CONFIG")
	if configDir == "" {
		configDir = filepath.Join(getHomeDir(), configFileDir)
	}
	defaultConfigFilePath = filepath.Join(configDir, configFileName)
}

func getHomeDir() string {
	if homeDir == "" {
		homeDir = get()
	}
	return homeDir
}
