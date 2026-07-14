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
	"context"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	ef "github.com/notaryproject/ratify/v2/pkg/executor/core"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type GetExecutor func(context.Context) *ef.Executor

var (
	configHash string
	executor   ef.Executor
	CRLConf    CRLConfig
)

// Create a executor from configurationFile and setup config file watcher
func GetExecutorAndWatchForUpdate(configFilePath string) (GetExecutor, error) {
	configFilePath = getConfigurationFile(configFilePath)
	cf, err := Load(configFilePath)

	if err != nil {
		return func(context.Context) *ef.Executor { return &ef.Executor{} }, err
	}

	configHash = cf.fileHash
	CRLConf = cf.CRLConfig

	stores, verifiers, policyEnforcer, err := CreateFromConfig(cf)

	if err != nil {
		return func(context.Context) *ef.Executor { return &ef.Executor{} }, err
	}

	executor = ef.Executor{
		Verifiers:      verifiers,
		ReferrerStores: stores,
		PolicyEnforcer: policyEnforcer,
		Config:         &cf.ExecutorConfig,
	}

	err = watchForConfigurationChange(configFilePath)

	if err != nil {
		return func(context.Context) *ef.Executor { return &ef.Executor{} }, err
	}

	logrus.Info("configuration successfully loaded.")

	return func(context.Context) *ef.Executor { return &executor }, nil
}

func reloadExecutor(configFilePath string) {
	cf, err := Load(configFilePath)

	if err != nil {
		logrus.Warnf("failed to load from config file , err: %v", err)
		return
	}

	if configHash != cf.fileHash {
		stores, verifiers, policyEnforcer, err := CreateFromConfig(cf)

		newExecutor := ef.Executor{
			Verifiers:      verifiers,
			ReferrerStores: stores,
			PolicyEnforcer: policyEnforcer,
			Config:         &cf.ExecutorConfig,
		}

		if err != nil {
			logrus.Warnf("failed to store/verifier/policy objects from config, no updates loaded. err: %v", err)
			return
		}

		executor = newExecutor
		configHash = cf.fileHash
		logrus.Infof("configuration file has been updated, reloading executor succeeded")
	} else {
		logrus.Infof("no change found in config file, no executor update needed")
	}
}

// Setup a watcher on file at configFilePath, reload executor on file change
func watchForConfigurationChange(configFilePath string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return errors.Wrap(err, "new file watcher on configuration file failed ")
	}

	if err = watcher.Add(configFilePath); err != nil {
		logrus.Errorf("adding configuration file watcher failed, err: %v", err)
		return err
	}

	logrus.Infof("watcher added on configuration file %v", configFilePath)

	// setup for loop to listen for events
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					logrus.Warnf("no longer watching configuration file changes, file watcher event channel closed")
					return
				}

				logrus.Infof("file watcher event detected %v", event)

				// In a cluster scenario, a configMap will recreate the config file
				// after the remove event, the watcher will also be removed
				// since a watcher on a non existent file is not supported, we sleep until the file exist add the watcher back
				if event.Name == configFilePath && event.Op&fsnotify.Remove == fsnotify.Remove {
					logrus.Infof("config file remove event detected")
					sleepTime := 1 * time.Second
					waitTime := 60 //1min

					time.Sleep(sleepTime)
					_, err := os.Stat(configFilePath)

					for err != nil {
						if waitTime < 0 {
							logrus.Warnf("config file not found after waiting for %v sec, os.Stat error %v", waitTime, err)
							return
						}
						logrus.Infof("config file does not exist yet, sleeping again")
						_, err = os.Stat(configFilePath)
						time.Sleep(sleepTime)
						waitTime--
					}
					reloadExecutor(configFilePath)
					err = watcher.Add(configFilePath)

					if err != nil {
						logrus.Errorf("adding configuration file watcher failed, err: %v", err)
						continue
					}

					logrus.Infof("watcher added on configuration directory %v", configFilePath)
				}

				// In a local scenario, the configuration will be updated through a write event
				if event.Name == configFilePath && event.Op&fsnotify.Write == fsnotify.Write {
					reloadExecutor(configFilePath)
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					logrus.Errorf("configuration file watcher returned error : %v, watcher will be closed.", err)
					return
				}
			}
		}
	}()

	return nil
}
