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

package utils

import (
	"encoding/json"
	"fmt"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
	"github.com/notaryproject/ratify/v2/config"
	"github.com/notaryproject/ratify/v2/pkg/controllers"
	rc "github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	sf "github.com/notaryproject/ratify/v2/pkg/referrerstore/factory"
	"github.com/notaryproject/ratify/v2/pkg/verifier/types"
	"github.com/sirupsen/logrus"
)

func UpsertStoreMap(version, address, fullname, namespace string, storeConfig rc.StorePluginConfig) error {
	// if the default version is not suitable, the plugin configuration should specify the desired version
	if len(version) == 0 {
		version = config.GetDefaultPluginVersion()
		logrus.Infof("Version was empty, setting to default version: %v", version)
	}

	if address == "" {
		address = config.GetDefaultPluginPath()
		logrus.Infof("Address was empty, setting to default path %v", address)
	}
	storeReference, err := sf.CreateStoreFromConfig(storeConfig, version, []string{address})

	if err != nil || storeReference == nil {
		logrus.Error(err, "store factory failed to create store from store config")
		return fmt.Errorf("store factory failed to create store from store config, err: %w", err)
	}
	controllers.NamespacedStores.AddStore(namespace, fullname, storeReference)
	logrus.Infof("store '%v' added to store map in namespace: %s", storeReference.Name(), namespace)

	return nil
}

// Returns a store reference from spec
func CreateStoreConfig(raw []byte, name string, source *configv1beta1.PluginSource) (rc.StorePluginConfig, error) {
	storeConfig := rc.StorePluginConfig{}

	if string(raw) != "" {
		if err := json.Unmarshal(raw, &storeConfig); err != nil {
			logrus.Error(err, "unable to decode store parameters", "Parameters.Raw", raw)
			return rc.StorePluginConfig{}, err
		}
	}
	storeConfig[types.Name] = name
	if source != nil {
		storeConfig[types.Source] = source
	}

	return storeConfig, nil
}
