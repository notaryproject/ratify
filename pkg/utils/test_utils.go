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
	"context"
	"errors"
	"os"
	"path/filepath"

	configv1beta1 "github.com/ratify-project/ratify/api/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type MockResourceWriter struct {
	updateFailed bool
}

func (w MockResourceWriter) Create(_ context.Context, _ client.Object, _ client.Object, _ ...client.SubResourceCreateOption) error {
	return nil
}

func (w MockResourceWriter) Update(_ context.Context, _ client.Object, _ ...client.SubResourceUpdateOption) error {
	if w.updateFailed {
		return errors.New("update failed")
	}
	return nil
}

func (w MockResourceWriter) Apply(_ context.Context, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
	return nil
}

func (w MockResourceWriter) Patch(_ context.Context, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
	return nil
}

type MockStatusClient struct {
	UpdateFailed bool
}

func (c MockStatusClient) Status() client.SubResourceWriter {
	writer := MockResourceWriter{}
	writer.updateFailed = c.UpdateFailed
	return writer
}

func CreateScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()

	b := runtime.SchemeBuilder{
		clientgoscheme.AddToScheme,
		configv1beta1.AddToScheme,
	}

	if err := b.AddToScheme(scheme); err != nil {
		return nil, err
	}

	return scheme, nil
}

func KeyFor(obj client.Object) types.NamespacedName {
	return client.ObjectKeyFromObject(obj)
}

func CreatePlugin(pluginName string) (string, error) {
	tempDir, err := os.MkdirTemp("", "directory")
	if err != nil {
		return "", err
	}

	fullName := filepath.Join(tempDir, pluginName)
	file, err := os.Create(fullName)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return tempDir, nil
}
