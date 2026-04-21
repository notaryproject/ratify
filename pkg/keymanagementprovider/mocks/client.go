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
package mocks

import (
	"context"
	"errors"

	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type TestClient struct {
	client.Client
	GetFunc  func(ctx context.Context, key types.NamespacedName, obj client.Object) error
	ListFunc func(ctx context.Context, list client.ObjectList) error
}

func (m TestClient) Get(_ context.Context, key types.NamespacedName, obj client.Object, _ ...client.GetOption) error {
	if m.GetFunc != nil {
		return m.GetFunc(context.Background(), key, obj)
	}
	return nil
}

func (m TestClient) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	if m.ListFunc != nil {
		return m.ListFunc(context.Background(), list)
	}
	return nil
}

type mockSubResourceWriter struct {
	updateFailed bool
}

func (m *TestClient) Status() client.StatusWriter {
	return &mockSubResourceWriter{updateFailed: false}
}

func (m *mockSubResourceWriter) Create(_ context.Context, _ client.Object, _ client.Object, _ ...client.SubResourceCreateOption) error {
	return nil
}

func (m *mockSubResourceWriter) Apply(_ context.Context, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
	return nil
}

func (m *mockSubResourceWriter) Patch(_ context.Context, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
	return nil
}

func (m *mockSubResourceWriter) Update(_ context.Context, _ client.Object, _ ...client.SubResourceUpdateOption) error {
	if m.updateFailed {
		return errors.New("update failed")
	}
	return nil
}
