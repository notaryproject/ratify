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

package dapr

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/dapr/go-sdk/client"
)

const (
	testCacheName = "test-cache"
	testKey       = "test_key"
	testValue     = "test_value"
)

type TestDaprClient struct {
	client.Client
	stateValues map[string]string
	throwError  error
	mdValues    map[string]string
}

func (d *TestDaprClient) GetState(_ context.Context, _, key string, _ map[string]string) (item *client.StateItem, err error) {
	if d.throwError != nil {
		return nil, d.throwError
	}
	return &client.StateItem{
		Key:   key,
		Value: []byte(d.stateValues[key]),
	}, nil
}

func (d *TestDaprClient) SaveState(_ context.Context, _, key string, value []byte, md map[string]string, _ ...client.StateOption) error {
	if d.throwError != nil {
		return d.throwError
	}
	d.stateValues[key] = string(value)
	d.mdValues = md
	return nil
}

func (d *TestDaprClient) DeleteState(_ context.Context, _, key string, _ map[string]string) error {
	if d.throwError != nil {
		return d.throwError
	}
	delete(d.stateValues, key)
	return nil
}

func TestDaprCacheProvider_Get_Expected(t *testing.T) {
	d := &daprCache{
		daprClient: &TestDaprClient{
			stateValues: map[string]string{
				"test_key": "test_value",
			},
		},
		cacheName: testCacheName,
	}
	val, ok := d.Get(context.Background(), testKey)
	if !ok {
		t.Errorf("expected ok to be true")
	}
	if val != testValue {
		t.Errorf("expected value to be %s", testValue)
	}
}

func TestDaprCacheProvider_Get_Error(t *testing.T) {
	d := &daprCache{
		daprClient: &TestDaprClient{
			throwError: fmt.Errorf("test error"),
		},
		cacheName: testCacheName,
	}
	_, ok := d.Get(context.Background(), testKey)
	if ok {
		t.Errorf("expected ok to be false")
	}
}

func TestDaprCacheProvider_Set_Expected(t *testing.T) {
	d := &daprCache{
		daprClient: &TestDaprClient{
			stateValues: map[string]string{},
		},
		cacheName: testCacheName,
	}
	ok := d.Set(context.Background(), testKey, testValue)
	if !ok {
		t.Errorf("expected ok to be true")
	}
	rawJSON := d.daprClient.(*TestDaprClient).stateValues[testKey]
	var value string
	err := json.Unmarshal([]byte(rawJSON), &value)
	if err != nil {
		t.Errorf("expected err to be nil")
	}
	if value != testValue {
		t.Errorf("expected value to be %s", testValue)
	}
}

func TestDaprCacheProvider_Set_Error(t *testing.T) {
	d := &daprCache{
		daprClient: &TestDaprClient{
			throwError: fmt.Errorf("test error"),
		},
		cacheName: testCacheName,
	}
	ok := d.Set(context.Background(), testKey, testValue)
	if ok {
		t.Errorf("expected ok to be false")
	}
}

func TestDaprCacheProvider_SetWithTTL_Expected(t *testing.T) {
	d := &daprCache{
		daprClient: &TestDaprClient{
			stateValues: map[string]string{},
		},
		cacheName: testCacheName,
	}
	ok := d.SetWithTTL(context.Background(), testKey, testValue, 10*time.Second)
	if !ok {
		t.Errorf("expected ok to be true")
	}
	rawJSON := d.daprClient.(*TestDaprClient).stateValues[testKey]
	var value string
	err := json.Unmarshal([]byte(rawJSON), &value)
	if err != nil {
		t.Errorf("expected err to be nil")
	}
	if value != testValue {
		t.Errorf("expected value to be %s", testValue)
	}
	if d.daprClient.(*TestDaprClient).mdValues["ttlInSeconds"] != "10" {
		t.Errorf("expected ttlInSeconds to be 10")
	}
}

func TestDaprCacheProvider_SetWithTTL_Error(t *testing.T) {
	d := &daprCache{
		daprClient: &TestDaprClient{
			throwError: fmt.Errorf("test error"),
		},
		cacheName: testCacheName,
	}
	ok := d.SetWithTTL(context.Background(), testKey, testValue, 10)
	if ok {
		t.Errorf("expected ok to be false")
	}
}

func TestDaprCacheProvider_SetWithTTL_InvalidTTL(t *testing.T) {
	d := &daprCache{
		daprClient: &TestDaprClient{},
		cacheName:  testCacheName,
	}
	ok := d.SetWithTTL(context.Background(), testKey, testValue, -10)
	if ok {
		t.Errorf("expected ok to be false")
	}
}

func TestDaprCacheProvider_Delete_Expected(t *testing.T) {
	d := &daprCache{
		daprClient: &TestDaprClient{
			stateValues: map[string]string{
				testKey: testValue,
			},
		},
		cacheName: testCacheName,
	}
	ok := d.Delete(context.Background(), testKey)
	if !ok {
		t.Errorf("expected ok to be true")
	}
	_, ok = d.daprClient.(*TestDaprClient).stateValues[testKey]
	if ok {
		t.Errorf("expected key to be deleted")
	}
}

func TestDaprCacheProvider_Delete_Error(t *testing.T) {
	d := &daprCache{
		daprClient: &TestDaprClient{
			throwError: fmt.Errorf("test error"),
		},
		cacheName: testCacheName,
	}
	ok := d.Delete(context.Background(), testKey)
	if ok {
		t.Errorf("expected ok to be false")
	}
}
