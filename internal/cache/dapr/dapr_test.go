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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dapr/go-sdk/client"
	"github.com/notaryproject/ratify/v2/internal/cache"
)

const (
	testCacheName = "test-cache"
	testKey       = "test_key"
	testValue     = "test_value"
)

// testDaprClient is a stub implementation of stateClient for unit tests.
type testDaprClient struct {
	stateValues map[string]string
	throwError  error
	mdValues    map[string]string
}

func (d *testDaprClient) GetState(_ context.Context, _, key string, _ map[string]string) (*client.StateItem, error) {
	if d.throwError != nil {
		return nil, d.throwError
	}
	value, ok := d.stateValues[key]
	if !ok {
		return &client.StateItem{Key: key}, nil
	}
	return &client.StateItem{
		Key:   key,
		Value: []byte(value),
	}, nil
}

func (d *testDaprClient) SaveState(_ context.Context, _, key string, value []byte, md map[string]string, _ ...client.StateOption) error {
	if d.throwError != nil {
		return d.throwError
	}
	d.stateValues[key] = string(value)
	d.mdValues = md
	return nil
}

func (d *testDaprClient) DeleteState(_ context.Context, _, key string, _ map[string]string) error {
	if d.throwError != nil {
		return d.throwError
	}
	delete(d.stateValues, key)
	return nil
}

func TestDaprCache_Get_Expected(t *testing.T) {
	marshalled, _ := json.Marshal(testValue)
	d := &Cache[string]{
		daprClient: &testDaprClient{
			stateValues: map[string]string{
				testKey: string(marshalled),
			},
		},
		cacheName: testCacheName,
	}
	val, err := d.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if val != testValue {
		t.Errorf("expected value to be %s, got %s", testValue, val)
	}
}

func TestDaprCache_Get_NotFound(t *testing.T) {
	d := &Cache[string]{
		daprClient: &testDaprClient{
			stateValues: map[string]string{},
		},
		cacheName: testCacheName,
	}
	_, err := d.Get(context.Background(), testKey)
	if !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDaprCache_Get_Error(t *testing.T) {
	d := &Cache[string]{
		daprClient: &testDaprClient{
			throwError: fmt.Errorf("test error"),
		},
		cacheName: testCacheName,
	}
	if _, err := d.Get(context.Background(), testKey); err == nil {
		t.Errorf("expected an error, got nil")
	}
}

func TestDaprCache_Set_Expected(t *testing.T) {
	d := &Cache[string]{
		daprClient: &testDaprClient{
			stateValues: map[string]string{},
		},
		cacheName: testCacheName,
	}
	if err := d.Set(context.Background(), testKey, testValue, 0); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	rawJSON := d.daprClient.(*testDaprClient).stateValues[testKey]
	var value string
	if err := json.Unmarshal([]byte(rawJSON), &value); err != nil {
		t.Fatalf("expected valid json, got %v", err)
	}
	if value != testValue {
		t.Errorf("expected value to be %s, got %s", testValue, value)
	}
}

func TestDaprCache_Set_Error(t *testing.T) {
	d := &Cache[string]{
		daprClient: &testDaprClient{
			throwError: fmt.Errorf("test error"),
		},
		cacheName: testCacheName,
	}
	if err := d.Set(context.Background(), testKey, testValue, 0); err == nil {
		t.Errorf("expected an error, got nil")
	}
}

func TestDaprCache_Set_WithTTL(t *testing.T) {
	d := &Cache[string]{
		daprClient: &testDaprClient{
			stateValues: map[string]string{},
		},
		cacheName: testCacheName,
	}
	if err := d.Set(context.Background(), testKey, testValue, 10*time.Second); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	rawJSON := d.daprClient.(*testDaprClient).stateValues[testKey]
	var value string
	if err := json.Unmarshal([]byte(rawJSON), &value); err != nil {
		t.Fatalf("expected valid json, got %v", err)
	}
	if value != testValue {
		t.Errorf("expected value to be %s, got %s", testValue, value)
	}
	if d.daprClient.(*testDaprClient).mdValues["ttlInSeconds"] != "10" {
		t.Errorf("expected ttlInSeconds to be 10, got %s", d.daprClient.(*testDaprClient).mdValues["ttlInSeconds"])
	}
}

func TestDaprCache_Set_DefaultTTL(t *testing.T) {
	d := &Cache[string]{
		daprClient: &testDaprClient{
			stateValues: map[string]string{},
		},
		cacheName: testCacheName,
		ttl:       30 * time.Second,
	}
	if err := d.Set(context.Background(), testKey, testValue, 0); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if d.daprClient.(*testDaprClient).mdValues["ttlInSeconds"] != "30" {
		t.Errorf("expected default ttlInSeconds to be 30, got %s", d.daprClient.(*testDaprClient).mdValues["ttlInSeconds"])
	}
}

func TestDaprCache_Set_SubSecondTTL(t *testing.T) {
	d := &Cache[string]{
		daprClient: &testDaprClient{
			stateValues: map[string]string{},
		},
		cacheName: testCacheName,
	}
	if err := d.Set(context.Background(), testKey, testValue, 500*time.Millisecond); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got := d.daprClient.(*testDaprClient).mdValues["ttlInSeconds"]; got != "1" {
		t.Errorf("expected sub-second TTL to round up to 1, got %s", got)
	}
}

func TestDaprCache_Delete_Expected(t *testing.T) {
	d := &Cache[string]{
		daprClient: &testDaprClient{
			stateValues: map[string]string{
				testKey: testValue,
			},
		},
		cacheName: testCacheName,
	}
	if err := d.Delete(context.Background(), testKey); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if _, ok := d.daprClient.(*testDaprClient).stateValues[testKey]; ok {
		t.Errorf("expected key to be deleted")
	}
}

func TestDaprCache_Delete_Error(t *testing.T) {
	d := &Cache[string]{
		daprClient: &testDaprClient{
			throwError: fmt.Errorf("test error"),
		},
		cacheName: testCacheName,
	}
	if err := d.Delete(context.Background(), testKey); err == nil {
		t.Errorf("expected an error, got nil")
	}
}
