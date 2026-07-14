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

package cache

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type TestCacheFactory struct {
	shouldError bool
}

type TestCache struct{}

func (t TestCache) Get(_ context.Context, _ string) (string, bool) {
	return "", false
}

func (t TestCache) Set(_ context.Context, _ string, _ interface{}) bool {
	return false
}

func (t TestCache) SetWithTTL(_ context.Context, _ string, _ interface{}, _ time.Duration) bool {
	return false
}

func (t TestCache) Delete(_ context.Context, _ string) bool {
	return false
}

func (t TestCache) Clear(_ context.Context) bool {
	return false
}

func (t TestCacheFactory) Create(_ context.Context, _ string, _ int) (CacheProvider, error) {
	if t.shouldError {
		return nil, fmt.Errorf("error creating cache provider")
	}
	return TestCache{}, nil
}

// TestRegister_Expected tests the Register function
func TestRegister_Expected(t *testing.T) {
	Register("test-expected", TestCacheFactory{})
	if len(cacheProviderFactories) != 1 {
		t.Errorf("Expected 1 cache provider factory, got %d", len(cacheProviderFactories))
	}
	if _, ok := cacheProviderFactories["test-expected"]; !ok {
		t.Errorf("Expected cache provider factory named test-expected")
	}
}

// TestRegister_Panic tests the Register function and expects a panic
func TestRegister_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic")
		}
	}()
	Register("test-panic", TestCacheFactory{})
	Register("test-panic", TestCacheFactory{})
}

// TestNewCacheProvider_Expected tests the NewCacheProvider function
func TestNewCacheProvider_Expected(t *testing.T) {
	Register("test-newcacheprovider-expected", TestCacheFactory{})
	_, err := NewCacheProvider(context.Background(), "test-newcacheprovider-expected", "test", DefaultCacheSize)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}
}

// TestNewCacheProvider_NotFound tests the NewCacheProvider function and expects an error
func TestNewCacheProvider_NotFound(t *testing.T) {
	Register("test-newcacheprovider-notfound", TestCacheFactory{})
	_, err := NewCacheProvider(context.Background(), "notfound", "test", DefaultCacheSize)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

// TestNewCacheProvider_Error tests the NewCacheProvider function and expects an error
func TestNewCacheProvider_Error(t *testing.T) {
	Register("test-newcacheprovider-error", TestCacheFactory{shouldError: true})
	_, err := NewCacheProvider(context.Background(), "test-newcacheprovider-error", "test", DefaultCacheSize)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

// TestGetCacheProvider_Expected tests the GetCacheProvider function
func TestGetCacheProvider_Expected(t *testing.T) {
	Register("test-getcacheprovider-expected", TestCacheFactory{})
	_, err := NewCacheProvider(context.Background(), "test-getcacheprovider-expected", "test", DefaultCacheSize)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}
	cacheProvider := GetCacheProvider()
	if cacheProvider == nil {
		t.Errorf("Expected cache provider, got nil")
	}
}

// TestGetCacheProvider_NotInitialized tests the GetCacheProvider function and expects an error
func TestGetCacheProvider_NotInitialized(t *testing.T) {
	memoryCache = nil
	provider := GetCacheProvider()
	if provider != nil {
		t.Errorf("Expected nil, got %v", provider)
	}
}
