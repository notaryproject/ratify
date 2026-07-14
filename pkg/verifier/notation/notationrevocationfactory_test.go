// Copyright The Ratify Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notation

import (
	"net/http"
	"runtime"
	"testing"

	"github.com/notaryproject/notation-core-go/revocation"
	"github.com/notaryproject/notation-go/dir"
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewRevocationFactoryImpl(t *testing.T) {
	factory := CreateCRLHandlerFromConfig()
	assert.NotNil(t, factory)
}

func TestNewFetcher(t *testing.T) {
	tests := []struct {
		name       string
		cacheRoot  string
		httpClient *http.Client
		wantErr    bool
		firstCall  bool
	}{
		{
			name:       "create CRL fetcher failure with nil httpClient on first call",
			cacheRoot:  "",
			httpClient: nil,
			firstCall:  true,
			wantErr:    true,
		},
		{
			name:       "recreate CRL fetcher failure on second call",
			cacheRoot:  "/valid/path",
			httpClient: &http.Client{},
			firstCall:  false,
			wantErr:    true,
		},
	}
	globalFetcher = nil
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := &CRLHandler{httpClient: tt.httpClient}
			fetcher, err := factory.NewFetcher()
			if tt.firstCall {
				// Fetcher is initialized in sequential execution before this test, skip the test to avoid test failure
				t.Skip("skipping on first call")
			}
			if !tt.firstCall && tt.wantErr {
				assert.Nil(t, fetcher)
				assert.Nil(t, globalFetcher)
				assert.Equal(t, err, re.ErrorCodeConfigInvalid.WithDetail("failed to create CRL fetcher"))
			}
		})
	}
	// fix globalFetcher to avoid test failure
	globalFetcher, _ = CreateCRLFetcher(&http.Client{}, dir.PathCRLCache)
}

func TestNewValidator(t *testing.T) {
	factory := CreateCRLHandlerFromConfig()
	opts := revocation.Options{}

	validator, err := factory.NewValidator(opts)
	assert.NoError(t, err)
	assert.NotNil(t, validator)
}
func TestNewFileCache(t *testing.T) {
	tests := []struct {
		name      string
		cacheRoot string
		wantErr   bool
	}{
		{
			name:      "valid cache root",
			cacheRoot: "/valid/path",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("skipping test on Windows")
			}
			cache, err := newFileCache(tt.cacheRoot)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cache)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cache)
			}
		})
	}
}
