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
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"

	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/ratify/v2/config"
	"github.com/stretchr/testify/assert"
)

func TestSupportCRL(t *testing.T) {
	t.Run("certificate with CRL distribution points", func(t *testing.T) {
		cert := &x509.Certificate{
			CRLDistributionPoints: []string{"http://example.com/crl"},
		}
		assert.True(t, SupportCRL(cert))
	})

	t.Run("certificate without CRL distribution points", func(t *testing.T) {
		cert := &x509.Certificate{}
		assert.False(t, SupportCRL(cert))
	})

	t.Run("nil certificate", func(t *testing.T) {
		assert.False(t, SupportCRL(nil))
	})
}
func TestCacheCRL(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{}
	cacheRoot := "/tmp/cache"
	fetcher, _ := CreateCRLFetcher(httpClient, cacheRoot)

	t.Run("nil fetcher", func(t *testing.T) {
		certs := []*x509.Certificate{
			{
				CRLDistributionPoints: []string{"http://example.com/crl"},
			},
		}
		CacheCRL(ctx, certs, nil)
		// Check logs if necessary
		t.Log("CRL fetcher is nil")
	})

	t.Run("certificate without CRL distribution points", func(t *testing.T) {
		certs := []*x509.Certificate{
			{},
		}
		CacheCRL(ctx, certs, fetcher)
		// Check logs if necessary
		t.Log("Certificate does not support CRL")
	})

	t.Run("certificates with CRL distribution points", func(t *testing.T) {
		certs := []*x509.Certificate{
			{
				CRLDistributionPoints: []string{"http://example.com/crl1"},
			},
			{
				CRLDistributionPoints: []string{"http://example.com/crl2"},
			},
		}
		CacheCRL(ctx, certs, fetcher)
		// Check logs if necessary
		t.Log("Completed fetching CRLs")
	})
}
func TestIntermittentFailCacheCRL(t *testing.T) {
	ctx := context.Background()
	t.Run("fetch CRL fails", func(t *testing.T) {
		// Mock fetcher to simulate failure
		mockFetcher := &MockFetcher{
			flag: true,
			FetchFunc: func(_ context.Context, _ string) (*corecrl.Bundle, error) {
				return &corecrl.Bundle{}, nil
			},
		}
		certs := []*x509.Certificate{
			{
				CRLDistributionPoints: []string{"http://example.com/crl1"},
			},
			{
				CRLDistributionPoints: []string{"http://example.com/crl2"},
			},
			{
				CRLDistributionPoints: []string{"http://example.com/crl3"},
			},
			{
				CRLDistributionPoints: []string{"http://example.com/crl4"},
			},
		}
		CacheCRL(ctx, certs, mockFetcher)
		// Check logs if necessary
		t.Log("Completed fetching CRLs with intermittent failures")
	})
}

func TestCreateCRLFetcher(t *testing.T) {
	httpClient := &http.Client{}
	cacheRoot := "/tmp/cache"

	t.Run("successful fetcher creation without cache", func(t *testing.T) {
		// Disable cache
		config.CRLConf.Cache.Enabled = false
		fetcher, err := CreateCRLFetcher(httpClient, cacheRoot)
		assert.NoError(t, err)
		assert.NotNil(t, fetcher)
	})

	t.Run("successful fetcher creation with cache", func(t *testing.T) {
		// Enable cache
		config.CRLConf.Cache.Enabled = true
		fetcher, err := CreateCRLFetcher(httpClient, cacheRoot)
		assert.NoError(t, err)
		assert.NotNil(t, fetcher)
	})

	t.Run("error in creating HTTP fetcher", func(t *testing.T) {
		// Simulate error by passing nil httpClient
		fetcher, err := CreateCRLFetcher(nil, cacheRoot)
		assert.Error(t, err)
		assert.Nil(t, fetcher)
	})
}

// MockFetcher is a mock implementation of corecrl.Fetcher for testing purposes
type MockFetcher struct {
	flag      bool
	FetchFunc func(ctx context.Context, url string) (*corecrl.Bundle, error)
}

func (m *MockFetcher) Fetch(ctx context.Context, url string) (*corecrl.Bundle, error) {
	m.flag = !m.flag
	if m.flag {
		return nil, fmt.Errorf("failed to fetch CRL from %s", url)
	}
	return m.FetchFunc(ctx, url)
}
