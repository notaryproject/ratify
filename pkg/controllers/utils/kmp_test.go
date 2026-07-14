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
	"reflect"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/config"
	_ "github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/inline"
)

func TestSpecToKeyManagementProviderProvider(t *testing.T) {
	testCases := []struct {
		name      string
		raw       []byte
		kmpType   string
		resource  string
		expectErr bool
	}{
		{
			name:      "empty spec",
			expectErr: true,
		},
		{
			name:      "missing inline provider required fields",
			raw:       []byte("{\"type\": \"inline\"}"),
			kmpType:   "inline",
			resource:  "test",
			expectErr: true,
		},
		{
			name:      "valid spec",
			raw:       []byte(`{"type": "inline", "contentType": "certificate", "value": "-----BEGIN CERTIFICATE-----\nMIID2jCCAsKgAwIBAgIQXy2VqtlhSkiZKAGhsnkjbDANBgkqhkiG9w0BAQsFADBvMRswGQYDVQQD\nExJyYXRpZnkuZXhhbXBsZS5jb20xDzANBgNVBAsTBk15IE9yZzETMBEGA1UEChMKTXkgQ29tcGFu\neTEQMA4GA1UEBxMHUmVkbW9uZDELMAkGA1UECBMCV0ExCzAJBgNVBAYTAlVTMB4XDTIzMDIwMTIy\nNDUwMFoXDTI0MDIwMTIyNTUwMFowbzEbMBkGA1UEAxMScmF0aWZ5LmV4YW1wbGUuY29tMQ8wDQYD\nVQQLEwZNeSBPcmcxEzARBgNVBAoTCk15IENvbXBhbnkxEDAOBgNVBAcTB1JlZG1vbmQxCzAJBgNV\nBAgTAldBMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL10bM81\npPAyuraORABsOGS8M76Bi7Guwa3JlM1g2D8CuzSfSTaaT6apy9GsccxUvXd5cmiP1ffna5z+EFmc\nizFQh2aq9kWKWXDvKFXzpQuhyqD1HeVlRlF+V0AfZPvGt3VwUUjNycoUU44ctCWmcUQP/KShZev3\n6SOsJ9q7KLjxxQLsUc4mg55eZUThu8mGB8jugtjsnLUYvIWfHhyjVpGrGVrdkDMoMn+u33scOmrt\nsBljvq9WVo4T/VrTDuiOYlAJFMUae2Ptvo0go8XTN3OjLblKeiK4C+jMn9Dk33oGIT9pmX0vrDJV\nX56w/2SejC1AxCPchHaMuhlwMpftBGkCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQC\nMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAU0eaKkZj+MS9jCp9Dg1zdv3v/aKww\nHQYDVR0OBBYEFNHmipGY/jEvYwqfQ4Nc3b97/2isMA0GCSqGSIb3DQEBCwUAA4IBAQBNDcmSBizF\nmpJlD8EgNcUCy5tz7W3+AAhEbA3vsHP4D/UyV3UgcESx+L+Nye5uDYtTVm3lQejs3erN2BjW+ds+\nXFnpU/pVimd0aYv6mJfOieRILBF4XFomjhrJOLI55oVwLN/AgX6kuC3CJY2NMyJKlTao9oZgpHhs\nLlxB/r0n9JnUoN0Gq93oc1+OLFjPI7gNuPXYOP1N46oKgEmAEmNkP1etFrEjFRgsdIFHksrmlOlD\nIed9RcQ087VLjmuymLgqMTFX34Q3j7XgN2ENwBSnkHotE9CcuGRW+NuiOeJalL8DBmFXXWwHTKLQ\nPp5g6m1yZXylLJaFLKz7tdMmO355\n-----END CERTIFICATE-----\n"}`),
			kmpType:   "inline",
			resource:  "test",
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SpecToKeyManagementProvider(tc.raw, tc.kmpType, tc.resource)
			if tc.expectErr != (err != nil) {
				t.Fatalf("Expected error to be %t, got %t", tc.expectErr, err != nil)
			}
		})
	}
}

// TestRawToKeyManagementProviderConfig tests the rawToKeyManagementProviderConfig method
func TestRawToKeyManagementProviderConfig(t *testing.T) {
	testCases := []struct {
		name         string
		resource     string
		raw          []byte
		expectErr    bool
		expectConfig config.KeyManagementProviderConfig
	}{
		{
			name:         "empty Raw",
			raw:          []byte{},
			expectErr:    true,
			expectConfig: config.KeyManagementProviderConfig{},
		},
		{
			name:         "unmarshal failure",
			resource:     "test",
			raw:          []byte("invalid"),
			expectErr:    true,
			expectConfig: config.KeyManagementProviderConfig{},
		},
		{
			name:      "valid Raw",
			resource:  "test",
			raw:       []byte("{\"type\": \"inline\"}"),
			expectErr: false,
			expectConfig: config.KeyManagementProviderConfig{
				"type":     "inline",
				"resource": "test",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := rawToKeyManagementProviderConfig(tc.raw, "inline", "test")

			if tc.expectErr != (err != nil) {
				t.Fatalf("Expected error to be %t, got %t", tc.expectErr, err != nil)
			}
			if !reflect.DeepEqual(config, tc.expectConfig) {
				t.Fatalf("Expected config to be %v, got %v", tc.expectConfig, config)
			}
		})
	}
}
