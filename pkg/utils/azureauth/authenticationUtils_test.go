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

package azureauth

import (
	"context"
	"os"
	"testing"
)

func TestGetAuthority(t *testing.T) {
	tests := []struct {
		name          string
		authorityHost string
		tenantID      string
		want          string
	}{
		{
			name:          "authority host with trailing slash",
			authorityHost: "https://login.microsoftonline.com/",
			tenantID:      "tenant-id",
			want:          "https://login.microsoftonline.com/tenant-id",
		},
		{
			name:          "authority host without trailing slash",
			authorityHost: "https://login.microsoftonline.com",
			tenantID:      "tenant-id",
			want:          "https://login.microsoftonline.com/tenant-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAuthority(tt.authorityHost, tt.tenantID); got != tt.want {
				t.Fatalf("getAuthority() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetAADAccessTokenReturnsErrorForInvalidAuthority(t *testing.T) {
	tokenFile := t.TempDir() + "/token"
	if err := os.WriteFile(tokenFile, []byte("token"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", tokenFile)
	t.Setenv("AZURE_AUTHORITY_HOST", "://invalid-authority")

	if _, err := GetAADAccessToken(context.Background(), "tenant-id", "client-id", "scope"); err == nil {
		t.Fatal("GetAADAccessToken() error = nil, want error")
	}
}
