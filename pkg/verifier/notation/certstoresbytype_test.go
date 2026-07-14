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

package notation

import "testing"

func TestNewCertStoreByTypeInvalidInput(t *testing.T) {
	tests := []struct {
		name      string
		conf      verificationCertStores
		expectErr bool
	}{
		{
			name: "invalid certStores type",
			conf: verificationCertStores{
				trustStoreTypeCA: []string{},
			},
			expectErr: true,
		},
		{
			name: "invalid certProviderList type",
			conf: verificationCertStores{
				trustStoreTypeCA: map[string]interface{}{
					"certstore1": "akv1",
					"certstore2": []interface{}{"akv3", "akv4"},
				},
			},
			expectErr: true,
		},
		{
			name: "invalid certProvider type",
			conf: verificationCertStores{
				trustStoreTypeCA: map[string]interface{}{
					"certstore1": []interface{}{"akv1", []string{}},
				},
			},
			expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newCertStoreByType(tt.conf)
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}
