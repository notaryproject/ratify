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

package builtin

import (
	"reflect"
	"testing"

	"github.com/notaryproject/ratify-go/plugin"
)

func TestBuiltinPlugins(t *testing.T) {
	tests := []struct {
		kind string
		got  []string
		want []string
	}{
		{kind: "verifier", got: plugin.Default.VerifierTypes(), want: []string{"cosign", "notation"}},
		{kind: "store", got: plugin.Default.StoreTypes(), want: []string{"filesystem-oci-store", "registry-store"}},
		{kind: "policy enforcer", got: plugin.Default.PolicyEnforcerTypes(), want: []string{"threshold-policy"}},
		{kind: "key provider", got: plugin.Default.KeyProviderTypes(), want: []string{"azurekeyvault", "files", "inline"}},
	}
	for _, tt := range tests {
		if !reflect.DeepEqual(tt.got, tt.want) {
			t.Errorf("%s types = %v, want %v", tt.kind, tt.got, tt.want)
		}
	}
}
