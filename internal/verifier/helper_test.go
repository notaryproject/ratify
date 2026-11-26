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

package verifier

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-go/plugin"
)

var (
	testFactoriesMu sync.Mutex
	testFactories   = map[string]plugin.VerifierFactory{}
)

// registerTestVerifier makes factory available under typ in plugin.Default for
// the duration of the test. As plugin.Default does not support
// unregistration, a dispatching factory is registered once per type and the
// test specific factory is removed when the test ends.
func registerTestVerifier(t *testing.T, typ string, factory plugin.VerifierFactory) {
	t.Helper()
	testFactoriesMu.Lock()
	defer testFactoriesMu.Unlock()
	if _, ok := testFactories[typ]; !ok {
		// The error is ignored as the dispatcher may have been registered by
		// a previous run of the test (e.g. go test -count=2).
		_ = plugin.Default.RegisterVerifier(typ, func(ctx context.Context, opts plugin.VerifierOptions) (ratify.Verifier, error) {
			testFactoriesMu.Lock()
			f := testFactories[typ]
			testFactoriesMu.Unlock()
			if f == nil {
				return nil, fmt.Errorf("no test factory set for verifier type %q", typ)
			}
			return f(ctx, opts)
		})
	}
	testFactories[typ] = factory
	t.Cleanup(func() {
		testFactoriesMu.Lock()
		defer testFactoriesMu.Unlock()
		testFactories[typ] = nil
	})
}
