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
	"time"

	"github.com/notaryproject/ratify-go"

	"github.com/notaryproject/ratify/v2/pkg/metrics"
)

// reportVerifierDuration is a package variable so that tests can observe the
// reported metric.
var reportVerifierDuration = metrics.ReportVerifierDuration

// instrumentedVerifier wraps a [ratify.Verifier] and reports the duration and
// outcome of every Verify call as the ratify_verifier_duration metric. All
// other methods are delegated to the wrapped verifier unchanged.
type instrumentedVerifier struct {
	ratify.Verifier
}

// Verify verifies the artifact with the wrapped verifier and reports the
// metric. A verifier error is reported with error=true, and a completed
// verification with a failing result is reported with success=false and
// error=false.
func (v *instrumentedVerifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	start := time.Now()
	result, err := v.Verifier.Verify(ctx, opts)
	success := err == nil && result != nil && result.Err == nil
	reportVerifierDuration(ctx, time.Since(start).Milliseconds(), v.Name(), success, err != nil)
	return result, err
}
