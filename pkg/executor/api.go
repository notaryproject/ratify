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

package executor

import (
	"context"
	"time"

	"github.com/notaryproject/ratify/v2/pkg/executor/types"
)

// VerifyParameters describes the subject verification parameters
type VerifyParameters struct {
	Subject        string   `json:"subjectReference"`
	ReferenceTypes []string `json:"referenceTypes,omitempty"`
}

// Executor is an interface that defines methods to verify a subject
type Executor interface {
	// VerifySubject returns the result of verifying a subject
	VerifySubject(ctx context.Context, verifyParameters VerifyParameters) (types.VerifyResult, error)

	// GetVerifyRequestTimeout returns the timeout for the verification request configured with the executor
	GetVerifyRequestTimeout() time.Duration

	// GetMutationRequestTimeout returns the timeout for the mutation request configured with the executor
	GetMutationRequestTimeout() time.Duration
}
