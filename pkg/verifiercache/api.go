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

package verifiercache

import (
	"context"
	"time"

	et "github.com/notaryproject/ratify/v2/pkg/executor/types"
)

// VerifierCache is an interface that defines methods to set/get results from a cache
type VerifierCache interface {
	// GetVerifyResult gets the result from the cache with the given subject as the key
	GetVerifyResult(ctx context.Context, subjectRefString string) (et.VerifyResult, bool)

	// SetVerifyResult sets the verify result in the cache with the given TTL
	SetVerifyResult(ctx context.Context, subjectRefString string, verifyResult et.VerifyResult, ttl time.Duration)
}
