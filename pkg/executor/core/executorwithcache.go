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

package core

import (
	"context"
	"time"

	"github.com/notaryproject/ratify/v2/pkg/executor"
	"github.com/notaryproject/ratify/v2/pkg/executor/types"
	"github.com/notaryproject/ratify/v2/pkg/verifiercache"
)

// ExecutorWithCache wraps the executor with a verifier cache
type ExecutorWithCache struct {
	base                   executor.Executor
	verifierCache          verifiercache.VerifierCache
	verfierCacheItemExpiry time.Duration
}

func (executor ExecutorWithCache) VerifySubject(ctx context.Context, verifyParameters executor.VerifyParameters) (types.VerifyResult, error) {
	// check the cache for the existence of item
	cachedResult, ok := executor.verifierCache.GetVerifyResult(ctx, verifyParameters.Subject)

	if ok {
		return cachedResult, nil
	}

	result, err := executor.base.VerifySubject(ctx, verifyParameters)

	if err == nil {
		executor.verifierCache.SetVerifyResult(ctx, verifyParameters.Subject, result, executor.verfierCacheItemExpiry)
	}

	return result, err
}
