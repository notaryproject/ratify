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

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
)

type TestVerifier struct {
	CanVerifyFunc    func(artifactType string) bool
	VerifyResult     func(artifactType string) bool
	nestedReferences []string
}

func (s *TestVerifier) Name() string {
	return "verifier-testVerifier"
}

func (s *TestVerifier) Type() string {
	return "testVerifier"
}

func (s *TestVerifier) CanVerify(_ context.Context, referenceDescriptor ocispecs.ReferenceDescriptor) bool {
	return s.CanVerifyFunc(referenceDescriptor.ArtifactType)
}

func (s *TestVerifier) Verify(_ context.Context,
	_ common.Reference,
	referenceDescriptor ocispecs.ReferenceDescriptor,
	_ referrerstore.ReferrerStore) (verifier.VerifierResult, error) {
	return verifier.VerifierResult{
		IsSuccess: s.VerifyResult(referenceDescriptor.ArtifactType),
	}, nil
}

func (s *TestVerifier) GetNestedReferences() []string {
	return s.nestedReferences
}
