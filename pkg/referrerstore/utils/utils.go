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
	"context"

	"github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
)

var logOpt = logger.Option{
	ComponentType: logger.ReferrerStore,
}

func ResolveSubjectDescriptor(ctx context.Context, stores *[]referrerstore.ReferrerStore, subRef common.Reference) (*ocispecs.SubjectDescriptor, error) {
	for _, referrerStore := range *stores {
		desc, err := referrerStore.GetSubjectDescriptor(ctx, subRef)
		if err == nil {
			return desc, nil
		}
		logger.GetLogger(ctx, logOpt).Warn(errors.ErrorCodeGetSubjectDescriptorFailure.NewError(errors.ReferrerStore, referrerStore.Name(), errors.EmptyLink, err, "failed to resolve the subject descriptor", errors.HideStackTrace))
	}

	return nil, errors.ErrorCodeReferrerStoreFailure.WithDetail("could not resolve descriptor for a subject from any stores").WithComponentType(errors.ReferrerStore)
}
