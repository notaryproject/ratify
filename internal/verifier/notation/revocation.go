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

import (
	"net/http"

	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-go/dir"
	notationcrl "github.com/notaryproject/notation-go/verifier/crl"
)

func createCRLFetcher(cacheEnabled bool) (corecrl.Fetcher, error) {
	fetcher, err := corecrl.NewHTTPFetcher(&http.Client{})
	if err != nil {
		return nil, err
	}
	if !cacheEnabled {
		return fetcher, nil
	}

	cacheRoot, err := dir.CacheFS().SysPath(dir.PathCRLCache)
	if err != nil {
		return nil, err
	}
	cache, err := notationcrl.NewFileCache(cacheRoot)
	if err != nil {
		return nil, err
	}
	fetcher.Cache = cache
	return fetcher, nil
}
