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

package registrystore

import (
	"net/http"

	"github.com/notaryproject/ratify/v2/pkg/metrics"
)

// reportRegistryRequestCount is a package variable so that tests can observe
// the reported metric.
var reportRegistryRequestCount = metrics.ReportRegistryRequestCount

// metricsTransport is an [http.RoundTripper] that reports every response
// received from a registry as the ratify_registry_request_count metric,
// labeled with the status code and the registry host. Requests that fail
// without a response are not counted.
type metricsTransport struct {
	base http.RoundTripper
}

// RoundTrip sends the request with the base transport and reports the
// response.
func (t *metricsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil {
		reportRegistryRequestCount(req.Context(), resp.StatusCode, req.URL.Host)
	}
	return resp, err
}

// withRequestMetrics returns a copy of client whose transport reports the
// ratify_registry_request_count metric. The given client is not modified, so
// a shared client such as [http.DefaultClient] is never instrumented globally.
func withRequestMetrics(client *http.Client) *http.Client {
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	instrumented := *client
	instrumented.Transport = &metricsTransport{base: base}
	return &instrumented
}
