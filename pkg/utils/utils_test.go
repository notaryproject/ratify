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
	"fmt"
	"strings"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/opencontainers/go-digest"
)

const (
	testRepo      = "docker.io/test/hello:v1"
	testNamespace = "test"
)

func TestParseDigest_ReturnsExpected(t *testing.T) {
	dg, err := ParseDigest("sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb")

	if dg == "" || err != nil {
		t.Fatalf("digest parsing failed. expected digest but returned error %v", err)
	}

	dg, err = ParseDigest("sha256:c570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb")

	if dg != "" || err == nil {
		t.Fatal("digest parsing expected to fail but succeeded")
	}
}

func TestParseSubjectReference_ReturnsExpected(t *testing.T) {
	getDigest := func(dig string) digest.Digest {
		dg, _ := digest.Parse(dig)
		return dg
	}
	testcases := []struct {
		input          string
		output         common.Reference
		isDefaultTest  bool
		expectedErrMsg string
	}{
		{
			input: "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
			output: common.Reference{
				Path:   "localhost:5000/net-monitor",
				Digest: getDigest("sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb"),
			},
		},
		{
			input: "net-monitor@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
			output: common.Reference{
				Path:   "docker.io/library/net-monitor",
				Digest: getDigest("sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb"),
			},
			isDefaultTest: true,
		},
		{
			input:          "/localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
			output:         common.Reference{},
			expectedErrMsg: "failed to parse subject reference",
		},
		{
			input: "localhost:5000/net-monitor:v1",
			output: common.Reference{
				Path:   "localhost:5000/net-monitor",
				Tag:    "v1",
				Digest: "",
			},
		},
		{
			input:          "localhost:5000/net&monitor:v1",
			output:         common.Reference{},
			expectedErrMsg: "failed to parse subject reference",
		},
		{
			input: "hello-world",
			output: common.Reference{
				Path: "docker.io/library/hello-world",
				Tag:  "latest",
			},
		},
		{
			input: "prom/prometheus",
			output: common.Reference{
				Path: "docker.io/prom/prometheus",
				Tag:  "latest",
			},
		},
	}

	for _, testcase := range testcases {
		actual, err := ParseSubjectReference(testcase.input)
		if err != nil {
			if testcase.expectedErrMsg == "" {
				t.Fatalf("parsing subject reference failed with err %v", err)
			} else if !strings.Contains(err.Error(), testcase.expectedErrMsg) {
				t.Fatalf("parsing subject reference expected to fail with err %v actual %v", testcase.expectedErrMsg, err)
			}
		} else {
			if actual.Path != testcase.output.Path {
				t.Fatalf("parsing subject reference failed expected path %v actual %v", testcase.output.Path, actual.Path)
			}

			if actual.Tag != testcase.output.Tag {
				t.Fatalf("parsing subject reference failed expected tag %v actual %v", testcase.output.Tag, actual.Tag)
			}

			if actual.Digest != testcase.output.Digest {
				t.Fatalf("parsing subject reference failed expected digest %v actual %v", testcase.output.Digest, actual.Digest)
			}
		}
	}
}

func TestTrimSpaceAndToLower_ReturnsExpected(t *testing.T) {
	testcases := []struct {
		input  string
		output string
	}{
		{
			input:  "Notary ",
			output: "notary",
		},
		{
			input:  " AzureKeyvault ",
			output: "azurekeyvault",
		},
	}

	for _, testcase := range testcases {
		actual := TrimSpaceAndToLower(testcase.input)
		if testcase.output != actual {
			t.Fatalf("TrimSpaceAndToLower output expected %v actual %v", testcase.input, actual)
		}
	}
}

func TestParseRequestKey(t *testing.T) {
	testCases := []struct {
		name   string
		key    string
		result RequestKey
	}{
		{
			name: "namespaced image",
			key:  fmt.Sprintf("[%s]%s", testNamespace, testRepo),
			result: RequestKey{
				Subject:   testRepo,
				Namespace: testNamespace,
			},
		},
		{
			name: "clustered image",
			key:  testRepo,
			result: RequestKey{
				Subject:   testRepo,
				Namespace: "",
			},
		},
		{
			name: "no valid image",
			key:  fmt.Sprintf("[%s]", testNamespace),
			result: RequestKey{
				Subject:   "",
				Namespace: testNamespace,
			},
		},
		{
			name:   "empty string",
			key:    "",
			result: RequestKey{},
		},
		{
			name:   "invalid key",
			key:    "\n",
			result: RequestKey{},
		},
	}

	for _, tc := range testCases {
		result, _ := ParseRequestKey(tc.key)
		if result.Subject != tc.result.Subject {
			t.Fatalf("ParseRequestKey output expected %v actual %v", tc.result.Subject, result.Subject)
		}
	}
}
