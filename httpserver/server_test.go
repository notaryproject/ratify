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

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"

	ratifyerrors "github.com/ratify-project/ratify/errors"
	exconfig "github.com/ratify-project/ratify/pkg/executor/config"
	"github.com/ratify-project/ratify/pkg/executor/core"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	config "github.com/ratify-project/ratify/pkg/policyprovider/configpolicy"
	"github.com/sirupsen/logrus"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/opencontainers/go-digest"
	"github.com/ratify-project/ratify/pkg/policyprovider/types"
	"github.com/ratify-project/ratify/pkg/referrerstore"
	"github.com/ratify-project/ratify/pkg/referrerstore/mocks"
	"github.com/ratify-project/ratify/pkg/verifier"
)

const testArtifactType string = "test-type1"
const testImageNameTagged string = "localhost:5000/net-monitor:v1"

func testGetExecutor(context.Context) *core.Executor {
	return &core.Executor{
		Verifiers:      []verifier.ReferenceVerifier{},
		ReferrerStores: []referrerstore.ReferrerStore{},
		PolicyEnforcer: nil,
		Config:         nil,
	}
}

func TestNewServer_Expected(t *testing.T) {
	testAddress := "localhost:5000"
	testGetExecutor := testGetExecutor
	testCertDir := "/tmp"
	testCACertFiles := []string{"/tmp/ca.crt"}
	testCacheTTL := 6 * time.Second
	testMetricsEnabled := true
	testMetricsType := "test-metrics"
	testMetricsPort := 1010

	server, err := NewServer(context.Background(), testAddress, testGetExecutor, testCertDir, testCACertFiles, testCacheTTL, testMetricsEnabled, testMetricsType, testMetricsPort)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if server == nil {
		t.Fatalf("unexpected nil server")
	}
	if server.Address != testAddress {
		t.Fatalf("unexpected address: %s", server.Address)
	}
	if server.GetExecutor == nil {
		t.Fatalf("unexpected nil executor")
	}
	if server.CertDirectory != testCertDir {
		t.Fatalf("unexpected cert directory: %s", server.CertDirectory)
	}
	if len(server.CaCertFiles) != 1 || server.CaCertFiles[0] != testCACertFiles[0] {
		t.Fatalf("unexpected ca cert files: %v", server.CaCertFiles)
	}
	if server.CacheTTL != testCacheTTL {
		t.Fatalf("unexpected cache ttl: %v", server.CacheTTL)
	}
	if server.MetricsEnabled != testMetricsEnabled {
		t.Fatalf("unexpected metrics enabled: %v", server.MetricsEnabled)
	}
	if server.MetricsType != testMetricsType {
		t.Fatalf("unexpected metrics type: %s", server.MetricsType)
	}
	if server.MetricsPort != testMetricsPort {
		t.Fatalf("unexpected metrics port: %d", server.MetricsPort)
	}
}

func TestServer_Timeout_Failed(t *testing.T) {
	timeoutDuration := 6
	t.Run("server_timeout_fail", func(t *testing.T) {
		body := new(bytes.Buffer)

		_ = json.NewEncoder(body).Encode(externaldata.NewProviderRequest([]string{testImageNameTagged}))
		request := httptest.NewRequest(http.MethodPost, "/ratify/gatekeeper/v1/verify", bytes.NewReader(body.Bytes()))
		logrus.Infof("policies successfully created. %s", body.Bytes())

		responseRecorder := httptest.NewRecorder()

		testDigest := digest.FromString("test")
		configPolicy := config.PolicyEnforcer{
			ArtifactTypePolicies: map[string]types.ArtifactTypeVerifyPolicy{
				testArtifactType: types.AnyVerifySuccess,
			}}
		store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
			{
				ArtifactType: testArtifactType,
			}},
			ResolveMap: map[string]digest.Digest{
				"v1": testDigest,
			},
		}
		ver := &core.TestVerifier{
			CanVerifyFunc: func(at string) bool {
				return at == testArtifactType
			},
			VerifyResult: func(_ string) bool {
				time.Sleep(time.Duration(timeoutDuration) * time.Second)
				return true
			},
		}

		ex := &core.Executor{
			PolicyEnforcer: configPolicy,
			ReferrerStores: []referrerstore.ReferrerStore{store},
			Verifiers:      []verifier.ReferenceVerifier{ver},
		}

		getExecutor := func(context.Context) *core.Executor {
			return ex
		}

		server := &Server{
			GetExecutor: getExecutor,
			Context:     request.Context(),

			keyMutex: keyMutex{},
		}

		handler := contextHandler{
			context: server.Context,
			handler: processTimeout(server.verify, server.GetExecutor(nil).GetVerifyRequestTimeout(), false),
		}

		handler.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusInternalServerError {
			t.Errorf("Want status '%d', got '%d'", http.StatusInternalServerError, responseRecorder.Code)
		}
	})
}

// TestServer_MultipleSubjects_Success tests multiple subjects are verified concurrently
func TestServer_MultipleSubjects_Success(t *testing.T) {
	testImageNames := []string{"localhost:5000/net-monitor:v1", "localhost:5000/net-monitor:v2"}
	t.Run("server_multiple_subjects_success", func(t *testing.T) {
		body := new(bytes.Buffer)

		if err := json.NewEncoder(body).Encode(externaldata.NewProviderRequest(testImageNames)); err != nil {
			t.Fatalf("failed to encode request body: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/ratify/gatekeeper/v1/verify", bytes.NewReader(body.Bytes()))
		logrus.Infof("policies successfully created. %s", body.Bytes())

		responseRecorder := httptest.NewRecorder()

		testDigest := digest.FromString("test")
		configPolicy := config.PolicyEnforcer{
			ArtifactTypePolicies: map[string]types.ArtifactTypeVerifyPolicy{
				testArtifactType: types.AnyVerifySuccess,
			}}
		store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
			{
				ArtifactType: testArtifactType,
			}},
			ResolveMap: map[string]digest.Digest{
				"v1": testDigest,
				"v2": testDigest,
			},
			ExtraSubject: testImageNames[0],
		}
		ver := &core.TestVerifier{
			CanVerifyFunc: func(at string) bool {
				return at == testArtifactType
			},
			VerifyResult: func(_ string) bool {
				return true
			},
		}

		ex := &core.Executor{
			PolicyEnforcer: configPolicy,
			ReferrerStores: []referrerstore.ReferrerStore{store},
			Verifiers:      []verifier.ReferenceVerifier{ver},
			Config: &exconfig.ExecutorConfig{
				VerificationRequestTimeout: nil,
				MutationRequestTimeout:     nil,
			},
		}

		getExecutor := func(context.Context) *core.Executor {
			return ex
		}

		server := &Server{
			GetExecutor: getExecutor,
			Context:     request.Context(),

			keyMutex: keyMutex{},
		}

		handler := contextHandler{
			context: server.Context,
			handler: processTimeout(server.verify, server.GetExecutor(nil).GetVerifyRequestTimeout(), false),
		}

		handler.ServeHTTP(responseRecorder, request)
		var respBody externaldata.ProviderResponse
		if err := json.NewDecoder(responseRecorder.Result().Body).Decode(&respBody); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}
		retFirstKey := respBody.Response.Items[0].Key
		if retFirstKey != testImageNames[1] {
			t.Fatalf("Expected first subject response to be %s but got %s", testImageNames[1], retFirstKey)
		}
	})
}

func TestServer_Mutation_Success(t *testing.T) {
	timeoutDuration := 6
	testDigest := digest.FromString("test")
	testImageNameDigested := fmt.Sprintf("localhost:5000/net-monitor@%s", testDigest)
	t.Run("server_timeout_fail", func(t *testing.T) {
		body := new(bytes.Buffer)

		if err := json.NewEncoder(body).Encode(externaldata.NewProviderRequest([]string{testImageNameTagged})); err != nil {
			t.Fatalf("failed to encode request body: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/ratify/gatekeeper/v1/mutate", bytes.NewReader(body.Bytes()))
		logrus.Infof("policies successfully created. %s", body.Bytes())

		responseRecorder := httptest.NewRecorder()

		configPolicy := config.PolicyEnforcer{
			ArtifactTypePolicies: map[string]types.ArtifactTypeVerifyPolicy{
				testArtifactType: types.AnyVerifySuccess,
			}}
		store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
			{
				ArtifactType: testArtifactType,
			}},
			ResolveMap: map[string]digest.Digest{
				"v1": testDigest,
			},
		}
		ver := &core.TestVerifier{
			CanVerifyFunc: func(at string) bool {
				return at == testArtifactType
			},
			VerifyResult: func(_ string) bool {
				time.Sleep(time.Duration(timeoutDuration) * time.Second)
				return true
			},
		}

		ex := &core.Executor{
			PolicyEnforcer: configPolicy,
			ReferrerStores: []referrerstore.ReferrerStore{store},
			Verifiers:      []verifier.ReferenceVerifier{ver},
		}

		getExecutor := func(context.Context) *core.Executor {
			return ex
		}

		server := &Server{
			GetExecutor:       getExecutor,
			Context:           request.Context(),
			MutationStoreName: store.Name(),

			keyMutex: keyMutex{},
		}

		handler := contextHandler{
			context: server.Context,
			handler: processTimeout(server.mutate, server.GetExecutor(nil).GetMutationRequestTimeout(), true),
		}

		handler.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusOK {
			t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
		}

		var respBody externaldata.ProviderResponse
		if err := json.NewDecoder(responseRecorder.Result().Body).Decode(&respBody); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}
		retFirstValue := respBody.Response.Items[0].Value
		if retFirstValue != testImageNameDigested {
			t.Fatalf("Expected mutation response to be %s but got %s", testImageNameDigested, retFirstValue)
		}
	})
}

// TestServer_Mutation_ReferrerStoreConfigInvalid_Failure tests the case where the ReferrerStoreConfig is not provide
func TestServer_Mutation_ReferrerStoreConfigInvalid_Failure(t *testing.T) {
	timeoutDuration := 6
	testDigest := digest.FromString("test")
	t.Run("server_timeout_fail", func(t *testing.T) {
		body := new(bytes.Buffer)

		if err := json.NewEncoder(body).Encode(externaldata.NewProviderRequest([]string{testImageNameTagged})); err != nil {
			t.Fatalf("failed to encode request body: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/ratify/gatekeeper/v1/mutate", bytes.NewReader(body.Bytes()))
		logrus.Infof("policies successfully created. %s", body.Bytes())

		responseRecorder := httptest.NewRecorder()

		configPolicy := config.PolicyEnforcer{
			ArtifactTypePolicies: map[string]types.ArtifactTypeVerifyPolicy{
				testArtifactType: types.AnyVerifySuccess,
			}}
		store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
			{
				ArtifactType: testArtifactType,
			}},
			ResolveMap: map[string]digest.Digest{
				"v1": testDigest,
			},
		}
		ver := &core.TestVerifier{
			CanVerifyFunc: func(at string) bool {
				return at == testArtifactType
			},
			VerifyResult: func(_ string) bool {
				time.Sleep(time.Duration(timeoutDuration) * time.Second)
				return true
			},
		}

		ex := &core.Executor{
			PolicyEnforcer: configPolicy,
			ReferrerStores: []referrerstore.ReferrerStore{},
			Verifiers:      []verifier.ReferenceVerifier{ver},
		}

		getExecutor := func(context.Context) *core.Executor {
			return ex
		}

		server := &Server{
			GetExecutor:       getExecutor,
			Context:           request.Context(),
			MutationStoreName: store.Name(),

			keyMutex: keyMutex{},
		}

		handler := contextHandler{
			context: server.Context,
			handler: processTimeout(server.mutate, server.GetExecutor(nil).GetMutationRequestTimeout(), true),
		}

		handler.ServeHTTP(responseRecorder, request)
		logrus.Infof("response: %v", responseRecorder)
		if responseRecorder.Code != http.StatusOK {
			t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
		}

		var respBody externaldata.ProviderResponse
		if err := json.NewDecoder(responseRecorder.Result().Body).Decode(&respBody); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}
		retFirstErr := respBody.Response.Items[0].Error
		expectedErr := ratifyerrors.ErrorCodeConfigInvalid.WithComponentType(ratifyerrors.ReferrerStore).WithDetail("referrer store config should have at least one store").Error()
		if retFirstErr != expectedErr {
			t.Fatalf("Expected first subject error to be %s but got %s", expectedErr, retFirstErr)
		}
	})
}

func TestServer_MultipleRequestsForSameSubject_Success(t *testing.T) {
	testImageNames := []string{"localhost:5000/net-monitor:v1", "localhost:5000/net-monitor:v1"}
	t.Run("server_multiple_subjects_success", func(t *testing.T) {
		body := new(bytes.Buffer)

		if err := json.NewEncoder(body).Encode(externaldata.NewProviderRequest(testImageNames)); err != nil {
			t.Fatalf("failed to encode request body: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/ratify/gatekeeper/v1/verify", bytes.NewReader(body.Bytes()))
		logrus.Infof("policies successfully created. %s", body.Bytes())

		responseRecorder := httptest.NewRecorder()

		testDigest := digest.FromString("test")
		configPolicy := config.PolicyEnforcer{
			ArtifactTypePolicies: map[string]types.ArtifactTypeVerifyPolicy{
				testArtifactType: types.AnyVerifySuccess,
			}}
		store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
			{
				ArtifactType: testArtifactType,
			}},
			ResolveMap: map[string]digest.Digest{
				"v1": testDigest,
				"v2": testDigest,
			},
			ExtraSubject: testImageNames[0],
		}
		ver := &core.TestVerifier{
			CanVerifyFunc: func(at string) bool {
				return at == testArtifactType
			},
			VerifyResult: func(_ string) bool {
				return true
			},
		}

		verifyTimeout := 5000
		ex := &core.Executor{
			PolicyEnforcer: configPolicy,
			ReferrerStores: []referrerstore.ReferrerStore{store},
			Verifiers:      []verifier.ReferenceVerifier{ver},
			Config: &exconfig.ExecutorConfig{
				VerificationRequestTimeout: &verifyTimeout,
				MutationRequestTimeout:     nil,
			},
		}

		getExecutor := func(context.Context) *core.Executor {
			return ex
		}

		server := &Server{
			GetExecutor: getExecutor,
			Context:     request.Context(),

			keyMutex: keyMutex{},
		}

		handler := contextHandler{
			context: server.Context,
			handler: processTimeout(server.verify, server.GetExecutor(nil).GetVerifyRequestTimeout(), false),
		}

		handler.ServeHTTP(responseRecorder, request)
		var respBody externaldata.ProviderResponse
		if err := json.NewDecoder(responseRecorder.Result().Body).Decode(&respBody); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}
		retFirstKey := respBody.Response.Items[0].Key
		if retFirstKey != testImageNames[1] {
			t.Fatalf("Expected first subject response to be %s but got %s", testImageNames[1], retFirstKey)
		}
	})
}

// TestServer_Verify_ParseReference_Failure tests the case where the reference is not parseable
func TestServer_Verify_ParseReference_Failure(t *testing.T) {
	testImageNames := []string{"&&"}
	t.Run("server_verify_parsereference_failure", func(t *testing.T) {
		body := new(bytes.Buffer)

		if err := json.NewEncoder(body).Encode(externaldata.NewProviderRequest(testImageNames)); err != nil {
			t.Fatalf("failed to encode request body: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/ratify/gatekeeper/v1/verify", bytes.NewReader(body.Bytes()))
		logrus.Infof("policies successfully created. %s", body.Bytes())

		responseRecorder := httptest.NewRecorder()

		ex := &core.Executor{
			PolicyEnforcer: config.PolicyEnforcer{},
			ReferrerStores: []referrerstore.ReferrerStore{&mocks.TestStore{}},
			Verifiers:      []verifier.ReferenceVerifier{&core.TestVerifier{}},
			Config: &exconfig.ExecutorConfig{
				VerificationRequestTimeout: nil,
				MutationRequestTimeout:     nil,
			},
		}

		getExecutor := func(context.Context) *core.Executor {
			return ex
		}

		server := &Server{
			GetExecutor: getExecutor,
			Context:     request.Context(),

			keyMutex: keyMutex{},
		}

		handler := contextHandler{
			context: server.Context,
			handler: processTimeout(server.verify, server.GetExecutor(nil).GetVerifyRequestTimeout(), false),
		}

		handler.ServeHTTP(responseRecorder, request)
		var respBody externaldata.ProviderResponse
		if err := json.NewDecoder(responseRecorder.Result().Body).Decode(&respBody); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}
		retFirstKey := respBody.Response.Items[0].Key
		retFirstErr := respBody.Response.Items[0].Error
		if retFirstKey != testImageNames[0] {
			t.Fatalf("Expected first subject response to be %s but got %s", testImageNames[0], retFirstKey)
		}
		expectedErr := ratifyerrors.ErrorCodeReferenceInvalid.WithDetail("failed to parse subject reference").Error()
		if retFirstErr != expectedErr {
			t.Fatalf("Expected first subject error to be: %s,: but got %s", expectedErr, retFirstErr)
		}
	})
}

// TestServer_Verify_PolicyEnforcerConfigInvalid_Failure tests the case where the PolicyEnforcer CR is not provide
func TestServer_Verify_PolicyEnforcerConfigInvalid_Failure(t *testing.T) {
	timeoutDuration := 6
	testImageNames := []string{"net-monitor"}
	testDigest := digest.FromString("test")
	t.Run("server_timeout_fail", func(t *testing.T) {
		body := new(bytes.Buffer)

		if err := json.NewEncoder(body).Encode(externaldata.NewProviderRequest(testImageNames)); err != nil {
			t.Fatalf("failed to encode request body: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/ratify/gatekeeper/v1/verify", bytes.NewReader(body.Bytes()))
		logrus.Infof("policies successfully created. %s", body.Bytes())

		responseRecorder := httptest.NewRecorder()

		store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
			{
				ArtifactType: testArtifactType,
			}},
			ResolveMap: map[string]digest.Digest{
				"v1": testDigest,
			},
		}
		ver := &core.TestVerifier{
			CanVerifyFunc: func(at string) bool {
				return at == testArtifactType
			},
			VerifyResult: func(_ string) bool {
				time.Sleep(time.Duration(timeoutDuration) * time.Second)
				return true
			},
		}

		ex := &core.Executor{
			PolicyEnforcer: nil,
			ReferrerStores: []referrerstore.ReferrerStore{store},
			Verifiers:      []verifier.ReferenceVerifier{ver},
		}

		getExecutor := func(context.Context) *core.Executor {
			return ex
		}

		server := &Server{
			GetExecutor:       getExecutor,
			Context:           request.Context(),
			MutationStoreName: store.Name(),

			keyMutex: keyMutex{},
		}

		handler := contextHandler{
			context: server.Context,
			handler: processTimeout(server.verify, server.GetExecutor(nil).GetVerifyRequestTimeout(), false),
		}

		handler.ServeHTTP(responseRecorder, request)
		logrus.Infof("response: %v", responseRecorder)
		if responseRecorder.Code != http.StatusOK {
			t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
		}

		var respBody externaldata.ProviderResponse
		if err := json.NewDecoder(responseRecorder.Result().Body).Decode(&respBody); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}
		retFirstErr := respBody.Response.Items[0].Error
		expectedErr := ratifyerrors.ErrorCodeConfigInvalid.WithComponentType(ratifyerrors.PolicyProvider).WithDetail("policy provider config is not provided").Error()
		if retFirstErr != expectedErr {
			t.Fatalf("Expected first subject error to be %s but got %s", expectedErr, retFirstErr)
		}
	})
}

// TestServer_Verify_VerifierConfig_Failure tests the case where the VerifierConfig CR is not provide
func TestServer_Verify_VerifierConfigInvalid_Failure(t *testing.T) {
	testImageNames := []string{"net-monitor"}
	testDigest := digest.FromString("test")
	t.Run("server_timeout_fail", func(t *testing.T) {
		body := new(bytes.Buffer)

		if err := json.NewEncoder(body).Encode(externaldata.NewProviderRequest(testImageNames)); err != nil {
			t.Fatalf("failed to encode request body: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/ratify/gatekeeper/v1/verify", bytes.NewReader(body.Bytes()))
		logrus.Infof("policies successfully created. %s", body.Bytes())

		responseRecorder := httptest.NewRecorder()

		configPolicy := config.PolicyEnforcer{
			ArtifactTypePolicies: map[string]types.ArtifactTypeVerifyPolicy{
				testArtifactType: types.AnyVerifySuccess,
			}}
		store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
			{
				ArtifactType: testArtifactType,
			}},
			ResolveMap: map[string]digest.Digest{
				"v1": testDigest,
			},
		}

		ex := &core.Executor{
			PolicyEnforcer: configPolicy,
			ReferrerStores: []referrerstore.ReferrerStore{store},
			Verifiers:      []verifier.ReferenceVerifier{},
		}

		getExecutor := func(context.Context) *core.Executor {
			return ex
		}

		server := &Server{
			GetExecutor:       getExecutor,
			Context:           request.Context(),
			MutationStoreName: store.Name(),

			keyMutex: keyMutex{},
		}

		handler := contextHandler{
			context: server.Context,
			handler: processTimeout(server.verify, server.GetExecutor(nil).GetVerifyRequestTimeout(), false),
		}

		handler.ServeHTTP(responseRecorder, request)
		logrus.Infof("response: %v", responseRecorder)
		if responseRecorder.Code != http.StatusOK {
			t.Errorf("Want status '%d', got '%d'", http.StatusOK, responseRecorder.Code)
		}

		var respBody externaldata.ProviderResponse
		if err := json.NewDecoder(responseRecorder.Result().Body).Decode(&respBody); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}
		retFirstErr := respBody.Response.Items[0].Error
		expectedErr := ratifyerrors.ErrorCodeConfigInvalid.WithComponentType(ratifyerrors.Verifier).WithDetail("verifiers config should have at least one verifier").Error()
		if retFirstErr != expectedErr {
			t.Fatalf("Expected first subject error to be %s but got %s", expectedErr, retFirstErr)
		}
	})
}

// TestServe_serverGracefulShutdown tests the case where the server is shutdown gracefully
func TestServer_serverGracefulShutdown(t *testing.T) {
	// create a server that sleeps for 5 seconds before responding
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
		fmt.Fprintln(w, "request succeeded")
	}))

	// start the server
	go func() {
		_ = startServerWithGracefulShutdown(false, ts.Config, ts.Listener, "", "")
	}()

	// wait a second for server to come online
	time.Sleep(1 * time.Second)

	// create a client that makes a request to the server and validates response
	client := &http.Client{Transport: &http.Transport{}}
	go func() {
		url := "http://" + ts.Listener.Addr().String()
		res, err := client.Get(url)
		if err != nil {
			fmt.Printf("Expected no error but got %v", err)
		}

		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			fmt.Printf("Expected no error but got %v", err)
		}
		if string(body) != "request succeeded\n" {
			fmt.Printf("Expected response body to be 'request succeeded' but got %s", string(body))
		}
	}()
	// wait a second for client to make request and reach server
	time.Sleep(1 * time.Second)
	// send SIGTERM to server
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}
	err = proc.Signal(syscall.SIGTERM)
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}
	// wait some time to see shutdown logs
	time.Sleep(5 * time.Second)
}
