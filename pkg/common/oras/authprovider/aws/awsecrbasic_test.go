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

package aws

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

const (
	testUsername = "AWS"
	// #nosec G101 (Ref: https://github.com/securego/gosec/issues/295)
	testPassword              = "eyJwYXlsb2FkIjoiOThPNTFqemhaUmZWVG"
	testProxy                 = "PROXY_ENDPOINT"
	testHost                  = "123456789012.dkr.ecr.us-east-2.amazonaws.com"
	testArtifact              = testHost + "/foo:latest"
	testArtifactWithoutRegion = "public.ecr.aws/foo/foo:latest"
)

// Verifies that awsEcrBasicAuthProvider is properly constructed by mocking EcrAuthToken

func mockAuthProvider() awsEcrBasicAuthProvider {
	// Setup
	ecrAuthToken := EcrAuthToken{}
	ecrAuthToken.AuthData = make(map[string]types.AuthorizationData)

	creds := []string{testUsername, testPassword}
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(creds, ":")))

	expiry := aws.Time(time.Now().Add(time.Minute * 10))

	ecrAuthToken.AuthData[testHost] = types.AuthorizationData{
		AuthorizationToken: aws.String(encoded),
		ExpiresAt:          expiry,
		ProxyEndpoint:      aws.String(testProxy),
	}

	return awsEcrBasicAuthProvider{
		ecrAuthToken: ecrAuthToken,
		providerName: awsEcrAuthProviderName,
	}
}

func TestAwsEcrBasicAuthProvider_Create(t *testing.T) {
	authProviderConfig := map[string]interface{}{
		"name": "awsEcrBasic",
	}

	factory := AwsEcrBasicProviderFactory{}
	_, err := factory.Create(authProviderConfig)

	if err != nil {
		t.Fatalf("create failed %v", err)
	}
}

func TestAwsEcrBasicAuthProvider_Enabled(t *testing.T) {
	authProvider := mockAuthProvider()

	ctx := context.Background()

	if !authProvider.Enabled(ctx) {
		t.Fatal("enabled should have returned true but returned false")
	}

	authProvider.providerName = ""
	if authProvider.Enabled(ctx) {
		t.Fatal("enabled should have returned false but returned true")
	}
}

func TestAwsEcrBasicAuthProvider_ProvidesWithArtifact(t *testing.T) {
	authProvider := mockAuthProvider()

	_, err := authProvider.Provide(context.TODO(), testArtifact)
	if err != nil {
		t.Fatalf("encountered error: %+v", err)
	}
}

func TestAwsEcrBasicAuthProvider_ProvidesWithHost(t *testing.T) {
	authProvider := mockAuthProvider()

	_, err := authProvider.Provide(context.TODO(), testHost)
	if err != nil {
		t.Fatalf("encountered error: %+v", err)
	}
}

func TestAwsEcrBasicAuthProvider_GetAuthTokenWithoutRegion(t *testing.T) {
	authProvider := mockAuthProvider()

	// Note: AWS_REGION is optional now - will be derived from registry if not set
	// This test verifies that artifacts without region information fail appropriately
	_, err := authProvider.getEcrAuthToken(testArtifactWithoutRegion)
	if err == nil {
		t.Fatalf("expected error: %+v", err)
	}

	expectedMessage := "failed to get region from image"
	if err.Error() != expectedMessage {
		t.Fatalf("expected message: %s, instead got error: %s", expectedMessage, err.Error())
	}
}
