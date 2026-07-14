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

package azure

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAuthClient is a mock implementation of AuthClient.
type MockAuthClient struct {
	mock.Mock
}

// Mock method for ExchangeAADAccessTokenForACRRefreshToken
func (m *MockAuthClient) ExchangeAADAccessTokenForACRRefreshToken(ctx context.Context, grantType azcontainerregistry.PostContentSchemaGrantType, service string, options *azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions) (azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenResponse, error) {
	args := m.Called(ctx, grantType, service, options)
	return args.Get(0).(azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenResponse), args.Error(1)
}

// MockAuthClientFactory is a mock implementation of AuthClientFactory.
type MockAuthClientFactory struct {
	mock.Mock
}

// Mock method for CreateAuthClient
func (m *MockAuthClientFactory) CreateAuthClient(serverURL string, options *azcontainerregistry.AuthenticationClientOptions) (AuthClient, error) {
	args := m.Called(serverURL, options)
	return args.Get(0).(AuthClient), args.Error(1)
}

// MockRegistryHostGetter is a mock implementation of RegistryHostGetter.
type MockRegistryHostGetter struct {
	mock.Mock
}

// Mock method for GetRegistryHost
func (m *MockRegistryHostGetter) GetRegistryHost(artifact string) (string, error) {
	args := m.Called(artifact)
	return args.String(0), args.Error(1)
}

func TestDefaultAuthClientFactoryImpl_CreateAuthClient(t *testing.T) {
	factory := &defaultAuthClientFactoryImpl{}
	serverURL := "https://example.com"
	options := &azcontainerregistry.AuthenticationClientOptions{}

	client, err := factory.CreateAuthClient(serverURL, options)
	assert.Nil(t, err)
	assert.NotNil(t, client)
}

func TestDefaultAuthClientFactory(t *testing.T) {
	serverURL := "https://example.com"
	options := &azcontainerregistry.AuthenticationClientOptions{}

	client, err := defaultAuthClientFactory(serverURL, options)
	assert.Nil(t, err)
	assert.NotNil(t, client)
}

func TestDefaultRegistryHostGetterImpl_GetRegistryHost(t *testing.T) {
	getter := &defaultRegistryHostGetterImpl{}
	artifact := "example.azurecr.io/myArtifact"

	host, err := getter.GetRegistryHost(artifact)
	assert.Nil(t, err)
	assert.Equal(t, "example.azurecr.io", host)
}

func TestAuthenticationClientWrapper_ExchangeAADAccessTokenForACRRefreshToken(t *testing.T) {
	mockClient := new(MockAuthClient)
	wrapper := &AuthenticationClientWrapper{client: mockClient}
	ctx := context.Background()
	grantType := azcontainerregistry.PostContentSchemaGrantType("grantType")
	service := "service"
	options := &azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{}

	mockClient.On("ExchangeAADAccessTokenForACRRefreshToken", ctx, grantType, service, options).Return(azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenResponse{}, nil)

	_, err := wrapper.ExchangeAADAccessTokenForACRRefreshToken(ctx, grantType, service, options)
	assert.Nil(t, err)
}
