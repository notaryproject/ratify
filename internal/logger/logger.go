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

package logger

import (
	"context"
	"fmt"
	"net/http"
	"time"

	logstash "github.com/bshuster-repo/logrus-logstash-hook"
	dcontext "github.com/docker/distribution/context"
	"github.com/google/uuid"
	re "github.com/notaryproject/ratify/v2/errors"
	icontext "github.com/notaryproject/ratify/v2/internal/context"
	"github.com/sirupsen/logrus"
)

// ContextKey defines the key type used for the context.
type ContextKey string

// String returns the string representation of the context key.
func (c ContextKey) String() string {
	return string(c)
}

type componentType string

// Option is used for each component to add customized fields to the logger.
type Option struct {
	ComponentType componentType
}

// Config is the configuration for the logger.
type Config struct {
	Formatter      string                 `json:"formatter,omitempty"`
	RequestHeaders map[string]interface{} `json:"requestHeaders"`
}

var traceIDHeaderNames = make([]string, 0)

const (
	// ContextKeyTraceID is the context key for the trace ID.
	ContextKeyTraceID = ContextKey("trace-id")
	// ContextKeyComponentType is the context key for the component type.
	ContextKeyComponentType = ContextKey("component-type")
	// Executor is the component type for the executor.
	Executor componentType = "executor"
	// Server is the component type for the Ratify http server.
	Server componentType = "server"
	// CommandLine is the component type for the Ratify command line.
	CommandLine componentType = "commandLine"
	// ReferrerStore is the component type for the referrer store.
	ReferrerStore componentType = "referrerStore"
	// Cache is the component type for the cache.
	Cache componentType = "cache"
	// CertProvider is the component type for certificate provider.
	CertProvider componentType = "certificateProvider"
	// KeyManagementProvider is the component type for key management provider.
	KeyManagementProvider componentType = "keyManagementProvider"
	// AuthProvider is the component type for auth provider.
	AuthProvider componentType = "authProvider"
	// PolicyProvider is the component type for policy provider.
	PolicyProvider componentType = "policyProvider"
	// Verifier is the component type for verifier.
	Verifier componentType = "verifier"
	// Plugin is the component type for plugin.
	Plugin componentType = "plugin"

	traceIDHeaderName = "traceIDHeaderName"
)

// InitLogConfig initializes log configuration for the server.
func InitLogConfig(config Config) error {
	initTraceIDHeaders(config.RequestHeaders)
	return setFormatter(config.Formatter)
}

// InitContext initializes the context with required loggers for a request.
func InitContext(ctx context.Context, r *http.Request) context.Context {
	return setTraceID(ctx, r)
}

// GetLogger returns a logger with provided values.
func GetLogger(ctx context.Context, opt Option) dcontext.Logger {
	ctx = dcontext.WithLogger(ctx, dcontext.GetLogger(ctx, icontext.ContextKeyNamespace))
	ctx = context.WithValue(ctx, ContextKeyComponentType, opt.ComponentType)
	return dcontext.GetLogger(ctx, ContextKeyComponentType)
}

// GetTraceID returns the trace ID from the context.
func GetTraceID(ctx context.Context) string {
	traceID := ctx.Value(ContextKeyTraceID)
	if traceID == nil {
		return ""
	}
	return traceID.(string)
}

// setTraceID sets the trace ID in the context. If the trace ID is not present in the request headers, a new one is generated.
func setTraceID(ctx context.Context, r *http.Request) context.Context {
	traceID := ""
	for _, headerName := range traceIDHeaderNames {
		if traceID = r.Header.Get(headerName); traceID != "" {
			break
		}
	}
	if traceID == "" {
		traceID = uuid.New().String()
	}
	ctx = context.WithValue(ctx, ContextKeyTraceID, traceID)
	return dcontext.WithLogger(ctx, dcontext.GetLogger(ctx, ContextKeyTraceID))
}

// SetTraceIDHeader sets the trace ID in the http header.
func SetTraceIDHeader(ctx context.Context, header http.Header) http.Header {
	traceID := ctx.Value(ContextKeyTraceID)
	if traceID != nil {
		for _, headerName := range traceIDHeaderNames {
			header.Set(headerName, traceID.(string))
		}
	}
	return header
}

// initTraceIDHeaders initializes traceIDHeaderNames with the header names provided in the config.
func initTraceIDHeaders(headers map[string]interface{}) {
	if headers == nil {
		return
	}
	if _, ok := headers[traceIDHeaderName]; ok {
		if names, ok := headers[traceIDHeaderName].([]string); ok {
			traceIDHeaderNames = append(traceIDHeaderNames, names...)
		}
	}
}

// setFormatter sets the formatter for the logger.
func setFormatter(formatter string) error {
	switch formatter {
	case "text", "":
		logrus.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339Nano,
			DisableQuote:    true,
		})
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		})
	case "logstash":
		logrus.SetFormatter(&logstash.LogstashFormatter{
			Formatter: &logrus.JSONFormatter{
				TimestampFormat: time.RFC3339Nano,
			},
		})
	default:
		return re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("unsupported logging formatter: %s", formatter))
	}
	return nil
}
