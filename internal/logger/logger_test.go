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
	"errors"
	"net/http"
	"reflect"
	"runtime"
	"testing"

	logstash "github.com/bshuster-repo/logrus-logstash-hook"
	icontext "github.com/notaryproject/ratify/v2/internal/context"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	traceIDName       = "x-trace-id"
	testTraceID       = "test-trace-id"
	testComponentType = componentType("test")
)

var (
	testHeader = http.Header{}
)

func init() {
	testHeader.Set(traceIDName, testTraceID)
}

func cleanup() {
	traceIDHeaderNames = []string{}
}

func TestInitContext(t *testing.T) {
	defer cleanup()
	testCases := []struct {
		name            string
		r               *http.Request
		headerNames     []string
		expectedTraceID string
	}{
		{
			name:        "no headers set",
			headerNames: []string{},
			r:           &http.Request{},
		},
		{
			name: "request has its own traceIDHeader",
			headerNames: []string{
				traceIDName,
			},
			r: &http.Request{
				Header: testHeader,
			},
			expectedTraceID: testTraceID,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			traceIDHeaderNames = tc.headerNames
			ctx := InitContext(context.Background(), tc.r)
			traceID := GetTraceID(ctx)
			if traceID == "" {
				t.Fatalf("expected non-empty traceID, but got empty one")
			}
			if tc.expectedTraceID != "" && traceID != tc.expectedTraceID {
				t.Fatalf("expected traceID %s, but got %s", tc.expectedTraceID, traceID)
			}
		})
	}
}

func TestSetTraceIDHeader(t *testing.T) {
	defer cleanup()

	traceIDHeaderNames = []string{traceIDName}
	header := http.Header{}
	header = SetTraceIDHeader(context.Background(), header)
	if header.Get(traceIDName) != "" {
		t.Fatalf("expected empty traceID, but got %s", header.Get(traceIDName))
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyTraceID, testTraceID)
	header = SetTraceIDHeader(ctx, header)
	if header.Get(traceIDName) != testTraceID {
		t.Fatalf("expected traceID %s, but got %s", testTraceID, header.Get(traceIDName))
	}
}

func TestGetLogger(t *testing.T) {
	opt := Option{
		ComponentType: testComponentType,
	}
	logger := GetLogger(context.Background(), opt)
	entry := logger.WithError(errors.New("test"))
	ct := entry.Data["component-type"]
	if ct != testComponentType {
		t.Fatalf("expected component type %s, but got %s", testComponentType, ct)
	}
}

func TestInitTraceIDHeaders(t *testing.T) {
	defer cleanup()

	testCases := []struct {
		name          string
		headers       map[string]interface{}
		expectedNames []string
	}{
		{
			name:          "no headers set",
			headers:       nil,
			expectedNames: make([]string, 0),
		},
		{
			name: "headers do not contain traceIDHeader",
			headers: map[string]interface{}{
				traceIDHeaderName: "test",
			},
			expectedNames: make([]string, 0),
		},
		{
			name: "headers contain traceIDHeader",
			headers: map[string]interface{}{
				traceIDHeaderName: []string{traceIDName},
			},
			expectedNames: []string{traceIDName},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initTraceIDHeaders(tc.headers)
			if !reflect.DeepEqual(tc.expectedNames, traceIDHeaderNames) {
				t.Fatalf("expected traceIDHeaderNames %v, but got %v", tc.expectedNames, traceIDHeaderNames)
			}
		})
	}
}

func TestSetFormatter(t *testing.T) {
	t.Run("TextFormatter", func(t *testing.T) {
		err := setFormatter("text")
		assert.NoError(t, err)

		// Assert that the formatter is set to TextFormatter
		assert.IsType(t, &logrus.TextFormatter{}, logrus.StandardLogger().Formatter)
	})

	t.Run("JSONFormatter", func(t *testing.T) {
		err := setFormatter("json")
		assert.NoError(t, err)

		// Assert that the formatter is set to JSONFormatter
		assert.IsType(t, &logrus.JSONFormatter{}, logrus.StandardLogger().Formatter)
	})

	t.Run("LogstashFormatter", func(t *testing.T) {
		err := setFormatter("logstash")
		assert.NoError(t, err)

		// Assert that the formatter is set to LogstashFormatter
		_, ok := logrus.StandardLogger().Formatter.(*logstash.LogstashFormatter)
		assert.True(t, ok)
	})

	t.Run("UnsupportedFormatter", func(t *testing.T) {
		err := setFormatter("unsupported")
		assert.Error(t, err)

		// Assert that an error is returned for unsupported formatter
		expectedErrMsg := "unsupported logging formatter: unsupported"
		assert.Contains(t, err.Error(), expectedErrMsg)
	})
}

func TestInitLogConfig(t *testing.T) {
	config := Config{
		Formatter: "text",
		RequestHeaders: map[string]interface{}{
			traceIDHeaderName: []string{traceIDName},
		},
	}
	if err := InitLogConfig(config); err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
}

func TestGetLogger_PreservesContextFields(t *testing.T) {
	defer cleanup()
	traceIDHeaderNames = []string{traceIDName}

	ctx := InitContext(context.Background(), &http.Request{Header: testHeader})
	ctx = icontext.SetContextWithNamespace(ctx, "test-namespace")

	// Repeated calls must keep returning the same request-scoped fields.
	for i := 0; i < 3; i++ {
		entry := GetLogger(ctx, Option{ComponentType: testComponentType})
		assert.Equal(t, testTraceID, entry.Data[ContextKeyTraceID.String()])
		assert.Equal(t, "test-namespace", entry.Data["namespace"])
		assert.Equal(t, testComponentType, entry.Data[ContextKeyComponentType.String()])
		assert.Equal(t, runtime.Version(), entry.Data["go.version"])
	}
}

func TestWithLoggerGetLogger(t *testing.T) {
	t.Run("returns stored entry with its fields", func(t *testing.T) {
		base := logrus.New()
		stored := logrus.NewEntry(base).WithField("stored", "value")
		ctx := withLogger(context.Background(), stored)
		ctx = context.WithValue(ctx, ContextKeyTraceID, testTraceID)

		entry := getLogger(ctx, ContextKeyTraceID)
		assert.Same(t, base, entry.Logger)
		assert.Equal(t, "value", entry.Data["stored"])
		assert.Equal(t, testTraceID, entry.Data[ContextKeyTraceID.String()])
		assert.NotContains(t, entry.Data, "go.version")
	})

	t.Run("falls back to standard logger", func(t *testing.T) {
		entry := getLogger(context.Background(), ContextKeyTraceID)
		assert.Same(t, logrus.StandardLogger(), entry.Logger)
		assert.Equal(t, runtime.Version(), entry.Data["go.version"])
		assert.NotContains(t, entry.Data, ContextKeyTraceID.String())
	})
}
