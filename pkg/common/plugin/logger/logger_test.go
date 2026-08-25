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
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestNewLogger_DefaultsToStdout asserts that info, debug, and warn loggers
// default to stdout.
func TestNewLogger_DefaultsToStdout(t *testing.T) {
	l := NewLogger()

	if got := l.infoLogger.Writer(); got != os.Stdout {
		t.Errorf("infoLogger writer = %v, want os.Stdout", got)
	}
	if got := l.debugLogger.Writer(); got != os.Stdout {
		t.Errorf("debugLogger writer = %v, want os.Stdout", got)
	}
	if got := l.warnLogger.Writer(); got != os.Stdout {
		t.Errorf("warnLogger writer = %v, want os.Stdout", got)
	}
}

func TestLogger_SetOutputAndWrite(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger()
	l.SetOutput(&buf)

	l.Info("hello-info")
	l.Infof("info-%d", 1)
	l.Debug("hello-debug")
	l.Debugf("debug-%d", 2)
	l.Warn("hello-warn")
	l.Warnf("warn-%d", 3)

	out := buf.String()
	for _, want := range []string{
		"INFO: hello-info",
		"INFO: info-1",
		"DEBUG: hello-debug",
		"DEBUG: debug-2",
		"WARN: hello-warn",
		"WARN: warn-3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}
