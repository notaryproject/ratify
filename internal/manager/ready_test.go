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

package manager

import (
	"testing"
	"time"
)

func TestNewReadySignal(t *testing.T) {
	rs := NewReadySignal()
	if rs == nil {
		t.Fatal("expected non-nil ReadySignal")
	}
	if rs.IsReady() {
		t.Fatal("new ReadySignal should not be ready")
	}
}

func TestReadySignal_MarkReady(t *testing.T) {
	rs := NewReadySignal()
	rs.MarkReady()
	if !rs.IsReady() {
		t.Fatal("expected IsReady() to be true after MarkReady()")
	}
}

func TestReadySignal_MarkReadyIdempotent(t *testing.T) {
	rs := NewReadySignal()
	rs.MarkReady()
	rs.MarkReady() // should not panic
	if !rs.IsReady() {
		t.Fatal("expected IsReady() to be true")
	}
}

func TestReadySignal_DoneChannel(t *testing.T) {
	rs := NewReadySignal()

	select {
	case <-rs.Done():
		t.Fatal("Done channel should not be closed before MarkReady")
	default:
	}

	rs.MarkReady()

	select {
	case <-rs.Done():
		// expected
	case <-time.After(time.Second):
		t.Fatal("Done channel should be closed after MarkReady")
	}
}

func TestReadySignal_NilReceiver(t *testing.T) {
	var rs *ReadySignal
	if rs.IsReady() {
		t.Fatal("nil receiver IsReady() should return false")
	}
	if rs.Done() != nil {
		t.Fatal("nil receiver Done() should return nil")
	}
	// Should not panic
	rs.MarkReady()
}

func TestReadySignal_Checker_NotReady(t *testing.T) {
	rs := NewReadySignal()
	checker := rs.Checker()

	if checker.Name() != managerCheckerName {
		t.Fatalf("expected checker name %q, got %q", managerCheckerName, checker.Name())
	}

	err := checker.Check()
	if err == nil {
		t.Fatal("expected error when not ready")
	}
	if err.Error() != "controller-runtime manager is not ready" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadySignal_Checker_Ready(t *testing.T) {
	rs := NewReadySignal()
	rs.MarkReady()
	checker := rs.Checker()

	if err := checker.Check(); err != nil {
		t.Fatalf("expected no error when ready, got %v", err)
	}
}
