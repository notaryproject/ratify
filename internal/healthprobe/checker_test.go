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

package healthprobe

import (
	"errors"
	"sync"
	"testing"
)

func TestNewChecker(t *testing.T) {
	tests := []struct {
		name    string
		cName   string
		fn      func() error
		wantErr string
	}{
		{
			name:  "valid checker",
			cName: "test",
			fn:    func() error { return nil },
		},
		{
			name:    "empty name",
			cName:   "",
			fn:      func() error { return nil },
			wantErr: "checker name is required",
		},
		{
			name:    "nil function",
			cName:   "test",
			fn:      nil,
			wantErr: "checker function is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewChecker(tt.cName, tt.fn)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("expected error %q, got %v", tt.wantErr, err)
				}
				if c != nil {
					t.Fatal("expected nil checker on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Name() != tt.cName {
				t.Fatalf("expected name %q, got %q", tt.cName, c.Name())
			}
		})
	}
}

func TestMustNewChecker_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	MustNewChecker("", nil)
}

func TestMustNewChecker_Valid(t *testing.T) {
	c := MustNewChecker("ok", func() error { return nil })
	if c.Name() != "ok" {
		t.Fatalf("expected name %q, got %q", "ok", c.Name())
	}
}

func TestCheckerFunc_NilReceiver(t *testing.T) {
	var c *CheckerFunc
	if c.Name() != "" {
		t.Fatal("nil receiver Name() should return empty string")
	}
	if err := c.Check(); err == nil || err.Error() != "checker is nil" {
		t.Fatalf("nil receiver Check() should return 'checker is nil', got %v", err)
	}
}

func TestCheckerFunc_NilFn(t *testing.T) {
	c := &CheckerFunc{name: "broken"}
	if err := c.Check(); err == nil || err.Error() != "checker function is nil" {
		t.Fatalf("expected 'checker function is nil', got %v", err)
	}
}

func TestCheckerFunc_ReturnsError(t *testing.T) {
	expected := errors.New("something failed")
	c := MustNewChecker("failing", func() error { return expected })
	if err := c.Check(); !errors.Is(err, expected) {
		t.Fatalf("expected %v, got %v", expected, err)
	}
}

func TestCheckerFunc_ReturnsNil(t *testing.T) {
	c := MustNewChecker("healthy", func() error { return nil })
	if err := c.Check(); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRegistry_RegisterLiveness(t *testing.T) {
	r := NewRegistry()
	c := MustNewChecker("live1", func() error { return nil })

	if err := r.RegisterLiveness(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checkers := r.LivenessCheckers()
	if len(checkers) != 1 || checkers[0].Name() != "live1" {
		t.Fatal("expected one liveness checker named 'live1'")
	}
}

func TestRegistry_RegisterReadiness(t *testing.T) {
	r := NewRegistry()
	c := MustNewChecker("ready1", func() error { return nil })

	if err := r.RegisterReadiness(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checkers := r.ReadinessCheckers()
	if len(checkers) != 1 || checkers[0].Name() != "ready1" {
		t.Fatal("expected one readiness checker named 'ready1'")
	}
}

func TestRegistry_DuplicateDetection(t *testing.T) {
	r := NewRegistry()
	target := []HealthChecker{MustNewChecker("dup", func() error { return nil })}

	err := r.register(&target, MustNewChecker("dup", func() error { return nil }))
	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}
	if err.Error() != `checker "dup" is already registered` {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRegistry_Register_EmptyName(t *testing.T) {
	r := NewRegistry()
	err := r.register(&[]HealthChecker{}, &CheckerFunc{fn: func() error { return nil }})
	if err == nil || err.Error() != "checker name is required" {
		t.Fatalf("expected empty name error, got %v", err)
	}
}

func TestRegistry_Register_NilRegistry(t *testing.T) {
	checker := MustNewChecker("live", func() error { return nil })
	target := []HealthChecker{}
	var r *Registry
	if err := r.register(&target, checker); err == nil || err.Error() != "registry is nil" {
		t.Fatalf("expected nil registry error, got %v", err)
	}
}

func TestRegistry_NilChecker(t *testing.T) {
	r := NewRegistry()
	err := r.RegisterLiveness(nil)
	if err == nil || err.Error() != "checker is nil" {
		t.Fatalf("expected 'checker is nil', got %v", err)
	}
}

func TestRegistry_SnapshotIsolation(t *testing.T) {
	r := NewRegistry()
	c1 := MustNewChecker("first", func() error { return nil })
	_ = r.RegisterLiveness(c1)

	snapshot := r.LivenessCheckers()

	c2 := MustNewChecker("second", func() error { return nil })
	_ = r.RegisterLiveness(c2)

	// Snapshot should not contain the checker added after it was taken.
	if len(snapshot) != 1 {
		t.Fatalf("snapshot should have 1 checker, got %d", len(snapshot))
	}

	// New snapshot should have both.
	current := r.LivenessCheckers()
	if len(current) != 2 {
		t.Fatalf("current should have 2 checkers, got %d", len(current))
	}
}

func TestRegistry_NilRegistry(t *testing.T) {
	var r *Registry
	if checkers := r.LivenessCheckers(); checkers != nil {
		t.Fatal("nil registry LivenessCheckers() should return nil")
	}
	if checkers := r.ReadinessCheckers(); checkers != nil {
		t.Fatal("nil registry ReadinessCheckers() should return nil")
	}
}

func TestRegistry_ConcurrentAccess(_ *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c := MustNewChecker(
				// Use unique names to avoid duplicate error
				errors.New("checker").Error()+string(rune('A'+idx)),
				func() error { return nil },
			)
			_ = r.RegisterLiveness(c)
			_ = r.LivenessCheckers()
		}(i)
	}
	wg.Wait()
}
