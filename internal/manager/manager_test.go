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
	"context"
	"errors"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type fakeRunnableAdder struct {
	runnable manager.Runnable
	addErr   error
}

func (f *fakeRunnableAdder) Add(r manager.Runnable) error {
	f.runnable = r
	return f.addErr
}

func TestAddExecutorReadySignal(t *testing.T) {
	t.Run("no-op when the CRD manager is disabled", func(t *testing.T) {
		adder := &fakeRunnableAdder{}
		if err := addExecutorReadySignal(adder, make(chan struct{}), true); err != nil {
			t.Fatalf("addExecutorReadySignal() error = %v, want nil", err)
		}
		if adder.runnable != nil {
			t.Error("expected no runnable to be registered when the CRD manager is disabled")
		}
	})

	t.Run("no-op when the channel is nil", func(t *testing.T) {
		adder := &fakeRunnableAdder{}
		if err := addExecutorReadySignal(adder, nil, false); err != nil {
			t.Fatalf("addExecutorReadySignal() error = %v, want nil", err)
		}
		if adder.runnable != nil {
			t.Error("expected no runnable to be registered for a nil channel")
		}
	})

	t.Run("registered runnable closes the channel", func(t *testing.T) {
		adder := &fakeRunnableAdder{}
		ready := make(chan struct{})
		if err := addExecutorReadySignal(adder, ready, false); err != nil {
			t.Fatalf("addExecutorReadySignal() error = %v, want nil", err)
		}
		if adder.runnable == nil {
			t.Fatal("expected a runnable to be registered")
		}

		select {
		case <-ready:
			t.Fatal("expected the channel to stay open before the runnable runs")
		default:
		}

		if err := adder.runnable.Start(context.Background()); err != nil {
			t.Fatalf("runnable.Start() error = %v, want nil", err)
		}
		select {
		case <-ready:
		default:
			t.Error("expected the channel to be closed after the runnable runs")
		}
	})

	t.Run("propagates the add error", func(t *testing.T) {
		wantErr := errors.New("add failed")
		adder := &fakeRunnableAdder{addErr: wantErr}
		if err := addExecutorReadySignal(adder, make(chan struct{}), false); !errors.Is(err, wantErr) {
			t.Fatalf("addExecutorReadySignal() error = %v, want %v", err, wantErr)
		}
	})
}
