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

package controller

import (
	"errors"
	"testing"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
)

func TestExecutorReconciler_isLeader(t *testing.T) {
	closed := make(chan struct{})
	close(closed)

	tests := []struct {
		name    string
		elected <-chan struct{}
		want    bool
	}{
		{
			name:    "nil channel is treated as elected",
			elected: nil,
			want:    true,
		},
		{
			name:    "open channel is not yet elected",
			elected: make(chan struct{}),
			want:    false,
		},
		{
			name:    "closed channel is elected",
			elected: closed,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ExecutorReconciler{Elected: tt.elected}
			if got := r.isLeader(); got != tt.want {
				t.Errorf("isLeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatusUpToDate(t *testing.T) {
	errBoom := errors.New("boom")

	tests := []struct {
		name     string
		executor *configv2alpha1.Executor
		err      error
		want     bool
	}{
		{
			name:     "success reflected",
			executor: &configv2alpha1.Executor{Status: configv2alpha1.ExecutorStatus{Succeeded: true}},
			err:      nil,
			want:     true,
		},
		{
			name:     "success not yet reflected",
			executor: &configv2alpha1.Executor{},
			err:      nil,
			want:     false,
		},
		{
			name:     "error reflected",
			executor: &configv2alpha1.Executor{Status: configv2alpha1.ExecutorStatus{Succeeded: false, Error: "boom"}},
			err:      errBoom,
			want:     true,
		},
		{
			name:     "error not yet reflected",
			executor: &configv2alpha1.Executor{},
			err:      errBoom,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statusUpToDate(tt.executor, tt.err); got != tt.want {
				t.Errorf("statusUpToDate() = %v, want %v", got, tt.want)
			}
		})
	}
}
