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

package jsonutil

import (
	"encoding/json"
	"testing"
)

func TestRawMessage(t *testing.T) {
	tests := []struct {
		name    string
		in      any
		want    string
		wantErr bool
	}{
		{name: "nil", in: nil, want: ""},
		{name: "raw message", in: json.RawMessage(`{"a":1}`), want: `{"a":1}`},
		{name: "map", in: map[string]any{"a": 1}, want: `{"a":1}`},
		{name: "unsupported", in: make(chan int), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RawMessage(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RawMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if string(got) != tt.want {
				t.Fatalf("RawMessage() = %s, want %s", got, tt.want)
			}
		})
	}
}
