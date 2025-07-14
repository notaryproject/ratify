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
	"reflect"
	"testing"
)

func TestCopy(t *testing.T) {
	tests := []struct {
		name    string
		data    any
		want    any
		wantErr bool
	}{
		{
			name: "map to struct",
			data: map[string]any{
				"Foo": 42,
				"Bar": "test",
			},
			want: struct {
				Foo int
				Bar string
			}{
				Foo: 42,
				Bar: "test",
			},
		},
		{
			name: "struct to map",
			data: struct {
				Foo int
				Bar string
			}{
				Foo: 42,
				Bar: "test",
			},
			want: map[string]any{
				"Foo": float64(42),
				"Bar": "test",
			},
		},
		{
			name: "struct to struct",
			data: struct {
				Foo   int
				Bar   string
				Hello string
			}{
				Foo:   42,
				Bar:   "test",
				Hello: "world",
			},
			want: struct {
				Foo int
				Bar string
			}{
				Foo: 42,
				Bar: "test",
			},
		},
		{
			name: "incompatible types: string to struct",
			data: "not a struct",
			want: struct {
				Foo int
			}{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create a new instance of the type we want to copy into
			data := reflect.New(reflect.TypeOf(tt.want)).Elem()
			pointer := data.Addr().Interface()

			// copy the data into the new instance
			if err := Copy(pointer, tt.data); (err != nil) != tt.wantErr {
				t.Errorf("Copy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// check if the copy was successful by comparing the data
			value := data.Interface()
			if !reflect.DeepEqual(value, tt.want) {
				t.Errorf("Copy() = %v, want %v", data, tt.want)
			}
		})
	}
}
