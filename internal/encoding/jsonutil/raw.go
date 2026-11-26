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

import "encoding/json"

// RawMessage converts plugin parameters decoded from a configuration file or
// a custom resource into raw JSON that is passed through to plugin factories.
// A nil value results in nil.
func RawMessage(v any) (json.RawMessage, error) {
	switch v := v.(type) {
	case nil:
		return nil, nil
	case json.RawMessage:
		return v, nil
	}
	return json.Marshal(v)
}
