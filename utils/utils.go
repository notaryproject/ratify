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

package utils

import (
	"net/url"
	"strings"
)

func SanitizeString(input string) string {
	sanitized := strings.Replace(input, "\n", "", -1)
	sanitized = strings.Replace(sanitized, "\r", "", -1)
	return sanitized
}

func SanitizeURL(input url.URL) string {
	return SanitizeString(input.String())
}

func MakePtr[T any](value T) *T {
	b := value
	return &b
}
