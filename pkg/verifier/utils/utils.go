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
	"strings"

	"github.com/notaryproject/ratify/v2/internal/constants"
)

// return true if string looks like a K8s namespaced resource. e.g. namespace/name
func IsNamespacedNamed(name string) bool {
	return strings.Contains(name, constants.NamespaceSeperator)
}
