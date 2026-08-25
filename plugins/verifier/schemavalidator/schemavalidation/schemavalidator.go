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

package schemavalidation

import (
	"errors"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

// Validates content from a byte array against a URL schema or from a canonical file path
func Validate(schema string, content []byte) error {
	sl := gojsonschema.NewReferenceLoader(schema)
	dl := gojsonschema.NewBytesLoader(content)

	result, err := gojsonschema.Validate(sl, dl)

	if err != nil {
		return err
	}

	if result.Valid() {
		return nil
	}
	var e string
	for _, desc := range result.Errors() {
		e += fmt.Sprintf("%s:", desc.Description())
	}
	return errors.New(e)
}

// Validates content from a byte array against a schema from a byte array
// This is useful for testing and restricted environments as it allows loading of schemas from files
func ValidateAgainstOfflineSchema(schema []byte, content []byte) error {
	sl := gojsonschema.NewBytesLoader(schema)
	dl := gojsonschema.NewBytesLoader(content)

	result, err := gojsonschema.Validate(sl, dl)
	if err != nil {
		return err
	}

	if result.Valid() {
		return nil
	}
	var e string
	for _, desc := range result.Errors() {
		e += fmt.Sprintf("%s:", desc.Description())
	}
	return errors.New(e)
}
