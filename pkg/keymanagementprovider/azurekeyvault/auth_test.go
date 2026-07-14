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
package azurekeyvault

import (
	"fmt"
	"testing"
	"time"
)

// Vendored from https://github.com/Azure/go-autorest/blob/7dd32b67be4e6c9386b9ba7b1c44a51263f05270/autorest/adal/token_test.go
func TestParseExpiresOn(t *testing.T) {
	n := time.Now().UTC()
	amPM := "AM"
	if n.Hour() >= 12 {
		amPM = "PM"
	}
	testcases := []struct {
		Name   string
		String string
		Value  int64
	}{
		{
			Name:   "integer",
			String: "3600",
			Value:  3600,
		},
		{
			Name:   "timestamp with AM/PM",
			String: fmt.Sprintf("%d/%d/%d %d:%02d:%02d %s +00:00", n.Month(), n.Day(), n.Year(), n.Hour(), n.Minute(), n.Second(), amPM),
			Value:  n.Unix(),
		},
		{
			Name:   "timestamp without AM/PM",
			String: fmt.Sprintf("%02d/%02d/%02d %02d:%02d:%02d +00:00", n.Month(), n.Day(), n.Year(), n.Hour(), n.Minute(), n.Second()),
			Value:  n.Unix(),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.Name, func(subT *testing.T) {
			jn, err := parseExpiresOn(tc.String)
			if err != nil {
				subT.Error(err)
			}
			i, err := jn.Int64()
			if err != nil {
				subT.Error(err)
			}
			if i != tc.Value {
				subT.Logf("expected %d, got %d", tc.Value, i)
				subT.Fail()
			}
		})
	}
}
