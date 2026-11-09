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

package httpserver

import (
	"context"
	"net/http"

	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/ratify-project/ratify/utils"
	"github.com/sirupsen/logrus"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ContextHandler defines a http handler with a context input
type ContextHandler func(ctx context.Context, w http.ResponseWriter, r *http.Request) error

// contextHandler is http handler wrappered by a context
type contextHandler struct {
	context context.Context
	handler ContextHandler
}

// ServeHTTP serves an HTTP request and implements the http.Handler interface.
func (ch *contextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sanitizedMethod := utils.SanitizeString(r.Method)
	sanitizedURL := utils.SanitizeURL(*r.URL)
	logrus.Debugf("received request %s %s ", sanitizedMethod, sanitizedURL)
	if err := ch.handler(ch.context, w, r); err != nil {
		logrus.Errorf("request %s %s failed with error %v", sanitizedMethod, sanitizedURL, err)
		if serveErr := errcode.ServeJSON(w, err); serveErr != nil {
			logrus.Errorf("request %s %s failed to send with error  %v", sanitizedMethod, sanitizedURL, serveErr)
		}
	}
}
