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

package plugin

import (
	"context"
	"strings"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	sm "github.com/notaryproject/ratify/v2/pkg/referrerstore/mocks"
)

const (
	testPlugin = "test-plugin"
	testPath   = "test-path"
)

type TestExecutor struct {
	find    func(plugin string, paths []string) (string, error)
	execute func(ctx context.Context, pluginPath string, cmdArgs []string, stdinData []byte, environ []string) ([]byte, error)
}

func (e *TestExecutor) ExecutePlugin(ctx context.Context, pluginPath string, cmdArgs []string, stdinData []byte, environ []string) ([]byte, error) {
	return e.execute(ctx, pluginPath, cmdArgs, stdinData, environ)
}

func (e *TestExecutor) FindInPaths(plugin string, paths []string) (string, error) {
	return e.find(plugin, paths)
}

func TestNewVerifier_Expected(t *testing.T) {
	verifierConfig := map[string]interface{}{
		"name":             "test-verifier",
		"type":             "test-verifier",
		"artifactTypes":    "test1,test2",
		"nestedReferences": "ref1,ref2",
	}

	verifier, err := NewVerifier("1.0.0", verifierConfig, []string{})
	if err != nil {
		t.Fatalf("failed to create plugin store %v", err)
	}

	if vc, ok := verifier.(*VerifierPlugin); !ok {
		t.Fatal("type assertion failed. expected plugin verifier")
	} else if len(vc.artifactTypes) != 2 {
		t.Fatalf("expected number of artifact Types 2, actual %d", len(vc.artifactTypes))
	} else if len(vc.nestedReferences) != 2 {
		t.Fatalf("expected number of nested references is 2, actual %d", len(vc.nestedReferences))
	}
}

func TestVerify_IsSuccessTrue_Expected(t *testing.T) {
	testPlugin := "test-plugin"
	testExecutor := &TestExecutor{
		find: func(_ string, _ []string) (string, error) {
			return testPath, nil
		},
		execute: func(_ context.Context, pluginPath string, cmdArgs []string, stdinData []byte, environ []string) ([]byte, error) {
			if pluginPath != testPath {
				t.Fatalf("mismatch in plugin path expected %s actual %s", testPath, pluginPath)
			}
			if cmdArgs != nil {
				t.Fatal("cmdArgs is expected to be nil")
			}
			stdData := string(stdinData[:])
			if !strings.Contains(stdData, testPlugin) || !strings.Contains(stdData, "test-type") {
				t.Fatalf("missing config data in stdin expected to have %s actual %s", "test-plugin, test-type", stdData)
			}

			commandCheck := false
			versionCheck := false
			subjectCheck := false
			for _, env := range environ {
				if strings.Contains(env, CommandEnvKey) && strings.Contains(env, VerifyCommand) {
					commandCheck = true
				} else if strings.Contains(env, VersionEnvKey) && strings.Contains(env, "1.0.0") {
					versionCheck = true
				} else if strings.Contains(env, SubjectEnvKey) && strings.Contains(env, "localhost") {
					subjectCheck = true
				}
			}

			if !commandCheck {
				t.Fatalf("missing command env")
			}

			if !versionCheck {
				t.Fatalf("missing version env")
			}

			if !subjectCheck {
				t.Fatalf("missing subject env")
			}

			verifierResult := ` {"isSuccess":true}`
			return []byte(verifierResult), nil
		},
	}

	verifierConfig := map[string]interface{}{
		"name": testPlugin,
	}
	verifierPlugin := &VerifierPlugin{
		name:          testPlugin,
		artifactTypes: []string{"test-type"},
		version:       "1.0.0",
		executor:      testExecutor,
		rawConfig:     verifierConfig,
	}

	subject := common.Reference{
		Original: "localhost",
	}
	ref := ocispecs.ReferenceDescriptor{
		ArtifactType: "test-type",
	}

	result, err := verifierPlugin.Verify(context.Background(), subject, ref, &sm.TestStore{})

	if err != nil {
		t.Fatalf("plugin execution failed %v", err)
	}

	if !result.IsSuccess {
		t.Fatal("plugin expected to return isSuccess as true but got as false")
	}
}

func TestVerify_IsSuccessFalse_Expected(t *testing.T) {
	testPlugin := "test-plugin"
	testExecutor := &TestExecutor{
		find: func(_ string, _ []string) (string, error) {
			return testPath, nil
		},
		execute: func(_ context.Context, pluginPath string, cmdArgs []string, stdinData []byte, environ []string) ([]byte, error) {
			if pluginPath != testPath {
				t.Fatalf("mismatch in plugin path expected %s actual %s", testPath, pluginPath)
			}
			if cmdArgs != nil {
				t.Fatal("cmdArgs is expected to be nil")
			}
			stdData := string(stdinData[:])
			if !strings.Contains(stdData, testPlugin) || !strings.Contains(stdData, "test-type") {
				t.Fatalf("missing config data in stdin expected to have %s actual %s", "test-plugin, test-type", stdData)
			}

			commandCheck := false
			versionCheck := false
			subjectCheck := false
			for _, env := range environ {
				if strings.Contains(env, CommandEnvKey) && strings.Contains(env, VerifyCommand) {
					commandCheck = true
				} else if strings.Contains(env, VersionEnvKey) && strings.Contains(env, "1.0.0") {
					versionCheck = true
				} else if strings.Contains(env, SubjectEnvKey) && strings.Contains(env, "localhost") {
					subjectCheck = true
				}
			}

			if !commandCheck {
				t.Fatalf("missing command env")
			}

			if !versionCheck {
				t.Fatalf("missing version env")
			}

			if !subjectCheck {
				t.Fatalf("missing subject env")
			}

			verifierResult := ` {"isSuccess":false}`
			return []byte(verifierResult), nil
		},
	}

	verifierConfig := map[string]interface{}{
		"name": testPlugin,
	}
	verifierPlugin := &VerifierPlugin{
		name:          testPlugin,
		artifactTypes: []string{"test-type"},
		version:       "1.0.0",
		executor:      testExecutor,
		rawConfig:     verifierConfig,
	}

	subject := common.Reference{
		Original: "localhost",
	}
	ref := ocispecs.ReferenceDescriptor{
		ArtifactType: "test-type",
	}

	result, err := verifierPlugin.Verify(context.Background(), subject, ref, &sm.TestStore{})

	if err != nil {
		t.Fatalf("plugin execution failed %v", err)
	}

	if result.IsSuccess {
		t.Fatal("plugin expected to return isSuccess as false but got as true")
	}
}
