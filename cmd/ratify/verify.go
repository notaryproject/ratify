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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/notaryproject/ratify/v2/internal/executor"
	"github.com/spf13/cobra"
)

const (
	outputText = "text"
	outputJSON = "json"

	configFileName = "config.json"
	configFileDir  = ".ratify"
)

// verifyOptions holds the parsed flags for the `ratify verify` command.
type verifyOptions struct {
	subject    string
	configPath string
	output     string
}

// newVerifyCmd creates the `ratify verify` command.
func newVerifyCmd() *cobra.Command {
	opts := &verifyOptions{}
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an artifact against the configured verifiers and policy",
		Long: `Verify resolves the given subject artifact, verifies all associated
artifacts (such as signatures and attestations) using the configured verifiers,
and evaluates the results against the configured policy.

The command exits with a non-zero status code if the artifact does not satisfy
the policy or if an error occurs during verification.`,
		Example: `  # Verify an artifact using the default configuration file
  ratify verify --subject myregistry.io/repo@sha256:abc123

  # Verify an artifact using a custom configuration file and JSON output
  ratify verify --subject myregistry.io/repo:v1 --config ./config.json --output json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerify(cmd, opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.subject, "subject", "s", "", "subject artifact reference to verify (required)")
	flags.StringVarP(&opts.configPath, "config", "c", "", "path to the ratify configuration file (default \"$HOME/.ratify/config.json\")")
	flags.StringVarP(&opts.output, "output", "o", outputText, "output format, one of: text, json")
	_ = cmd.MarkFlagRequired("subject")
	return cmd
}

// runVerify executes the verification workflow for the `verify` command.
func runVerify(cmd *cobra.Command, opts *verifyOptions) error {
	if opts.output != outputText && opts.output != outputJSON {
		return fmt.Errorf("invalid output format %q: must be one of %q or %q", opts.output, outputText, outputJSON)
	}

	scopedExecutor, err := loadExecutor(opts.configPath)
	if err != nil {
		return err
	}

	result, err := scopedExecutor.ValidateArtifact(cmd.Context(), opts.subject)
	if err != nil {
		return fmt.Errorf("failed to verify artifact %q: %w", opts.subject, err)
	}

	if err := printResult(cmd.OutOrStdout(), opts.subject, opts.output, result); err != nil {
		return err
	}

	if !result.Succeeded {
		return fmt.Errorf("artifact %q failed verification", opts.subject)
	}
	return nil
}

// loadExecutor reads the configuration file and builds a scoped executor.
func loadExecutor(configPath string) (*executor.ScopedExecutor, error) {
	path, err := resolveConfigPath(configPath)
	if err != nil {
		return nil, err
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file %q: %w", path, err)
	}

	var opts executor.Options
	if err := json.Unmarshal(body, &opts); err != nil {
		return nil, fmt.Errorf("failed to parse configuration file %q: %w", path, err)
	}

	scopedExecutor, err := executor.NewScopedExecutor(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize executor: %w", err)
	}
	return scopedExecutor, nil
}

// resolveConfigPath returns the configuration file path to use. It mirrors the
// resolution order used by the Ratify Gatekeeper provider: an explicit path, the
// RATIFY_CONFIG directory, or the default "$HOME/.ratify/config.json".
func resolveConfigPath(configPath string) (string, error) {
	if configPath != "" {
		return configPath, nil
	}
	if dir := os.Getenv("RATIFY_CONFIG"); dir != "" {
		return filepath.Join(dir, configFileName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve home directory for default configuration path: %w", err)
	}
	return filepath.Join(home, configFileDir, configFileName), nil
}
