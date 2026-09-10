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
	"github.com/spf13/cobra"
)

// newRootCmd creates the root `ratify` command and wires up its subcommands.
func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ratify",
		Short: "Ratify is a verification engine for supply chain artifacts",
		Long: `Ratify verifies supply chain artifacts (such as signatures and
attestations) against a configurable set of verifiers, stores, and policies.

The CLI is built on top of the ratify-go library and shares the same
configuration format as the Ratify Gatekeeper provider.`,
		// Usage is only helpful for flag/argument errors; keep runtime errors
		// (e.g. a failed verification) from printing the full usage text.
		SilenceUsage: true,
	}

	cmd.AddCommand(newVerifyCmd())
	cmd.AddCommand(newVersionCmd())
	return cmd
}
