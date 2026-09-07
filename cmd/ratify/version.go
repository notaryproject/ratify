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
	"fmt"

	"github.com/notaryproject/ratify/v2/internal/version"
	"github.com/spf13/cobra"
)

// newVersionCmd creates the `ratify version` command.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the ratify version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Version:        %s\n", version.Version)
			fmt.Fprintf(w, "Git Tag:        %s\n", version.GitTag)
			fmt.Fprintf(w, "Git Commit:     %s\n", version.GitCommitHash)
			fmt.Fprintf(w, "Git Tree State: %s\n", version.GitTreeState)
			return nil
		},
	}
}
