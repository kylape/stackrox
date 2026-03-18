package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  `Print version, commit, build date, and runtime information.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			info := map[string]string{
				"version":    version,
				"commit":     commit,
				"build_date": buildDate,
				"go_version": runtime.Version(),
				"os":         runtime.GOOS,
				"arch":       runtime.GOARCH,
			}

			if GetOutputFormat() == "json" || !isTerminal(os.Stdout) {
				return json.NewEncoder(os.Stdout).Encode(info)
			}

			fmt.Printf("acs version %s\n", version)
			fmt.Printf("  commit:     %s\n", commit)
			fmt.Printf("  built:      %s\n", buildDate)
			fmt.Printf("  go version: %s\n", runtime.Version())
			fmt.Printf("  os/arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}
