package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/vivshankar/verifyctl/pkg/cmd/login"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "verifyctl",
	Short: "verifyctl controls the IBM Security Verify tenant.",
	Long: `verifyctl controls the IBM Security Verify tenant.

  Find more information at: https://github.com/vivshankar/verifyctl`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(login.NewCommand())
}
