package cmd

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

func ExitOnError(cmd *cobra.Command, err error) {
	if err == nil {
		return
	}

	_, _ = io.WriteString(cmd.ErrOrStderr(), err.Error())
	_ = cmd.Usage()
	os.Exit(1)
}
