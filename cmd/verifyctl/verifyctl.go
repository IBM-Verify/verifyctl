package main

import (
	"fmt"
	"os"

	"github.com/vivshankar/verifyctl/pkg/cmd"
	"github.com/vivshankar/verifyctl/pkg/config"
	cmdutil "github.com/vivshankar/verifyctl/pkg/util/cmd"
)

func main() {
	config, err := config.NewCLIConfig().LoadFromFile()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	verifyCmd := cmd.NewRootCmd(config, nil)
	cmdutil.ExitOnError(verifyCmd, verifyCmd.Execute())
}
