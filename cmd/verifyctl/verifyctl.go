package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ibm-security-verify/verifyctl/pkg/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
)

func main() {

	logger, err := cmdutil.NewLoggerWithFileOutput()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	ctx, err := config.NewContextWithVerifyContext(context.Background(), logger)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	config, err := config.NewCLIConfig().LoadFromFile()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	verifyCmd := cmd.NewRootCmd(config, nil)
	cmdutil.ExitOnError(verifyCmd, verifyCmd.ExecuteContext(ctx))

	logger.Writer().Close()
}
