package cmd

import (
	"fmt"
	"os"
)

func ExitOnError(err error) {
	if err == nil {
		return
	}

	fmt.Println(err.Error())
	os.Exit(1)
}
