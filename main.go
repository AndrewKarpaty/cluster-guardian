package main

import (
	"os"

	"github.com/AndrewKarpaty/cluster-guardian/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
