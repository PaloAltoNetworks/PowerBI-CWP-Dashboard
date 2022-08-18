/*
Copyright © 2022 Palo Alto Networks

*/

package main

import (
	"custom-reporting/cmd/custom-reporting"
	"fmt"
)

func main() {
	cmd, _ := custom_reporting.CreateCLI()
	if err := cmd.Execute(); err != nil {
		fmt.Printf("Failed to execute CLI: %v\n", err)
	}
}
