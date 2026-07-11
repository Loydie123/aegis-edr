package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	Version    = "unknown"
	CommitHash = "unknown"
	BuildTime  = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "aegis",
		Short: "AEGIS Endpoint Detection and Response Client",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("AEGIS CLI Client version %s (%s) built on %s\n", Version, CommitHash, BuildTime)
			fmt.Println("Use 'aegis --help' for usage details.")
		},
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
