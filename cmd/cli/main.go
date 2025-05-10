package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "zerolarec",
	Short: "Zerolarec CLI - end to end secrets management tool",
	Long: `Zerolarec CLI is a command-line interface for managing secrets.
It provides secure access to your secrets through a gRPC interface.`,
}

var (
	configPathFlag  string
	accessTokenFlag string

	getUserIDFlag string
)

func init() {
	rootCmd.AddCommand(initCmd)

	rootCmd.PersistentFlags().StringVar(&configPathFlag, "config", "zerolarec_config.yaml", "path to the config file")
	rootCmd.PersistentFlags().StringVar(&accessTokenFlag, "access-token", "", "access token")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("error executing root command: %v\n", err)
		os.Exit(1)
	}
}
